"""
main.py — Adaptive IPS Entry Point
====================================
Wires all modules together and starts the IPS engine + web dashboard.

Usage (on Kali Linux as root):
    sudo python3 main.py --interface eth0 --port 5000

Options
-------
  --interface  Network interface to capture on   (default: eth0)
  --port       Dashboard HTTP port               (default: 5000)
  --dry-run    Log iptables commands without executing (safe for testing)
  --no-ai      Disable AI layer (rule-based only)
  --debug      Enable Flask debug mode
"""

import argparse
import logging
import os
import sys
import signal
import threading
import time
import queue

# ── Logging setup (must happen before imports that log) ──────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ips.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("main")

# ── Workspace path ───────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

import config
from ips.capture    import PacketCapture, PacketWindow
from ips.features   import FeatureExtractor
from ips.detector   import AnomalyDetector
from ips.decision   import DecisionEngine, Verdict
from ips.mitigation import MitigationEngine
from ips.database   import Database
from ips.whitelist  import WhitelistManager
from ips.health     import HealthMonitor

# ── Import dashboard lazily (avoid Flask import cost at top) ─
from dashboard.app import create_app


# ════════════════════════════════════════════════════════════
#  IPSEngine — central orchestrator
# ════════════════════════════════════════════════════════════

class IPSEngine:
    """
    Orchestrates:
      PacketCapture → PacketWindow → FeatureExtractor
        → DecisionEngine (rules + AI) → MitigationEngine + Database
    """

    def __init__(self, interface: str, dry_run: bool = False,
                 use_ai: bool = True):
        self.interface  = interface
        self.dry_run    = dry_run
        self.use_ai     = use_ai
        self.start_time: float = 0.0
        self._running   = False

        # Module instances
        self.db         = Database()
        self.whitelist  = WhitelistManager()
        self.mitigation = MitigationEngine(dry_run=dry_run)
        self.detector   = AnomalyDetector() if use_ai else None
        self.decision   = DecisionEngine(
            detector       = self.detector or _NoopDetector(),
            on_block       = self._on_block,
            on_warn        = self._on_warn,
            collect_normal = use_ai,
        )
        self.window     = PacketWindow(window_seconds=config.PACKET_TIMEOUT)
        self.health     = HealthMonitor(db=self.db)
        self.capture    = PacketCapture(
            interface      = interface,
            packet_callback= self._packet_callback,
        )

        # SSE push callback (injected by dashboard)
        self._push_event = None

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self) -> None:
        logger.info("═" * 58)
        logger.info("  Adaptive IPS starting on interface '%s'", self.interface)
        logger.info("  AI layer: %s | dry-run: %s", self.use_ai, self.dry_run)
        logger.info("═" * 58)

        self.start_time = time.time()
        self._running   = True

        # Start sub-systems
        self.mitigation.start()
        self.health.start(engine=self)
        if self.detector:
            self.detector.start_background_trainer()

        # Analysis thread
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True, name="Analyzer"
        )
        self._analysis_thread.start()

        # Packet capture (blocks internally via AsyncSniffer)
        self.capture.start()
        logger.info("IPS engine fully started. Dashboard at http://0.0.0.0:%d", config.DASHBOARD_PORT)

    def stop(self) -> None:
        logger.info("Shutting down IPS engine …")
        self._running = False
        self.capture.stop()
        self.mitigation.stop()
        logger.info("IPS engine stopped")

    # ── Packet callback (sniffer thread) ──────────────────────

    def _packet_callback(self, pkt) -> None:
        """Receives every captured packet; adds it to the time window."""
        self.window.add(pkt)

    # ── Analysis loop (dedicated thread) ─────────────────────

    def _analysis_loop(self) -> None:
        """
        Every PACKET_TIMEOUT seconds, drain the window, extract features
        for each source IP, and run the decision engine.
        """
        while self._running:
            time.sleep(config.PACKET_TIMEOUT)
            window_end   = time.time()
            window_start = window_end - config.PACKET_TIMEOUT

            snapshot = self.window.snapshot_and_clear()

            for src_ip, pkts in snapshot.items():
                # Skip whitelisted IPs
                if self.whitelist.is_whitelisted(src_ip):
                    continue

                # Skip already-blocked IPs (avoid double processing)
                if self.mitigation.is_blocked(src_ip):
                    continue

                features = FeatureExtractor.extract(
                    src_ip, pkts, window_start, window_end
                )

                # Skip noise (< 3 packets)
                if features.total_packets < 3:
                    continue

                result = self.decision.evaluate(features)

                # Persist to DB (only WARN + BLOCK to avoid flooding)
                if result.verdict != Verdict.ALLOW:
                    self.db.log_event(result.to_dict())

                # Push to SSE
                if result.verdict != Verdict.ALLOW and self._push_event:
                    try:
                        self._push_event(result.to_dict())
                    except Exception:
                        pass

    # ── Decision callbacks ────────────────────────────────────

    def _on_block(self, result) -> None:
        ip = result.src_ip
        logger.warning("🚫 BLOCKING %s: %s", ip, result.reason)
        blocked = self.mitigation.block_ip(ip, reason=result.reason)
        if blocked:
            self.db.log_blocked(ip, result.reason,
                                auto_unblock_at=time.time() + config.BLOCK_TTL)

    def _on_warn(self, result) -> None:
        logger.warning("⚠️  WARNING  %s: %s", result.src_ip, result.reason)


# ── Noop detector for --no-ai mode ───────────────────────────

class _NoopDetector:
    """Stub that satisfies DecisionEngine's detector interface."""
    def predict(self, _f):  return False, 0.0
    def add_sample(self, _f): pass
    @property
    def is_trained(self): return False
    @property
    def sample_count(self): return 0
    @property
    def stats(self): return {"trained": False, "samples": 0,
                             "predictions": 0, "anomalies": 0,
                             "last_trained": 0}


# ════════════════════════════════════════════════════════════
#  CLI & startup
# ════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Adaptive Intrusion Prevention System"
    )
    p.add_argument("--interface", "-i", default=config.INTERFACE,
                   help="Network interface (default: %(default)s)")
    p.add_argument("--port", "-p", type=int, default=config.DASHBOARD_PORT,
                   help="Dashboard port (default: %(default)s)")
    p.add_argument("--dry-run", action="store_true",
                   help="Log iptables commands without executing")
    p.add_argument("--no-ai", action="store_true",
                   help="Disable AI anomaly detection (rule-based only)")
    p.add_argument("--debug", action="store_true",
                   help="Enable Flask debug mode")
    return p.parse_args()


def main():
    args = parse_args()

    # Override config from CLI
    config.INTERFACE      = args.interface
    config.DASHBOARD_PORT = args.port

    # ── Create IPS engine ─────────────────────────────────────
    engine = IPSEngine(
        interface = args.interface,
        dry_run   = args.dry_run,
        use_ai    = not args.no_ai,
    )

    # ── Create Flask dashboard ────────────────────────────────
    flask_app = create_app(ips_engine=engine)
    engine._push_event = flask_app.push_event

    # ── Graceful shutdown on SIGINT / SIGTERM ─────────────────
    def _shutdown(sig, frame):
        logger.info("Signal %s received — shutting down …", sig)
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Start IPS engine in background ───────────────────────
    try:
        engine.start()
    except PermissionError:
        logger.error("Permission denied — please run as root: sudo python3 main.py")
        sys.exit(1)
    except Exception as exc:
        logger.error("Failed to start capture: %s", exc)
        logger.info("Tip: Check interface name or use --dry-run for testing")
        # Continue to serve dashboard even without live capture
        engine.start_time = time.time()

    # ── Run Flask dashboard (blocking) ────────────────────────
    logger.info("Dashboard: http://0.0.0.0:%d", args.port)
    flask_app.run(
        host  = config.DASHBOARD_HOST,
        port  = args.port,
        debug = args.debug,
        use_reloader = False,    # reloader breaks threads
        threaded     = True,
    )


if __name__ == "__main__":
    main()
