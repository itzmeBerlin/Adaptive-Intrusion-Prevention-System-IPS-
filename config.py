# ============================================================
#  Adaptive IPS — Global Configuration
# ============================================================
import os

# ── Network ──────────────────────────────────────────────────
INTERFACE          = os.environ.get("IPS_IFACE", "eth0")   # Override via env
BPF_FILTER         = "tcp"
PACKET_TIMEOUT     = 5          # seconds per analysis window

# ── Thresholds (rule-based layer) ────────────────────────────
SYN_FLOOD_THRESHOLD      = 100  # SYN packets per window to trigger rule
INCOMPLETE_HANDSHAKE_RATIO = 0.8  # SYN without ACK fraction
PACKET_RATE_THRESHOLD    = 500  # packets/s per source IP

# ── AI Anomaly Detection ─────────────────────────────────────
ISOLATION_FOREST_CONTAMINATION = 0.05   # expected fraction of anomalies
ANOMALY_SCORE_THRESHOLD        = -0.1   # Isolation Forest raw score cutoff
AI_RETRAIN_INTERVAL            = 300    # seconds between model retrains

# ── Mitigation ───────────────────────────────────────────────
BLOCK_TTL          = 300        # seconds before auto-unblock (self-healing)
IPTABLES_CHAIN     = "INPUT"
MAX_BLOCKED_IPS    = 1000

# ── Whitelist ────────────────────────────────────────────────
WHITELISTED_IPS    = {
    "127.0.0.1",
    "::1",
}

# ── Database ─────────────────────────────────────────────────
DB_PATH            = os.path.join(os.path.dirname(__file__), "ips_events.db")

# ── Dashboard ────────────────────────────────────────────────
DASHBOARD_HOST     = "0.0.0.0"
DASHBOARD_PORT     = 5000
DASHBOARD_DEBUG    = False
SECRET_KEY         = os.environ.get("IPS_SECRET", "adaptive-ips-secret-2024")

# ── Logging ──────────────────────────────────────────────────
LOG_FILE           = os.path.join(os.path.dirname(__file__), "ips.log")
LOG_LEVEL          = "INFO"
