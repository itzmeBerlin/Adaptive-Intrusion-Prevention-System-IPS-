#!/usr/bin/env python3
"""
check_install.py — Pre-flight Installation Checker
====================================================
Run this BEFORE starting the IPS to verify all dependencies and
the system environment are correctly configured.

Usage:
    python3 check_install.py
    # Or with venv:
    venv/bin/python3 check_install.py
"""

import sys
import os
import subprocess
import importlib

# ── Colour helpers ────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

OK   = f"{GREEN}  ✓{RESET}"
FAIL = f"{RED}  ✗{RESET}"
WARN = f"{YELLOW}  ⚠{RESET}"
INFO = f"{CYAN}  →{RESET}"

errors   = 0
warnings = 0


def check(label: str, ok: bool, detail: str = "", fatal: bool = True):
    global errors, warnings
    if ok:
        print(f"{OK}  {label}" + (f"  {CYAN}({detail}){RESET}" if detail else ""))
    elif fatal:
        errors += 1
        print(f"{FAIL}  {label}" + (f"  {RED}» {detail}{RESET}" if detail else ""))
    else:
        warnings += 1
        print(f"{WARN}  {label}" + (f"  {YELLOW}» {detail}{RESET}" if detail else ""))


def section(title: str):
    print(f"\n{BOLD}{CYAN}{'─'*48}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*48}{RESET}")


# ══════════════════════════════════════════════════════════════
print(f"\n{BOLD}╔══════════════════════════════════════════════╗")
print(      "║  Adaptive IPS — Installation Checker v1.0    ║")
print(      f"╚══════════════════════════════════════════════╝{RESET}")

# ── Python version ────────────────────────────────────────────
section("Python Environment")
py_ver = sys.version_info
check(
    f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro}",
    py_ver >= (3, 9),
    "requires ≥ 3.9" if py_ver < (3, 9) else "",
)
check("Running as root" if os.name != "nt" else "Platform",
      os.geteuid() == 0 if hasattr(os, "geteuid") else True,
      "iptables + raw sockets require root" if os.name != "nt" else "Windows detected",
      fatal=False)

# ── Python packages ───────────────────────────────────────────
section("Python Packages")
REQUIRED = {
    "scapy":        ("2.5.0",  "pip install scapy"),
    "flask":        ("3.0.0",  "pip install flask"),
    "sklearn":      ("1.4.0",  "pip install scikit-learn"),
    "numpy":        ("1.26.0", "pip install numpy"),
    "psutil":       ("5.9.0",  "pip install psutil"),
}

for pkg, (min_ver, install_hint) in REQUIRED.items():
    try:
        mod = importlib.import_module(pkg)
        ver = getattr(mod, "__version__", "?")
        check(f"{pkg} {ver}", True)
    except ImportError:
        check(f"{pkg} (missing)", False,
              f"{install_hint}",
              fatal=(pkg not in ("psutil",)))

# ── Project files ─────────────────────────────────────────────
section("Project Files")
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
REQUIRED_FILES = [
    "config.py",
    "main.py",
    "requirements.txt",
    "ips/__init__.py",
    "ips/capture.py",
    "ips/features.py",
    "ips/detector.py",
    "ips/decision.py",
    "ips/mitigation.py",
    "ips/database.py",
    "ips/whitelist.py",
    "ips/health.py",
    "dashboard/__init__.py",
    "dashboard/app.py",
    "dashboard/templates/index.html",
    "dashboard/static/css/style.css",
    "dashboard/static/js/dashboard.js",
]
for f in REQUIRED_FILES:
    path = os.path.join(PROJECT_ROOT, f)
    check(f, os.path.isfile(path),
          f"not found: {path}", fatal=True)

# ── Module imports ────────────────────────────────────────────
section("IPS Module Imports")
IPS_MODULES = [
    ("config",            "config"),
    ("Packet capture",    "ips.capture"),
    ("Feature extractor", "ips.features"),
    ("AI detector",       "ips.detector"),
    ("Decision engine",   "ips.decision"),
    ("Mitigation",        "ips.mitigation"),
    ("Database",          "ips.database"),
    ("Whitelist",         "ips.whitelist"),
    ("Health monitor",    "ips.health"),
    ("Dashboard app",     "dashboard.app"),
]
sys.path.insert(0, PROJECT_ROOT)
for label, mod_name in IPS_MODULES:
    try:
        importlib.import_module(mod_name)
        check(label, True)
    except Exception as exc:
        check(label, False, str(exc)[:80])

# ── Network interface ─────────────────────────────────────────
section("Network")
try:
    from scapy.all import get_if_list
    ifaces = get_if_list()
    check("Network interfaces detected", bool(ifaces),
          f"found: {', '.join(ifaces[:5])}")

    import config as cfg
    iface_ok = cfg.INTERFACE in ifaces
    check(f"Configured interface '{cfg.INTERFACE}'", iface_ok,
          f"available: {', '.join(ifaces)}" if not iface_ok else "",
          fatal=False)
except Exception as exc:
    check("Scapy interface list", False, str(exc), fatal=False)

# ── iptables ──────────────────────────────────────────────────
section("System Tools")
for tool in ["iptables", "hping3", "tcpdump"]:
    result = subprocess.run(
        ["which", tool], capture_output=True, text=True
    )
    found = result.returncode == 0
    path  = result.stdout.strip() if found else "not found"
    check(
        f"{tool}",
        found,
        path if found else f"install: apt install {tool}",
        fatal=(tool == "iptables"),
    )

# ── Database write test ───────────────────────────────────────
section("Database")
try:
    import sqlite3, tempfile
    db_path = os.path.join(PROJECT_ROOT, "ips_events.db")
    # Try a test connection
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS _check (id INTEGER PRIMARY KEY)")
    conn.execute("DROP TABLE _check")
    conn.close()
    check("SQLite read/write", True, db_path)
except Exception as exc:
    check("SQLite read/write", False, str(exc))

# ── Flask port ────────────────────────────────────────────────
section("Dashboard")
try:
    import socket
    with socket.socket() as s:
        in_use = s.connect_ex(("127.0.0.1", 5000)) == 0
    check("Port 5000 available", not in_use,
          "port 5000 already in use — use --port to change",
          fatal=False)
except Exception:
    pass

# ══════════════════════════════════════════════════════════════
print(f"\n{BOLD}{'═'*48}{RESET}")
if errors == 0 and warnings == 0:
    print(f"{GREEN}{BOLD}  ✓ All checks passed! Ready to run.{RESET}")
    print(f"\n  {INFO} sudo python3 main.py --interface eth1\n")
elif errors == 0:
    print(f"{YELLOW}{BOLD}  ⚠ {warnings} warning(s) — system may work with limitations.{RESET}")
    print(f"\n  {INFO} sudo python3 main.py --interface eth1 --dry-run\n")
else:
    print(f"{RED}{BOLD}  ✗ {errors} error(s) must be fixed before running.{RESET}")
    print(f"\n  {INFO} Run:  sudo bash setup.sh\n")
print(f"{BOLD}{'═'*48}{RESET}\n")

sys.exit(0 if errors == 0 else 1)
