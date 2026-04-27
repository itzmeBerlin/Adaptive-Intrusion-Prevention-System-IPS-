# 🛡️ Adaptive Intrusion Prevention System (IPS)

> A hybrid, real-time network security system combining **TCP behavioral analysis**, **AI-driven anomaly detection** (Isolation Forest), and **kernel-level automated mitigation** via `iptables` — with a live web dashboard.

---

## ✨ Key Features

| Feature | Details |
|---------|---------|
| **Real-time TCP analysis** | Scapy AsyncSniffer captures live packets with BPF filter |
| **AI anomaly detection** | Isolation Forest on 10 feature dimensions — unsupervised, zero-label |
| **Hybrid decision engine** | Rule-based thresholds + AI score → ALLOW / WARN / BLOCK |
| **Kernel-level mitigation** | Automatic `iptables DROP` rules on detected attackers |
| **Self-healing** | TTL-based auto-unblock (default 300s) — no manual cleanup |
| **Whitelist** | Static + dynamic + CIDR network trust lists |
| **Live dashboard** | Flask SSE + Chart.js — real-time timeline, donut, feed, tables |
| **Audit logging** | SQLite database of every detection event |
| **Kali Linux ready** | One-command setup script, systemd service included |

---

## 📁 Project Structure

```
p m/
├── main.py                    ← Entry point — IPS engine + dashboard launcher
├── config.py                  ← All tunable parameters
├── requirements.txt
├── setup.sh                   ← Kali Linux automated setup
├── test_attack.sh             ← hping3 SYN flood simulation (attacker VM)
├── whitelist.txt              ← Persistent dynamic whitelist
│
├── ips/
│   ├── capture.py             ← Scapy AsyncSniffer + PacketWindow
│   ├── features.py            ← 10-dim TrafficFeatures extractor
│   ├── detector.py            ← Isolation Forest AI anomaly detector
│   ├── decision.py            ← Hybrid rule+AI decision engine
│   ├── mitigation.py          ← iptables DROP rule manager + self-healing
│   ├── database.py            ← SQLite event logger + query API
│   ├── whitelist.py           ← WhitelistManager + SelfHealingScheduler
│   └── health.py              ← CPU/memory monitor (psutil)
│
├── dashboard/
│   ├── app.py                 ← Flask REST API + SSE stream
│   ├── templates/index.html   ← Dashboard HTML
│   └── static/
│       ├── css/style.css      ← Dark glassmorphism UI
│       └── js/dashboard.js    ← Real-time Chart.js + SSE client
│
└── docs/
    ├── architecture.md        ← System diagram + data flow
    └── guide.md               ← Full VM setup + attack + detection guide
```

---

## 🚀 Quick Start (Kali Linux)

### 1. Install

```bash
git clone <repo-url> adaptive-ips
cd adaptive-ips
sudo bash setup.sh
```

### 2. Run

```bash
sudo python3 main.py --interface eth1
```

Dashboard → `http://localhost:5000`

### 3. Test (from attacker VM)

```bash
bash test_attack.sh 192.168.56.101 eth1
```

---

## ⚙️ Configuration (`config.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `INTERFACE` | `eth0` | Capture interface |
| `PACKET_TIMEOUT` | `5` s | Analysis window duration |
| `SYN_FLOOD_THRESHOLD` | `100` | SYNs/window to trigger rule |
| `INCOMPLETE_HANDSHAKE_RATIO` | `0.8` | Max (SYN−SYN-ACK)/SYN |
| `PACKET_RATE_THRESHOLD` | `500` | Packets/s per IP |
| `BLOCK_TTL` | `300` s | Self-healing unblock delay |
| `ISOLATION_FOREST_CONTAMINATION` | `0.05` | Expected anomaly fraction |
| `ANOMALY_SCORE_THRESHOLD` | `-0.10` | AI score cut-off |
| `AI_RETRAIN_INTERVAL` | `300` s | Model retrain frequency |

---

## 🧠 How the AI Works

```
Normal traffic accumulates → Feature vectors buffered
        ↓
Isolation Forest trains every 300s (background thread)
        ↓
Each IP's 5-second window → 10-feature vector → score_samples()
        ↓
score < -0.10 → AI anomaly flag → contributes to WARN / BLOCK
```

**Features analyzed** (per IP per 5-second window):
`syn_count` · `ack_count` · `syn_ack_count` · `fin_count` · `rst_count`
· `total_packets` · `packet_rate` · `syn_ratio` · `handshake_ratio` · `incomplete_ratio`

---

## 🖥️ Dashboard Pages

| Page | What you see |
|------|-------------|
| **Dashboard** | KPI cards, timeline chart, donut, top attackers, live feed |
| **Live Events** | Filterable table of all ALLOW/WARN/BLOCK events |
| **Blocked IPs** | Active blocks, countdown timers, manual unblock |
| **Whitelist** | Static, dynamic and CIDR trust lists |
| **AI Engine** | Model training status, sample count, CPU/RAM usage |
| **Audit Logs** | Colour-coded console of all log entries |

---

## 🔌 REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/status` | Engine status, KPIs, uptime |
| `GET` | `/api/stream` | SSE event stream (live push) |
| `GET` | `/api/events` | Detection events (`?limit=N&verdict=BLOCK`) |
| `GET` | `/api/blocked` | Currently blocked IPs |
| `POST` | `/api/block/<ip>` | Manually block an IP |
| `POST` | `/api/unblock/<ip>` | Manually unblock an IP |
| `GET` | `/api/whitelist` | All whitelist entries |
| `POST` | `/api/whitelist` | Add IP to whitelist (JSON `{ip}`) |
| `DELETE` | `/api/whitelist/<ip>` | Remove from dynamic whitelist |
| `GET` | `/api/top-attackers` | Top N IPs by BLOCK count |
| `GET` | `/api/timeline` | Per-minute event counts |
| `GET` | `/api/ai-stats` | Isolation Forest statistics |
| `GET` | `/api/health` | CPU / memory usage snapshot |
| `GET` | `/api/export/csv` | Export events to CSV file |

---

## 🧪 Testing

### Dry-run mode (no iptables changes)

```bash
sudo python3 main.py --interface eth1 --dry-run
```

### Rule-only mode (no AI)

```bash
sudo python3 main.py --interface eth1 --no-ai
```

### Validate installation

```bash
python3 check_install.py
```

### Manual SYN flood (hping3)

```bash
# Light test (50 SYNs)
sudo hping3 -S -p 80 -c 50 <victim_ip>

# Full flood (stops automatically after 30s)
bash test_attack.sh <victim_ip> eth1
```

---

## 🔍 Verify Detection

```bash
# 1. Check iptables rule was added
sudo iptables -L INPUT -n --line-numbers

# 2. Tail the log
tail -f ips.log | grep -E "BLOCK|WARN"

# 3. Query the database
sqlite3 ips_events.db \
  "SELECT datetime(timestamp,'unixepoch'), src_ip, verdict FROM events ORDER BY id DESC LIMIT 10;"
```

---

## 🔒 Security Notes

- Run as **root** (required for raw packet capture and iptables)
- Use **`--dry-run`** in shared/production environments to audit without making changes
- The **whitelist** prevents blocking your own management IP — add it before testing
- Block TTL (default 300s) ensures no permanent lockouts from false positives
- During initial AI **learning phase** (~50 packets), only rule-based detection is active

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `scapy` | ≥ 2.5.0 | Packet capture & parsing |
| `flask` | ≥ 3.0.0 | Web dashboard & REST API |
| `scikit-learn` | ≥ 1.4.0 | Isolation Forest |
| `numpy` | ≥ 1.26.0 | Feature vector operations |
| `psutil` | ≥ 5.9.0 | CPU/memory monitoring |

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

> **Uniqueness**: Unlike traditional static firewalls, this system acts as a *smart prevention layer* — it monitors TCP handshake completion in real time, adapts via AI retraining, auto-heals blocked IPs, and bridges behavioral detection directly to kernel-level enforcement via iptables — all with minimal CPU overhead optimized for small-scale Linux servers.
