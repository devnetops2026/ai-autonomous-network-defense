# AI Autonomous Network Defense

Hackathon Project - CloudHackrzz

## Features
- Network simulation using Mininet
- AI-based anomaly detection
- Automated firewall response
- DevOps pipeline for integration
- Folder-monitoring agentic AI pipeline for CSV log ingestion and JSON remediation output

## Tech Stack
- Python
- Mininet
- Machine Learning
- Linux Networking
- GitHub CI/CD

## Agentic AI Quick Start

The `agentic_ai.py` script watches a folder for CSV logs, detects suspicious sources, classifies them as `DDoS`, `Port Scan`, or `Compromised Host`, and writes JSON files into an output folder for remediation review.

### 1. Install dependencies

```bash
python -m pip install pandas numpy scikit-learn
```

`scikit-learn` is optional at runtime. If it is missing, the script falls back to a simpler heuristic anomaly scorer.

### 2. Folder layout

```text
data/
  incoming_logs/        <- drop new CSV files here
  sample_logs/          <- small hand-made sample log
  dataset/              <- larger sample attack datasets
outputs/
  agentic_json/         <- generated JSON alerts
```

### 3. Process one file immediately

```bash
python agentic_ai.py --single-file data/sample_logs/traffic_log.csv
python agentic_ai.py --single-file data/dataset/portscan_log.csv
python agentic_ai.py --single-file data/dataset/compromised_log.csv
```

### 4. Monitor a folder every 20 seconds for 2 minutes

```bash
python agentic_ai.py --logs-dir data/incoming_logs --output-dir outputs/agentic_json --poll-seconds 20 --duration-seconds 120
```

Drop CSV files into `data/incoming_logs` while the script is running. Each new file is processed once.

### 5. JSON output format

Each detection is saved as a standalone JSON file plus a batch summary JSON:

```json
{
  "timestamp": "2026-03-12 10:20:16",
  "threat_type": "DDoS",
  "affected_hosts": ["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.9"],
  "severity": "critical",
  "recommended_fix": [
    "iptables -A INPUT -s 10.0.0.9 -j DROP",
    "ufw deny from 10.0.0.9",
    "tcpdump -nn host 10.0.0.9 -c 50"
  ]
}
```

### 6. Sample logs for testing

Use the CSVs already in the repo:

- `data/sample_logs/traffic_log.csv`
- `data/dataset/portscan_log.csv`
- `data/dataset/compromised_log.csv`
- `data/dataset/ddos_log.csv`

### 7. Safe automation guidance

- Treat generated commands as recommendations, not blind production actions.
- Apply them only on a lab VM, Mininet environment, or disposable network clone first.
- Keep JSON generation separate from enforcement so another teammate can review before execution.
- Prefer logging and alerting before using host isolation commands on shared systems.
