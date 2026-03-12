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

The `agentic_ai.py` script watches a folder for CSV logs, detects suspicious sources, classifies them as `DDoS`, `Port Scan`, or `Compromised Host`, and writes one final JSON file per CSV into a single output folder for remediation review.

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

### 4. Monitor a folder every 20 seconds until you stop it manually

```bash
python agentic_ai.py --logs-dir data/incoming_logs --output-dir outputs/agentic_json --poll-seconds 20
```

Drop CSV files into `data/incoming_logs` while the script is running. Each new file is processed once.
Stop the script manually with `Ctrl+C`.

### 5. JSON output format

Each CSV is saved as one summary JSON file in `outputs/agentic_json`:

```json
{
  "batch_name": "traffic_log",
  "created_at": "2026-03-12 20:10:00",
  "detection_count": 1,
  "detections": [
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
- Hand off the single folder `outputs/agentic_json` to the teammate building the fix executor.
- Keep JSON generation separate from enforcement so another teammate can review before execution.
- Prefer logging and alerting before using host isolation commands on shared systems.
