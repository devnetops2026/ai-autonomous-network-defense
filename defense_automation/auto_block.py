# defense_automation/auto_block.py
import json
from pathlib import Path
from datetime import datetime

MITIGATION_FILE = Path("outputs/mitigation.json")
LOG_FILE = Path("logs/mitigation.log")

PRIORITY = {
    "alert_only": 1,
    "block_src_ip": 2,
    "isolate_host": 3,
}

def choose_higher_action(current, new):
    if current is None:
        return new
    return new if PRIORITY.get(new["recommended_action"], 0) > PRIORITY.get(current["recommended_action"], 0) else current

def load_mitigation_entries():
    if not MITIGATION_FILE.exists():
        print("mitigation.json not found")
        return []

    with open(MITIGATION_FILE, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        print("Unexpected mitigation.json format: expected a list")
        return []

    return data

def consolidate_actions(entries):
    grouped = {}

    for item in entries:
        src_ip = item.get("src_ip")
        if not src_ip:
            continue

        existing = grouped.get(src_ip)
        grouped[src_ip] = choose_higher_action(existing, item)

    return grouped

def log_action(src_ip, action, reason):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now().isoformat()} | src_ip={src_ip} | action={action} | reason={reason}\n")

def apply_action(src_ip, action, reason):
    if action == "isolate_host":
        print(f"[ACTION] ISOLATE host {src_ip} | reason={reason}")
        # real command goes here later

    elif action == "block_src_ip":
        print(f"[ACTION] BLOCK source IP {src_ip} | reason={reason}")
        # real command goes here later

    elif action == "alert_only":
        print(f"[ACTION] ALERT for {src_ip} | reason={reason}")

    else:
        print(f"[ACTION] UNKNOWN action for {src_ip}: {action}")

    log_action(src_ip, action, reason)

def main():
    entries = load_mitigation_entries()
    if not entries:
        print("No suspicious entries found")
        return

    consolidated = consolidate_actions(entries)

    print(f"Loaded {len(entries)} suspicious entries")
    print(f"Consolidated to {len(consolidated)} unique source IP actions")

    for src_ip, item in consolidated.items():
        apply_action(
            src_ip,
            item.get("recommended_action", "alert_only"),
            item.get("action_reason", "no_reason_provided")
        )

if __name__ == "__main__":
    main()