import json
import time
import subprocess
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_DIR = BASE_DIR / "outputs" / "agentic_json"
LOG_FILE = BASE_DIR / "logs" / "mitigation.log"
PROCESSED_FILE = BASE_DIR / "logs" / "processed_files.json"
APPLIED_FILE = BASE_DIR / "logs" / "applied_actions.json"

SWITCHES = ["s1", "s2"]

PRIORITY = {
    "alert_only": 1,
    "close_port": 2,
    "block_src_ip": 3,
    "isolate_host": 4,
}

def load_json_file(path, default):
    if path.exists():
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default
    return default

def save_json_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def log_action(src_ip, action, reason, source_file):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(
            f"{datetime.now().isoformat()} | file={source_file} | "
            f"src_ip={src_ip} | action={action} | reason={reason}\n"
        )

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[OK] {' '.join(cmd)}")
    else:
        print(f"[ERROR] {' '.join(cmd)}")
        if result.stderr:
            print(result.stderr.strip())

def add_drop_rule(switch, src_ip, priority):
    cmd = [
        "sudo",
        "ovs-ofctl",
        "-O",
        "OpenFlow13",
        "add-flow",
        switch,
        f"priority={priority},ip,nw_src={src_ip},actions=drop"
    ]
    run_cmd(cmd)

def add_port_drop_rule(switch, port, priority=150):
    cmd = [
        "sudo",
        "ovs-ofctl",
        "-O",
        "OpenFlow13",
        "add-flow",
        switch,
        f"priority={priority},ip,tcp,tp_dst={port},actions=drop"
    ]
    run_cmd(cmd)

def choose_higher_action(current, new):
    if current is None:
        return new
    current_priority = PRIORITY.get(current.get("recommended_action"), 0)
    new_priority = PRIORITY.get(new.get("recommended_action"), 0)
    return new if new_priority > current_priority else current

def map_ai_entry_to_action(item):
    if "src_ip" in item and "recommended_action" in item:
        return {
            "src_ip": item.get("src_ip"),
            "recommended_action": item.get("recommended_action", "alert_only"),
            "action_reason": item.get("action_reason", "no_reason_provided")
        }

    source_ip = item.get("source_ip")
    severity = str(item.get("severity", "")).lower()
    threat_type = str(item.get("threat_type", "unknown_threat")).lower()

    if not source_ip:
        return None

    if "port" in threat_type and "scan" in threat_type:
        return {
            "src_ip": source_ip,
            "recommended_action": "close_port",
            "action_reason": f"{item.get('threat_type', 'Port Scan')}_{severity}",
            "target_port": 22
        }

    if severity == "critical":
        action = "isolate_host"
    elif severity == "high":
        action = "block_src_ip"
    else:
        action = "alert_only"

    return {
        "src_ip": source_ip,
        "recommended_action": action,
        "action_reason": f"{item.get('threat_type', 'unknown_threat')}_{severity}"
    }

def normalize_entries(data):
    raw_entries = []

    if isinstance(data, dict):
        if "detections" in data and isinstance(data["detections"], list):
            raw_entries = data["detections"]
        else:
            raw_entries = [data]
    elif isinstance(data, list):
        raw_entries = data
    else:
        return []

    normalized = []
    for item in raw_entries:
        mapped = map_ai_entry_to_action(item)
        if mapped:
            normalized.append(mapped)

    return normalized

def consolidate_actions(entries):
    grouped = {}
    for item in entries:
        src_ip = item.get("src_ip")
        if not src_ip:
            continue
        existing = grouped.get(src_ip)
        grouped[src_ip] = choose_higher_action(existing, item)
    return grouped

def apply_action(src_ip, action, reason, source_file, applied_actions, item=None):
    key = f"{src_ip}:{action}"

    if action == "close_port" and item is not None:
        key = f"{action}:{item.get('target_port', 22)}"

    if key in applied_actions:
        print(f"[SKIP] Already applied {key}")
        return

    if action == "isolate_host":
        print(f"[ACTION] ISOLATE host {src_ip} | reason={reason}")
        for switch in SWITCHES:
            add_drop_rule(switch, src_ip, priority=200)

    elif action == "block_src_ip":
        print(f"[ACTION] BLOCK source IP {src_ip} | reason={reason}")
        add_drop_rule("s1", src_ip, priority=100)

    elif action == "close_port":
        target_port = 22
        if item is not None:
            target_port = item.get("target_port", 22)

        print(f"[ACTION] CLOSE port {target_port} | reason={reason}")
        for switch in SWITCHES:
            add_port_drop_rule(switch, target_port, priority=150)

    elif action == "alert_only":
        print(f"[ACTION] ALERT for {src_ip} | reason={reason}")

    else:
        print(f"[SKIP] Unknown action for {src_ip}: {action}")
        return

    applied_actions.append(key)
    log_action(src_ip, action, reason, source_file)

def process_new_files():
    processed_files = load_json_file(PROCESSED_FILE, [])
    applied_actions = load_json_file(APPLIED_FILE, [])

    json_files = sorted(INPUT_DIR.glob("*.json"))
    if not json_files:
        print("No JSON files found.")
        return

    for file_path in json_files:
        if file_path.name in processed_files:
            continue

        print(f"\n[PROCESSING] {file_path.name}")
        data = load_json_file(file_path, None)
        if data is None:
            print(f"[SKIP] Could not parse {file_path.name}")
            processed_files.append(file_path.name)
            continue

        entries = normalize_entries(data)
        if not entries:
            print(f"[SKIP] No actionable entries in {file_path.name}")
            processed_files.append(file_path.name)
            continue

        consolidated = consolidate_actions(entries)

        for src_ip, item in consolidated.items():
            apply_action(
                src_ip=src_ip,
                action=item.get("recommended_action", "alert_only"),
                reason=item.get("action_reason", "no_reason_provided"),
                source_file=file_path.name,
                applied_actions=applied_actions,
                item=item
            )

        processed_files.append(file_path.name)

    save_json_file(PROCESSED_FILE, processed_files)
    save_json_file(APPLIED_FILE, applied_actions)

if __name__ == "__main__":
    process_new_files()