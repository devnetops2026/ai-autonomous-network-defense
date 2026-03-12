import pandas as pd
import json
from pathlib import Path

INPUT_FILE = "data/sample_logs/traffic_log.csv"
OUTPUT_FILE = "outputs/mitigation.json"

PACKET_THRESHOLD = 300
ISOLATION_THRESHOLD = 450
SUSPICIOUS_PORTS = {22, 23, 3389}

def decide_action(reasons, packet_count, dst_port):
    # High severity
    if packet_count >= ISOLATION_THRESHOLD and "possible_syn_flood" in reasons:
        return "isolate_host", "critical_syn_flood_behavior"

    if packet_count >= ISOLATION_THRESHOLD and dst_port in SUSPICIOUS_PORTS:
        return "isolate_host", "critical_attack_on_sensitive_port"

    if len(reasons) >= 2 and packet_count >= ISOLATION_THRESHOLD:
        return "isolate_host", "multiple_high_confidence_indicators"

    # Medium severity
    if "possible_syn_flood" in reasons:
        return "block_src_ip", "suspected_syn_flood"

    if "high_packet_count" in reasons:
        return "block_src_ip", "abnormally_high_traffic_volume"

    # Low severity
    if "suspicious_destination_port" in reasons:
        return "alert_only", "access_to_sensitive_port"

    return "alert_only", "general_suspicious_activity"

def detect_anomalies(df: pd.DataFrame):
    suspicious = []

    for _, row in df.iterrows():
        reasons = []

        packet_count = int(row["packet_count"])
        dst_port = int(row["dst_port"])

        if packet_count > PACKET_THRESHOLD:
            reasons.append("high_packet_count")

        if dst_port in SUSPICIOUS_PORTS:
            reasons.append("suspicious_destination_port")

        if row["flag"] == "SYN" and packet_count > 200:
            reasons.append("possible_syn_flood")

        if reasons:
            action, action_reason = decide_action(reasons, packet_count, dst_port)

            suspicious.append({
                "timestamp": row["timestamp"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": dst_port,
                "packet_count": packet_count,
                "reasons": reasons,
                "recommended_action": action,
                "action_reason": action_reason
            })

    return suspicious

def save_output(results, output_file):
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

def main():
    df = pd.read_csv(INPUT_FILE)
    results = detect_anomalies(df)
    save_output(results, OUTPUT_FILE)

    print("\nDetection complete.")
    print(f"Suspicious entries found: {len(results)}")
    print(f"Output saved to: {OUTPUT_FILE}")

    for item in results:
        print(item)

if __name__ == "__main__":
    main()