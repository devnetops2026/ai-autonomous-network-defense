import pandas as pd
import json
from pathlib import Path

INPUT_FILE = "data/sample_logs/traffic_log.csv"
OUTPUT_FILE = "outputs/mitigation.json"

PACKET_THRESHOLD = 300
SUSPICIOUS_PORTS = {22, 23, 3389}

def detect_anomalies(df: pd.DataFrame):
    suspicious = []

    for _, row in df.iterrows():
        reasons = []

        if row["packet_count"] > PACKET_THRESHOLD:
            reasons.append("high_packet_count")

        if int(row["dst_port"]) in SUSPICIOUS_PORTS:
            reasons.append("suspicious_destination_port")

        if row["flag"] == "SYN" and row["packet_count"] > 200:
            reasons.append("possible_syn_flood")

        if reasons:
            suspicious.append({
                "timestamp": row["timestamp"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "dst_port": int(row["dst_port"]),
                "packet_count": int(row["packet_count"]),
                "reasons": reasons,
                "recommended_action": "block_src_ip"
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