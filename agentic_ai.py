import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover - depends on local environment
    IsolationForest = None


REQUIRED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "packet_count",
    "bytes",
}

SENSITIVE_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 3389, 5900}


@dataclass
class MonitorConfig:
    logs_dir: Path = Path("data/incoming_logs")
    output_dir: Path = Path("outputs/agentic_json")
    poll_seconds: int = 20
    duration_seconds: int = 120
    contamination: float = 0.12
    min_group_rows: int = 3


def is_private_ip(value: str) -> bool:
    try:
        return ip_address(str(value)).is_private
    except ValueError:
        return False


def parse_timestamp(series: pd.Series) -> pd.Series:
    as_text = series.astype(str).str.strip()
    numeric = pd.to_numeric(as_text, errors="coerce")
    parsed = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns]")

    if numeric.notna().any():
        numeric_dt = pd.to_datetime(numeric, unit="s", errors="coerce")
        parsed.loc[numeric.notna()] = numeric_dt.loc[numeric.notna()]

    non_numeric = numeric.isna()
    if non_numeric.any():
        parsed.loc[non_numeric] = pd.to_datetime(as_text.loc[non_numeric], errors="coerce")

    return parsed


def load_log_file(file_path: Path) -> pd.DataFrame:
    df = pd.read_csv(file_path)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"{file_path.name} is missing columns: {sorted(missing)}")

    df = df.copy()
    df["timestamp"] = parse_timestamp(df["timestamp"])
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip"])

    for column in ("src_port", "dst_port", "packet_count", "bytes"):
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    if "flag" not in df.columns:
        df["flag"] = "UNKNOWN"
    else:
        df["flag"] = df["flag"].fillna("UNKNOWN").astype(str)

    df["protocol"] = df["protocol"].fillna("UNKNOWN").astype(str).str.upper()
    return df


def build_source_features(df: pd.DataFrame) -> pd.DataFrame:
    grouped = df.groupby("src_ip", dropna=True)
    features = grouped.agg(
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        flow_count=("src_ip", "size"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        unique_protocols=("protocol", "nunique"),
        total_packets=("packet_count", "sum"),
        avg_packets=("packet_count", "mean"),
        max_packets=("packet_count", "max"),
        total_bytes=("bytes", "sum"),
        avg_bytes=("bytes", "mean"),
    ).reset_index()

    syn_ratio = (
        df.assign(is_syn=df["flag"].astype(str).str.upper().eq("SYN").astype(int))
        .groupby("src_ip")["is_syn"]
        .mean()
        .reset_index(name="syn_ratio")
    )
    sensitive_ratio = (
        df.assign(hit_sensitive=df["dst_port"].isin(SENSITIVE_PORTS).astype(int))
        .groupby("src_ip")["hit_sensitive"]
        .mean()
        .reset_index(name="sensitive_port_ratio")
    )

    features = features.merge(syn_ratio, on="src_ip", how="left")
    features = features.merge(sensitive_ratio, on="src_ip", how="left")

    features["duration_seconds"] = (
        features["last_seen"] - features["first_seen"]
    ).dt.total_seconds().clip(lower=1)
    features["packets_per_second"] = features["total_packets"] / features["duration_seconds"]
    features["bytes_per_packet"] = features["total_bytes"] / features["total_packets"].clip(lower=1)
    features["private_src"] = features["src_ip"].map(is_private_ip).astype(int)

    return features.fillna(0)


def score_anomalies(features: pd.DataFrame, contamination: float) -> pd.DataFrame:
    numeric_columns = [
        "flow_count",
        "unique_dst_ips",
        "unique_dst_ports",
        "unique_protocols",
        "total_packets",
        "avg_packets",
        "max_packets",
        "total_bytes",
        "avg_bytes",
        "syn_ratio",
        "sensitive_port_ratio",
        "duration_seconds",
        "packets_per_second",
        "bytes_per_packet",
        "private_src",
    ]

    if IsolationForest is not None and len(features) >= 5:
        model = IsolationForest(
            n_estimators=200,
            contamination=min(contamination, 0.49),
            random_state=42,
        )
        matrix = features[numeric_columns].replace([np.inf, -np.inf], 0).fillna(0)
        model.fit(matrix)
        scores = -model.score_samples(matrix)
        labels = model.predict(matrix)
        features = features.copy()
        features["anomaly_score"] = np.round(scores, 4)
        features["is_anomaly"] = labels == -1
        return features

    features = features.copy()
    volume_score = features["total_packets"].rank(pct=True)
    spread_score = features["unique_dst_ports"].rank(pct=True)
    burst_score = features["packets_per_second"].rank(pct=True)
    features["anomaly_score"] = np.round((volume_score + spread_score + burst_score) / 3, 4)
    features["is_anomaly"] = features["anomaly_score"] >= 0.75
    return features


def classify_threat(source_logs: pd.DataFrame, source_features: pd.Series) -> Tuple[str, str, List[str]]:
    unique_dst_ports = int(source_features["unique_dst_ports"])
    unique_dst_ips = int(source_features["unique_dst_ips"])
    total_packets = float(source_features["total_packets"])
    avg_packets = float(source_features["avg_packets"])
    packets_per_second = float(source_features["packets_per_second"])
    syn_ratio = float(source_features["syn_ratio"])
    sensitive_port_ratio = float(source_features["sensitive_port_ratio"])
    src_ip = source_features["src_ip"]

    reasons: List[str] = []

    if unique_dst_ports >= 15 and avg_packets <= 5:
        threat_type = "Port Scan"
        reasons.append(f"source touched {unique_dst_ports} destination ports with very small flows")
    elif (
        packets_per_second >= 120
        or (syn_ratio >= 0.6 and total_packets >= 200)
        or (total_packets >= 1200 and avg_packets >= 20)
    ):
        threat_type = "DDoS"
        reasons.append(f"traffic volume reached {int(total_packets)} packets at {packets_per_second:.1f} packets/sec")
        if syn_ratio >= 0.6:
            reasons.append("high SYN ratio suggests flooding behavior")
    else:
        threat_type = "Compromised Host"
        reasons.append(f"internal host contacted {unique_dst_ips} peers in an abnormal pattern")
        if sensitive_port_ratio >= 0.2:
            reasons.append("a notable share of connections targeted sensitive services")

    if threat_type == "Port Scan":
        severity = "medium" if unique_dst_ports < 40 else "high"
    elif threat_type == "DDoS":
        severity = "critical" if total_packets >= 1500 or packets_per_second >= 200 else "high"
    else:
        severity = "high" if unique_dst_ips >= 3 or sensitive_port_ratio >= 0.3 else "medium"

    commands = recommended_fix_commands(threat_type, src_ip, source_logs)
    return threat_type, severity, reasons


def recommended_fix_commands(threat_type: str, src_ip: str, source_logs: pd.DataFrame) -> List[str]:
    dst_ip = str(source_logs["dst_ip"].mode().iat[0]) if not source_logs["dst_ip"].mode().empty else "TARGET_IP"

    if threat_type == "DDoS":
        return [
            f"iptables -A INPUT -s {src_ip} -j DROP",
            f"ufw deny from {src_ip}",
            f"tcpdump -nn host {src_ip} -c 50",
        ]

    if threat_type == "Port Scan":
        return [
            f"iptables -A INPUT -s {src_ip} -j DROP",
            f"iptables -A INPUT -p tcp -s {src_ip} --syn -j DROP",
            f"ss -ant | findstr {src_ip}",
        ]

    return [
        f"iptables -A OUTPUT -s {src_ip} -j DROP",
        f"arp -a | findstr {src_ip}",
        f"ping -n 1 {dst_ip}",
    ]


def meets_heuristic_threshold(feature_row: pd.Series) -> bool:
    return any(
        [
            feature_row["unique_dst_ports"] >= 15 and feature_row["avg_packets"] <= 5,
            feature_row["syn_ratio"] >= 0.6 and feature_row["total_packets"] >= 200,
            feature_row["packets_per_second"] >= 120,
            feature_row["private_src"] == 1
            and feature_row["unique_dst_ips"] >= 3
            and feature_row["unique_dst_ports"] <= 5
            and feature_row["total_packets"] >= 150,
        ]
    )


def build_detection_records(source_logs: pd.DataFrame, scored_features: pd.DataFrame, min_group_rows: int) -> List[Dict[str, object]]:
    detections: List[Dict[str, object]] = []

    for _, feature_row in scored_features.iterrows():
        if not (bool(feature_row["is_anomaly"]) or meets_heuristic_threshold(feature_row)):
            continue

        src_ip = feature_row["src_ip"]
        host_logs = source_logs[source_logs["src_ip"] == src_ip].copy()

        if len(host_logs) < min_group_rows:
            continue

        threat_type, severity, reasons = classify_threat(host_logs, feature_row)
        if (
            threat_type == "Compromised Host"
            and int(feature_row["unique_dst_ips"]) < 2
            and int(feature_row["unique_dst_ports"]) <= 2
        ):
            continue

        affected_hosts = sorted({src_ip, *host_logs["dst_ip"].astype(str).tolist()})
        timestamp = feature_row["last_seen"]
        recommended_fix = recommended_fix_commands(threat_type, src_ip, host_logs)

        detections.append(
            {
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_type": threat_type,
                "affected_hosts": affected_hosts,
                "severity": severity,
                "recommended_fix": recommended_fix,
                "source_ip": src_ip,
                "anomaly_score": float(feature_row["anomaly_score"]),
                "evidence": reasons,
                "supporting_metrics": {
                    "flow_count": int(feature_row["flow_count"]),
                    "unique_dst_ips": int(feature_row["unique_dst_ips"]),
                    "unique_dst_ports": int(feature_row["unique_dst_ports"]),
                    "total_packets": int(feature_row["total_packets"]),
                    "packets_per_second": round(float(feature_row["packets_per_second"]), 2),
                    "syn_ratio": round(float(feature_row["syn_ratio"]), 2),
                },
            }
        )

    return detections


def safe_slug(text: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in text).strip("_").lower()


def write_detection_outputs(detections: List[Dict[str, object]], output_dir: Path, batch_name: str) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written_files: List[Path] = []

    for index, detection in enumerate(detections, start=1):
        timestamp = detection["timestamp"].replace(":", "-").replace(" ", "_")
        filename = f"{timestamp}_{safe_slug(detection['threat_type'])}_{index}.json"
        file_path = output_dir / filename
        with open(file_path, "w", encoding="utf-8") as handle:
            json.dump(detection, handle, indent=2)
        written_files.append(file_path)

    summary_path = output_dir / f"{batch_name}_summary.json"
    summary_payload = {
        "batch_name": batch_name,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "detections": detections,
    }
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary_payload, handle, indent=2)
    written_files.append(summary_path)

    return written_files


def process_log_file(file_path: Path, config: MonitorConfig) -> List[Path]:
    logs = load_log_file(file_path)
    if logs.empty:
        print(f"[SKIP] {file_path.name} has no usable rows")
        return []

    features = build_source_features(logs)
    scored = score_anomalies(features, config.contamination)
    detections = build_detection_records(logs, scored, config.min_group_rows)

    if not detections:
        print(f"[OK] {file_path.name}: no actionable anomalies found")
        return []

    batch_name = file_path.stem
    written_files = write_detection_outputs(detections, config.output_dir, batch_name)
    print(f"[ALERT] {file_path.name}: wrote {len(written_files)} JSON file(s)")
    return written_files


def monitor_folder(config: MonitorConfig) -> None:
    config.logs_dir.mkdir(parents=True, exist_ok=True)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    processed_files = set()
    deadline = datetime.now() + timedelta(seconds=config.duration_seconds)

    print(f"Monitoring {config.logs_dir} every {config.poll_seconds}s until {deadline.strftime('%Y-%m-%d %H:%M:%S')}")

    while True:
        csv_files = sorted(config.logs_dir.glob("*.csv"))
        new_files = [path for path in csv_files if path not in processed_files]

        for file_path in new_files:
            try:
                process_log_file(file_path, config)
            except Exception as exc:  # pragma: no cover - operator feedback path
                print(f"[ERROR] {file_path.name}: {exc}")
            finally:
                processed_files.add(file_path)

        if datetime.now() >= deadline:
            break

        time.sleep(config.poll_seconds)

    print("Monitoring window finished.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hackathon-ready agentic AI for network log monitoring.")
    parser.add_argument("--logs-dir", default="data/incoming_logs", help="Folder containing incoming CSV logs.")
    parser.add_argument("--output-dir", default="outputs/agentic_json", help="Folder for JSON remediation files.")
    parser.add_argument("--poll-seconds", type=int, default=20, help="How often to scan for new CSVs.")
    parser.add_argument("--duration-seconds", type=int, default=120, help="How long to monitor the folder.")
    parser.add_argument("--contamination", type=float, default=0.12, help="Isolation Forest anomaly rate.")
    parser.add_argument(
        "--single-file",
        default="",
        help="Process one CSV file immediately instead of monitoring a folder.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    config = MonitorConfig(
        logs_dir=Path(args.logs_dir),
        output_dir=Path(args.output_dir),
        poll_seconds=args.poll_seconds,
        duration_seconds=args.duration_seconds,
        contamination=args.contamination,
    )

    if args.single_file:
        process_log_file(Path(args.single_file), config)
        return

    monitor_folder(config)


if __name__ == "__main__":
    main()
