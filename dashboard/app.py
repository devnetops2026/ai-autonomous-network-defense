from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd
from flask import Flask, jsonify, render_template, request

from scripts.block_ip import block_ip_action

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DATA_DIR = BASE_DIR / "data"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
DATASET_DIR = PROJECT_ROOT / "data" / "dataset"
AGENTIC_JSON_DIR = OUTPUTS_DIR / "agentic_json"

ALERTS_FILE = DATA_DIR / "alerts.csv"
SCENARIO_FILES: Dict[str, Path] = {
    "normal": DATASET_DIR / "normal_target_log.csv",
    "ddos": DATASET_DIR / "ddos_log.csv",
    "portscan": DATASET_DIR / "portscan_log.csv",
    "compromised": DATASET_DIR / "compromised_log.csv",
}
SCENARIO_SUMMARY_FILES: Dict[str, Path] = {
    "ddos": AGENTIC_JSON_DIR / "ddos_log_summary.json",
    "portscan": AGENTIC_JSON_DIR / "portscan_log_summary.json",
    "compromised": AGENTIC_JSON_DIR / "compromised_log_summary.json",
}

SCENARIO_ALIASES = {
    "normal": "normal",
    "ddos": "ddos",
    "port_scan": "portscan",
    "portscan": "portscan",
    "compromised": "compromised",
    "compromised_host": "compromised",
}

app = Flask(__name__, template_folder="templates", static_folder="static")

# This keeps current simulator selection for the live hackathon demo.
ACTIVE_SCENARIO = "normal"
ACTION_HISTORY: List[Dict[str, Any]] = []


def _normalize_scenario(value: str | None) -> str:
    if not value:
        return ACTIVE_SCENARIO
    key = value.strip().lower().replace("-", "_").replace(" ", "_")
    return SCENARIO_ALIASES.get(key, "normal")


def _to_datetime(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    use_epoch = numeric.notna().sum() >= (len(series) * 0.7)
    if use_epoch:
        return pd.to_datetime(numeric, unit="s", errors="coerce")
    return pd.to_datetime(series, errors="coerce")


def _load_traffic(scenario: str) -> pd.DataFrame:
    path = SCENARIO_FILES.get(scenario)
    if path is None or not path.exists():
        return pd.DataFrame(
            columns=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "protocol",
                "src_port",
                "dst_port",
                "packet_count",
                "bytes",
            ]
        )

    df = pd.read_csv(path)
    for col in ["src_ip", "dst_ip", "protocol"]:
        if col not in df.columns:
            df[col] = "unknown"

    for col in ["src_port", "dst_port", "packet_count", "bytes"]:
        if col not in df.columns:
            df[col] = 0

    df["timestamp"] = _to_datetime(df["timestamp"])
    df["packet_count"] = pd.to_numeric(df["packet_count"], errors="coerce").fillna(1)
    df["packet_count"] = df["packet_count"].clip(lower=0)
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0)
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["src_ip"] = df["src_ip"].fillna("unknown").astype(str)
    df["dst_ip"] = df["dst_ip"].fillna("unknown").astype(str)
    df["protocol"] = df["protocol"].fillna("UNKNOWN").astype(str).str.upper()
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp")
    return df


def _aggregate_traffic(df: pd.DataFrame) -> Dict[str, Any]:
    if df.empty:
        return {
            "timeseries": {"timestamp": [], "packets": [], "bytes": []},
            "protocol_distribution": {"protocols": [], "counts": []},
            "top_talkers": {"ips": [], "packets": []},
            "port_usage": {"ports": [], "packets": []},
        }

    per_second = (
        df.set_index("timestamp")
        .resample("1s")
        .agg({"packet_count": "sum", "bytes": "sum"})
        .reset_index()
    )

    protocol_dist = df.groupby("protocol")["packet_count"].sum().reset_index()
    top_talkers = (
        df.groupby("src_ip")["packet_count"]
        .sum()
        .reset_index()
        .sort_values("packet_count", ascending=False)
        .head(8)
    )
    port_usage = (
        df.dropna(subset=["dst_port"])
        .groupby("dst_port")["packet_count"]
        .sum()
        .reset_index()
        .sort_values("packet_count", ascending=False)
        .head(12)
    )

    return {
        "timeseries": {
            "timestamp": per_second["timestamp"].dt.strftime("%H:%M:%S").tolist(),
            "packets": per_second["packet_count"].round(2).tolist(),
            "bytes": per_second["bytes"].round(2).tolist(),
        },
        "protocol_distribution": {
            "protocols": protocol_dist["protocol"].tolist(),
            "counts": protocol_dist["packet_count"].round(2).tolist(),
        },
        "top_talkers": {
            "ips": top_talkers["src_ip"].tolist(),
            "packets": top_talkers["packet_count"].round(2).tolist(),
        },
        "port_usage": {
            "ports": port_usage["dst_port"].astype("Int64").astype(str).tolist(),
            "packets": port_usage["packet_count"].round(2).tolist(),
        },
    }


def _metrics(df: pd.DataFrame, scenario: str, alerts_count: int) -> Dict[str, Any]:
    if df.empty:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "flows": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "peak_packets_per_second": 0,
            "avg_packet_size": 0,
            "risk_score": 0,
            "health": "Unknown",
        }

    per_second = df.set_index("timestamp").resample("1s").agg({"packet_count": "sum"})
    total_packets = float(df["packet_count"].sum())
    total_bytes = float(df["bytes"].sum())

    scenario_risk_base = {
        "normal": 15,
        "ddos": 85,
        "portscan": 70,
        "compromised": 90,
    }

    peak_pps = float(per_second["packet_count"].max()) if not per_second.empty else 0.0
    alert_factor = min(alerts_count * 4, 20)
    throughput_factor = min(peak_pps / 50, 20)
    risk_score = min(int(scenario_risk_base.get(scenario, 30) + alert_factor + throughput_factor), 100)

    if risk_score >= 85:
        health = "Critical"
    elif risk_score >= 65:
        health = "Degraded"
    elif risk_score >= 35:
        health = "Warning"
    else:
        health = "Healthy"

    return {
        "total_packets": int(total_packets),
        "total_bytes": int(total_bytes),
        "flows": int(len(df)),
        "unique_sources": int(df["src_ip"].nunique()),
        "unique_destinations": int(df["dst_ip"].nunique()),
        "peak_packets_per_second": round(peak_pps, 2),
        "avg_packet_size": round(total_bytes / max(total_packets, 1), 2),
        "risk_score": risk_score,
        "health": health,
    }


def _heuristic_alerts(df: pd.DataFrame, scenario: str) -> List[Dict[str, Any]]:
    if df.empty:
        return []

    out: List[Dict[str, Any]] = []
    by_src = (
        df.groupby("src_ip")
        .agg(
            total_packets=("packet_count", "sum"),
            unique_ports=("dst_port", "nunique"),
            unique_dsts=("dst_ip", "nunique"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
        .sort_values("total_packets", ascending=False)
    )

    if scenario == "ddos":
        top = by_src.head(3)
        for _, row in top.iterrows():
            out.append(
                {
                    "timestamp": row["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": row["src_ip"],
                    "attack_type": "DDoS",
                    "severity": "HIGH",
                    "anomaly_score": min(round(row["total_packets"] / 5000, 2), 1.0),
                }
            )

    elif scenario == "portscan":
        top = by_src.sort_values("unique_ports", ascending=False).head(3)
        for _, row in top.iterrows():
            out.append(
                {
                    "timestamp": row["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": row["src_ip"],
                    "attack_type": "Port Scan",
                    "severity": "HIGH" if row["unique_ports"] > 100 else "MEDIUM",
                    "anomaly_score": min(round(row["unique_ports"] / 1000, 2), 1.0),
                }
            )

    elif scenario == "compromised":
        top = by_src.head(3)
        for _, row in top.iterrows():
            out.append(
                {
                    "timestamp": row["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": row["src_ip"],
                    "attack_type": "Compromised Host",
                    "severity": "CRITICAL",
                    "anomaly_score": min(round(row["total_packets"] / 3500, 2), 1.0),
                }
            )

    else:
        top = by_src.head(2)
        for _, row in top.iterrows():
            out.append(
                {
                    "timestamp": row["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": row["src_ip"],
                    "attack_type": "Baseline Activity",
                    "severity": "LOW",
                    "anomaly_score": 0.15,
                }
            )

    return out


def _load_alerts_from_csv() -> List[Dict[str, Any]]:
    if not ALERTS_FILE.exists():
        return []

    df = pd.read_csv(ALERTS_FILE)
    required = {"timestamp", "ip", "attack_type", "severity", "anomaly_score"}
    if not required.issubset(set(df.columns)):
        return []

    out: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        out.append(
            {
                "timestamp": str(row["timestamp"]),
                "ip": str(row["ip"]),
                "attack_type": str(row["attack_type"]),
                "severity": str(row["severity"]).upper(),
                "anomaly_score": float(row["anomaly_score"]),
            }
        )
    return out


def _safe_read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _normalize_detection(obj: Dict[str, Any], source_file: Path) -> Dict[str, Any]:
    return {
        "timestamp": str(obj.get("timestamp", "unknown")),
        "threat_type": str(obj.get("threat_type", obj.get("attack_type", "Unknown"))),
        "severity": str(obj.get("severity", "unknown")).upper(),
        "source_ip": str(obj.get("source_ip", obj.get("src_ip", "unknown"))),
        "affected_hosts": obj.get("affected_hosts", []),
        "anomaly_score": float(obj.get("anomaly_score", 0.0)),
        "recommended_fix": obj.get("recommended_fix", []),
        "evidence": obj.get("evidence", obj.get("reasons", [])),
        "source_file": str(source_file.relative_to(PROJECT_ROOT)),
    }


def _load_agentic_detections(scenario: str) -> List[Dict[str, Any]]:
    if scenario == "normal":
        return []

    summary_path = SCENARIO_SUMMARY_FILES.get(scenario)
    if summary_path is None or not summary_path.exists():
        return []

    payload = _safe_read_json(summary_path)
    if not isinstance(payload, dict):
        return []

    detections = payload.get("detections", [])
    if not isinstance(detections, list):
        return []

    normalized = [
        _normalize_detection(item, summary_path)
        for item in detections
        if isinstance(item, dict)
    ]

    normalized.sort(key=lambda item: pd.to_datetime(item.get("timestamp"), errors="coerce"), reverse=True)
    return normalized


def _agentic_alerts(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "timestamp": item["timestamp"],
            "ip": item["source_ip"],
            "attack_type": item["threat_type"],
            "severity": item["severity"],
            "anomaly_score": float(item["anomaly_score"]),
        }
        for item in detections
    ]


def _agentic_remediations(detections: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    breakdown: Dict[str, int] = {}
    for item in detections:
        label = item["threat_type"]
        breakdown[label] = breakdown.get(label, 0) + 1

    return detections[:10], breakdown


def _load_remediation_actions() -> List[Dict[str, Any]]:
    if not OUTPUTS_DIR.exists():
        return []

    records: List[Dict[str, Any]] = []
    for json_path in OUTPUTS_DIR.rglob("*.json"):
        payload = _safe_read_json(json_path)
        if payload is None:
            continue

        if isinstance(payload, dict) and isinstance(payload.get("detections"), list):
            for item in payload["detections"]:
                if isinstance(item, dict):
                    records.append(_normalize_detection(item, json_path))
            continue

        if isinstance(payload, dict) and (
            "threat_type" in payload or "attack_type" in payload or "recommended_fix" in payload
        ):
            records.append(_normalize_detection(payload, json_path))
            continue

        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                normalized = {
                    "timestamp": str(item.get("timestamp", "unknown")),
                    "threat_type": "Heuristic Mitigation",
                    "severity": "MEDIUM",
                    "source_ip": str(item.get("source_ip", item.get("src_ip", "unknown"))),
                    "affected_hosts": [str(item.get("dst_ip", "unknown"))],
                    "anomaly_score": 0.5,
                    "recommended_fix": [str(item.get("recommended_action", "review_alert"))],
                    "evidence": item.get("reasons", []),
                    "source_file": str(json_path.relative_to(PROJECT_ROOT)),
                }
                records.append(normalized)

    def _sort_key(item: Dict[str, Any]) -> pd.Timestamp:
        return pd.to_datetime(item.get("timestamp"), errors="coerce")

    records.sort(key=_sort_key, reverse=True)
    return records


def _filter_remediations_for_scenario(
    remediations: List[Dict[str, Any]], scenario: str
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    if not remediations:
        return [], {}

    keyword = {
        "ddos": "ddos",
        "portscan": "port",
        "compromised": "compromised",
        "normal": "",
    }.get(scenario, "")

    if keyword:
        filtered = [r for r in remediations if keyword in r["threat_type"].lower()]
    else:
        filtered = remediations

    if not filtered:
        filtered = remediations[:8]

    filtered = filtered[:10]

    breakdown: Dict[str, int] = {}
    for item in filtered:
        label = item["threat_type"]
        breakdown[label] = breakdown.get(label, 0) + 1

    return filtered, breakdown


def _record_action(action: str, status: str, detail: str, target: str = "") -> None:
    ACTION_HISTORY.insert(
        0,
        {
            "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "target": target,
            "status": status,
            "detail": detail,
        },
    )
    del ACTION_HISTORY[50:]


def _build_dashboard_payload(scenario: str) -> Dict[str, Any]:
    df = _load_traffic(scenario)
    detections = _load_agentic_detections(scenario)

    if detections:
        alerts = _agentic_alerts(detections)
        remediations, threat_breakdown = _agentic_remediations(detections)
    else:
        heur_alerts = _heuristic_alerts(df, scenario)
        csv_alerts = _load_alerts_from_csv()

        if scenario == "normal":
            alerts = heur_alerts
        elif scenario == "ddos":
            alerts = [
                a
                for a in (heur_alerts + csv_alerts)
                if "ddos" in a["attack_type"].lower() or "syn" in a["attack_type"].lower()
            ]
        elif scenario == "portscan":
            alerts = [a for a in (heur_alerts + csv_alerts) if "port" in a["attack_type"].lower()]
        else:
            alerts = [
                a
                for a in (heur_alerts + csv_alerts)
                if "comprom" in a["attack_type"].lower() or "ssh" in a["attack_type"].lower()
            ]

        alerts = alerts[:10]
        remediations_all = _load_remediation_actions()
        remediations, threat_breakdown = _filter_remediations_for_scenario(remediations_all, scenario)

    metrics = _metrics(df, scenario, len(alerts))

    return {
        "scenario": scenario,
        "available_scenarios": list(SCENARIO_FILES.keys()),
        "metrics": metrics,
        "traffic": _aggregate_traffic(df),
        "alerts": alerts,
        "remediations": remediations,
        "threat_breakdown": threat_breakdown,
        "last_updated": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/dashboard")
def api_dashboard():
    scenario = _normalize_scenario(request.args.get("scenario"))
    payload = _build_dashboard_payload(scenario)
    return jsonify(payload)


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify({"active": ACTIVE_SCENARIO, "scenarios": list(SCENARIO_FILES.keys())})


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    global ACTIVE_SCENARIO

    payload = request.get_json(force=True, silent=True) or {}
    scenario = _normalize_scenario(payload.get("scenario"))
    ACTIVE_SCENARIO = scenario
    dashboard_payload = _build_dashboard_payload(scenario)
    return jsonify(
        {
            "status": "ok",
            "active_scenario": scenario,
            "message": f"Simulation switched to: {scenario}",
            "dashboard": dashboard_payload,
        }
    )


@app.route("/api/actions")
def api_actions():
    return jsonify({"actions": ACTION_HISTORY})


@app.route("/api/block_ip", methods=["POST"])
def api_block_ip():
    payload = request.get_json(force=True, silent=True) or {}
    ip = str(payload.get("ip", "")).strip()
    if not ip:
        return jsonify({"status": "error", "detail": "Missing ip"}), 400

    success, detail = block_ip_action(ip)
    status = "ok" if success else "error"
    _record_action("block_ip", status, detail, ip)
    return jsonify({"status": status, "detail": detail, "ip": ip, "action": "block_ip"})


@app.route("/api/isolate_host", methods=["POST"])
def api_isolate_host():
    payload = request.get_json(force=True, silent=True) or {}
    host = str(payload.get("host", "")).strip()
    if not host:
        return jsonify({"status": "error", "detail": "Missing host"}), 400

    detail = f"Isolation command dispatched for {host} (demo mode)"
    _record_action("isolate_host", "ok", detail, host)
    return jsonify({"status": "ok", "host": host, "detail": detail, "action": "isolate_host"})


@app.route("/api/reset_network", methods=["POST"])
def api_reset_network():
    detail = "Network reset command dispatched (demo mode)"
    _record_action("reset_network", "ok", detail, "all")
    return jsonify({"status": "ok", "detail": detail, "action": "reset_network"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
