from pathlib import Path
from typing import Dict, Any, List

import pandas as pd
from flask import Flask, jsonify, render_template, request

from scripts.block_ip import block_ip_action

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

TRAFFIC_LOGS_FILE = DATA_DIR / "traffic_logs.csv"
ALERTS_FILE = DATA_DIR / "alerts.csv"
TOPOLOGY_FILE = DATA_DIR / "topology.json"


app = Flask(__name__, template_folder="templates", static_folder="static")


def _load_traffic() -> pd.DataFrame:
    if not TRAFFIC_LOGS_FILE.exists():
        return pd.DataFrame(
            columns=["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_count", "bytes"]
        )
    return pd.read_csv(TRAFFIC_LOGS_FILE)


def _load_alerts() -> pd.DataFrame:
    if not ALERTS_FILE.exists():
        return pd.DataFrame(columns=["timestamp", "ip", "attack_type", "severity", "anomaly_score"])
    return pd.read_csv(ALERTS_FILE)


def _aggregate_traffic(df: pd.DataFrame) -> Dict[str, Any]:
    if df.empty:
        return {
            "timeseries": {"timestamp": [], "packets": [], "bytes": []},
            "protocol_distribution": {"protocols": [], "counts": []},
            "top_talkers": {"ips": [], "packets": []},
            "port_usage": {"ports": [], "packets": []},
        }

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    per_second = (
        df.set_index("timestamp")
        .resample("1S")
        .agg({"packet_count": "sum", "bytes": "sum"})
        .reset_index()
    )

    protocol_dist = df.groupby("protocol")["packet_count"].sum().reset_index()
    top_talkers = (
        df.groupby("src_ip")["packet_count"]
        .sum()
        .reset_index()
        .sort_values("packet_count", ascending=False)
        .head(5)
    )
    port_usage = (
        df.groupby("dst_port")["packet_count"]
        .sum()
        .reset_index()
        .sort_values("packet_count", ascending=False)
        .head(10)
    )

    return {
        "timeseries": {
            "timestamp": per_second["timestamp"].dt.strftime("%H:%M:%S").tolist(),
            "packets": per_second["packet_count"].tolist(),
            "bytes": per_second["bytes"].tolist(),
        },
        "protocol_distribution": {
            "protocols": protocol_dist["protocol"].tolist(),
            "counts": protocol_dist["packet_count"].tolist(),
        },
        "top_talkers": {
            "ips": top_talkers["src_ip"].tolist(),
            "packets": top_talkers["packet_count"].tolist(),
        },
        "port_usage": {
            "ports": port_usage["dst_port"].astype(str).tolist(),
            "packets": port_usage["packet_count"].tolist(),
        },
    }


def _serialize_alerts(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if df.empty:
        return []
    return [
        {
            "timestamp": str(row["timestamp"]),
            "ip": row["ip"],
            "attack_type": row["attack_type"],
            "severity": row["severity"],
            "anomaly_score": float(row["anomaly_score"]),
        }
        for _, row in df.iterrows()
    ]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/traffic")
def api_traffic():
    df = _load_traffic()
    aggregated = _aggregate_traffic(df)
    return jsonify(aggregated)


@app.route("/api/alerts")
def api_alerts():
    df = _load_alerts()
    alerts = _serialize_alerts(df)
    return jsonify({"alerts": alerts})


@app.route("/api/topology")
def api_topology():
    import json

    if not TOPOLOGY_FILE.exists():
        return jsonify({"nodes": [], "links": []})

    with open(TOPOLOGY_FILE, "r") as f:
        topo = json.load(f)
    return jsonify(topo)


@app.route("/api/block_ip", methods=["POST"])
def api_block_ip():
    payload = request.get_json(force=True, silent=True) or {}
    ip = payload.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "Missing ip"}), 400

    success, detail = block_ip_action(ip)
    status = "ok" if success else "error"
    return jsonify({"status": status, "detail": detail, "ip": ip})


@app.route("/api/isolate_host", methods=["POST"])
def api_isolate_host():
    payload = request.get_json(force=True, silent=True) or {}
    host = payload.get("host")
    if not host:
        return jsonify({"status": "error", "message": "Missing host"}), 400
    # Placeholder for DevOps integration to isolate host via controller
    return jsonify({"status": "ok", "host": host, "detail": "Isolation command dispatched"})


@app.route("/api/reset_network", methods=["POST"])
def api_reset_network():
    # Placeholder for DevOps integration to reset network state
    return jsonify({"status": "ok", "detail": "Network reset command dispatched"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)

