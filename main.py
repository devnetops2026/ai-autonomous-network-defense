import json

from network_simulation.topology import start_network
from defense_automation.auto_block import block_ip


def monitor_traffic():
    print("Monitoring network traffic...")


def read_mitigations():
    try:
        with open("outputs/mitigation.json") as f:
            alerts = json.load(f)
        return alerts
    except FileNotFoundError:
        return []


def main():
    print("Starting AI Autonomous Network Defense System")

    start_network()
    monitor_traffic()

    alerts = read_mitigations()

    if not alerts:
        print("No threats detected")
        return

    for alert in alerts:
        attacker_ip = alert["src_ip"]
        print(f"Threat detected from {attacker_ip}")
        block_ip(attacker_ip)


if __name__ == "__main__":
    main()