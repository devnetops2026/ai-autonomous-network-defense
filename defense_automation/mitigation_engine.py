import json
from defense_automation.auto_block import block_ip

MITIGATION_FILE = "outputs/mitigation.json"

def isolate_host(ip):
    print(f"Isolating host {ip}")
    # placeholder for network isolation logic

def send_alert(alert):
    print(f"Alert generated for {alert['src_ip']}")

def apply_mitigations():

    try:
        with open(MITIGATION_FILE) as f:
            alerts = json.load(f)

        for alert in alerts:

            action = alert["recommended_action"]
            ip = alert["src_ip"]

            if action == "block_src_ip":
                block_ip(ip)

            elif action == "isolate_host":
                isolate_host(ip)

            elif action == "alert_only":
                send_alert(alert)

    except FileNotFoundError:
        print("No mitigation file found")

if __name__ == "__main__":  
    apply_mitigations()