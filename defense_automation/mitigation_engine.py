import json
from defense_automation.auto_block import block_ip

MITIGATION_FILE = "outputs/mitigation.json"

def apply_mitigations():
    try:
        with open(MITIGATION_FILE) as f:
            alerts = json.load(f)

        for alert in alerts:
            if alert["recommended_action"] == "block_src_ip":
                ip = alert["src_ip"]
                print(f"Blocking attacker {ip}")
                block_ip(ip)

    except FileNotFoundError:
        print("No mitigation file found")

if __name__ == "__main__":  
    apply_mitigations()