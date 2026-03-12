from network_simulation.topology import start_network
from ai_detection.anomaly_detector import detect_anomaly
from automation.auto_block import block_ip

def monitor_traffic():
    print("Monitoring network traffic...")

def main():
    print("Starting AI Autonomous Network Defense System")

    # start simulated network
    start_network()

    # monitor traffic
    monitor_traffic()
    
    # run AI detection
    attacker_ip = detect_anomaly()

    if attacker_ip:
        print(f"Threat detected from {attacker_ip}")
        block_ip(attacker_ip)
    else:
        print("No threats detected")

if __name__ == "__main__":
    main()