print()from network_simulation.topology import start_network
from ai_detection.anomaly_detector import detect_anomaly
from automation.auto_block import block_attacker

def main():
    print("Starting network simulation...")
    start_network()

    print("Monitoring traffic...")
    anomaly = detect_anomaly()

    if anomaly:
        print("Threat detected!")
        block_attacker()
    
if __name__ == "__main__":
    main()