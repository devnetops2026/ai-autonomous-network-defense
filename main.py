from network_simulation.topology import start_network
from defense_automation.mitigation_engine import apply_mitigations
import subprocess


def monitor_traffic():
    print("Monitoring network traffic...")


def run_ai_detection():
    print("Running AI detection...")
    subprocess.run(["python", "ai_engine/detect.py"], check=True)


def main():
    print("Starting AI Autonomous Network Defense System")

    start_network()
    monitor_traffic()

    print("Running AI detection on network traffic logs...")

    run_ai_detection()

    apply_mitigations()


if __name__ == "__main__":
    main()