import os
import time

def main():
    target_ip = "10.0.0.2"   # change later if needed
    interval = 2

    print(f"Starting normal traffic to {target_ip} every {interval} seconds...")
    while True:
        os.system(f"ping -c 1 {target_ip} > /dev/null 2>&1")
        print(f"Sent normal ping to {target_ip}")
        time.sleep(interval)

if __name__ == "__main__":
    main()