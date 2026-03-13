import subprocess
import sys

SWITCHES = ["s1", "s2"]

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[OK] {' '.join(cmd)}")
    else:
        print(f"[ERROR] {' '.join(cmd)}")
        if result.stderr:
            print(result.stderr.strip())

def rollback_host(src_ip: str):
    for switch in SWITCHES:
        run_cmd([
            "sudo", "ovs-ofctl", "-O", "OpenFlow13", "--strict",
            "del-flows", switch,
            f"priority=200,ip,nw_src={src_ip}"
        ])
        run_cmd([
            "sudo", "ovs-ofctl", "-O", "OpenFlow13", "--strict",
            "del-flows", switch,
            f"priority=100,ip,nw_src={src_ip}"
        ])

def rollback_port(port: int):
    for switch in SWITCHES:
        run_cmd([
            "sudo", "ovs-ofctl", "-O", "OpenFlow13", "--strict",
            "del-flows", switch,
            f"priority=150,ip,tcp,tp_dst={port}"
        ])

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python defense_automation/rollback.py host <ip>")
        print("  python defense_automation/rollback.py port <port>")
        return

    mode = sys.argv[1]
    value = sys.argv[2]

    if mode == "host":
        rollback_host(value)
    elif mode == "port":
        rollback_port(int(value))
    else:
        print("Invalid mode. Use 'host' or 'port'.")

if __name__ == "__main__":
    main()