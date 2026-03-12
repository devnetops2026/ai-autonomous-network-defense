from __future__ import annotations

import os
from typing import Tuple

import requests


DEVOPS_API_URL = os.getenv("DEVOPS_API_URL", "").rstrip("/")


def block_ip_action(ip: str) -> Tuple[bool, str]:
    """
    Dispatch a request to block an IP at the network controller layer.

    This is the integration point for DevOps / SDN:
    Dashboard → DevOps API → Ryu/OpenFlow flow rule.
    """
    if DEVOPS_API_URL:
        try:
            resp = requests.post(
                f"{DEVOPS_API_URL}/block_ip",
                json={"ip": ip},
                timeout=3,
            )
            if resp.ok:
                return True, "DevOps API accepted block command"
            return False, f"DevOps API error: {resp.status_code}"
        except Exception as exc:
            return False, f"DevOps API exception: {exc}"

    # Fallback: simulate success for demo purposes
    print(f"[DEVOPS SIMULATION] Blocking IP via Ryu flow rule: {ip}")
    return True, "Simulated block command (configure DEVOPS_API_URL for real controller)"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python block_ip.py <ip>")
        raise SystemExit(1)

    ip_arg = sys.argv[1]
    ok, msg = block_ip_action(ip_arg)
    status = "OK" if ok else "ERROR"
    print(f"[{status}] {msg}")

