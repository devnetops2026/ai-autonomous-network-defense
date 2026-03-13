# AI Autonomous Network Defense System

An **AI-driven autonomous network defense framework** that detects network anomalies and automatically mitigates threats using **Software Defined Networking (SDN)**.

The system integrates **AI-based anomaly detection**, **Mininet network simulation**, and **OpenFlow-based automated mitigation** to defend against real-world traffic anomalies.

---

# Project Overview

Modern networks face threats such as **DDoS attacks, port scanning, and compromised hosts** etc. Manual incident response is slow and often reactive.

This project demonstrates an **autonomous defense pipeline** where:

1. Network telemetry is generated from the simulated network
2. AI detection agents analyze network behavior
3. Detected threats are converted into mitigation recommendations
4. DevOps automation enforces mitigation via **OpenFlow rules**
5. Incidents are logged for security auditing
6. Network connectivity can be **rolled back dynamically**

The system operates **autonomously without manual intervention**.

---

# System Architecture

```
Network Traffic (Mininet)
        │
        ▼
Network Logs
        │
        ▼
AI Detection Agent
        │
        ▼
Agentic JSON Output
        │
        ▼
DevOps Automation Engine
(process_agentic_outputs.py)
        │
        ▼
OpenFlow Mitigation Rules
        │
        ▼
SDN Switch Enforcement
        │
        ▼
Incident Logging + Host Quarantine
```

---

# Technologies Used

| Component | Technology |
|--------|-------------|
| Network Simulation | Mininet |
| SDN Control | Open vSwitch + OpenFlow |
| Detection Engine | AI Agent |
| Automation Layer | Python |
| Logging | JSON + Log Files |
| Virtual Environment | Python venv |

---

# Implemented Threat Scenarios

The system detects and mitigates **three major network threats**.

---

## 1. Distributed Denial of Service (DDoS)

### Attack
A host floods the network with high-volume traffic.

### Detection
The AI engine identifies abnormal traffic patterns and generates mitigation recommendations.

### Mitigation
The system installs an **OpenFlow rule** to isolate the attacker.

```
priority=200,ip,nw_src=<attacker_ip>,actions=drop
```

### Demo Result

```
h1 ping h4
100% packet loss
```

The attacker host is blocked from communicating with the network.

---

## 2. Port Scanning

### Attack
An attacker scans multiple ports on a target machine to discover open services.

### Detection
The AI engine detects suspicious port probing behavior.

### Mitigation
The SDN controller closes the targeted service port.

```
priority=150,ip,tcp,tp_dst=<port>,actions=drop
```

### Demo Result

```
nc -zv <target_ip> <port>
Connection timed out
```

The scanned port is blocked at the network layer.

---

## 3. Compromised Host

### Attack
An internal host begins communicating with multiple machines in an abnormal pattern indicating potential compromise.

### Detection
The AI system detects unusual internal communication behavior.

### Mitigation
The compromised host is **quarantined from the network**.

```
priority=200,ip,nw_src=<compromised_ip>,actions=drop
```

### Demo Result

```
Compromised host → network
100% packet loss
```

Other hosts continue functioning normally, preventing lateral movement.

---

# Autonomous Incident Recording

When a host is detected as compromised, the system automatically generates an **incident record**.

Example:

```
incidents/compromised_hosts/
2026-03-12_13-14-50_10.0.0.3.json
```

The record contains:

- timestamp
- source IP
- threat type
- severity
- supporting metrics
- mitigation status

This enables **security auditing and future monitoring integration**.

---

# Rollback Mechanism

The system supports **dynamic rollback of mitigation rules** without restarting the network.

Example:

```
python defense_automation/rollback.py host 10.0.0.1
```

After rollback:

```
h1 ping h4
connectivity restored
```

This allows the network to **recover automatically once the threat is resolved**.

---

# Project Structure

```
ai-autonomous-network-defense
│
├── defense_automation
│   ├── process_agentic_outputs.py
│   ├── auto_block.py
│   └── rollback.py
│
├── outputs
│   └── agentic_json
│
├── logs
│   ├── mitigation.log
│   ├── processed_files.json
│   └── applied_actions.json
│
├── incidents
│   └── compromised_hosts
│
└── README.md
```

---

# Running the System

### Activate Python Environment

```
source venv/bin/activate
```

### Start Mininet Network

```
sudo mn --topo single,5 --switch ovsk --controller remote
```

### Run Mitigation Automation

```
python defense_automation/process_agentic_outputs.py
```

### Verify Installed OpenFlow Rules

```
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

# Demonstration Workflow

1. Show normal network connectivity

```
pingall
```

2. Simulate attack traffic

3. Run mitigation engine

```
python defense_automation/process_agentic_outputs.py
```

4. Verify mitigation effect

5. Optionally rollback mitigation

```
python defense_automation/rollback.py host <ip>
```

---

# Key Features

- AI-driven anomaly detection
- Autonomous mitigation using SDN
- Multiple threat scenario handling
- Dynamic OpenFlow rule enforcement
- Incident logging and audit trail
- Real-time rollback mechanism
- Fully automated network defense pipeline

---

# Future Improvements

- Real-time telemetry streaming
- Kubernetes deployment
- Advanced ML threat models
- Adaptive mitigation strategies

---

# Authors

DevOps & Automation Engineer  : REHANN JOHN

AI Detection Module  : ANKIT KG

Network Simulation & Traffic Generation : GR ADHISH

Security Engineer & Dashboard : Adhitya Dinesh

---