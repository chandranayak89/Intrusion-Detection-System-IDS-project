# Attack Simulation Module for IDS Testing

This module provides functionality to simulate various network attacks for testing the effectiveness of the Intrusion Detection System (IDS).

## Overview

The Attack Simulation Module enables controlled testing of the IDS by generating realistic attack traffic. This helps in:

- Validating detection capabilities
- Testing false positive/negative rates
- Training and tuning detection models
- Demonstrating IDS functionality

## Features

- **Multiple Attack Types**: Port scanning, DDoS, SQL injection, brute force attacks
- **Configurable Attacks**: Customize attack parameters through config files
- **Scenario-Based Testing**: Run multi-phase attack scenarios
- **Safe Execution**: All attacks are simulated and can be run in controlled environments
- **Extensible Framework**: Easy to add new attack types

## Requirements

- Python 3.6+
- Scapy (optional, for advanced packet manipulation)
- PyYAML (for scenario configuration files)

## Usage

You can use the attack simulation module in several ways:

### 1. Run the Demo

```bash
python run_attack_simulation.py demo
```

This will run a basic demonstration of port scanning and brute force attacks.

### 2. Run a Specific Attack

```bash
# Run a port scan
python run_attack_simulation.py port-scan --target 192.168.1.1 --scan-type tcp_connect

# Run a brute force attack
python run_attack_simulation.py brute-force --target 192.168.1.1 --port 22 --protocol ssh

# Run a DDoS attack
python run_attack_simulation.py ddos --target 192.168.1.1 --port 80 --attack-type http_flood --duration 10

# Run a SQL injection attack
python run_attack_simulation.py sql-injection --target http://192.168.1.1 --path /login
```

### 3. Run a Multi-Phase Attack Scenario

```bash
python run_attack_simulation.py scenario --file scenarios/multi_phase_attack.yaml
```

## Attack Scenario Configuration

Attack scenarios are defined in YAML files that specify a sequence of attacks. Example:

```yaml
name: "Multi-Phase Attack Scenario"
description: "This scenario simulates a reconnaissance phase followed by an exploitation attempt"
attacks:
  - type: "port_scan"
    target: "192.168.1.1"
    ports: [22, 80, 443]
    scan_type: "tcp_connect"
    
  - type: "brute_force"
    target: "192.168.1.1"
    target_port: 22
    protocol: "ssh"
```

## Supported Attack Types

### Port Scan Simulation

The `PortScanSimulator` class supports different types of port scans:

- **TCP Connect Scan**: Full TCP connection attempts to target ports
- **SYN Scan**: Send SYN packets and analyze responses (requires Scapy)
- **FIN Scan**: Send FIN packets to detect open ports through lack of response (requires Scapy)

### DDoS Attack Simulation

The `DDoSSimulator` class supports several DDoS attack types:

- **SYN Flood**: Send a large volume of SYN packets to overwhelm the target
- **HTTP Flood**: Send numerous HTTP requests to exhaust web server resources
- **UDP Flood**: Send UDP packets to various ports to consume bandwidth

### SQL Injection Simulation

The `SQLInjectionSimulator` class attempts SQL injection attacks against web applications:

- Uses common SQL injection payloads
- Targets specified parameters in web requests
- Configurable with custom payloads

### Brute Force Simulation

The `BruteForceSimulator` class simulates password guessing attacks:

- **SSH Brute Force**: Attempt multiple SSH login combinations
- **FTP Brute Force**: Try various credentials against FTP servers
- **HTTP Basic Auth Brute Force**: Attack HTTP basic authentication

## Extending the Module

You can add new attack types by creating a subclass of `AttackSimulator`:

```python
from src.testing.attack_simulation import AttackSimulator

class MyCustomAttack(AttackSimulator):
    def __init__(self, config=None):
        super().__init__(config)
        # Initialize attack-specific parameters
        
    def setup(self):
        # Set up the attack
        return True
        
    def run(self):
        # Implement the attack logic
        return True
        
    def cleanup(self):
        # Clean up after the attack
        return True
```

Your new attack type can then be used with the existing framework by adding it to the `create_attack_simulator` function.

## Security Notice

This module is designed for testing IDS functionality in controlled environments only. Using these simulations against systems without proper authorization is illegal and unethical. 