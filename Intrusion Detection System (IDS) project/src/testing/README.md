# Attack Simulation & Testing Framework for IDS

This package provides a comprehensive framework for simulating various network attacks and evaluating the effectiveness of your Intrusion Detection System (IDS).

## Overview

The Attack Simulation & Testing Framework enables:

1. **Attack Simulation**: Generate realistic attack traffic for testing IDS capabilities
2. **IDS Evaluation**: Measure detection performance using standard metrics
3. **MITRE ATT&CK Integration**: Map attacks to the MITRE ATT&CK framework
4. **Test Environment Management**: Set up controlled environments for testing

## Modules

### 1. Attack Simulation Module

The attack simulation module provides functionality to simulate various network attacks, including:
- Port scanning
- DDoS attacks
- SQL injection
- Brute force login attempts

For detailed information on the attack simulation capabilities, see the [Attack Simulation README](README_ATTACK_SIMULATION.md).

### 2. Evaluation Framework

The evaluation framework provides tools for:
- Running test scenarios
- Collecting and analyzing IDS alerts
- Matching alerts to known attack events
- Calculating performance metrics (precision, recall, F1-score)
- Generating comprehensive evaluation reports

### 3. Test Environment Setup

Tools for creating and managing controlled test environments:
- Network configuration
- Target system setup
- IDS deployment
- Attack system preparation

### 4. Metasploit Integration

Optional integration with Metasploit for advanced penetration testing:
- Run exploits from the Metasploit framework
- Track exploit success/failure
- Integrate exploit results with evaluation metrics

## Requirements

- Python 3.6+
- Scapy (for packet-level attack simulations)
- PyYAML (for configuration files)
- pandas and numpy (for data analysis)
- scikit-learn (for evaluation metrics)
- Metasploit (optional, for penetration testing)

## Usage

### Running a Complete Evaluation

```bash
python run_evaluation.py --env-config config/test_environment.yaml \
                         --scenario scenarios/multi_phase_attack.yaml \
                         --alert-log logs/ids_alerts.log \
                         --event-log logs/attack_events.log \
                         --output evaluation_report.json
```

### Attack Simulation Only

```bash
python run_attack_simulation.py scenario --file scenarios/multi_phase_attack.yaml
```

### Using Metasploit for Penetration Testing

```bash
python run_evaluation.py --metasploit --exploit exploit/unix/ftp/vsftpd_234_backdoor \
                         --target 192.168.1.10
```

## Directory Structure

- `attack_simulation.py`: Core attack simulation module
- `evaluation_framework.py`: IDS evaluation framework
- `run_attack_simulation.py`: CLI for running attack simulations
- `run_evaluation.py`: CLI for running evaluations
- `config/`: Configuration files for test environments
- `scenarios/`: Attack scenario definitions
- `examples/`: Example files showing logs and reports

## MITRE ATT&CK Integration

The framework maps attacks to the MITRE ATT&CK framework, providing:
- Technique IDs and names
- Tactic categorization
- Links to MITRE documentation
- Coverage statistics

Current mappings include:
- **T1046** (Network Service Discovery) - Port scanning
- **T1110** (Brute Force) - SSH/FTP/HTTP brute force attacks
- **T1190** (Exploit Public-Facing Application) - SQL injection attacks
- **T1498** (Network Denial of Service) - DDoS attacks

## Extending the Framework

You can extend the framework by:
1. Adding new attack simulators (by subclassing `AttackSimulator`)
2. Creating custom test scenarios
3. Integrating additional penetration testing tools
4. Expanding MITRE ATT&CK mappings

## Security Notice

This framework is designed for testing IDS functionality in controlled environments only. Using these simulations against systems without proper authorization is illegal and unethical.

## License

This module is part of the IDS project and is subject to the same license terms. 