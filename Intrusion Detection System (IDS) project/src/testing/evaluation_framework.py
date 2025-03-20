#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Evaluation Framework for IDS Testing
This module provides tools for evaluating IDS performance against simulated attacks.
"""

import os
import sys
import time
import json
import yaml
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union, Optional, Any
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Add the project root directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Import attack simulation module
from src.testing.attack_simulation import (
    AttackSimulator, PortScanSimulator, DDoSSimulator, 
    SQLInjectionSimulator, BruteForceSimulator,
    run_attack_scenario, load_scenario_from_file
)

# Setup logging
logger = logging.getLogger('ids.testing.evaluation')

# MITRE ATT&CK Technique Mappings
MITRE_MAPPINGS = {
    "port_scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation."
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained."
    },
    "ddos": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to disrupt legitimate user access to network resources."
    },
    "sql_injection": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries may exploit vulnerabilities in public-facing applications to gain initial access."
    }
}

class IDSEvaluator:
    """
    Class for evaluating IDS performance against simulated attacks.
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the evaluator.
        
        Args:
            config_path (str, optional): Path to the evaluator configuration file
        """
        self.config = {}
        if config_path:
            self.load_config(config_path)
            
        # Initialize metrics storage
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        self.alerts = []
        self.attack_events = []
        self.metrics = {}
        
    def load_config(self, config_path):
        """
        Load configuration from a file.
        
        Args:
            config_path (str): Path to the configuration file
        """
        try:
            with open(config_path, 'r') as f:
                ext = os.path.splitext(config_path)[1].lower()
                
                if ext in ('.yaml', '.yml'):
                    self.config = yaml.safe_load(f)
                elif ext == '.json':
                    self.config = json.load(f)
                else:
                    raise ValueError(f"Unsupported file format: {ext}")
                    
            logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
    
    def run_test_scenario(self, scenario_path):
        """
        Run a test scenario from a file.
        
        Args:
            scenario_path (str): Path to the scenario file
            
        Returns:
            bool: True if scenario completed successfully, False otherwise
        """
        logger.info(f"Running test scenario from {scenario_path}")
        
        # Load the scenario
        scenario_config = load_scenario_from_file(scenario_path)
        if not scenario_config:
            logger.error(f"Failed to load scenario from file: {scenario_path}")
            return False
        
        # Record start time
        start_time = datetime.now()
        
        # Run the scenario
        success = run_attack_scenario(scenario_config)
        
        # Record end time
        end_time = datetime.now()
        
        if not success:
            logger.error("Test scenario failed")
            return False
        
        # Record basic information about the test run
        self.scenario_info = {
            "name": scenario_config.get("name", "Unknown Scenario"),
            "description": scenario_config.get("description", ""),
            "start_time": start_time,
            "end_time": end_time,
            "duration": (end_time - start_time).total_seconds(),
            "attacks": scenario_config.get("attacks", [])
        }
        
        # Map attacks to MITRE ATT&CK framework
        self._map_to_mitre()
        
        logger.info(f"Test scenario completed: {self.scenario_info['name']}")
        return True
    
    def collect_alerts(self, alert_file_path):
        """
        Collect IDS alerts from a log file.
        
        Args:
            alert_file_path (str): Path to the IDS alert log file
            
        Returns:
            int: Number of alerts collected
        """
        logger.info(f"Collecting alerts from {alert_file_path}")
        
        try:
            # Load the alerts from file
            with open(alert_file_path, 'r') as f:
                for line in f:
                    try:
                        # Parse the alert (format depends on your IDS)
                        alert = json.loads(line.strip())
                        self.alerts.append(alert)
                    except json.JSONDecodeError:
                        # If not JSON, try other formats or simple parsing
                        parts = line.strip().split('|')
                        if len(parts) >= 3:
                            alert = {
                                "timestamp": parts[0].strip(),
                                "signature_id": parts[1].strip(),
                                "message": parts[2].strip()
                            }
                            self.alerts.append(alert)
                        
            logger.info(f"Collected {len(self.alerts)} alerts")
            return len(self.alerts)
            
        except Exception as e:
            logger.error(f"Error collecting alerts: {e}")
            return 0
    
    def collect_attack_events(self, event_file_path):
        """
        Collect known attack events from a log file.
        
        Args:
            event_file_path (str): Path to the attack events log file
            
        Returns:
            int: Number of attack events collected
        """
        logger.info(f"Collecting attack events from {event_file_path}")
        
        try:
            # Load the attack events from file
            with open(event_file_path, 'r') as f:
                for line in f:
                    try:
                        # Parse the event
                        event = json.loads(line.strip())
                        self.attack_events.append(event)
                    except json.JSONDecodeError:
                        # If not JSON, try other formats or simple parsing
                        parts = line.strip().split('|')
                        if len(parts) >= 3:
                            event = {
                                "timestamp": parts[0].strip(),
                                "type": parts[1].strip(),
                                "details": parts[2].strip()
                            }
                            self.attack_events.append(event)
                        
            logger.info(f"Collected {len(self.attack_events)} attack events")
            return len(self.attack_events)
            
        except Exception as e:
            logger.error(f"Error collecting attack events: {e}")
            return 0
    
    def match_alerts_to_attacks(self, time_window=60):
        """
        Match IDS alerts to known attack events.
        
        Args:
            time_window (int): Time window in seconds to match alerts to attacks
            
        Returns:
            dict: Matching statistics
        """
        logger.info(f"Matching alerts to attacks with time window of {time_window} seconds")
        
        # Convert timestamps to datetime objects
        for alert in self.alerts:
            if isinstance(alert.get("timestamp"), str):
                try:
                    alert["timestamp"] = datetime.fromisoformat(alert["timestamp"].replace('Z', '+00:00'))
                except ValueError:
                    # Try other common formats
                    try:
                        alert["timestamp"] = datetime.strptime(alert["timestamp"], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        logger.warning(f"Could not parse timestamp: {alert['timestamp']}")
                        
        for event in self.attack_events:
            if isinstance(event.get("timestamp"), str):
                try:
                    event["timestamp"] = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
                except ValueError:
                    # Try other common formats
                    try:
                        event["timestamp"] = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        logger.warning(f"Could not parse timestamp: {event['timestamp']}")
        
        # Initialize counters
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        
        # Match alerts to attacks
        matched_events = set()
        
        for alert in self.alerts:
            matched = False
            
            for i, event in enumerate(self.attack_events):
                if i in matched_events:
                    continue
                    
                # Check if alert timestamp is within the time window of the attack event
                if hasattr(alert.get("timestamp"), "timestamp") and hasattr(event.get("timestamp"), "timestamp"):
                    time_diff = abs((alert["timestamp"] - event["timestamp"]).total_seconds())
                    
                    if time_diff <= time_window:
                        # This is a true positive
                        self.true_positives += 1
                        matched_events.add(i)
                        matched = True
                        break
            
            if not matched:
                # This is a false positive
                self.false_positives += 1
        
        # Count unmatched attack events (false negatives)
        self.false_negatives = len(self.attack_events) - len(matched_events)
        
        # Calculate metrics
        self._calculate_metrics()
        
        logger.info(f"Matching completed: {self.true_positives} true positives, {self.false_positives} false positives, {self.false_negatives} false negatives")
        
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.metrics.get("precision", 0),
            "recall": self.metrics.get("recall", 0),
            "f1_score": self.metrics.get("f1_score", 0)
        }
    
    def _calculate_metrics(self):
        """
        Calculate evaluation metrics.
        """
        # Prevent division by zero
        if self.true_positives + self.false_positives == 0:
            precision = 0
        else:
            precision = self.true_positives / (self.true_positives + self.false_positives)
            
        if self.true_positives + self.false_negatives == 0:
            recall = 0
        else:
            recall = self.true_positives / (self.true_positives + self.false_negatives)
            
        if precision + recall == 0:
            f1 = 0
        else:
            f1 = 2 * (precision * recall) / (precision + recall)
            
        self.metrics = {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives
        }
    
    def _map_to_mitre(self):
        """
        Map attacks in the scenario to the MITRE ATT&CK framework.
        """
        mitre_techniques = []
        
        if hasattr(self, 'scenario_info') and 'attacks' in self.scenario_info:
            for attack in self.scenario_info['attacks']:
                attack_type = attack.get('type')
                
                if attack_type in MITRE_MAPPINGS:
                    technique = MITRE_MAPPINGS[attack_type].copy()
                    technique['attack_name'] = attack.get('name', attack_type)
                    technique['attack_description'] = attack.get('description', '')
                    mitre_techniques.append(technique)
                
        self.mitre_techniques = mitre_techniques
        
    def get_mitre_report(self):
        """
        Get a report of the MITRE ATT&CK techniques used in the scenario.
        
        Returns:
            dict: MITRE ATT&CK techniques report
        """
        if not hasattr(self, 'mitre_techniques'):
            self._map_to_mitre()
            
        return {
            "scenario_name": self.scenario_info.get("name", "Unknown Scenario") if hasattr(self, 'scenario_info') else "Unknown Scenario",
            "techniques": self.mitre_techniques,
            "tactics": list(set(t["tactic"] for t in self.mitre_techniques)),
            "technique_count": len(self.mitre_techniques)
        }
    
    def generate_report(self, output_file=None):
        """
        Generate an evaluation report.
        
        Args:
            output_file (str, optional): Path to save the report
            
        Returns:
            dict: Evaluation report
        """
        # Create the report
        report = {
            "timestamp": datetime.now().isoformat(),
            "scenario": self.scenario_info if hasattr(self, 'scenario_info') else {},
            "metrics": self.metrics,
            "mitre": self.get_mitre_report(),
            "alert_count": len(self.alerts),
            "attack_event_count": len(self.attack_events)
        }
        
        # Save the report to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to {output_file}")
            except Exception as e:
                logger.error(f"Error saving report: {e}")
        
        return report
        
def create_controlled_environment(config_path):
    """
    Create a controlled test environment based on configuration.
    
    Args:
        config_path (str): Path to the environment configuration file
        
    Returns:
        dict: Environment setup information
    """
    logger.info(f"Setting up controlled test environment from {config_path}")
    
    try:
        # Load the configuration
        with open(config_path, 'r') as f:
            ext = os.path.splitext(config_path)[1].lower()
            
            if ext in ('.yaml', '.yml'):
                config = yaml.safe_load(f)
            elif ext == '.json':
                config = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {ext}")
        
        # Set up the environment (implementation depends on your infrastructure)
        # This is a placeholder for actual environment setup code
        
        return {
            "status": "success",
            "message": "Controlled environment successfully created",
            "config": config
        }
        
    except Exception as e:
        logger.error(f"Error setting up controlled environment: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

def metasploit_integration(target, exploit, options=None):
    """
    Integration with Metasploit for penetration testing.
    This is a simplified placeholder implementation.
    
    Args:
        target (str): Target IP or hostname
        exploit (str): Metasploit exploit path
        options (dict, optional): Exploit options
        
    Returns:
        dict: Results of the exploit attempt
    """
    logger.info(f"Running Metasploit exploit {exploit} against {target}")
    
    # This is a placeholder - in a real implementation, you would use the Metasploit API
    # or subprocess to run msfconsole commands
    
    # Example implementation using subprocess (commented out)
    """
    import subprocess
    
    # Build the RC file content
    rc_content = f"use {exploit}\n"
    rc_content += f"set RHOSTS {target}\n"
    
    if options:
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
    
    rc_content += "run\n"
    rc_content += "exit\n"
    
    # Write the RC file
    with open("msf_exploit.rc", "w") as f:
        f.write(rc_content)
    
    # Run Metasploit
    result = subprocess.run(
        ["msfconsole", "-q", "-r", "msf_exploit.rc"],
        capture_output=True,
        text=True
    )
    
    # Clean up
    os.remove("msf_exploit.rc")
    
    return {
        "status": "success" if "Exploit completed" in result.stdout else "failure",
        "output": result.stdout,
        "error": result.stderr
    }
    """
    
    # Simulated result for placeholder implementation
    return {
        "status": "simulated",
        "message": "This is a placeholder for Metasploit integration",
        "target": target,
        "exploit": exploit,
        "options": options
    }

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create evaluator
    evaluator = IDSEvaluator()
    
    # Run a test scenario
    evaluator.run_test_scenario("scenarios/multi_phase_attack.yaml")
    
    # Collect alerts and attack events
    # evaluator.collect_alerts("logs/ids_alerts.log")
    # evaluator.collect_attack_events("logs/attack_events.log")
    
    # Match alerts to attacks
    # evaluator.match_alerts_to_attacks()
    
    # Generate a report
    report = evaluator.generate_report("evaluation_report.json")
    
    print(json.dumps(report, indent=2)) 