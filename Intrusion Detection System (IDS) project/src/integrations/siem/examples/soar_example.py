#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SOAR Integration Example
Demonstrates how to use the SOAR integration module to send alerts and create cases
in TheHive and Splunk SOAR.
"""

import os
import sys
import yaml
import logging
import datetime
import argparse
from typing import Dict, Any, List

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

# Import SOAR integration components
from src.integrations.siem.soar_integration import (
    SoarIntegration,
    TheHiveConnector,
    SplunkSoarConnector
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("soar-example")

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load SOAR configuration from YAML file
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return {}

def initialize_soar(config: Dict[str, Any]) -> SoarIntegration:
    """
    Initialize SOAR integration with configured connectors
    
    Args:
        config: SOAR configuration dictionary
        
    Returns:
        Initialized SoarIntegration instance
    """
    soar = SoarIntegration()
    
    # Initialize TheHive connector if enabled
    thehive_config = config.get('thehive', {})
    if thehive_config.get('enabled', False):
        try:
            thehive = TheHiveConnector(
                api_url=thehive_config.get('api_url', ''),
                api_key=thehive_config.get('api_key', ''),
                verify_ssl=thehive_config.get('verify_ssl', True),
                proxies=thehive_config.get('proxies'),
                org_name=thehive_config.get('org_name', 'default'),
                default_tlp=thehive_config.get('default_tlp', 2)
            )
            soar.add_connector('thehive', thehive)
            logger.info("TheHive connector initialized")
        except Exception as e:
            logger.error(f"Error initializing TheHive connector: {e}")
    
    # Initialize Splunk SOAR connector if enabled
    splunk_config = config.get('splunk_soar', {})
    if splunk_config.get('enabled', False):
        try:
            splunk = SplunkSoarConnector(
                api_url=splunk_config.get('api_url', ''),
                api_token=splunk_config.get('api_token', ''),
                verify_ssl=splunk_config.get('verify_ssl', True),
                container_label=splunk_config.get('container_label', 'IDS Alert'),
                default_severity=splunk_config.get('default_severity', 'medium'),
                default_sensitivity=splunk_config.get('default_sensitivity', 'amber')
            )
            soar.add_connector('splunk_soar', splunk)
            logger.info("Splunk SOAR connector initialized")
        except Exception as e:
            logger.error(f"Error initializing Splunk SOAR connector: {e}")
    
    return soar

def create_sample_alert(config: Dict[str, Any], alert_type: str = "network_scan") -> Dict[str, Any]:
    """
    Create a sample alert based on the template in the configuration
    
    Args:
        config: SOAR configuration dictionary
        alert_type: Type of alert to create
        
    Returns:
        Alert data dictionary
    """
    # Get alert template
    template = config.get('alert_template', {})
    
    # Get current time
    detection_time = datetime.datetime.now().isoformat()
    
    # Sample data
    source_ip = "192.168.1.100"
    destination_ip = "192.168.1.1"
    severity = "medium"
    description = "Potential network scan detected from internal host."
    
    # Format template
    alert_data = {
        "title": template.get('title', '').format(alert_type=alert_type),
        "description": template.get('description', '').format(
            detection_time=detection_time,
            source_ip=source_ip,
            destination_ip=destination_ip,
            severity=severity,
            description=description,
            alert_type=alert_type
        ),
        "type": template.get('type', 'ids_alert'),
        "source": template.get('source', 'IDS'),
        "severity": severity,
        "tlp": template.get('tlp', 2),
        "tags": [tag.format(alert_type=alert_type) for tag in template.get('tags', [])],
        "id": f"IDS-ALERT-{int(datetime.datetime.now().timestamp())}",
        "observables": [
            {
                "type": "ip",
                "value": source_ip,
                "description": "Source IP",
                "tags": ["source", "internal"]
            },
            {
                "type": "ip",
                "value": destination_ip,
                "description": "Destination IP",
                "tags": ["destination", "internal"]
            }
        ],
        "custom_fields": {
            "alert_id": f"IDS-{int(datetime.datetime.now().timestamp())}",
            "detection_source": "IDS",
            "detection_type": alert_type
        }
    }
    
    return alert_data

def create_sample_case(config: Dict[str, Any], 
                      alerts: List[Dict[str, Any]],
                      case_title: str = "Multiple Suspicious Activities") -> Dict[str, Any]:
    """
    Create a sample case based on the template in the configuration
    
    Args:
        config: SOAR configuration dictionary
        alerts: List of related alerts
        case_title: Title of the case
        
    Returns:
        Case data dictionary
    """
    # Get case template
    template = config.get('case_template', {})
    
    # Determine highest severity
    severities = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    highest_severity = "low"
    
    for alert in alerts:
        alert_severity = alert.get("severity", "low").lower()
        if severities.get(alert_severity, 0) > severities.get(highest_severity, 0):
            highest_severity = alert_severity
    
    # Create description with alert summaries
    description = "This case contains the following alerts:\n\n"
    for alert in alerts:
        description += f"- {alert.get('title', 'Unknown Alert')} ({alert.get('id', 'Unknown ID')})\n"
    
    # Format template
    case_data = {
        "title": template.get('title', '').format(case_title=case_title),
        "description": template.get('description', '').format(
            description=description,
            case_title=case_title
        ),
        "severity": highest_severity,
        "tlp": template.get('tlp', 2),
        "tags": template.get('tags', []),
        "tasks": config.get('default_tasks', []),
        "observables": [],
        "custom_fields": {
            "case_id": f"IDS-CASE-{int(datetime.datetime.now().timestamp())}",
            "related_alerts": [alert.get('id', '') for alert in alerts],
            "alert_count": len(alerts)
        }
    }
    
    # Collect unique observables from all alerts
    observable_values = set()
    
    for alert in alerts:
        for observable in alert.get("observables", []):
            value = observable.get("value", "")
            if value and value not in observable_values:
                observable_values.add(value)
                case_data["observables"].append(observable)
    
    return case_data

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='SOAR Integration Example')
    parser.add_argument('--config', type=str, 
                        default='src/integrations/siem/config/soar_config.yaml',
                        help='Path to SOAR configuration file')
    parser.add_argument('--alert', action='store_true',
                        help='Create a sample alert')
    parser.add_argument('--case', action='store_true',
                        help='Create a sample case')
    parser.add_argument('--alert-type', type=str, default='network_scan',
                        help='Type of alert to create')
    parser.add_argument('--case-title', type=str, default='Multiple Suspicious Activities',
                        help='Title of the case to create')
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    if not config:
        logger.error("Failed to load configuration")
        return 1
    
    # Initialize SOAR integration
    soar = initialize_soar(config)
    
    # Create and send sample alert
    if args.alert:
        logger.info(f"Creating sample alert of type: {args.alert_type}")
        alert_data = create_sample_alert(config, args.alert_type)
        
        logger.info("Sending alert to SOAR platforms...")
        alert_ids = soar.create_alert(alert_data)
        
        for name, alert_id in alert_ids.items():
            if alert_id:
                logger.info(f"Successfully created alert in {name} with ID: {alert_id}")
            else:
                logger.warning(f"Failed to create alert in {name}")
    
    # Create and send sample case
    if args.case:
        # Create multiple sample alerts
        logger.info("Creating sample alerts for case")
        alerts = [
            create_sample_alert(config, "network_scan"),
            create_sample_alert(config, "brute_force"),
            create_sample_alert(config, "malware_detection")
        ]
        
        logger.info(f"Creating sample case: {args.case_title}")
        case_data = create_sample_case(config, alerts, args.case_title)
        
        logger.info("Sending case to SOAR platforms...")
        case_ids = soar.create_case(case_data)
        
        for name, case_id in case_ids.items():
            if case_id:
                logger.info(f"Successfully created case in {name} with ID: {case_id}")
            else:
                logger.warning(f"Failed to create case in {name}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 