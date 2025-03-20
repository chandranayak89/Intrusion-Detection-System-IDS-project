#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SIEM & Incident Response Integration Example
Demonstrates how to use the SIEM integration modules together to enrich IDS alerts,
send them to SOAR platforms, and notify security teams.
"""

import os
import sys
import json
import yaml
import logging
import argparse
import datetime
from typing import Dict, List, Any, Optional

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

# Import SIEM integration components
from src.integrations.siem.log_enrichment import (
    LogEnricher,
    GeoIPEnricher,
    DNSEnricher,
    ThreatIntelEnricher
)
from src.integrations.siem.notification import (
    NotificationManager,
    SlackNotifier,
    EmailNotifier,
    PagerDutyNotifier
)
from src.integrations.siem.soar_integration import (
    SoarIntegration,
    TheHiveConnector,
    SplunkSoarConnector
)
from src.integrations.siem.siem_connector import (
    AlertFormatter,
    SiemConnector
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("siem-example")

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
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

def create_sample_alert() -> Dict[str, Any]:
    """
    Create a sample IDS alert
    
    Returns:
        Alert data dictionary
    """
    # Generate a timestamp
    timestamp = datetime.datetime.now()
    
    # Create a sample alert
    alert = {
        "id": f"IDS-ALERT-{int(timestamp.timestamp())}",
        "timestamp": timestamp.isoformat(),
        "title": "Potential Port Scan Detected",
        "description": "Multiple connection attempts detected from a single source IP to various ports",
        "severity": "medium",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.1",
        "protocol": "TCP",
        "source_port": 49152,
        "destination_ports": [22, 23, 25, 80, 443, 445, 3389],
        "alert_type": "port_scan",
        "rule_id": "IDS-PORTSCAN-001",
        "rule_name": "TCP Port Scan",
        "packet_count": 37,
        "duration_seconds": 5.2,
        "observables": [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "description": "Source IP"
            },
            {
                "type": "ip",
                "value": "192.168.1.1",
                "description": "Destination IP"
            }
        ],
        "network_context": {
            "vlan_id": 100,
            "network_zone": "Internal"
        },
        "device_context": {
            "hostname": "endpoint-workstation-35",
            "mac_address": "00:11:22:33:44:55"
        }
    }
    
    return alert

def initialize_enricher(config: Dict[str, Any]) -> LogEnricher:
    """
    Initialize log enrichment components
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Initialized LogEnricher instance
    """
    enricher = LogEnricher()
    
    # Add GeoIP enricher if configured
    geoip_config = config.get('geoip', {})
    if geoip_config.get('enabled', False):
        try:
            geoip_enricher = GeoIPEnricher(
                db_path=geoip_config.get('db_path'),
                cache_size=geoip_config.get('cache_size', 1000),
                cache_ttl=geoip_config.get('cache_ttl', 86400),
                field_name=geoip_config.get('field_name', 'geoip'),
                ip_fields=geoip_config.get('ip_fields')
            )
            enricher.add_enricher(geoip_enricher)
            logger.info("Added GeoIP enricher")
        except Exception as e:
            logger.error(f"Error initializing GeoIP enricher: {e}")
    
    # Add DNS enricher if configured
    dns_config = config.get('dns', {})
    if dns_config.get('enabled', False):
        try:
            dns_enricher = DNSEnricher(
                cache_size=dns_config.get('cache_size', 1000),
                cache_ttl=dns_config.get('cache_ttl', 3600),
                field_name=dns_config.get('field_name', 'dns'),
                ip_fields=dns_config.get('ip_fields'),
                hostname_fields=dns_config.get('hostname_fields'),
                dns_servers=dns_config.get('dns_servers'),
                timeout=dns_config.get('timeout', 2.0)
            )
            enricher.add_enricher(dns_enricher)
            logger.info("Added DNS enricher")
        except Exception as e:
            logger.error(f"Error initializing DNS enricher: {e}")
    
    # Add threat intelligence enricher if configured
    ti_config = config.get('threat_intel', {})
    if ti_config.get('enabled', False):
        try:
            ti_enricher = ThreatIntelEnricher(
                api_key=ti_config.get('api_key'),
                api_url=ti_config.get('api_url'),
                cache_size=ti_config.get('cache_size', 1000),
                cache_ttl=ti_config.get('cache_ttl', 86400),
                field_name=ti_config.get('field_name', 'threat_intel'),
                indicator_fields=ti_config.get('indicator_fields'),
                timeout=ti_config.get('timeout', 10.0)
            )
            enricher.add_enricher(ti_enricher)
            logger.info("Added Threat Intelligence enricher")
        except Exception as e:
            logger.error(f"Error initializing Threat Intelligence enricher: {e}")
    
    return enricher

def initialize_notification_manager(config: Dict[str, Any]) -> NotificationManager:
    """
    Initialize notification components
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Initialized NotificationManager instance
    """
    manager = NotificationManager()
    
    # Add Slack notifier if configured
    slack_config = config.get('slack', {})
    if slack_config.get('enabled', False):
        try:
            slack_notifier = SlackNotifier(
                webhook_url=slack_config.get('webhook_url', ''),
                channel=slack_config.get('channel'),
                username=slack_config.get('username', 'IDS Alert System'),
                icon_emoji=slack_config.get('icon_emoji', ':warning:'),
                timeout=slack_config.get('timeout', 5.0),
                include_full_data=slack_config.get('include_full_data', False)
            )
            manager.add_notifier('slack', slack_notifier)
            logger.info("Added Slack notifier")
        except Exception as e:
            logger.error(f"Error initializing Slack notifier: {e}")
    
    # Add Email notifier if configured
    email_config = config.get('email', {})
    if email_config.get('enabled', False):
        try:
            email_notifier = EmailNotifier(
                smtp_server=email_config.get('smtp_server', ''),
                smtp_port=email_config.get('smtp_port', 587),
                use_tls=email_config.get('use_tls', True),
                username=email_config.get('username'),
                password=email_config.get('password'),
                from_address=email_config.get('from_address', 'ids-alerts@example.com'),
                to_addresses=email_config.get('to_addresses', []),
                cc_addresses=email_config.get('cc_addresses', []),
                bcc_addresses=email_config.get('bcc_addresses', []),
                template_path=email_config.get('template_path')
            )
            manager.add_notifier('email', email_notifier)
            logger.info("Added Email notifier")
        except Exception as e:
            logger.error(f"Error initializing Email notifier: {e}")
    
    # Add PagerDuty notifier if configured
    pagerduty_config = config.get('pagerduty', {})
    if pagerduty_config.get('enabled', False):
        try:
            pagerduty_notifier = PagerDutyNotifier(
                api_key=pagerduty_config.get('api_key', ''),
                timeout=pagerduty_config.get('timeout', 10.0),
                service_id=pagerduty_config.get('service_id'),
                source=pagerduty_config.get('source', 'IDS'),
                component=pagerduty_config.get('component', 'Security'),
                include_full_data=pagerduty_config.get('include_full_data', False)
            )
            manager.add_notifier('pagerduty', pagerduty_notifier)
            logger.info("Added PagerDuty notifier")
        except Exception as e:
            logger.error(f"Error initializing PagerDuty notifier: {e}")
    
    return manager

def initialize_soar_integration(config: Dict[str, Any]) -> SoarIntegration:
    """
    Initialize SOAR integration components
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Initialized SoarIntegration instance
    """
    soar = SoarIntegration()
    
    # Add TheHive connector if configured
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
            logger.info("Added TheHive connector")
        except Exception as e:
            logger.error(f"Error initializing TheHive connector: {e}")
    
    # Add Splunk SOAR connector if configured
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
            logger.info("Added Splunk SOAR connector")
        except Exception as e:
            logger.error(f"Error initializing Splunk SOAR connector: {e}")
    
    return soar

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='SIEM Integration Example')
    parser.add_argument('--config', type=str, 
                        default='src/integrations/siem/config/siem_config.yaml',
                        help='Path to SIEM configuration file')
    parser.add_argument('--save-enriched', type=str,
                        help='Save enriched alert to specified JSON file')
    parser.add_argument('--notify', action='store_true',
                        help='Send notifications')
    parser.add_argument('--soar', action='store_true',
                        help='Send to SOAR platforms')
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    if not config:
        logger.error("Failed to load configuration")
        return 1
    
    # Create a sample alert
    logger.info("Creating sample IDS alert")
    alert = create_sample_alert()
    
    # Initialize log enricher
    enricher = initialize_enricher(config)
    
    # Enrich the alert
    logger.info("Enriching the alert with contextual metadata")
    enriched_alert = enricher.enrich(alert)
    
    # Print enrichment summary
    print("\n=== Alert Enrichment Summary ===")
    print(f"Original Fields: {len(alert.keys())}")
    print(f"Enriched Fields: {len(enriched_alert.keys())}")
    
    if 'geoip' in enriched_alert:
        print("\nGeoIP Enrichment:")
        for ip, data in enriched_alert['geoip'].items():
            if 'country_name' in data:
                print(f"  {ip}: {data.get('country_name')}, {data.get('city')}")
    
    if 'dns' in enriched_alert:
        print("\nDNS Enrichment:")
        for item, data in enriched_alert['dns'].items():
            if 'hostnames' in data:
                print(f"  {item} resolves to: {', '.join(data['hostnames'])}")
            if 'ip_addresses' in data:
                print(f"  {item} has IPs: {', '.join(data['ip_addresses'])}")
    
    if 'threat_intel' in enriched_alert:
        print("\nThreat Intelligence Enrichment:")
        for indicator, data in enriched_alert['threat_intel'].items():
            status = "MALICIOUS" if data.get('malicious', False) else "CLEAN"
            print(f"  {indicator}: {status}")
    
    # Save enriched alert if requested
    if args.save_enriched:
        try:
            with open(args.save_enriched, 'w') as file:
                json.dump(enriched_alert, file, indent=2)
            logger.info(f"Saved enriched alert to {args.save_enriched}")
        except Exception as e:
            logger.error(f"Error saving enriched alert: {e}")
    
    # Send notifications if requested
    if args.notify:
        logger.info("Initializing notification manager")
        notification_manager = initialize_notification_manager(config)
        
        # Create notification data
        notification = {
            "title": enriched_alert.get("title", "IDS Alert"),
            "message": enriched_alert.get("description", ""),
            "severity": enriched_alert.get("severity", "medium"),
            "data": {
                "Alert ID": enriched_alert.get("id"),
                "Timestamp": enriched_alert.get("timestamp"),
                "Source IP": enriched_alert.get("source_ip"),
                "Destination IP": enriched_alert.get("destination_ip"),
                "Alert Type": enriched_alert.get("alert_type")
            },
            "tags": ["ids", enriched_alert.get("alert_type", "")]
        }
        
        # Add GeoIP info if available
        if 'geoip' in enriched_alert and enriched_alert.get('source_ip') in enriched_alert['geoip']:
            geoip = enriched_alert['geoip'][enriched_alert.get('source_ip')]
            if 'country_name' in geoip:
                notification["data"]["Source Location"] = f"{geoip.get('city', '')}, {geoip.get('country_name', '')}"
        
        # Add threat intel info if available
        if 'threat_intel' in enriched_alert:
            for indicator, data in enriched_alert['threat_intel'].items():
                if data.get('malicious', False):
                    notification["data"]["Threat Intel"] = f"Malicious indicator detected: {indicator}"
                    notification["tags"].append("malicious")
                    # Escalate severity if malicious
                    notification["severity"] = "high"
                    break
        
        logger.info("Sending notifications")
        results = notification_manager.send_notification(**notification)
        
        # Print notification results
        print("\n=== Notification Results ===")
        for notifier, success in results.items():
            status = "SUCCESS" if success else "FAILED"
            print(f"  {notifier}: {status}")
    
    # Send to SOAR platforms if requested
    if args.soar:
        logger.info("Initializing SOAR integration")
        soar_integration = initialize_soar_integration(config)
        
        logger.info("Sending alert to SOAR platforms")
        alert_ids = soar_integration.create_alert(enriched_alert)
        
        # Print SOAR results
        print("\n=== SOAR Integration Results ===")
        for platform, alert_id in alert_ids.items():
            status = f"SUCCESS (ID: {alert_id})" if alert_id else "FAILED"
            print(f"  {platform}: {status}")
    
    print("\nSIEM integration example completed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 