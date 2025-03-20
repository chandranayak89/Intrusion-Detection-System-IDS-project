#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SIEM & Incident Response Integration Module
This module provides integration with SIEM systems and incident response platforms:
1. SOAR Integration (TheHive, Splunk SOAR)
2. Log Enrichment (GeoIP, DNS lookups)
3. Webhook & API Triggers (Slack, Email, PagerDuty)
"""

import logging

# Set up package-level logger
logger = logging.getLogger("ids.integrations.siem")
logger.setLevel(logging.INFO)

# Import components
from .soar_integration import SoarIntegration, TheHiveConnector, SplunkSoarConnector
from .log_enrichment import LogEnricher, GeoIPEnricher, DNSEnricher, ThreatIntelEnricher
from .notification import NotificationManager, SlackNotifier, EmailNotifier, PagerDutyNotifier
from .siem_connector import SiemConnector, AlertFormatter

__all__ = [
    # SOAR Integration
    'SoarIntegration',
    'TheHiveConnector',
    'SplunkSoarConnector',
    
    # Log Enrichment
    'LogEnricher',
    'GeoIPEnricher',
    'DNSEnricher',
    'ThreatIntelEnricher',
    
    # Notification
    'NotificationManager',
    'SlackNotifier',
    'EmailNotifier',
    'PagerDutyNotifier',
    
    # SIEM Connector
    'SiemConnector',
    'AlertFormatter'
] 