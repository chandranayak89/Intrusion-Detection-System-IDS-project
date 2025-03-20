#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SIEM Connector Module
Provides base classes for SIEM system integration and alert formatting.
"""

import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Union, Callable
from abc import ABC, abstractmethod

# Configure logging
logger = logging.getLogger("ids.integrations.siem.connector")

class AlertFormatter:
    """Formats IDS alerts for SIEM system consumption"""
    
    def __init__(self, 
                 timestamp_format: str = "%Y-%m-%dT%H:%M:%S.%fZ",
                 include_raw_data: bool = False,
                 field_mapping: Optional[Dict[str, str]] = None):
        """
        Initialize the alert formatter
        
        Args:
            timestamp_format: Format string for timestamps
            include_raw_data: Whether to include raw alert data
            field_mapping: Optional mapping of IDS fields to SIEM fields
        """
        self.timestamp_format = timestamp_format
        self.include_raw_data = include_raw_data
        self.field_mapping = field_mapping or {}
    
    def format_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format an IDS alert for SIEM consumption
        
        Args:
            alert: Raw IDS alert
            
        Returns:
            Formatted alert ready for SIEM ingestion
        """
        formatted = {}
        
        # Apply field mapping if provided
        for ids_field, siem_field in self.field_mapping.items():
            if ids_field in alert:
                formatted[siem_field] = alert[ids_field]
        
        # If no mapping provided, use all fields
        if not self.field_mapping:
            formatted = dict(alert)
        
        # Ensure timestamps are properly formatted
        for field in ['timestamp', 'event_time', 'detection_time']:
            if field in formatted:
                if isinstance(formatted[field], datetime.datetime):
                    formatted[field] = formatted[field].strftime(self.timestamp_format)
                elif isinstance(formatted[field], (int, float)):
                    # Convert epoch timestamp to formatted string
                    formatted[field] = datetime.datetime.fromtimestamp(
                        formatted[field]
                    ).strftime(self.timestamp_format)
        
        # Include raw data if requested
        if self.include_raw_data:
            formatted['raw_alert'] = json.dumps(alert)
        
        # Add standardized fields
        formatted['siem_ingest_time'] = datetime.datetime.utcnow().strftime(self.timestamp_format)
        
        return formatted

    def format_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format multiple IDS alerts for SIEM consumption
        
        Args:
            alerts: List of raw IDS alerts
            
        Returns:
            List of formatted alerts ready for SIEM ingestion
        """
        return [self.format_alert(alert) for alert in alerts]

class SiemConnector(ABC):
    """Base class for SIEM system connectors"""
    
    def __init__(self, 
                 formatter: Optional[AlertFormatter] = None,
                 batch_size: int = 100,
                 auto_reconnect: bool = True,
                 max_retries: int = 3):
        """
        Initialize the SIEM connector
        
        Args:
            formatter: Alert formatter instance
            batch_size: Maximum batch size for sending alerts
            auto_reconnect: Whether to automatically reconnect on failure
            max_retries: Maximum number of retry attempts
        """
        self.formatter = formatter or AlertFormatter()
        self.batch_size = batch_size
        self.auto_reconnect = auto_reconnect
        self.max_retries = max_retries
        self.connected = False
        self.stats = {
            "alerts_sent": 0,
            "batches_sent": 0,
            "connection_failures": 0,
            "send_failures": 0,
            "reconnect_attempts": 0
        }
    
    @abstractmethod
    def connect(self) -> bool:
        """
        Connect to the SIEM system
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> bool:
        """
        Disconnect from the SIEM system
        
        Returns:
            True if disconnection successful, False otherwise
        """
        pass
    
    @abstractmethod
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Send a single alert to the SIEM system
        
        Args:
            alert: Alert data
            
        Returns:
            True if send successful, False otherwise
        """
        pass
    
    @abstractmethod
    def send_alerts_batch(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Send a batch of alerts to the SIEM system
        
        Args:
            alerts: List of alert data
            
        Returns:
            True if send successful, False otherwise
        """
        pass
    
    def send_alerts(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Send multiple alerts to the SIEM system with automatic batching
        
        Args:
            alerts: List of alert data
            
        Returns:
            True if all sends successful, False otherwise
        """
        if not self.connected and self.auto_reconnect:
            self._try_reconnect()
            
        if not self.connected:
            logger.error("Cannot send alerts: not connected to SIEM system")
            return False
        
        # Format the alerts
        formatted_alerts = self.formatter.format_alerts(alerts)
        
        # Send in batches
        success = True
        for i in range(0, len(formatted_alerts), self.batch_size):
            batch = formatted_alerts[i:i+self.batch_size]
            
            # Try to send the batch
            batch_success = False
            for attempt in range(self.max_retries):
                if self.send_alerts_batch(batch):
                    self.stats["batches_sent"] += 1
                    self.stats["alerts_sent"] += len(batch)
                    batch_success = True
                    break
                else:
                    logger.warning(f"Failed to send batch (attempt {attempt+1}/{self.max_retries})")
                    self.stats["send_failures"] += 1
                    
                    # Try to reconnect if configured
                    if self.auto_reconnect:
                        self._try_reconnect()
            
            # Update overall success flag
            success = success and batch_success
            
        return success
    
    def _try_reconnect(self) -> bool:
        """
        Try to reconnect to the SIEM system
        
        Returns:
            True if reconnection successful, False otherwise
        """
        self.stats["reconnect_attempts"] += 1
        logger.info(f"Attempting to reconnect to SIEM system (attempt {self.stats['reconnect_attempts']})")
        
        try:
            # First disconnect if already connected
            if self.connected:
                self.disconnect()
                
            # Try to connect
            success = self.connect()
            if not success:
                self.stats["connection_failures"] += 1
                logger.error("Failed to reconnect to SIEM system")
            
            return success
        except Exception as e:
            self.stats["connection_failures"] += 1
            logger.error(f"Error reconnecting to SIEM system: {e}")
            return False
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get connector statistics
        
        Returns:
            Dictionary with connection and send statistics
        """
        return self.stats 