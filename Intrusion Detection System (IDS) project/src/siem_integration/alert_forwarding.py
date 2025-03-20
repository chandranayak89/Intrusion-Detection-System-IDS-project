#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Alert Forwarding Module
This module handles forwarding alerts to SIEM systems.
"""

import os
import sys
import logging
import json
import socket
import time
import threading
import queue
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Setup logging
logger = logging.getLogger('ids.alert_forwarding')

class AlertForwarder:
    """Base class for alert forwarding implementations."""
    
    def __init__(self, config=None):
        """
        Initialize the alert forwarder.
        
        Args:
            config (dict, optional): Configuration parameters
        """
        self.config = config or {}
        
    def send_alert(self, alert_type, alert_data, packet=None):
        """
        Send an alert.
        
        Args:
            alert_type (str): Type of alert ('signature', 'anomaly')
            alert_data (dict): Alert data
            packet (dict, optional): Packet that triggered the alert
            
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement send_alert()")
        
    def _format_alert(self, alert_type, alert_data, packet=None):
        """
        Format an alert for sending.
        
        Args:
            alert_type (str): Type of alert ('signature', 'anomaly')
            alert_data (dict): Alert data
            packet (dict, optional): Packet that triggered the alert
            
        Returns:
            dict: Formatted alert
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'data': alert_data
        }
        
        if packet:
            # Add relevant packet information to the alert
            packet_info = {
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip'),
                'src_port': packet.get('src_port'),
                'dst_port': packet.get('dst_port'),
                'protocol': packet.get('protocol'),
                'length': packet.get('length')
            }
            
            # Add payload information if available (truncated for alerts)
            if 'payload' in packet:
                payload = packet['payload']
                if isinstance(payload, str) and len(payload) > 200:
                    packet_info['payload'] = payload[:200] + '...'
                else:
                    packet_info['payload'] = payload
                    
            alert['packet'] = packet_info
            
        return alert

class FileAlertForwarder(AlertForwarder):
    """Alert forwarder that writes alerts to a file."""
    
    def __init__(self, config=None):
        """
        Initialize the file alert forwarder.
        
        Args:
            config (dict, optional): Configuration parameters
        """
        super().__init__(config)
        
        # Get log file path from config
        self.log_file = self.config.get('log_file')
        if not self.log_file:
            # Use default log file in the project's logs directory
            logs_dir = self.config.get('logs_dir')
            if not logs_dir:
                logs_dir = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    'logs'
                )
            os.makedirs(logs_dir, exist_ok=True)
            
            self.log_file = os.path.join(logs_dir, 'alerts.log')
            
        logger.info(f"File alert forwarder initialized, writing to {self.log_file}")
        
    def send_alert(self, alert_type, alert_data, packet=None):
        """
        Send an alert by writing it to the log file.
        
        Args:
            alert_type (str): Type of alert ('signature', 'anomaly')
            alert_data (dict): Alert data
            packet (dict, optional): Packet that triggered the alert
            
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        try:
            alert = self._format_alert(alert_type, alert_data, packet)
            
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
                
            logger.debug(f"Alert written to {self.log_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error writing alert to file: {e}")
            return False

class SyslogAlertForwarder(AlertForwarder):
    """Alert forwarder that sends alerts to a syslog server."""
    
    def __init__(self, config=None):
        """
        Initialize the syslog alert forwarder.
        
        Args:
            config (dict, optional): Configuration parameters
        """
        super().__init__(config)
        
        # Get syslog server details from config
        self.server = self.config.get('server', 'localhost')
        self.port = int(self.config.get('port', 514))
        self.protocol = self.config.get('protocol', 'udp').lower()
        self.facility = int(self.config.get('facility', 1))  # user-level messages
        
        self.socket = None
        self.connected = False
        
        # Connect to syslog server
        self._connect()
        
    def _connect(self):
        """Connect to the syslog server."""
        try:
            if self.protocol == 'tcp':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.server, self.port))
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
            self.connected = True
            logger.info(f"Connected to syslog server at {self.server}:{self.port} using {self.protocol.upper()}")
            
        except Exception as e:
            logger.error(f"Error connecting to syslog server: {e}")
            self.connected = False
            
    def _format_syslog_message(self, alert):
        """
        Format an alert as a syslog message.
        
        Args:
            alert (dict): Formatted alert
            
        Returns:
            str: Syslog message
        """
        # Calculate priority value (facility * 8 + severity)
        # Severity: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
        severity = 4  # Default to Warning
        
        if alert['type'] == 'signature':
            alert_severity = alert['data'].get('severity', '').lower()
            if alert_severity == 'critical':
                severity = 2
            elif alert_severity == 'high':
                severity = 3
            elif alert_severity == 'medium':
                severity = 4
            elif alert_severity == 'low':
                severity = 5
                
        priority = self.facility * 8 + severity
        
        # Format timestamp
        timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%b %d %H:%M:%S')
        
        # Format hostname
        hostname = socket.gethostname()
        
        # Format message content
        if alert['type'] == 'signature':
            content = f"IDS-SIGNATURE-MATCH: {alert['data'].get('name', 'Unknown')} - {alert['data'].get('rule_id', 'Unknown')}"
        else:
            content = f"IDS-ANOMALY-DETECTED: Score {alert['data']}"
            
        # Add packet info if available
        if 'packet' in alert:
            packet = alert['packet']
            content += f" - {packet.get('src_ip', '')}:{packet.get('src_port', '')} -> {packet.get('dst_ip', '')}:{packet.get('dst_port', '')}"
            
        # Construct full syslog message
        return f"<{priority}>{timestamp} {hostname} ids: {content}"
        
    def send_alert(self, alert_type, alert_data, packet=None):
        """
        Send an alert to the syslog server.
        
        Args:
            alert_type (str): Type of alert ('signature', 'anomaly')
            alert_data (dict): Alert data
            packet (dict, optional): Packet that triggered the alert
            
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        if not self.connected:
            self._connect()
            if not self.connected:
                logger.error("Cannot send alert: not connected to syslog server")
                return False
                
        try:
            alert = self._format_alert(alert_type, alert_data, packet)
            message = self._format_syslog_message(alert)
            
            if self.protocol == 'tcp':
                self.socket.sendall((message + '\n').encode('utf-8'))
            else:  # UDP
                self.socket.sendto(message.encode('utf-8'), (self.server, self.port))
                
            logger.debug(f"Alert sent to syslog server")
            return True
            
        except Exception as e:
            logger.error(f"Error sending alert to syslog server: {e}")
            self.connected = False
            return False
            
    def close(self):
        """Close the connection to the syslog server."""
        if self.socket:
            try:
                if self.protocol == 'tcp':
                    self.socket.close()
                self.socket = None
                self.connected = False
                logger.info("Connection to syslog server closed")
            except Exception as e:
                logger.error(f"Error closing syslog connection: {e}")

class ElasticsearchAlertForwarder(AlertForwarder):
    """Alert forwarder that sends alerts to Elasticsearch."""
    
    def __init__(self, config=None):
        """
        Initialize the Elasticsearch alert forwarder.
        
        Args:
            config (dict, optional): Configuration parameters
        """
        super().__init__(config)
        
        if not HAS_REQUESTS:
            logger.error("Requests library not available, Elasticsearch forwarding disabled")
            self.enabled = False
            return
            
        # Get Elasticsearch details from config
        self.es_url = self.config.get('elasticsearch_url', 'http://localhost:9200')
        self.index = self.config.get('index', 'ids-alerts')
        self.username = self.config.get('username')
        self.password = self.config.get('password')
        
        # Authentication
        self.auth = None
        if self.username and self.password:
            self.auth = (self.username, self.password)
            
        self.enabled = True
        logger.info(f"Elasticsearch alert forwarder initialized, sending to {self.es_url}/{self.index}")
        
    def send_alert(self, alert_type, alert_data, packet=None):
        """
        Send an alert to Elasticsearch.
        
        Args:
            alert_type (str): Type of alert ('signature', 'anomaly')
            alert_data (dict): Alert data
            packet (dict, optional): Packet that triggered the alert
            
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        if not self.enabled or not HAS_REQUESTS:
            logger.warning("Elasticsearch forwarding is disabled")
            return False
            
        try:
            alert = self._format_alert(alert_type, alert_data, packet)
            
            # Send to Elasticsearch
            url = f"{self.es_url}/{self.index}/_doc"
            headers = {'Content-Type': 'application/json'}
            
            response = requests.post(
                url,
                data=json.dumps(alert),
                headers=headers,
                auth=self.auth
            )
            
            response.raise_for_status()
            
            logger.debug(f"Alert sent to Elasticsearch: {response.json()}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending alert to Elasticsearch: {e}")
            return False

class AlertQueue:
    """Queue for handling alerts asynchronously."""
    
    def __init__(self, forwarders=None, queue_size=1000):
        """
        Initialize the alert queue.
        
        Args:
            forwarders (list, optional): List of alert forwarders
            queue_size (int): Maximum size of the queue
        """
        self.forwarders = forwarders or []
        self.queue = queue.Queue(maxsize=queue_size)
        self.thread = threading.Thread(target=self._process_queue)
        self.thread.daemon = True
        self.running = False
        
    def start(self):
        """Start the alert processing thread."""
        if not self.running:
            self.running = True
            self.thread.start()
            logger.info(f"Alert queue started with {len(self.forwarders)} forwarders")
            
    def stop(self):
        """Stop the alert processing thread."""
        self.running = False
        if self.thread.is_alive():
            self.thread.join(timeout=5.0)
            logger.info("Alert queue stopped")
            
    def add_forwarder(self, forwarder):
        """
        Add an alert forwarder.
        
        Args:
            forwarder (AlertForwarder): Alert forwarder to add
        """
        self.forwarders.append(forwarder)
        logger.info(f"Added alert forwarder: {forwarder.__class__.__name__}")
        
    def send_alert(self, alert_type, alert_data, packet=None):
        """
        Send an alert by adding it to the queue.
        
        Args:
            alert_type (str): Type of alert ('signature', 'anomaly')
            alert_data (dict): Alert data
            packet (dict, optional): Packet that triggered the alert
            
        Returns:
            bool: True if the alert was added to the queue, False otherwise
        """
        if not self.running:
            logger.warning("Alert queue is not running")
            return False
            
        try:
            self.queue.put((alert_type, alert_data, packet), block=False)
            return True
        except queue.Full:
            logger.warning("Alert queue is full, alert dropped")
            return False
            
    def _process_queue(self):
        """Process alerts from the queue."""
        while self.running:
            try:
                # Get an alert from the queue (with timeout)
                try:
                    alert_type, alert_data, packet = self.queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Forward the alert to all forwarders
                for forwarder in self.forwarders:
                    try:
                        forwarder.send_alert(alert_type, alert_data, packet)
                    except Exception as e:
                        logger.error(f"Error in forwarder {forwarder.__class__.__name__}: {e}")
                        
                # Mark the alert as processed
                self.queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing alert from queue: {e}")
                time.sleep(1.0)  # Avoid tight looping on error

# Global alert queue instance
_alert_queue = None

def initialize(config=None):
    """
    Initialize the alert forwarding system.
    
    Args:
        config (dict, optional): Configuration parameters
        
    Returns:
        AlertQueue: Initialized alert queue
    """
    global _alert_queue
    
    if _alert_queue:
        logger.info("Alert forwarding already initialized")
        return _alert_queue
        
    config = config or {}
    forwarders = []
    
    # Create forwarders based on config
    forwarder_configs = config.get('forwarders', [])
    for forwarder_config in forwarder_configs:
        forwarder_type = forwarder_config.get('type', '').lower()
        
        if forwarder_type == 'file':
            forwarders.append(FileAlertForwarder(forwarder_config))
        elif forwarder_type == 'syslog':
            forwarders.append(SyslogAlertForwarder(forwarder_config))
        elif forwarder_type == 'elasticsearch':
            forwarders.append(ElasticsearchAlertForwarder(forwarder_config))
        else:
            logger.warning(f"Unknown alert forwarder type: {forwarder_type}")
            
    # If no forwarders are configured, use file forwarder by default
    if not forwarders:
        logger.info("No alert forwarders configured, using file forwarder by default")
        forwarders.append(FileAlertForwarder())
        
    # Create and start alert queue
    _alert_queue = AlertQueue(forwarders)
    _alert_queue.start()
    
    return _alert_queue

def send_alert(alert_type, alert_data, packet=None):
    """
    Send an alert.
    
    Args:
        alert_type (str): Type of alert ('signature', 'anomaly')
        alert_data (dict): Alert data
        packet (dict, optional): Packet that triggered the alert
        
    Returns:
        bool: True if the alert was sent successfully, False otherwise
    """
    global _alert_queue
    
    if not _alert_queue:
        # Initialize with default configuration if not already initialized
        _alert_queue = initialize()
        
    return _alert_queue.send_alert(alert_type, alert_data, packet)

def shutdown():
    """Shutdown the alert forwarding system."""
    global _alert_queue
    
    if _alert_queue:
        _alert_queue.stop()
        _alert_queue = None
        logger.info("Alert forwarding system shut down")

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Initialize alert forwarding
    initialize({
        'forwarders': [
            {
                'type': 'file',
                'log_file': 'alerts_test.log'
            }
        ]
    })
    
    # Send test alerts
    send_alert('signature', {
        'rule_id': 'TEST-001',
        'name': 'Test Signature Alert',
        'description': 'This is a test signature alert',
        'severity': 'medium'
    }, {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP'
    })
    
    send_alert('anomaly', 0.95, {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP'
    })
    
    # Shutdown alert forwarding
    shutdown() 