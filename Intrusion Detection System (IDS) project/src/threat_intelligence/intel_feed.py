#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Threat Intelligence Feed Module
This module provides integration with external threat intelligence sources.
"""

import os
import sys
import logging
import json
import yaml
import ipaddress
import hashlib
import time
import datetime
import threading
import queue
import requests
from urllib.parse import urlparse
from collections import defaultdict

# Setup logging
logger = logging.getLogger('ids.threat_intelligence')

class ThreatIntelFeed:
    """Base class for threat intelligence feeds."""
    
    def __init__(self, name, config=None, cache_dir=None):
        """
        Initialize the threat intelligence feed.
        
        Args:
            name (str): Name of the feed
            config (dict, optional): Configuration dictionary
            cache_dir (str, optional): Directory to cache threat intelligence data
        """
        self.name = name
        self.config = config or {}
        
        # Set up cache directory
        if cache_dir:
            self.cache_dir = cache_dir
        else:
            # Use default cache directory
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.cache_dir = os.path.join(base_dir, 'data', 'threat_intel')
            
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize indicators cache
        self.indicators = {
            'ip': set(),
            'domain': set(),
            'url': set(),
            'hash': set(),
            'other': set()
        }
        
        # Track when the feed was last updated
        self.last_updated = None
    
    def update(self):
        """
        Update the threat intelligence feed.
        Must be implemented by subclasses.
        
        Returns:
            bool: True if successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement update()")
    
    def check_indicator(self, indicator_type, indicator_value):
        """
        Check if an indicator is in the threat feed.
        
        Args:
            indicator_type (str): Type of indicator ('ip', 'domain', 'url', 'hash', 'other')
            indicator_value (str): Value to check
            
        Returns:
            bool: True if the indicator is in the feed, False otherwise
        """
        if indicator_type not in self.indicators:
            logger.warning(f"Unknown indicator type: {indicator_type}")
            return False
            
        return indicator_value in self.indicators[indicator_type]
    
    def add_indicator(self, indicator_type, indicator_value):
        """
        Add an indicator to the feed.
        
        Args:
            indicator_type (str): Type of indicator ('ip', 'domain', 'url', 'hash', 'other')
            indicator_value (str): Value to add
        """
        if indicator_type not in self.indicators:
            logger.warning(f"Unknown indicator type: {indicator_type}")
            return
            
        self.indicators[indicator_type].add(indicator_value)
    
    def save_cache(self):
        """
        Save the indicators to cache.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cache_file = os.path.join(self.cache_dir, f"{self.name}_cache.json")
            
            # Convert sets to lists for JSON serialization
            serializable = {
                'name': self.name,
                'last_updated': self.last_updated.isoformat() if self.last_updated else None,
                'indicators': {k: list(v) for k, v in self.indicators.items()}
            }
            
            with open(cache_file, 'w') as f:
                json.dump(serializable, f, indent=2)
                
            logger.info(f"Saved {self.name} feed cache to {cache_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving cache for {self.name}: {e}")
            return False
    
    def load_cache(self):
        """
        Load the indicators from cache.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cache_file = os.path.join(self.cache_dir, f"{self.name}_cache.json")
            
            if not os.path.exists(cache_file):
                logger.info(f"No cache file found for {self.name}")
                return False
                
            with open(cache_file, 'r') as f:
                data = json.load(f)
                
            # Convert lists back to sets
            for indicator_type, indicators in data.get('indicators', {}).items():
                if indicator_type in self.indicators:
                    self.indicators[indicator_type] = set(indicators)
                    
            # Parse last updated timestamp
            if data.get('last_updated'):
                self.last_updated = datetime.datetime.fromisoformat(data['last_updated'])
                
            logger.info(f"Loaded {self.name} feed cache from {cache_file}")
            
            # Log statistics
            total_indicators = sum(len(v) for v in self.indicators.values())
            logger.info(f"Loaded {total_indicators} indicators from {self.name} feed cache")
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading cache for {self.name}: {e}")
            return False
    
    def is_cache_expired(self, max_age_hours=24):
        """
        Check if the cache is expired.
        
        Args:
            max_age_hours (int): Maximum age of the cache in hours
            
        Returns:
            bool: True if the cache is expired or doesn't exist, False otherwise
        """
        if not self.last_updated:
            return True
            
        # Calculate the age of the cache
        age = datetime.datetime.now() - self.last_updated
        
        # Convert age to hours
        age_hours = age.total_seconds() / 3600
        
        return age_hours > max_age_hours
    
    def update_if_needed(self, max_age_hours=24):
        """
        Update the feed if the cache is expired.
        
        Args:
            max_age_hours (int): Maximum age of the cache in hours
            
        Returns:
            bool: True if the feed was updated or loaded from cache, False otherwise
        """
        # Try to load from cache first
        if not self.load_cache():
            # If no cache exists, update the feed
            logger.info(f"No cache found for {self.name}, updating feed")
            return self.update()
            
        # Check if the cache is expired
        if self.is_cache_expired(max_age_hours):
            logger.info(f"Cache for {self.name} is expired, updating feed")
            return self.update()
            
        logger.info(f"Using cached data for {self.name} feed")
        return True

class AbuseIPDBFeed(ThreatIntelFeed):
    """Integration with AbuseIPDB threat intelligence feed."""
    
    def __init__(self, config=None, cache_dir=None):
        """
        Initialize the AbuseIPDB feed.
        
        Args:
            config (dict, optional): Configuration dictionary containing API key
            cache_dir (str, optional): Directory to cache threat intelligence data
        """
        super().__init__('abuseipdb', config, cache_dir)
        
        # API endpoints
        self.blacklist_endpoint = "https://api.abuseipdb.com/api/v2/blacklist"
        self.check_endpoint = "https://api.abuseipdb.com/api/v2/check"
        
        # Verify API key is present
        self.api_key = self.config.get('api_key')
        if not self.api_key:
            logger.warning("No API key provided for AbuseIPDB feed")
    
    def update(self):
        """
        Update the AbuseIPDB blacklist.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.api_key:
            logger.error("Cannot update AbuseIPDB feed: No API key provided")
            return False
            
        try:
            # Set up headers with API key
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            # Set up parameters for the blacklist request
            params = {
                'confidenceMinimum': self.config.get('confidence_minimum', 90),
                'limit': self.config.get('limit', 10000)
            }
            
            # Make the request
            logger.info(f"Fetching AbuseIPDB blacklist with confidence minimum {params['confidenceMinimum']}")
            response = requests.get(self.blacklist_endpoint, headers=headers, params=params)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch AbuseIPDB blacklist: {response.status_code} {response.text}")
                return False
                
            # Parse the response
            data = response.json()
            
            # Clear existing IP indicators
            self.indicators['ip'].clear()
            
            # Add IPs to indicators
            for item in data.get('data', []):
                ip = item.get('ipAddress')
                if ip:
                    self.indicators['ip'].add(ip)
                    
            # Update the last updated timestamp
            self.last_updated = datetime.datetime.now()
            
            # Save the cache
            self.save_cache()
            
            logger.info(f"Updated AbuseIPDB feed with {len(self.indicators['ip'])} malicious IPs")
            return True
            
        except Exception as e:
            logger.error(f"Error updating AbuseIPDB feed: {e}")
            return False
    
    def check_ip(self, ip_address):
        """
        Check an IP address against the AbuseIPDB API directly.
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            dict: Response data if successful, None otherwise
        """
        if not self.api_key:
            logger.error("Cannot check IP with AbuseIPDB: No API key provided")
            return None
            
        try:
            # Set up headers with API key
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            # Set up parameters for the check request
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': self.config.get('max_age_days', 30),
                'verbose': True
            }
            
            # Make the request
            response = requests.get(self.check_endpoint, headers=headers, params=params)
            
            if response.status_code != 200:
                logger.error(f"Failed to check IP with AbuseIPDB: {response.status_code} {response.text}")
                return None
                
            # Parse the response
            data = response.json().get('data', {})
            
            # Add the IP to our indicators if it's abusive
            if data.get('abuseConfidenceScore', 0) >= self.config.get('confidence_minimum', 90):
                self.indicators['ip'].add(ip_address)
                
            return data
            
        except Exception as e:
            logger.error(f"Error checking IP with AbuseIPDB: {e}")
            return None

class AlienVaultOTXFeed(ThreatIntelFeed):
    """Integration with AlienVault OTX threat intelligence feed."""
    
    def __init__(self, config=None, cache_dir=None):
        """
        Initialize the AlienVault OTX feed.
        
        Args:
            config (dict, optional): Configuration dictionary containing API key
            cache_dir (str, optional): Directory to cache threat intelligence data
        """
        super().__init__('alienvault_otx', config, cache_dir)
        
        # API endpoints
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.pulse_endpoint = f"{self.base_url}/pulses/subscribed"
        self.indicator_endpoint = f"{self.base_url}/indicators"
        
        # Verify API key is present
        self.api_key = self.config.get('api_key')
        if not self.api_key:
            logger.warning("No API key provided for AlienVault OTX feed")
            
        # Types of indicators to fetch
        self.indicator_types = self.config.get('indicator_types', ['IPv4', 'domain', 'hostname', 'URL', 'FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'])
    
    def update(self):
        """
        Update the AlienVault OTX indicators.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.api_key:
            logger.error("Cannot update AlienVault OTX feed: No API key provided")
            return False
            
        try:
            # Set up headers with API key
            headers = {
                'X-OTX-API-KEY': self.api_key
            }
            
            # Set up parameters for the pulse request
            params = {
                'limit': self.config.get('limit', 50),
                'modified_since': self.config.get('modified_since', '')
            }
            
            # Make the request
            logger.info(f"Fetching AlienVault OTX pulses")
            response = requests.get(self.pulse_endpoint, headers=headers, params=params)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch AlienVault OTX pulses: {response.status_code} {response.text}")
                return False
                
            # Parse the response
            data = response.json()
            
            # Clear existing indicators
            for key in self.indicators:
                self.indicators[key].clear()
                
            # Process the pulses
            pulses = data.get('results', [])
            logger.info(f"Processing {len(pulses)} AlienVault OTX pulses")
            
            for pulse in pulses:
                self._process_pulse(pulse)
                
            # Update the last updated timestamp
            self.last_updated = datetime.datetime.now()
            
            # Save the cache
            self.save_cache()
            
            # Log statistics
            total_indicators = sum(len(v) for v in self.indicators.values())
            logger.info(f"Updated AlienVault OTX feed with {total_indicators} indicators")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating AlienVault OTX feed: {e}")
            return False
    
    def _process_pulse(self, pulse):
        """
        Process a pulse and extract indicators.
        
        Args:
            pulse (dict): Pulse data
        """
        # Extract indicators from the pulse
        indicators = pulse.get('indicators', [])
        
        for indicator in indicators:
            indicator_type = indicator.get('type')
            indicator_value = indicator.get('indicator')
            
            if not indicator_type or not indicator_value:
                continue
                
            # Map OTX indicator types to our types
            if indicator_type == 'IPv4':
                self.indicators['ip'].add(indicator_value)
            elif indicator_type in ['domain', 'hostname']:
                self.indicators['domain'].add(indicator_value)
            elif indicator_type == 'URL':
                self.indicators['url'].add(indicator_value)
            elif indicator_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                self.indicators['hash'].add(indicator_value)
            else:
                self.indicators['other'].add(indicator_value)

class EmergingThreatsFeed(ThreatIntelFeed):
    """Integration with Emerging Threats open-source feed."""
    
    def __init__(self, config=None, cache_dir=None):
        """
        Initialize the Emerging Threats feed.
        
        Args:
            config (dict, optional): Configuration dictionary
            cache_dir (str, optional): Directory to cache threat intelligence data
        """
        super().__init__('emerging_threats', config, cache_dir)
        
        # Default list of feeds to fetch
        self.feeds = self.config.get('feeds', [
            'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            'https://rules.emergingthreats.net/blockrules/emerging-botcc.rules',
            'https://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules'
        ])
    
    def update(self):
        """
        Update the Emerging Threats indicators.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Clear existing indicators
            self.indicators['ip'].clear()
            self.indicators['domain'].clear()
            
            # Fetch each feed
            for feed_url in self.feeds:
                logger.info(f"Fetching Emerging Threats feed: {feed_url}")
                response = requests.get(feed_url)
                
                if response.status_code != 200:
                    logger.error(f"Failed to fetch {feed_url}: {response.status_code}")
                    continue
                    
                # Process the feed based on its format
                if feed_url.endswith('.txt'):
                    self._process_txt_feed(response.text)
                elif feed_url.endswith('.rules'):
                    self._process_rules_feed(response.text)
                    
            # Update the last updated timestamp
            self.last_updated = datetime.datetime.now()
            
            # Save the cache
            self.save_cache()
            
            # Log statistics
            logger.info(f"Updated Emerging Threats feed with {len(self.indicators['ip'])} IPs and {len(self.indicators['domain'])} domains")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating Emerging Threats feed: {e}")
            return False
    
    def _process_txt_feed(self, text):
        """
        Process a plain text feed containing IPs or domains.
        
        Args:
            text (str): Feed content
        """
        for line in text.split('\n'):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            # Check if the line is an IP address or a domain
            try:
                ipaddress.ip_address(line)
                self.indicators['ip'].add(line)
            except ValueError:
                # Not an IP address, assume it's a domain
                if '.' in line:
                    self.indicators['domain'].add(line)
    
    def _process_rules_feed(self, text):
        """
        Process a rules feed containing Snort/Suricata rules.
        
        Args:
            text (str): Feed content
        """
        for line in text.split('\n'):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            # Extract IPs from rules
            # Sample: alert ip [1.2.3.4,5.6.7.8] any -> $HOME_NET any ...
            if 'alert ip' in line or 'drop ip' in line:
                for part in line.split():
                    # Check if the part starts and ends with brackets
                    if part.startswith('[') and part.endswith(']'):
                        # Extract IPs from the bracketed list
                        ips = part[1:-1].split(',')
                        for ip in ips:
                            ip = ip.strip()
                            try:
                                ipaddress.ip_address(ip)
                                self.indicators['ip'].add(ip)
                            except ValueError:
                                pass

class ThreatIntelManager:
    """Manages multiple threat intelligence feeds."""
    
    def __init__(self, config=None, cache_dir=None):
        """
        Initialize the threat intelligence manager.
        
        Args:
            config (dict, optional): Configuration dictionary
            cache_dir (str, optional): Directory to cache threat intelligence data
        """
        self.config = config or {}
        
        # Set up cache directory
        if cache_dir:
            self.cache_dir = cache_dir
        else:
            # Use default cache directory
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.cache_dir = os.path.join(base_dir, 'data', 'threat_intel')
            
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize feeds
        self.feeds = {}
        self._init_feeds()
        
        # Initialize aggregate indicators
        self.aggregate_indicators = {
            'ip': set(),
            'domain': set(),
            'url': set(),
            'hash': set(),
            'other': set()
        }
        
        # Update interval in hours
        self.update_interval = self.config.get('update_interval', 24)
        
        # Auto update thread
        self.auto_update_thread = None
        self.stop_event = threading.Event()
        
        # Start auto update if enabled
        if self.config.get('auto_update', True):
            self.start_auto_update()
    
    def _init_feeds(self):
        """Initialize configured threat intelligence feeds."""
        # AbuseIPDB feed
        if self.config.get('abuseipdb', {}).get('enabled', False):
            logger.info("Initializing AbuseIPDB feed")
            self.feeds['abuseipdb'] = AbuseIPDBFeed(
                config=self.config.get('abuseipdb', {}),
                cache_dir=self.cache_dir
            )
            
        # AlienVault OTX feed
        if self.config.get('alienvault_otx', {}).get('enabled', False):
            logger.info("Initializing AlienVault OTX feed")
            self.feeds['alienvault_otx'] = AlienVaultOTXFeed(
                config=self.config.get('alienvault_otx', {}),
                cache_dir=self.cache_dir
            )
            
        # Emerging Threats feed
        if self.config.get('emerging_threats', {}).get('enabled', False):
            logger.info("Initializing Emerging Threats feed")
            self.feeds['emerging_threats'] = EmergingThreatsFeed(
                config=self.config.get('emerging_threats', {}),
                cache_dir=self.cache_dir
            )
    
    def update_feeds(self):
        """
        Update all enabled threat intelligence feeds.
        
        Returns:
            dict: Dictionary with feed names as keys and update status as values
        """
        results = {}
        
        for name, feed in self.feeds.items():
            logger.info(f"Updating {name} feed")
            results[name] = feed.update_if_needed(self.update_interval)
            
        # Aggregate indicators from all feeds
        self.aggregate_indicators()
        
        return results
    
    def aggregate_indicators(self):
        """
        Aggregate indicators from all feeds.
        
        Returns:
            dict: Dictionary with indicator types as keys and sets of indicators as values
        """
        # Clear existing aggregated indicators
        for key in self.aggregate_indicators:
            self.aggregate_indicators[key].clear()
            
        # Aggregate indicators from all feeds
        for feed in self.feeds.values():
            for indicator_type, indicators in feed.indicators.items():
                self.aggregate_indicators[indicator_type].update(indicators)
                
        # Log statistics
        total_indicators = sum(len(v) for v in self.aggregate_indicators.values())
        logger.info(f"Aggregated {total_indicators} indicators from all feeds")
        
        return self.aggregate_indicators
    
    def check_indicator(self, indicator_type, indicator_value):
        """
        Check if an indicator is in any of the feeds.
        
        Args:
            indicator_type (str): Type of indicator ('ip', 'domain', 'url', 'hash', 'other')
            indicator_value (str): Value to check
            
        Returns:
            dict: Dictionary with feed names as keys and boolean results as values
        """
        results = {}
        
        # Check if the indicator is in the aggregated set first
        if indicator_type in self.aggregate_indicators and indicator_value in self.aggregate_indicators[indicator_type]:
            # Check each individual feed
            for name, feed in self.feeds.items():
                results[name] = feed.check_indicator(indicator_type, indicator_value)
        else:
            # Indicator not found in any feed
            for name in self.feeds:
                results[name] = False
                
        return results
    
    def check_ip(self, ip_address):
        """
        Check if an IP address is in any of the feeds.
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            dict: Dictionary with feed names as keys and boolean results as values
        """
        return self.check_indicator('ip', ip_address)
    
    def check_domain(self, domain):
        """
        Check if a domain is in any of the feeds.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Dictionary with feed names as keys and boolean results as values
        """
        return self.check_indicator('domain', domain)
    
    def check_url(self, url):
        """
        Check if a URL is in any of the feeds.
        
        Args:
            url (str): URL to check
            
        Returns:
            dict: Dictionary with feed names as keys and boolean results as values
        """
        return self.check_indicator('url', url)
    
    def check_hash(self, file_hash):
        """
        Check if a file hash is in any of the feeds.
        
        Args:
            file_hash (str): File hash to check
            
        Returns:
            dict: Dictionary with feed names as keys and boolean results as values
        """
        return self.check_indicator('hash', file_hash)
    
    def check_packet(self, packet):
        """
        Check if a packet contains any indicators from the feeds.
        
        Args:
            packet (dict): Packet data dictionary
            
        Returns:
            dict: Dictionary with results for each indicator type
        """
        results = {
            'ip': {},
            'domain': {},
            'url': {},
            'hash': {},
            'matched': False
        }
        
        # Check IP addresses
        for ip_type in ['src_ip', 'dst_ip']:
            if ip_type in packet:
                ip = packet[ip_type]
                ip_results = self.check_ip(ip)
                if any(ip_results.values()):
                    results['ip'][ip] = ip_results
                    results['matched'] = True
                    
        # Check domains if payload is available
        if 'payload' in packet and isinstance(packet['payload'], str):
            payload = packet['payload']
            
            # Extract domains from payload (simplified example)
            # In a real implementation, you'd use more sophisticated extraction methods
            for line in payload.split('\n'):
                for word in line.split():
                    # Check if it's a domain-like string
                    if '.' in word and not word.startswith('http'):
                        domain = word.strip('.,:;()[]{}"\' \t\n\r')
                        if domain and '.' in domain:
                            domain_results = self.check_domain(domain)
                            if any(domain_results.values()):
                                results['domain'][domain] = domain_results
                                results['matched'] = True
                    
                    # Check if it's a URL-like string
                    elif word.startswith(('http://', 'https://')):
                        url = word.strip('.,:;()[]{}"\' \t\n\r')
                        if url:
                            url_results = self.check_url(url)
                            if any(url_results.values()):
                                results['url'][url] = url_results
                                results['matched'] = True
        
        return results
    
    def start_auto_update(self):
        """Start the auto-update thread."""
        if self.auto_update_thread is not None and self.auto_update_thread.is_alive():
            logger.warning("Auto-update thread is already running")
            return
            
        logger.info("Starting auto-update thread")
        self.stop_event.clear()
        self.auto_update_thread = threading.Thread(target=self._auto_update_worker, daemon=True)
        self.auto_update_thread.start()
    
    def stop_auto_update(self):
        """Stop the auto-update thread."""
        if self.auto_update_thread is None or not self.auto_update_thread.is_alive():
            logger.warning("Auto-update thread is not running")
            return
            
        logger.info("Stopping auto-update thread")
        self.stop_event.set()
        self.auto_update_thread.join(timeout=5.0)
        self.auto_update_thread = None
    
    def _auto_update_worker(self):
        """Worker function for the auto-update thread."""
        logger.info("Auto-update thread started")
        
        while not self.stop_event.is_set():
            # Update all feeds
            try:
                self.update_feeds()
            except Exception as e:
                logger.error(f"Error in auto-update thread: {e}")
                
            # Wait for the next update interval
            for _ in range(int(self.update_interval * 3600)):
                if self.stop_event.is_set():
                    break
                time.sleep(1)
                
        logger.info("Auto-update thread stopped")

def create_intel_manager(config=None, cache_dir=None):
    """
    Create and initialize a threat intelligence manager.
    
    Args:
        config (dict, optional): Configuration dictionary
        cache_dir (str, optional): Directory to cache threat intelligence data
        
    Returns:
        ThreatIntelManager: Initialized threat intelligence manager
    """
    # If config is a path to a file, load it
    if isinstance(config, str) and os.path.exists(config):
        try:
            ext = os.path.splitext(config)[1].lower()
            if ext in ('.yaml', '.yml'):
                with open(config, 'r') as f:
                    config = yaml.safe_load(f)
            elif ext == '.json':
                with open(config, 'r') as f:
                    config = json.load(f)
            else:
                logger.error(f"Unsupported config file format: {ext}")
                config = None
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            config = None
            
    # Create and initialize the manager
    manager = ThreatIntelManager(config, cache_dir)
    
    # Update feeds if auto-update is disabled
    if not config or not config.get('auto_update', True):
        manager.update_feeds()
        
    return manager

def get_default_config():
    """
    Get the default configuration for threat intelligence feeds.
    
    Returns:
        dict: Default configuration
    """
    return {
        'auto_update': True,
        'update_interval': 24,  # hours
        'abuseipdb': {
            'enabled': True,
            'api_key': '',  # Must be provided by the user
            'confidence_minimum': 90,
            'limit': 10000
        },
        'alienvault_otx': {
            'enabled': True,
            'api_key': '',  # Must be provided by the user
            'limit': 50,
            'indicator_types': ['IPv4', 'domain', 'hostname', 'URL', 'FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']
        },
        'emerging_threats': {
            'enabled': True,
            'feeds': [
                'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'https://rules.emergingthreats.net/blockrules/emerging-botcc.rules',
                'https://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules'
            ]
        }
    }

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create a threat intelligence manager with default config
    config = get_default_config()
    
    # For testing, we need to provide API keys
    # config['abuseipdb']['api_key'] = 'your_abuseipdb_api_key'
    # config['alienvault_otx']['api_key'] = 'your_alienvault_otx_api_key'
    
    manager = create_intel_manager(config)
    
    # Check an IP address (for testing)
    test_ip = '198.51.100.1'  # Example IP - use known malicious IP in real testing
    results = manager.check_ip(test_ip)
    print(f"Results for IP {test_ip}:")
    for feed, result in results.items():
        print(f"  {feed}: {'Malicious' if result else 'Not found'}")
    
    # To test with a simulated packet
    test_packet = {
        'src_ip': '198.51.100.1',
        'dst_ip': '203.0.113.1',
        'payload': 'GET /malicious.php HTTP/1.1\nHost: badsite.example.com\n'
    }
    packet_results = manager.check_packet(test_packet)
    print(f"Packet results: {'Matched' if packet_results['matched'] else 'No matches'}")
    for indicator_type, indicators in packet_results.items():
        if indicator_type != 'matched' and indicators:
            print(f"  {indicator_type} indicators found: {len(indicators)}")
    
    # Proper shutdown
    manager.stop_auto_update() 