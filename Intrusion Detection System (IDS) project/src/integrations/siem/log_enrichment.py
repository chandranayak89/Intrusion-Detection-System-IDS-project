#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Log Enrichment Module
Enriches IDS alerts with contextual metadata such as GeoIP information,
DNS lookups, and threat intelligence data.
"""

import os
import re
import json
import time
import socket
import logging
import ipaddress
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Callable, Set, Tuple
from abc import ABC, abstractmethod
from urllib.parse import urlparse
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger("ids.integrations.siem.log_enrichment")

class Enricher(ABC):
    """Base class for log enrichment"""
    
    @abstractmethod
    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single alert with additional context
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Enriched alert data dictionary
        """
        pass
    
    def enrich_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a batch of alerts with additional context
        
        Args:
            alerts: List of alert data dictionaries
            
        Returns:
            List of enriched alert data dictionaries
        """
        enriched_alerts = []
        for alert in alerts:
            enriched_alerts.append(self.enrich(alert))
        return enriched_alerts

class GeoIPEnricher(Enricher):
    """Enriches IP addresses with geolocation data"""
    
    def __init__(self, 
                db_path: Optional[str] = None,
                cache_size: int = 1000,
                cache_ttl: int = 86400,  # 24 hours in seconds
                field_name: str = "geoip",
                ip_fields: List[str] = None):
        """
        Initialize GeoIP enricher
        
        Args:
            db_path: Path to GeoIP database (MaxMind GeoLite2)
            cache_size: Maximum number of items in cache
            cache_ttl: Cache time-to-live in seconds
            field_name: Name of the field to add to alerts
            ip_fields: List of fields containing IP addresses to enrich
        """
        self.db_path = db_path
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.field_name = field_name
        self.ip_fields = ip_fields or ["source_ip", "destination_ip", "src_ip", "dst_ip", "ip"]
        
        # Initialize cache
        self.cache = {}
        self.cache_timestamps = {}
        
        # Load GeoIP database
        self.reader = None
        self.load_database()
    
    def load_database(self) -> None:
        """Load GeoIP database"""
        if not self.db_path:
            logger.warning("No GeoIP database path provided")
            return
            
        try:
            import geoip2.database
            self.reader = geoip2.database.Reader(self.db_path)
            logger.info(f"Loaded GeoIP database from {self.db_path}")
        except ImportError:
            logger.error("geoip2 package not found. Install with: pip install geoip2")
        except Exception as e:
            logger.error(f"Error loading GeoIP database: {e}")
    
    def get_geoip(self, ip: str) -> Dict[str, Any]:
        """
        Get GeoIP data for an IP address
        
        Args:
            ip: IP address
            
        Returns:
            GeoIP data dictionary
        """
        # Check if IP is valid
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {}
        
        # Check if IP is private
        try:
            if ipaddress.ip_address(ip).is_private:
                return {
                    "ip": ip,
                    "is_private": True,
                    "country_code": "**",
                    "country_name": "Private IP",
                    "city": "Private Network"
                }
        except ValueError:
            pass
        
        # Check cache
        current_time = time.time()
        if ip in self.cache:
            cache_time = self.cache_timestamps.get(ip, 0)
            if current_time - cache_time < self.cache_ttl:
                return self.cache[ip]
        
        # If no reader, return empty data
        if not self.reader:
            return {}
        
        try:
            # Query GeoIP database
            response = self.reader.city(ip)
            
            # Extract relevant information
            geoip_data = {
                "ip": ip,
                "is_private": False,
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "time_zone": response.location.time_zone,
                "continent": response.continent.name,
                "postal_code": response.postal.code,
                "registered_country": response.registered_country.name,
                "traits": {
                    "autonomous_system_number": response.traits.autonomous_system_number,
                    "autonomous_system_organization": response.traits.autonomous_system_organization,
                    "isp": response.traits.isp,
                    "organization": response.traits.organization
                }
            }
            
            # Add to cache
            self.cache[ip] = geoip_data
            self.cache_timestamps[ip] = current_time
            
            # Manage cache size
            if len(self.cache) > self.cache_size:
                # Remove oldest entries
                oldest_ips = sorted(self.cache_timestamps, key=self.cache_timestamps.get)[:len(self.cache) // 10]
                for old_ip in oldest_ips:
                    del self.cache[old_ip]
                    del self.cache_timestamps[old_ip]
            
            return geoip_data
            
        except Exception as e:
            logger.debug(f"Error getting GeoIP data for {ip}: {e}")
            return {}
    
    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with GeoIP data
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Enriched alert data dictionary
        """
        # Make a copy of the alert to avoid modifying the original
        enriched_alert = alert.copy()
        
        # Initialize GeoIP data in the enriched alert
        if self.field_name not in enriched_alert:
            enriched_alert[self.field_name] = {}
        
        # Extract IP addresses from alert
        ip_addresses = set()
        
        # Check standard fields
        for field in self.ip_fields:
            if field in alert and alert[field]:
                ip_addresses.add(alert[field])
        
        # Check observables
        for observable in alert.get("observables", []):
            if observable.get("type") == "ip" and observable.get("value"):
                ip_addresses.add(observable.get("value"))
        
        # Enrich each IP address
        for ip in ip_addresses:
            geoip_data = self.get_geoip(ip)
            if geoip_data:
                enriched_alert[self.field_name][ip] = geoip_data
        
        return enriched_alert

class DNSEnricher(Enricher):
    """Enriches IP addresses and hostnames with DNS information"""
    
    def __init__(self, 
                cache_size: int = 1000,
                cache_ttl: int = 3600,  # 1 hour in seconds
                field_name: str = "dns",
                ip_fields: List[str] = None,
                hostname_fields: List[str] = None,
                dns_servers: List[str] = None,
                timeout: float = 2.0):
        """
        Initialize DNS enricher
        
        Args:
            cache_size: Maximum number of items in cache
            cache_ttl: Cache time-to-live in seconds
            field_name: Name of the field to add to alerts
            ip_fields: List of fields containing IP addresses to enrich
            hostname_fields: List of fields containing hostnames to enrich
            dns_servers: List of DNS servers to use
            timeout: DNS lookup timeout in seconds
        """
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.field_name = field_name
        self.ip_fields = ip_fields or ["source_ip", "destination_ip", "src_ip", "dst_ip", "ip"]
        self.hostname_fields = hostname_fields or ["hostname", "domain", "fqdn", "host"]
        self.dns_servers = dns_servers
        self.timeout = timeout
        
        # Initialize cache
        self.cache = {}
        self.cache_timestamps = {}
        
        # Configure resolver if custom DNS servers are specified
        self.resolver = None
        if dns_servers:
            try:
                import dns.resolver
                self.resolver = dns.resolver.Resolver()
                self.resolver.nameservers = [socket.gethostbyname(server) for server in dns_servers]
                self.resolver.timeout = timeout
                self.resolver.lifetime = timeout
                logger.info(f"Configured DNS resolver with servers: {', '.join(dns_servers)}")
            except ImportError:
                logger.error("dnspython package not found. Install with: pip install dnspython")
            except Exception as e:
                logger.error(f"Error configuring DNS resolver: {e}")
    
    def resolve_hostname(self, hostname: str) -> List[str]:
        """
        Resolve a hostname to IP addresses
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            List of IP addresses
        """
        # Check cache
        cache_key = f"hostname:{hostname}"
        current_time = time.time()
        if cache_key in self.cache:
            cache_time = self.cache_timestamps.get(cache_key, 0)
            if current_time - cache_time < self.cache_ttl:
                return self.cache[cache_key]
        
        try:
            if self.resolver:
                # Use dnspython resolver
                import dns.resolver
                
                try:
                    answers = self.resolver.resolve(hostname, 'A')
                    ip_addresses = [answer.address for answer in answers]
                except dns.resolver.NXDOMAIN:
                    ip_addresses = []
                except Exception as e:
                    logger.debug(f"Error resolving hostname {hostname}: {e}")
                    ip_addresses = []
            else:
                # Use socket.gethostbyname
                try:
                    ip_addresses = [socket.gethostbyname(hostname)]
                except socket.gaierror:
                    ip_addresses = []
                except Exception as e:
                    logger.debug(f"Error resolving hostname {hostname}: {e}")
                    ip_addresses = []
            
            # Add to cache
            self.cache[cache_key] = ip_addresses
            self.cache_timestamps[cache_key] = current_time
            
            # Manage cache size
            self._manage_cache()
            
            return ip_addresses
            
        except Exception as e:
            logger.debug(f"Error resolving hostname {hostname}: {e}")
            return []
    
    def resolve_ip(self, ip: str) -> List[str]:
        """
        Resolve an IP address to hostnames
        
        Args:
            ip: IP address to resolve
            
        Returns:
            List of hostnames
        """
        # Check if IP is valid
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return []
        
        # Check cache
        cache_key = f"ip:{ip}"
        current_time = time.time()
        if cache_key in self.cache:
            cache_time = self.cache_timestamps.get(cache_key, 0)
            if current_time - cache_time < self.cache_ttl:
                return self.cache[cache_key]
        
        try:
            # Use socket.gethostbyaddr
            try:
                hostnames = [socket.gethostbyaddr(ip)[0]]
            except socket.herror:
                hostnames = []
            except Exception as e:
                logger.debug(f"Error resolving IP {ip}: {e}")
                hostnames = []
            
            # Add to cache
            self.cache[cache_key] = hostnames
            self.cache_timestamps[cache_key] = current_time
            
            # Manage cache size
            self._manage_cache()
            
            return hostnames
            
        except Exception as e:
            logger.debug(f"Error resolving IP {ip}: {e}")
            return []
    
    def _manage_cache(self) -> None:
        """Manage cache size by removing oldest entries"""
        if len(self.cache) > self.cache_size:
            # Remove oldest entries
            oldest_keys = sorted(self.cache_timestamps, key=self.cache_timestamps.get)[:len(self.cache) // 10]
            for old_key in oldest_keys:
                del self.cache[old_key]
                del self.cache_timestamps[old_key]
    
    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with DNS information
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Enriched alert data dictionary
        """
        # Make a copy of the alert to avoid modifying the original
        enriched_alert = alert.copy()
        
        # Initialize DNS data in the enriched alert
        if self.field_name not in enriched_alert:
            enriched_alert[self.field_name] = {}
        
        # Extract IP addresses from alert
        ip_addresses = set()
        
        # Check standard fields
        for field in self.ip_fields:
            if field in alert and alert[field]:
                ip_addresses.add(alert[field])
        
        # Check observables
        for observable in alert.get("observables", []):
            if observable.get("type") == "ip" and observable.get("value"):
                ip_addresses.add(observable.get("value"))
        
        # Extract hostnames from alert
        hostnames = set()
        
        # Check standard fields
        for field in self.hostname_fields:
            if field in alert and alert[field]:
                hostnames.add(alert[field])
        
        # Check observables
        for observable in alert.get("observables", []):
            if observable.get("type") in ["domain", "hostname"] and observable.get("value"):
                hostnames.add(observable.get("value"))
            elif observable.get("type") == "url" and observable.get("value"):
                try:
                    parsed_url = urlparse(observable.get("value"))
                    if parsed_url.netloc:
                        hostnames.add(parsed_url.netloc)
                except Exception:
                    pass
        
        # Enrich IP addresses with hostnames
        for ip in ip_addresses:
            resolved_hostnames = self.resolve_ip(ip)
            if resolved_hostnames:
                if ip not in enriched_alert[self.field_name]:
                    enriched_alert[self.field_name][ip] = {}
                enriched_alert[self.field_name][ip]["hostnames"] = resolved_hostnames
        
        # Enrich hostnames with IP addresses
        for hostname in hostnames:
            resolved_ips = self.resolve_hostname(hostname)
            if resolved_ips:
                if hostname not in enriched_alert[self.field_name]:
                    enriched_alert[self.field_name][hostname] = {}
                enriched_alert[self.field_name][hostname]["ip_addresses"] = resolved_ips
        
        return enriched_alert

class ThreatIntelEnricher(Enricher):
    """Enriches indicators with threat intelligence data"""
    
    def __init__(self, 
                api_key: Optional[str] = None,
                api_url: Optional[str] = None,
                cache_size: int = 1000,
                cache_ttl: int = 86400,  # 24 hours in seconds
                field_name: str = "threat_intel",
                indicator_fields: List[str] = None,
                batch_size: int = 10,
                timeout: float = 10.0):
        """
        Initialize threat intelligence enricher
        
        Args:
            api_key: API key for threat intelligence service
            api_url: URL for threat intelligence API
            cache_size: Maximum number of items in cache
            cache_ttl: Cache time-to-live in seconds
            field_name: Name of the field to add to alerts
            indicator_fields: List of fields containing indicators to enrich
            batch_size: Number of indicators to process in a batch
            timeout: API request timeout in seconds
        """
        self.api_key = api_key
        self.api_url = api_url
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.field_name = field_name
        self.indicator_fields = indicator_fields or [
            "ip", "source_ip", "destination_ip", "src_ip", "dst_ip", 
            "hostname", "domain", "hash", "url", "md5", "sha1", "sha256"
        ]
        self.batch_size = batch_size
        self.timeout = timeout
        
        # Initialize cache
        self.cache = {}
        self.cache_timestamps = {}
        
        # Initialize HTTP session
        self.session = None
        try:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json"
            })
            
            # Add API key to headers if provided
            if api_key:
                self.session.headers.update({
                    "X-OTX-API-KEY": api_key  # Default for AlienVault OTX
                })
                
            logger.info("Initialized threat intelligence enricher")
            
        except ImportError:
            logger.error("requests package not found. Install with: pip install requests")
    
    def get_indicator_type(self, indicator: str) -> str:
        """
        Determine the type of an indicator
        
        Args:
            indicator: Indicator value
            
        Returns:
            Indicator type (ip, domain, hash, url)
        """
        # Check if IP address
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass
        
        # Check if domain/hostname
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$', indicator):
            return "domain"
        
        # Check if URL
        if re.match(r'^(http|https|ftp)://', indicator):
            return "url"
        
        # Check if hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return "md5"
        elif re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return "sha1"
        elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return "sha256"
        
        # Unknown type
        return "unknown"
    
    def get_threat_intel(self, indicator: str, indicator_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Get threat intelligence data for an indicator
        
        Args:
            indicator: Indicator value
            indicator_type: Type of indicator (if known)
            
        Returns:
            Threat intelligence data dictionary
        """
        # Determine indicator type if not provided
        if not indicator_type:
            indicator_type = self.get_indicator_type(indicator)
            
        if indicator_type == "unknown":
            return {}
        
        # Check cache
        cache_key = f"{indicator_type}:{indicator}"
        current_time = time.time()
        if cache_key in self.cache:
            cache_time = self.cache_timestamps.get(cache_key, 0)
            if current_time - cache_time < self.cache_ttl:
                return self.cache[cache_key]
        
        # If no session or API URL, return empty data
        if not self.session or not self.api_url:
            return {
                "indicator": indicator,
                "type": indicator_type,
                "cached": False,
                "data_source": "none",
                "last_updated": datetime.now().isoformat(),
                "message": "No threat intelligence API configured"
            }
        
        try:
            # Build API URL based on indicator type
            # This example assumes AlienVault OTX API format
            # Modify for your specific threat intelligence API
            api_endpoint = f"{self.api_url}/indicators/{indicator_type}/{indicator}"
            
            # Send API request
            response = self.session.get(api_endpoint, timeout=self.timeout)
            
            if response.status_code == 200:
                # Extract relevant information
                data = response.json()
                
                # Format threat intel data
                threat_intel_data = {
                    "indicator": indicator,
                    "type": indicator_type,
                    "cached": False,
                    "data_source": "api",
                    "last_updated": datetime.now().isoformat()
                }
                
                # Example for AlienVault OTX
                if "pulse_info" in data:
                    pulse_info = data.get("pulse_info", {})
                    pulses = pulse_info.get("pulses", [])
                    
                    threat_intel_data.update({
                        "malicious": len(pulses) > 0,
                        "pulse_count": len(pulses),
                        "reputation": pulse_info.get("reputation", 0),
                        "categories": list(set(tag for pulse in pulses for tag in pulse.get("tags", []))),
                        "first_seen": min([pulse.get("created", "") for pulse in pulses], default=""),
                        "last_seen": max([pulse.get("modified", "") for pulse in pulses], default=""),
                        "sources": list(set(pulse.get("name", "") for pulse in pulses)),
                        "references": list(set(reference for pulse in pulses for reference in pulse.get("references", [])))
                    })
                else:
                    # Generic format for other APIs
                    threat_intel_data.update({
                        "malicious": data.get("malicious", False),
                        "categories": data.get("categories", []),
                        "first_seen": data.get("first_seen", ""),
                        "last_seen": data.get("last_seen", ""),
                        "sources": data.get("sources", []),
                        "references": data.get("references", [])
                    })
                
                # Add to cache
                self.cache[cache_key] = threat_intel_data
                self.cache_timestamps[cache_key] = current_time
                
                # Manage cache size
                if len(self.cache) > self.cache_size:
                    # Remove oldest entries
                    oldest_keys = sorted(self.cache_timestamps, key=self.cache_timestamps.get)[:len(self.cache) // 10]
                    for old_key in oldest_keys:
                        del self.cache[old_key]
                        del self.cache_timestamps[old_key]
                
                return threat_intel_data
            else:
                # API error
                logger.debug(f"Threat intelligence API error for {indicator}: {response.status_code} - {response.text}")
                
                # Create a minimal response for cache
                threat_intel_data = {
                    "indicator": indicator,
                    "type": indicator_type,
                    "cached": False,
                    "data_source": "none",
                    "last_updated": datetime.now().isoformat(),
                    "error": f"API returned status {response.status_code}",
                    "malicious": False
                }
                
                # Add to cache with shorter TTL for errors
                self.cache[cache_key] = threat_intel_data
                self.cache_timestamps[cache_key] = current_time
                
                return threat_intel_data
                
        except Exception as e:
            logger.debug(f"Error getting threat intelligence for {indicator}: {e}")
            
            # Create a minimal response for cache
            threat_intel_data = {
                "indicator": indicator,
                "type": indicator_type,
                "cached": False,
                "data_source": "none",
                "last_updated": datetime.now().isoformat(),
                "error": str(e),
                "malicious": False
            }
            
            # Add to cache with shorter TTL for errors
            self.cache[cache_key] = threat_intel_data
            self.cache_timestamps[cache_key] = current_time
            
            return threat_intel_data
    
    def enrich_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a batch of alerts with threat intelligence data
        
        Args:
            alerts: List of alert data dictionaries
            
        Returns:
            List of enriched alert data dictionaries
        """
        # This implementation uses a thread pool for concurrent processing
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return list(executor.map(self.enrich, alerts))
    
    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with threat intelligence data
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Enriched alert data dictionary
        """
        # Make a copy of the alert to avoid modifying the original
        enriched_alert = alert.copy()
        
        # Initialize threat intel data in the enriched alert
        if self.field_name not in enriched_alert:
            enriched_alert[self.field_name] = {}
        
        # Extract indicators from alert
        indicators = set()
        indicator_types = {}
        
        # Check standard fields
        for field in self.indicator_fields:
            if field in alert and alert[field]:
                indicator = alert[field]
                indicators.add(indicator)
                indicator_types[indicator] = self.get_indicator_type(indicator)
        
        # Check observables
        for observable in alert.get("observables", []):
            if observable.get("value"):
                indicator = observable.get("value")
                indicators.add(indicator)
                
                # Use the observable type if it maps to a valid indicator type
                observable_type = observable.get("type", "").lower()
                if observable_type in ["ip", "domain", "url", "md5", "sha1", "sha256"]:
                    indicator_types[indicator] = observable_type
                else:
                    indicator_types[indicator] = self.get_indicator_type(indicator)
        
        # Enrich each indicator
        for indicator in indicators:
            indicator_type = indicator_types.get(indicator, self.get_indicator_type(indicator))
            if indicator_type != "unknown":
                threat_intel_data = self.get_threat_intel(indicator, indicator_type)
                if threat_intel_data:
                    enriched_alert[self.field_name][indicator] = threat_intel_data
                    
                    # Add a malicious field to the alert if the indicator is malicious
                    if threat_intel_data.get("malicious", False):
                        if "malicious_indicators" not in enriched_alert:
                            enriched_alert["malicious_indicators"] = []
                        
                        enriched_alert["malicious_indicators"].append({
                            "indicator": indicator,
                            "type": indicator_type,
                            "categories": threat_intel_data.get("categories", []),
                            "sources": threat_intel_data.get("sources", [])
                        })
        
        return enriched_alert

class LogEnricher:
    """Composite enricher that applies multiple enrichment methods to IDS alerts"""
    
    def __init__(self):
        """Initialize the log enricher"""
        self.enrichers = []
    
    def add_enricher(self, enricher: Enricher) -> None:
        """
        Add an enricher
        
        Args:
            enricher: Enricher instance
        """
        self.enrichers.append(enricher)
    
    def remove_enricher(self, enricher: Enricher) -> None:
        """
        Remove an enricher
        
        Args:
            enricher: Enricher instance
        """
        if enricher in self.enrichers:
            self.enrichers.remove(enricher)
    
    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with all configured enrichers
        
        Args:
            alert: Alert data dictionary
            
        Returns:
            Enriched alert data dictionary
        """
        enriched_alert = alert.copy()
        
        for enricher in self.enrichers:
            try:
                enriched_alert = enricher.enrich(enriched_alert)
            except Exception as e:
                logger.error(f"Error applying enricher {type(enricher).__name__}: {e}")
        
        # Add enrichment timestamp
        enriched_alert["enrichment_time"] = datetime.now().isoformat()
        
        return enriched_alert
    
    def enrich_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a batch of alerts with all configured enrichers
        
        Args:
            alerts: List of alert data dictionaries
            
        Returns:
            List of enriched alert data dictionaries
        """
        enriched_alerts = []
        
        for alert in alerts:
            enriched_alerts.append(self.enrich(alert))
        
        return enriched_alerts 