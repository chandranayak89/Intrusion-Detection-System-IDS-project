#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Signature Detection Module
This module provides signature-based detection for known network attack patterns.
"""

import os
import re
import yaml
import logging
import ipaddress
from datetime import datetime

# Setup logging
logger = logging.getLogger('ids.signature_detection')

class SignatureRule:
    """Base class for signature detection rules."""
    
    def __init__(self, rule_id, name, description, severity):
        """
        Initialize a signature rule.
        
        Args:
            rule_id (str): Unique identifier for the rule
            name (str): Name of the rule
            description (str): Description of what the rule detects
            severity (str): Severity level ('low', 'medium', 'high', 'critical')
        """
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        
    def match(self, packet):
        """
        Check if the packet matches this rule.
        
        Args:
            packet (dict): Packet data
            
        Returns:
            bool: True if the packet matches this rule, False otherwise
        """
        raise NotImplementedError("Subclasses must implement match()")
        
    def to_dict(self):
        """
        Convert the rule to a dictionary.
        
        Returns:
            dict: Dictionary representation of the rule
        """
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity
        }
        
    @classmethod
    def from_dict(cls, rule_dict):
        """
        Create a rule from a dictionary.
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
            
        Returns:
            SignatureRule: Created rule
        """
        raise NotImplementedError("Subclasses must implement from_dict()")

class IPRule(SignatureRule):
    """Rule for matching IP addresses."""
    
    def __init__(self, rule_id, name, description, severity, ip_list, direction='src'):
        """
        Initialize an IP-based rule.
        
        Args:
            rule_id (str): Unique identifier for the rule
            name (str): Name of the rule
            description (str): Description of what the rule detects
            severity (str): Severity level ('low', 'medium', 'high', 'critical')
            ip_list (list): List of IP addresses or CIDR blocks to match
            direction (str): 'src' to match source IPs, 'dst' to match destination IPs, 'both' to match either
        """
        super().__init__(rule_id, name, description, severity)
        self.direction = direction
        self.ip_networks = []
        
        # Convert string IPs and CIDR blocks to network objects
        for ip in ip_list:
            try:
                self.ip_networks.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                logger.warning(f"Invalid IP address or CIDR block: {ip}")
                
    def match(self, packet):
        """
        Check if the packet's IP matches this rule.
        
        Args:
            packet (dict): Packet data with 'src_ip' and/or 'dst_ip' keys
            
        Returns:
            bool: True if the packet matches this rule, False otherwise
        """
        if not self.ip_networks:
            return False
            
        if 'src_ip' not in packet and 'dst_ip' not in packet:
            return False
            
        try:
            if self.direction in ('src', 'both') and 'src_ip' in packet:
                src_ip = ipaddress.ip_address(packet['src_ip'])
                if any(src_ip in network for network in self.ip_networks):
                    return True
                    
            if self.direction in ('dst', 'both') and 'dst_ip' in packet:
                dst_ip = ipaddress.ip_address(packet['dst_ip'])
                if any(dst_ip in network for network in self.ip_networks):
                    return True
        except ValueError:
            # Invalid IP in packet
            return False
            
        return False
        
    def to_dict(self):
        """
        Convert the rule to a dictionary.
        
        Returns:
            dict: Dictionary representation of the rule
        """
        result = super().to_dict()
        result.update({
            'type': 'ip',
            'direction': self.direction,
            'ip_list': [str(network) for network in self.ip_networks]
        })
        return result
        
    @classmethod
    def from_dict(cls, rule_dict):
        """
        Create an IP rule from a dictionary.
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
            
        Returns:
            IPRule: Created rule
        """
        return cls(
            rule_id=rule_dict['rule_id'],
            name=rule_dict['name'],
            description=rule_dict['description'],
            severity=rule_dict['severity'],
            ip_list=rule_dict['ip_list'],
            direction=rule_dict.get('direction', 'src')
        )

class PortRule(SignatureRule):
    """Rule for matching port numbers."""
    
    def __init__(self, rule_id, name, description, severity, port_list, direction='dst'):
        """
        Initialize a port-based rule.
        
        Args:
            rule_id (str): Unique identifier for the rule
            name (str): Name of the rule
            description (str): Description of what the rule detects
            severity (str): Severity level ('low', 'medium', 'high', 'critical')
            port_list (list): List of port numbers or ranges to match
            direction (str): 'src' to match source ports, 'dst' to match destination ports, 'both' to match either
        """
        super().__init__(rule_id, name, description, severity)
        self.direction = direction
        self.ports = set()
        
        # Process port list
        for port in port_list:
            if isinstance(port, int) or (isinstance(port, str) and port.isdigit()):
                self.ports.add(int(port))
            elif isinstance(port, str) and '-' in port:
                # Process port range
                start, end = port.split('-')
                if start.isdigit() and end.isdigit():
                    self.ports.update(range(int(start), int(end) + 1))
                    
    def match(self, packet):
        """
        Check if the packet's port matches this rule.
        
        Args:
            packet (dict): Packet data with 'src_port' and/or 'dst_port' keys
            
        Returns:
            bool: True if the packet matches this rule, False otherwise
        """
        if not self.ports:
            return False
            
        if 'src_port' not in packet and 'dst_port' not in packet:
            return False
            
        if self.direction in ('src', 'both') and 'src_port' in packet:
            if packet['src_port'] in self.ports:
                return True
                
        if self.direction in ('dst', 'both') and 'dst_port' in packet:
            if packet['dst_port'] in self.ports:
                return True
                
        return False
        
    def to_dict(self):
        """
        Convert the rule to a dictionary.
        
        Returns:
            dict: Dictionary representation of the rule
        """
        result = super().to_dict()
        
        # Convert ports back to ranges where possible for more compact representation
        port_list = list(self.ports)
        port_list.sort()
        compact_ports = []
        
        i = 0
        while i < len(port_list):
            start = port_list[i]
            end = start
            while i + 1 < len(port_list) and port_list[i + 1] == end + 1:
                end = port_list[i + 1]
                i += 1
            if start == end:
                compact_ports.append(str(start))
            else:
                compact_ports.append(f"{start}-{end}")
            i += 1
            
        result.update({
            'type': 'port',
            'direction': self.direction,
            'port_list': compact_ports
        })
        return result
        
    @classmethod
    def from_dict(cls, rule_dict):
        """
        Create a port rule from a dictionary.
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
            
        Returns:
            PortRule: Created rule
        """
        return cls(
            rule_id=rule_dict['rule_id'],
            name=rule_dict['name'],
            description=rule_dict['description'],
            severity=rule_dict['severity'],
            port_list=rule_dict['port_list'],
            direction=rule_dict.get('direction', 'dst')
        )

class PayloadRule(SignatureRule):
    """Rule for matching packet payload content."""
    
    def __init__(self, rule_id, name, description, severity, patterns, case_sensitive=False):
        """
        Initialize a payload-based rule.
        
        Args:
            rule_id (str): Unique identifier for the rule
            name (str): Name of the rule
            description (str): Description of what the rule detects
            severity (str): Severity level ('low', 'medium', 'high', 'critical')
            patterns (list): List of regex patterns to match in the payload
            case_sensitive (bool): Whether the pattern matching should be case-sensitive
        """
        super().__init__(rule_id, name, description, severity)
        self.case_sensitive = case_sensitive
        self.patterns = []
        
        # Compile regex patterns
        flags = 0 if case_sensitive else re.IGNORECASE
        for pattern in patterns:
            try:
                self.patterns.append(re.compile(pattern, flags))
            except re.error:
                logger.warning(f"Invalid regex pattern: {pattern}")
                
    def match(self, packet):
        """
        Check if the packet's payload matches this rule.
        
        Args:
            packet (dict): Packet data with 'payload' key
            
        Returns:
            bool: True if the packet matches this rule, False otherwise
        """
        if not self.patterns:
            return False
            
        if 'payload' not in packet:
            return False
            
        payload = packet['payload']
        if not isinstance(payload, str):
            try:
                payload = str(payload)
            except:
                return False
                
        for pattern in self.patterns:
            if pattern.search(payload):
                return True
                
        return False
        
    def to_dict(self):
        """
        Convert the rule to a dictionary.
        
        Returns:
            dict: Dictionary representation of the rule
        """
        result = super().to_dict()
        result.update({
            'type': 'payload',
            'case_sensitive': self.case_sensitive,
            'patterns': [pattern.pattern for pattern in self.patterns]
        })
        return result
        
    @classmethod
    def from_dict(cls, rule_dict):
        """
        Create a payload rule from a dictionary.
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
            
        Returns:
            PayloadRule: Created rule
        """
        return cls(
            rule_id=rule_dict['rule_id'],
            name=rule_dict['name'],
            description=rule_dict['description'],
            severity=rule_dict['severity'],
            patterns=rule_dict['patterns'],
            case_sensitive=rule_dict.get('case_sensitive', False)
        )

class CompositeRule(SignatureRule):
    """Rule composed of multiple other rules with logical operators."""
    
    def __init__(self, rule_id, name, description, severity, subrules, operator='and'):
        """
        Initialize a composite rule.
        
        Args:
            rule_id (str): Unique identifier for the rule
            name (str): Name of the rule
            description (str): Description of what the rule detects
            severity (str): Severity level ('low', 'medium', 'high', 'critical')
            subrules (list): List of rules that make up this composite rule
            operator (str): Logical operator to combine rules ('and', 'or')
        """
        super().__init__(rule_id, name, description, severity)
        self.subrules = subrules
        self.operator = operator.lower()
        
    def match(self, packet):
        """
        Check if the packet matches this composite rule.
        
        Args:
            packet (dict): Packet data
            
        Returns:
            bool: True if the packet matches this rule, False otherwise
        """
        if not self.subrules:
            return False
            
        if self.operator == 'and':
            return all(rule.match(packet) for rule in self.subrules)
        elif self.operator == 'or':
            return any(rule.match(packet) for rule in self.subrules)
        else:
            logger.warning(f"Unknown operator: {self.operator}")
            return False
            
    def to_dict(self):
        """
        Convert the rule to a dictionary.
        
        Returns:
            dict: Dictionary representation of the rule
        """
        result = super().to_dict()
        result.update({
            'type': 'composite',
            'operator': self.operator,
            'subrules': [rule.to_dict() for rule in self.subrules]
        })
        return result
        
    @classmethod
    def from_dict(cls, rule_dict, rule_factory):
        """
        Create a composite rule from a dictionary.
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
            rule_factory (function): Function to create rules from dictionaries
            
        Returns:
            CompositeRule: Created rule
        """
        subrules = [rule_factory(subrule) for subrule in rule_dict['subrules']]
        return cls(
            rule_id=rule_dict['rule_id'],
            name=rule_dict['name'],
            description=rule_dict['description'],
            severity=rule_dict['severity'],
            subrules=subrules,
            operator=rule_dict.get('operator', 'and')
        )

class RateBasedRule(SignatureRule):
    """Rule for detecting traffic based on rate thresholds."""
    
    def __init__(self, rule_id, name, description, severity, count, seconds, track_by='ip'):
        """
        Initialize a rate-based rule.
        
        Args:
            rule_id (str): Unique identifier for the rule
            name (str): Name of the rule
            description (str): Description of what the rule detects
            severity (str): Severity level ('low', 'medium', 'high', 'critical')
            count (int): Number of packets to trigger the rule
            seconds (int): Time window in seconds
            track_by (str): What to track ('ip', 'port', 'ip_port')
        """
        super().__init__(rule_id, name, description, severity)
        self.count = count
        self.seconds = seconds
        self.track_by = track_by
        self.history = {}
        
    def _get_track_key(self, packet):
        """
        Get the key to track for this packet.
        
        Args:
            packet (dict): Packet data
            
        Returns:
            str: Key for tracking
        """
        if self.track_by == 'ip':
            return packet.get('src_ip', '')
        elif self.track_by == 'port':
            return str(packet.get('dst_port', ''))
        elif self.track_by == 'ip_port':
            return f"{packet.get('src_ip', '')}:{packet.get('dst_port', '')}"
        else:
            return ''
            
    def _cleanup_history(self, current_time):
        """
        Remove old entries from history.
        
        Args:
            current_time (datetime): Current time
        """
        for key in list(self.history.keys()):
            # Remove timestamps older than the window
            self.history[key] = [
                ts for ts in self.history[key]
                if (current_time - ts).total_seconds() <= self.seconds
            ]
            
            # Remove entries with empty lists
            if not self.history[key]:
                del self.history[key]
                
    def match(self, packet):
        """
        Check if the packet's rate matches this rule.
        
        Args:
            packet (dict): Packet data
            
        Returns:
            bool: True if the packet matches this rule, False otherwise
        """
        key = self._get_track_key(packet)
        if not key:
            return False
            
        current_time = datetime.now()
        
        # Clean up old history entries
        self._cleanup_history(current_time)
        
        # Add this packet to history
        if key not in self.history:
            self.history[key] = []
        self.history[key].append(current_time)
        
        # Check if count threshold is exceeded in the time window
        return len(self.history[key]) >= self.count
        
    def to_dict(self):
        """
        Convert the rule to a dictionary.
        
        Returns:
            dict: Dictionary representation of the rule
        """
        result = super().to_dict()
        result.update({
            'type': 'rate',
            'count': self.count,
            'seconds': self.seconds,
            'track_by': self.track_by
        })
        return result
        
    @classmethod
    def from_dict(cls, rule_dict):
        """
        Create a rate-based rule from a dictionary.
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
            
        Returns:
            RateBasedRule: Created rule
        """
        return cls(
            rule_id=rule_dict['rule_id'],
            name=rule_dict['name'],
            description=rule_dict['description'],
            severity=rule_dict['severity'],
            count=rule_dict['count'],
            seconds=rule_dict['seconds'],
            track_by=rule_dict.get('track_by', 'ip')
        )

def create_rule_from_dict(rule_dict):
    """
    Create a rule from a dictionary.
    
    Args:
        rule_dict (dict): Dictionary containing rule parameters
        
    Returns:
        SignatureRule: Created rule
    """
    rule_type = rule_dict.get('type', '')
    
    if rule_type == 'ip':
        return IPRule.from_dict(rule_dict)
    elif rule_type == 'port':
        return PortRule.from_dict(rule_dict)
    elif rule_type == 'payload':
        return PayloadRule.from_dict(rule_dict)
    elif rule_type == 'rate':
        return RateBasedRule.from_dict(rule_dict)
    elif rule_type == 'composite':
        return CompositeRule.from_dict(rule_dict, create_rule_from_dict)
    else:
        logger.warning(f"Unknown rule type: {rule_type}")
        return None

def load_rules(rules_file):
    """
    Load rules from a YAML file.
    
    Args:
        rules_file (str): Path to the rules file
        
    Returns:
        list: List of SignatureRule objects
    """
    if not os.path.exists(rules_file):
        logger.warning(f"Rules file not found: {rules_file}")
        return []
        
    try:
        with open(rules_file, 'r') as f:
            rules_data = yaml.safe_load(f)
            
        if not rules_data or not isinstance(rules_data, dict) or 'rules' not in rules_data:
            logger.warning(f"Invalid rules file format: {rules_file}")
            return []
            
        rules = []
        for rule_dict in rules_data['rules']:
            rule = create_rule_from_dict(rule_dict)
            if rule:
                rules.append(rule)
                
        logger.info(f"Loaded {len(rules)} rules from {rules_file}")
        return rules
        
    except Exception as e:
        logger.error(f"Error loading rules from {rules_file}: {e}")
        return []

def save_rules(rules, rules_file):
    """
    Save rules to a YAML file.
    
    Args:
        rules (list): List of SignatureRule objects
        rules_file (str): Path to save the rules to
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        rules_data = {
            'rules': [rule.to_dict() for rule in rules]
        }
        
        directory = os.path.dirname(rules_file)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
        with open(rules_file, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False)
            
        logger.info(f"Saved {len(rules)} rules to {rules_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving rules to {rules_file}: {e}")
        return False

def check_signatures(packet, rules):
    """
    Check if a packet matches any signature rules.
    
    Args:
        packet (dict): Packet data
        rules (list): List of SignatureRule objects
        
    Returns:
        dict: Match information if a rule is matched, None otherwise
    """
    for rule in rules:
        if rule.match(packet):
            match_info = {
                'rule_id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'timestamp': datetime.now().isoformat()
            }
            logger.info(f"Signature match: {rule.name} (ID: {rule.rule_id})")
            return match_info
            
    return None

def create_default_rules():
    """
    Create a set of default signature rules.
    
    Returns:
        list: List of default SignatureRule objects
    """
    rules = []
    
    # SSH Brute Force Detection
    rules.append(RateBasedRule(
        rule_id="RATE-001",
        name="SSH Brute Force Attempt",
        description="Detects multiple SSH connection attempts",
        severity="high",
        count=5,
        seconds=60,
        track_by="ip_port"
    ))
    
    # Port Scan Detection
    rules.append(RateBasedRule(
        rule_id="RATE-002",
        name="Port Scan Detected",
        description="Detects port scanning activity",
        severity="medium",
        count=15,
        seconds=5,
        track_by="ip"
    ))
    
    # FTP Brute Force Detection
    rules.append(RateBasedRule(
        rule_id="RATE-003",
        name="FTP Brute Force Attempt",
        description="Detects multiple FTP connection attempts",
        severity="high",
        count=5,
        seconds=60,
        track_by="ip_port"
    ))
    
    # Known Malicious IPs
    rules.append(IPRule(
        rule_id="IP-001",
        name="Known Malicious IP",
        description="Detects traffic from known malicious IP addresses",
        severity="high",
        ip_list=["185.216.35.0/24", "192.99.142.0/24"],
        direction="src"
    ))
    
    # Tor Exit Nodes
    rules.append(IPRule(
        rule_id="IP-002",
        name="Tor Exit Node",
        description="Detects traffic from Tor exit nodes",
        severity="medium",
        ip_list=["109.70.100.0/24", "171.25.193.0/24"],
        direction="src"
    ))
    
    # Common SQL Injection Payloads
    rules.append(PayloadRule(
        rule_id="PAYLOAD-001",
        name="SQL Injection Attempt",
        description="Detects common SQL injection patterns",
        severity="critical",
        patterns=[
            "union\s+select",
            "select.*from",
            "or\s+1=1",
            "drop\s+table",
            "admin'--",
            ";\s*exec"
        ],
        case_sensitive=False
    ))
    
    # Common Command Injection Payloads
    rules.append(PayloadRule(
        rule_id="PAYLOAD-002",
        name="Command Injection Attempt",
        description="Detects common command injection patterns",
        severity="critical",
        patterns=[
            ";\s*(?:rm|nc|wget|curl|bash|sh|chmod|python)",
            "[|;&]\s*(?:cat|nc|wget|curl|bash|sh|chmod|python)",
            "/bin/(?:bash|sh|nc)"
        ],
        case_sensitive=False
    ))
    
    # XSS Payloads
    rules.append(PayloadRule(
        rule_id="PAYLOAD-003",
        name="XSS Attempt",
        description="Detects common XSS patterns",
        severity="high",
        patterns=[
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "ondblclick=",
            "document\\.cookie"
        ],
        case_sensitive=False
    ))
    
    # Suspicious Ports
    rules.append(PortRule(
        rule_id="PORT-001",
        name="Suspicious Port Access",
        description="Detects access to commonly exploited services",
        severity="medium",
        port_list=["21", "22", "23", "445", "1433", "3306", "3389"],
        direction="dst"
    ))
    
    # DNS Tunneling Detection (composite rule)
    dns_tunneling = CompositeRule(
        rule_id="COMP-001",
        name="DNS Tunneling",
        description="Detects potential DNS tunneling",
        severity="high",
        subrules=[
            PortRule(
                rule_id="PORT-002",
                name="DNS Port",
                description="DNS port traffic",
                severity="low",
                port_list=["53"],
                direction="dst"
            ),
            RateBasedRule(
                rule_id="RATE-004",
                name="High DNS Query Rate",
                description="Abnormally high rate of DNS queries",
                severity="medium",
                count=30,
                seconds=60,
                track_by="ip"
            )
        ],
        operator="and"
    )
    rules.append(dns_tunneling)
    
    return rules

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create default rules
    default_rules = create_default_rules()
    
    # Save rules to file
    config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config')
    os.makedirs(config_dir, exist_ok=True)
    save_rules(default_rules, os.path.join(config_dir, 'signature_rules.yaml'))
    
    # Test rule matching
    test_packet = {
        'src_ip': '192.99.142.10',
        'dst_ip': '10.0.0.1',
        'src_port': 45678,
        'dst_port': 22,
        'payload': 'SSH-2.0-OpenSSH_7.9'
    }
    
    match = check_signatures(test_packet, default_rules)
    if match:
        print(f"Match found: {match['name']} ({match['severity']})")
        print(f"Description: {match['description']}")
    else:
        print("No signature match found") 