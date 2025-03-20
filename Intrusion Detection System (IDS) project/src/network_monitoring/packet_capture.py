#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Packet Capture Module
This module handles capturing and processing network packets.
"""

import os
import sys
import logging
import time
import threading
import queue
import socket
import signal
import json
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    
try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False

# Setup logging
logger = logging.getLogger('ids.packet_capture')

class PacketCaptureThread(threading.Thread):
    """Thread for capturing packets in the background."""
    
    def __init__(self, interface=None, callback=None, bpf_filter="", use_pyshark=False, packet_count=0, buffer_size=100):
        """
        Initialize the packet capture thread.
        
        Args:
            interface (str, optional): Network interface to capture from
            callback (function, optional): Function to process captured packets
            bpf_filter (str, optional): BPF filter to apply to capture
            use_pyshark (bool): Whether to use PyShark (True) or Scapy (False)
            packet_count (int): Number of packets to capture (0 for indefinite)
            buffer_size (int): Size of the packet buffer
        """
        super().__init__()
        self.interface = interface
        self.callback = callback
        self.bpf_filter = bpf_filter
        self.use_pyshark = use_pyshark
        self.packet_count = packet_count
        self.packet_buffer = queue.Queue(maxsize=buffer_size)
        self.stop_flag = threading.Event()
        self.daemon = True  # Thread will exit when main thread exits
        
    def run(self):
        """Run the packet capture thread."""
        try:
            if self.use_pyshark and HAS_PYSHARK:
                self._run_pyshark()
            elif HAS_SCAPY:
                self._run_scapy()
            else:
                logger.error("Neither Scapy nor PyShark is available")
                return
        except Exception as e:
            logger.error(f"Error in packet capture thread: {e}")
            
    def _run_scapy(self):
        """Run packet capture using Scapy."""
        logger.info(f"Starting Scapy packet capture on interface {self.interface}")
        
        def packet_handler(packet):
            if self.stop_flag.is_set():
                return True  # Stop sniffing
                
            try:
                processed_packet = process_scapy_packet(packet)
                if processed_packet:
                    if self.packet_buffer.full():
                        # Remove oldest packet to make room
                        try:
                            self.packet_buffer.get_nowait()
                        except queue.Empty:
                            pass
                    
                    self.packet_buffer.put(processed_packet)
                    
                    if self.callback:
                        self.callback(processed_packet)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=packet_handler,
                store=0,
                count=self.packet_count or None,
                stop_filter=lambda p: self.stop_flag.is_set()
            )
        except Exception as e:
            logger.error(f"Error in Scapy packet capture: {e}")
            
    def _run_pyshark(self):
        """Run packet capture using PyShark."""
        logger.info(f"Starting PyShark packet capture on interface {self.interface}")
        
        try:
            # Create capture object
            if self.interface:
                capture = pyshark.LiveCapture(
                    interface=self.interface,
                    bpf_filter=self.bpf_filter
                )
            else:
                capture = pyshark.LiveCapture(
                    bpf_filter=self.bpf_filter
                )
                
            # Start capture loop
            for packet in capture.sniff_continuously(packet_count=self.packet_count):
                if self.stop_flag.is_set():
                    break
                    
                try:
                    processed_packet = process_pyshark_packet(packet)
                    if processed_packet:
                        if self.packet_buffer.full():
                            # Remove oldest packet to make room
                            try:
                                self.packet_buffer.get_nowait()
                            except queue.Empty:
                                pass
                        
                        self.packet_buffer.put(processed_packet)
                        
                        if self.callback:
                            self.callback(processed_packet)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    
        except Exception as e:
            logger.error(f"Error in PyShark packet capture: {e}")
            
    def stop(self):
        """Stop the packet capture thread."""
        logger.info("Stopping packet capture thread")
        self.stop_flag.set()
        
    def get_packet(self, block=True, timeout=None):
        """
        Get a packet from the buffer.
        
        Args:
            block (bool): Whether to block if buffer is empty
            timeout (float, optional): Timeout for blocking
            
        Returns:
            dict: Processed packet or None if timeout
        """
        try:
            return self.packet_buffer.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

def process_scapy_packet(packet):
    """
    Process a packet from Scapy.
    
    Args:
        packet: Scapy packet
        
    Returns:
        dict: Processed packet information
    """
    result = {
        'timestamp': datetime.now().isoformat(),
        'protocol': None,
    }
    
    # Process IP layer
    if IP in packet:
        result['src_ip'] = packet[IP].src
        result['dst_ip'] = packet[IP].dst
        result['ip_version'] = packet[IP].version
        result['ttl'] = packet[IP].ttl
        
        # Process TCP layer
        if TCP in packet:
            result['protocol'] = 'TCP'
            result['src_port'] = packet[TCP].sport
            result['dst_port'] = packet[TCP].dport
            result['tcp_flags'] = {
                'syn': packet[TCP].flags.S,
                'ack': packet[TCP].flags.A,
                'fin': packet[TCP].flags.F,
                'rst': packet[TCP].flags.R,
                'psh': packet[TCP].flags.P,
                'urg': packet[TCP].flags.U
            }
            
            # Extract payload
            if packet[TCP].payload:
                payload = bytes(packet[TCP].payload)
                try:
                    # Try to decode as UTF-8
                    result['payload'] = payload.decode('utf-8', errors='replace')
                except:
                    # Save as hex
                    result['payload'] = payload.hex()
                    result['payload_is_hex'] = True
                
                # Set payload length
                result['payload_len'] = len(payload)
            
        # Process UDP layer
        elif UDP in packet:
            result['protocol'] = 'UDP'
            result['src_port'] = packet[UDP].sport
            result['dst_port'] = packet[UDP].dport
            
            # Extract payload
            if packet[UDP].payload:
                payload = bytes(packet[UDP].payload)
                try:
                    # Try to decode as UTF-8
                    result['payload'] = payload.decode('utf-8', errors='replace')
                except:
                    # Save as hex
                    result['payload'] = payload.hex()
                    result['payload_is_hex'] = True
                
                # Set payload length
                result['payload_len'] = len(payload)
                
        # Process ICMP layer
        elif ICMP in packet:
            result['protocol'] = 'ICMP'
            result['icmp_type'] = packet[ICMP].type
            result['icmp_code'] = packet[ICMP].code
            
    # Set frame length
    result['length'] = len(packet)
    
    return result

def process_pyshark_packet(packet):
    """
    Process a packet from PyShark.
    
    Args:
        packet: PyShark packet
        
    Returns:
        dict: Processed packet information
    """
    result = {
        'timestamp': datetime.now().isoformat(),
        'protocol': None,
    }
    
    # Extract Ethernet layer info if available
    if hasattr(packet, 'eth'):
        result['src_mac'] = packet.eth.src
        result['dst_mac'] = packet.eth.dst
    
    # Extract IP layer info if available
    if hasattr(packet, 'ip'):
        result['src_ip'] = packet.ip.src
        result['dst_ip'] = packet.ip.dst
        result['ip_version'] = packet.ip.version
        result['ttl'] = packet.ip.ttl
        
        # Set frame length
        if hasattr(packet, 'length'):
            result['length'] = int(packet.length)
    
    # Extract IPv6 layer info if available
    elif hasattr(packet, 'ipv6'):
        result['src_ip'] = packet.ipv6.src
        result['dst_ip'] = packet.ipv6.dst
        result['ip_version'] = 6
        result['hop_limit'] = packet.ipv6.hlim
        
        # Set frame length
        if hasattr(packet, 'length'):
            result['length'] = int(packet.length)
    
    # Extract TCP layer info if available
    if hasattr(packet, 'tcp'):
        result['protocol'] = 'TCP'
        result['src_port'] = int(packet.tcp.srcport)
        result['dst_port'] = int(packet.tcp.dstport)
        
        # Extract TCP flags
        if hasattr(packet.tcp, 'flags'):
            flags_value = int(packet.tcp.flags, 16)
            result['tcp_flags'] = {
                'syn': bool(flags_value & 0x02),
                'ack': bool(flags_value & 0x10),
                'fin': bool(flags_value & 0x01),
                'rst': bool(flags_value & 0x04),
                'psh': bool(flags_value & 0x08),
                'urg': bool(flags_value & 0x20)
            }
        
        # Extract payload
        if hasattr(packet.tcp, 'payload'):
            result['payload'] = packet.tcp.payload
            result['payload_len'] = len(packet.tcp.payload)
    
    # Extract UDP layer info if available
    elif hasattr(packet, 'udp'):
        result['protocol'] = 'UDP'
        result['src_port'] = int(packet.udp.srcport)
        result['dst_port'] = int(packet.udp.dstport)
        
        # Extract payload
        if hasattr(packet.udp, 'payload'):
            result['payload'] = packet.udp.payload
            result['payload_len'] = len(packet.udp.payload)
    
    # Extract ICMP layer info if available
    elif hasattr(packet, 'icmp'):
        result['protocol'] = 'ICMP'
        result['icmp_type'] = int(packet.icmp.type)
        result['icmp_code'] = int(packet.icmp.code)
    
    return result

def extract_features(packet):
    """
    Extract features from a packet for machine learning.
    
    Args:
        packet (dict): Processed packet
        
    Returns:
        dict: Features extracted from the packet
    """
    features = {}
    
    # Basic features
    features['timestamp'] = packet.get('timestamp')
    features['protocol'] = packet.get('protocol')
    features['length'] = packet.get('length', 0)
    features['payload_len'] = packet.get('payload_len', 0)
    
    # IP-related features
    features['src_ip'] = packet.get('src_ip')
    features['dst_ip'] = packet.get('dst_ip')
    features['ttl'] = packet.get('ttl')
    
    # Port-related features
    features['src_port'] = packet.get('src_port')
    features['dst_port'] = packet.get('dst_port')
    
    # TCP-specific features
    if packet.get('protocol') == 'TCP' and 'tcp_flags' in packet:
        features['tcp_syn'] = packet['tcp_flags'].get('syn', False)
        features['tcp_ack'] = packet['tcp_flags'].get('ack', False)
        features['tcp_fin'] = packet['tcp_flags'].get('fin', False)
        features['tcp_rst'] = packet['tcp_flags'].get('rst', False)
        features['tcp_psh'] = packet['tcp_flags'].get('psh', False)
        features['tcp_urg'] = packet['tcp_flags'].get('urg', False)
    
    return features

def start_capture(interface=None, callback=None, bpf_filter="", use_pyshark=False,
                 packet_count=0, buffer_size=100):
    """
    Start packet capture.
    
    Args:
        interface (str, optional): Network interface to capture from
        callback (function, optional): Function to process captured packets
        bpf_filter (str, optional): BPF filter to apply to capture
        use_pyshark (bool): Whether to use PyShark (True) or Scapy (False)
        packet_count (int): Number of packets to capture (0 for indefinite)
        buffer_size (int): Size of the packet buffer
        
    Returns:
        PacketCaptureThread: The started capture thread
    """
    # Check dependencies
    if use_pyshark and not HAS_PYSHARK:
        logger.warning("PyShark not available, falling back to Scapy")
        use_pyshark = False
        
    if not HAS_SCAPY and not HAS_PYSHARK:
        logger.error("Neither Scapy nor PyShark is available")
        return None
        
    # Create and start capture thread
    capture_thread = PacketCaptureThread(
        interface=interface,
        callback=callback,
        bpf_filter=bpf_filter,
        use_pyshark=use_pyshark,
        packet_count=packet_count,
        buffer_size=buffer_size
    )
    capture_thread.start()
    
    return capture_thread

def stop_capture(capture_thread):
    """
    Stop packet capture.
    
    Args:
        capture_thread (PacketCaptureThread): The capture thread to stop
    """
    if capture_thread and capture_thread.is_alive():
        capture_thread.stop()
        capture_thread.join(timeout=2.0)

def list_interfaces():
    """
    List available network interfaces.
    
    Returns:
        list: Available network interfaces
    """
    if HAS_SCAPY:
        from scapy.config import conf
        return conf.ifaces.keys()
    elif HAS_PYSHARK:
        return pyshark.LiveCapture.list_interfaces()
    else:
        logger.error("Neither Scapy nor PyShark is available")
        return []

def save_packets_to_file(packets, output_file):
    """
    Save captured packets to a file.
    
    Args:
        packets (list): List of processed packets
        output_file (str): Path to output file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        directory = os.path.dirname(output_file)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
        # Write packets to file
        with open(output_file, 'w') as f:
            for packet in packets:
                f.write(json.dumps(packet) + '\n')
                
        logger.info(f"Saved {len(packets)} packets to {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving packets to {output_file}: {e}")
        return False

def load_packets_from_file(input_file):
    """
    Load packets from a file.
    
    Args:
        input_file (str): Path to input file
        
    Returns:
        list: Loaded packets
    """
    if not os.path.exists(input_file):
        logger.warning(f"Input file not found: {input_file}")
        return []
        
    try:
        packets = []
        with open(input_file, 'r') as f:
            for line in f:
                try:
                    packet = json.loads(line.strip())
                    packets.append(packet)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in line: {line}")
                    
        logger.info(f"Loaded {len(packets)} packets from {input_file}")
        return packets
        
    except Exception as e:
        logger.error(f"Error loading packets from {input_file}: {e}")
        return []

def _demo_packet_handler(packet):
    """Demo packet handler that prints packet info."""
    print(f"[{packet['timestamp']}] {packet.get('protocol', 'Unknown')} "
          f"{packet.get('src_ip', 'Unknown')}:{packet.get('src_port', '')} -> "
          f"{packet.get('dst_ip', 'Unknown')}:{packet.get('dst_port', '')} "
          f"({packet.get('length', 0)} bytes)")

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("Available interfaces:")
    for iface in list_interfaces():
        print(f"- {iface}")
        
    interface = input("Enter interface name (or leave empty for default): ").strip()
    if not interface:
        interface = None
        
    print("Starting packet capture...")
    
    # Set up signal handler for graceful shutdown
    stop_event = threading.Event()
    
    def signal_handler(sig, frame):
        print("Stopping packet capture...")
        stop_event.set()
        
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start packet capture
    capture_thread = start_capture(interface=interface, callback=_demo_packet_handler)
    
    # Wait for stop signal
    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        stop_capture(capture_thread)
        print("Packet capture stopped.") 