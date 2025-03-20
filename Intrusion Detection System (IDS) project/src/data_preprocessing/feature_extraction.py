#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Feature Extraction Module
This module handles extraction of features from network traffic data for IDS.
"""

import os
import logging
import pandas as pd
import numpy as np
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# Setup logging
logger = logging.getLogger('ids.feature_extraction')

class FeatureExtractor:
    """Base class for feature extraction from network traffic data."""
    
    def __init__(self, time_window=60):
        """
        Initialize the feature extractor.
        
        Args:
            time_window (int): Time window in seconds for temporal features
        """
        self.time_window = time_window
        self.packet_buffer = []
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'tcp_flags': Counter(),
            'protocols': Counter()
        })
        
    def add_packet(self, packet):
        """
        Add a packet to the buffer and update flow statistics.
        
        Args:
            packet (dict): Processed packet data
        """
        # Add packet to buffer
        self.packet_buffer.append(packet)
        
        # Clean old packets from buffer
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        # Convert timestamp string to datetime if needed
        if isinstance(packet.get('timestamp'), str):
            try:
                packet_time = datetime.fromisoformat(packet['timestamp'])
            except (ValueError, TypeError):
                packet_time = current_time
        else:
            packet_time = current_time
            
        # Remove packets older than the time window
        self.packet_buffer = [p for p in self.packet_buffer 
                             if datetime.fromisoformat(p['timestamp']) >= cutoff_time]
        
        # Update flow statistics
        if 'src_ip' in packet and 'dst_ip' in packet:
            # Define flow key (5-tuple or similar)
            flow_key = self._get_flow_key(packet)
            
            # Update statistics for this flow
            flow = self.flow_stats[flow_key]
            flow['packet_count'] += 1
            flow['byte_count'] += packet.get('length', 0)
            
            if flow['start_time'] is None:
                flow['start_time'] = packet_time
            flow['last_time'] = packet_time
            
            # Update TCP flags if available
            if packet.get('protocol') == 'TCP' and 'tcp_flags' in packet:
                for flag, value in packet['tcp_flags'].items():
                    if value:
                        flow['tcp_flags'][flag] += 1
                        
            # Update protocol counter
            if 'protocol' in packet:
                flow['protocols'][packet['protocol']] += 1
    
    def _get_flow_key(self, packet):
        """
        Get a key to identify a network flow.
        
        Args:
            packet (dict): Processed packet data
            
        Returns:
            tuple: Flow identifier
        """
        # Default: 5-tuple (protocol, src_ip, src_port, dst_ip, dst_port)
        protocol = packet.get('protocol', 'UNKNOWN')
        src_ip = packet.get('src_ip', '0.0.0.0')
        dst_ip = packet.get('dst_ip', '0.0.0.0')
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        
        return (protocol, src_ip, src_port, dst_ip, dst_port)
    
    def extract_basic_features(self, packet):
        """
        Extract basic features from a single packet.
        
        Args:
            packet (dict): Processed packet data
            
        Returns:
            dict: Basic features
        """
        features = {}
        
        # Packet metadata
        features['timestamp'] = packet.get('timestamp')
        features['protocol'] = packet.get('protocol')
        features['length'] = packet.get('length', 0)
        features['payload_len'] = packet.get('payload_len', 0)
        
        # IP-level features
        features['ttl'] = packet.get('ttl')
        
        # Port features
        features['src_port'] = packet.get('src_port')
        features['dst_port'] = packet.get('dst_port')
        
        # TCP-specific features
        if packet.get('protocol') == 'TCP' and 'tcp_flags' in packet:
            flags = packet['tcp_flags']
            features['tcp_syn'] = int(flags.get('syn', False))
            features['tcp_ack'] = int(flags.get('ack', False))
            features['tcp_fin'] = int(flags.get('fin', False))
            features['tcp_rst'] = int(flags.get('rst', False))
            features['tcp_psh'] = int(flags.get('psh', False))
            features['tcp_urg'] = int(flags.get('urg', False))
        
        return features
    
    def extract_flow_features(self, flow_key=None):
        """
        Extract statistical features from the current flow.
        
        Args:
            flow_key (tuple, optional): Flow identifier. If None, extract features for all flows.
            
        Returns:
            dict or list: Flow-based features
        """
        # If flow_key is provided, extract features for that flow
        if flow_key is not None and flow_key in self.flow_stats:
            return self._extract_single_flow_features(flow_key, self.flow_stats[flow_key])
        
        # Otherwise, extract features for all flows
        all_flow_features = []
        for key, flow in self.flow_stats.items():
            flow_features = self._extract_single_flow_features(key, flow)
            all_flow_features.append(flow_features)
            
        return all_flow_features
    
    def _extract_single_flow_features(self, flow_key, flow):
        """
        Extract features for a single flow.
        
        Args:
            flow_key (tuple): Flow identifier
            flow (dict): Flow statistics
            
        Returns:
            dict: Flow features
        """
        features = {}
        
        # Flow identifier
        protocol, src_ip, src_port, dst_ip, dst_port = flow_key
        features['protocol'] = protocol
        features['src_ip'] = src_ip
        features['src_port'] = src_port
        features['dst_ip'] = dst_ip
        features['dst_port'] = dst_port
        
        # Basic flow statistics
        features['packet_count'] = flow['packet_count']
        features['byte_count'] = flow['byte_count']
        
        # Calculate flow duration if timestamps are available
        if flow['start_time'] and flow['last_time']:
            duration = (flow['last_time'] - flow['start_time']).total_seconds()
            features['flow_duration'] = duration
            
            # Calculate rate features
            if duration > 0:
                features['packets_per_second'] = flow['packet_count'] / duration
                features['bytes_per_second'] = flow['byte_count'] / duration
            else:
                features['packets_per_second'] = 0
                features['bytes_per_second'] = 0
        
        # TCP flag statistics
        if protocol == 'TCP':
            for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']:
                features[f'tcp_{flag}_count'] = flow['tcp_flags'].get(flag, 0)
                
            # Flag combinations for attack detection
            features['syn_fin_ratio'] = self._safe_ratio(
                flow['tcp_flags'].get('syn', 0), 
                flow['tcp_flags'].get('fin', 0)
            )
            features['syn_rst_ratio'] = self._safe_ratio(
                flow['tcp_flags'].get('syn', 0), 
                flow['tcp_flags'].get('rst', 0)
            )
        
        # Protocol distribution
        for proto, count in flow['protocols'].items():
            features[f'protocol_{proto.lower()}_count'] = count
            
        return features
    
    def _safe_ratio(self, numerator, denominator, default=0):
        """
        Calculate ratio with protection against division by zero.
        
        Args:
            numerator (float): Numerator
            denominator (float): Denominator
            default (float): Default value if denominator is zero
            
        Returns:
            float: Ratio or default value
        """
        return numerator / denominator if denominator > 0 else default
    
    def extract_temporal_features(self):
        """
        Extract temporal features from the packet buffer.
        
        Returns:
            dict: Temporal features
        """
        features = {}
        
        # Count packets in the current time window
        features['packet_count'] = len(self.packet_buffer)
        
        if not self.packet_buffer:
            return features
        
        # Calculate packet sizes
        packet_sizes = [p.get('length', 0) for p in self.packet_buffer]
        features['avg_packet_size'] = np.mean(packet_sizes) if packet_sizes else 0
        features['std_packet_size'] = np.std(packet_sizes) if packet_sizes else 0
        features['min_packet_size'] = min(packet_sizes) if packet_sizes else 0
        features['max_packet_size'] = max(packet_sizes) if packet_sizes else 0
        
        # Protocol distribution
        protocols = Counter([p.get('protocol') for p in self.packet_buffer if p.get('protocol')])
        for protocol, count in protocols.items():
            if protocol:
                features[f'protocol_{protocol.lower()}_ratio'] = count / len(self.packet_buffer)
        
        # Unique IP addresses
        src_ips = set([p.get('src_ip') for p in self.packet_buffer if p.get('src_ip')])
        dst_ips = set([p.get('dst_ip') for p in self.packet_buffer if p.get('dst_ip')])
        features['unique_src_ips'] = len(src_ips)
        features['unique_dst_ips'] = len(dst_ips)
        
        # Unique ports
        src_ports = set([p.get('src_port') for p in self.packet_buffer if p.get('src_port')])
        dst_ports = set([p.get('dst_port') for p in self.packet_buffer if p.get('dst_port')])
        features['unique_src_ports'] = len(src_ports)
        features['unique_dst_ports'] = len(dst_ports)
        
        # TCP flags distribution (for detecting scanning)
        if any(p.get('protocol') == 'TCP' for p in self.packet_buffer):
            tcp_packets = [p for p in self.packet_buffer if p.get('protocol') == 'TCP']
            flags_count = defaultdict(int)
            
            for packet in tcp_packets:
                if 'tcp_flags' in packet:
                    for flag, value in packet['tcp_flags'].items():
                        if value:
                            flags_count[flag] += 1
            
            for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']:
                features[f'tcp_{flag}_ratio'] = flags_count[flag] / len(tcp_packets) if tcp_packets else 0
        
        return features
    
    def extract_all_features(self, packet=None):
        """
        Extract all features - packet-based, flow-based, and temporal.
        
        Args:
            packet (dict, optional): Current packet to extract features from
            
        Returns:
            dict: All extracted features
        """
        features = {}
        
        # Add new packet if provided
        if packet:
            self.add_packet(packet)
            # Extract basic features from current packet
            features.update(self.extract_basic_features(packet))
            
        # Extract flow features for the current packet's flow
        if packet:
            flow_key = self._get_flow_key(packet)
            flow_features = self.extract_flow_features(flow_key)
            features.update(flow_features)
        
        # Extract temporal features
        temporal_features = self.extract_temporal_features()
        features.update(temporal_features)
        
        return features

class NetworkFlowExtractor(FeatureExtractor):
    """Feature extractor specifically for network flow data."""
    
    def __init__(self, time_window=60, bidirectional=True):
        """
        Initialize the network flow extractor.
        
        Args:
            time_window (int): Time window in seconds for temporal features
            bidirectional (bool): Whether to consider flows bidirectionally
        """
        super().__init__(time_window)
        self.bidirectional = bidirectional
        
    def _get_flow_key(self, packet):
        """
        Get a key to identify a network flow, optionally bidirectional.
        
        Args:
            packet (dict): Processed packet data
            
        Returns:
            tuple: Flow identifier
        """
        protocol = packet.get('protocol', 'UNKNOWN')
        src_ip = packet.get('src_ip', '0.0.0.0')
        dst_ip = packet.get('dst_ip', '0.0.0.0')
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        
        if self.bidirectional:
            # Create a canonical key for bidirectional flows
            if (src_ip, src_port) > (dst_ip, dst_port):
                return (protocol, src_ip, src_port, dst_ip, dst_port)
            else:
                return (protocol, dst_ip, dst_port, src_ip, src_port)
        else:
            # Unidirectional flow
            return (protocol, src_ip, src_port, dst_ip, dst_port)
    
    def extract_advanced_flow_features(self, flow_key=None):
        """
        Extract advanced statistical features from flow data.
        
        Args:
            flow_key (tuple, optional): Flow identifier
            
        Returns:
            dict: Advanced flow features
        """
        # Get basic flow features
        flow_features = self.extract_flow_features(flow_key)
        
        if not flow_features:
            return {}
            
        # If we have multiple flows, just return the basic features
        if isinstance(flow_features, list):
            return flow_features
            
        # Add advanced features for a single flow
        advanced_features = flow_features.copy()
        
        # Extract IP-based features
        src_ip = flow_features.get('src_ip')
        dst_ip = flow_features.get('dst_ip')
        
        # Check if IPs are private
        try:
            if src_ip:
                src_ip_obj = ipaddress.ip_address(src_ip)
                advanced_features['src_ip_is_private'] = int(src_ip_obj.is_private)
            
            if dst_ip:
                dst_ip_obj = ipaddress.ip_address(dst_ip)
                advanced_features['dst_ip_is_private'] = int(dst_ip_obj.is_private)
        except ValueError:
            # Invalid IP address
            pass
        
        # Check for well-known ports
        src_port = flow_features.get('src_port', 0)
        dst_port = flow_features.get('dst_port', 0)
        
        advanced_features['src_port_is_well_known'] = int(src_port is not None and 0 < src_port < 1024)
        advanced_features['dst_port_is_well_known'] = int(dst_port is not None and 0 < dst_port < 1024)
        
        # Check for common service ports
        common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389, 1433, 8080}
        advanced_features['src_port_is_common'] = int(src_port in common_ports)
        advanced_features['dst_port_is_common'] = int(dst_port in common_ports)
        
        return advanced_features

def extract_features_for_packet(packet, extractor=None):
    """
    Extract features for a single packet.
    
    Args:
        packet (dict): Processed packet data
        extractor (FeatureExtractor, optional): Existing extractor to use
        
    Returns:
        dict: Extracted features
    """
    if extractor is None:
        extractor = FeatureExtractor()
        
    return extractor.extract_all_features(packet)

def extract_features_for_flow(packets, bidirectional=True):
    """
    Extract features for a flow consisting of multiple packets.
    
    Args:
        packets (list): List of processed packets
        bidirectional (bool): Whether to consider flows bidirectionally
        
    Returns:
        dict: Extracted flow features
    """
    extractor = NetworkFlowExtractor(bidirectional=bidirectional)
    
    # Add all packets to the extractor
    for packet in packets:
        extractor.add_packet(packet)
    
    # Extract features for all flows
    flow_features = extractor.extract_flow_features()
    
    # If we only have one flow, also get advanced features
    if flow_features and isinstance(flow_features, dict):
        return extractor.extract_advanced_flow_features()
    elif flow_features and len(flow_features) == 1:
        return extractor.extract_advanced_flow_features(
            extractor._get_flow_key(packets[0])
        )
    
    return flow_features

def extract_features_batch(packets_df):
    """
    Extract features from a batch of packets in a DataFrame.
    
    Args:
        packets_df (pd.DataFrame): DataFrame of packet data
        
    Returns:
        pd.DataFrame: DataFrame of extracted features
    """
    logger.info(f"Extracting features from {len(packets_df)} packets")
    
    # Group packets by flow
    def get_flow_key(row):
        return (
            row.get('protocol', 'UNKNOWN'),
            row.get('src_ip', '0.0.0.0'),
            row.get('src_port', 0),
            row.get('dst_ip', '0.0.0.0'),
            row.get('dst_port', 0)
        )
    
    packets_df['flow_key'] = packets_df.apply(get_flow_key, axis=1)
    grouped = packets_df.groupby('flow_key')
    
    # Extract features for each flow
    all_features = []
    for flow_key, flow_packets in grouped:
        packets_list = flow_packets.to_dict('records')
        flow_features = extract_features_for_flow(packets_list)
        
        if isinstance(flow_features, list):
            all_features.extend(flow_features)
        else:
            all_features.append(flow_features)
    
    # Convert to DataFrame
    features_df = pd.DataFrame(all_features)
    logger.info(f"Extracted features for {len(features_df)} flows")
    
    return features_df

def convert_ip_to_numeric(ip_str):
    """
    Convert an IP address string to a numeric value.
    
    Args:
        ip_str (str): IP address string
        
    Returns:
        int: Numeric representation of the IP
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return int(ip_obj)
    except (ValueError, TypeError):
        return 0

def preprocess_features_for_ml(features_df):
    """
    Preprocess extracted features for machine learning.
    
    Args:
        features_df (pd.DataFrame): DataFrame of extracted features
        
    Returns:
        pd.DataFrame: Preprocessed features
    """
    # Make a copy to avoid modifying the original DataFrame
    df = features_df.copy()
    
    # Convert IP addresses to numeric values
    if 'src_ip' in df.columns:
        df['src_ip_numeric'] = df['src_ip'].apply(convert_ip_to_numeric)
        df.drop('src_ip', axis=1, inplace=True)
    
    if 'dst_ip' in df.columns:
        df['dst_ip_numeric'] = df['dst_ip'].apply(convert_ip_to_numeric)
        df.drop('dst_ip', axis=1, inplace=True)
    
    # Handle categorical features
    if 'protocol' in df.columns:
        df = pd.get_dummies(df, columns=['protocol'], prefix=['protocol'])
    
    # Handle missing values
    df.fillna(0, inplace=True)
    
    return df

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create a sample packet
    sample_packet = {
        'timestamp': datetime.now().isoformat(),
        'protocol': 'TCP',
        'src_ip': '192.168.1.100',
        'dst_ip': '93.184.216.34',
        'src_port': 54321,
        'dst_port': 80,
        'length': 1500,
        'payload_len': 1460,
        'ttl': 64,
        'tcp_flags': {
            'syn': True,
            'ack': False,
            'fin': False,
            'rst': False,
            'psh': False,
            'urg': False
        }
    }
    
    # Extract features
    extractor = FeatureExtractor()
    features = extractor.extract_all_features(sample_packet)
    
    print("Extracted features:")
    for key, value in features.items():
        print(f"{key}: {value}")
        
    # Create a batch of packets
    packets = []
    for i in range(10):
        packet = sample_packet.copy()
        packet['timestamp'] = (datetime.now() + timedelta(seconds=i)).isoformat()
        packet['length'] = 1000 + i * 100
        packet['tcp_flags']['ack'] = i > 0  # After first packet, set ACK flag
        packets.append(packet)
        
    # Extract flow features
    flow_features = extract_features_for_flow(packets)
    print("\nFlow features:")
    for key, value in flow_features.items():
        print(f"{key}: {value}")
        
    # Convert to DataFrame and preprocess
    df = pd.DataFrame(packets)
    features_df = extract_features_batch(df)
    preprocessed_df = preprocess_features_for_ml(features_df)
    
    print("\nPreprocessed features shape:", preprocessed_df.shape)
    print("Preprocessed features columns:", preprocessed_df.columns.tolist()) 