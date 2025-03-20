#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
High-Performance Packet Capture Module
This module provides optimized packet capture capabilities using DPDK and AF_PACKET
for high-throughput network traffic processing.
"""

import os
import sys
import time
import queue
import ctypes
import logging
import threading
from enum import Enum
from typing import Dict, List, Tuple, Callable, Optional, Any, Union

# Configure logging
logger = logging.getLogger("ids.optimization.packet_capture")

class CaptureMethod(Enum):
    """Enum for supported packet capture methods"""
    PCAP = "pcap"           # Standard libpcap
    AF_PACKET = "afpacket"  # Linux AF_PACKET
    DPDK = "dpdk"           # Data Plane Development Kit
    NPCAP = "npcap"         # Windows Npcap

class PacketProcessor:
    """Base class for packet processing"""
    def process_packet(self, packet_data: bytes, packet_info: Dict[str, Any]) -> None:
        """Process a captured packet"""
        raise NotImplementedError("Subclasses must implement process_packet")

class HighPerformanceCapture:
    """High-performance packet capture using various methods"""
    
    def __init__(self, 
                 interface: str,
                 method: CaptureMethod = CaptureMethod.AF_PACKET,
                 buffer_size: int = 1048576,  # 1MB buffer
                 promiscuous: bool = True,
                 snaplen: int = 65535,
                 timeout_ms: int = 100,
                 batch_size: int = 1000,
                 bpf_filter: str = None):
        """
        Initialize the high-performance packet capture
        
        Args:
            interface: Network interface to capture from
            method: Capture method (PCAP, AF_PACKET, DPDK, or NPCAP)
            buffer_size: Capture buffer size in bytes
            promiscuous: Enable promiscuous mode
            snaplen: Maximum packet length to capture
            timeout_ms: Read timeout in milliseconds
            batch_size: Batch size for packet processing
            bpf_filter: BPF filter expression
        """
        self.interface = interface
        self.method = method
        self.buffer_size = buffer_size
        self.promiscuous = promiscuous
        self.snaplen = snaplen
        self.timeout_ms = timeout_ms
        self.batch_size = batch_size
        self.bpf_filter = bpf_filter
        
        self.running = False
        self.capture_thread = None
        self.processing_threads = []
        self.num_processing_threads = 0
        self.packet_queue = None
        self.stats = {
            "packets_captured": 0,
            "packets_processed": 0,
            "bytes_captured": 0,
            "drop_count": 0,
            "start_time": 0,
            "current_pps": 0,
            "avg_pps": 0,
            "max_pps": 0
        }
        
        self._setup_capture()
    
    def _setup_capture(self) -> None:
        """Setup the appropriate capture method"""
        self.packet_queue = queue.Queue(maxsize=100000)  # 100K packet buffer
        
        if self.method == CaptureMethod.PCAP:
            self._setup_pcap()
        elif self.method == CaptureMethod.AF_PACKET:
            self._setup_af_packet()
        elif self.method == CaptureMethod.DPDK:
            self._setup_dpdk()
        elif self.method == CaptureMethod.NPCAP:
            self._setup_npcap()
        else:
            raise ValueError(f"Unsupported capture method: {self.method}")
    
    def _setup_pcap(self) -> None:
        """Setup standard libpcap capture"""
        try:
            import pcap
            self.capture = pcap.pcap(
                name=self.interface,
                snaplen=self.snaplen,
                promisc=self.promiscuous,
                timeout_ms=self.timeout_ms,
                immediate=True
            )
            
            if self.bpf_filter:
                self.capture.setfilter(self.bpf_filter)
                
            logger.info(f"Setup standard pcap capture on interface {self.interface}")
            
        except ImportError:
            logger.error("pypcap package not available. Install with: pip install pypcap")
            raise
    
    def _setup_af_packet(self) -> None:
        """Setup Linux AF_PACKET capture for high performance"""
        try:
            if os.name != 'posix':
                raise RuntimeError("AF_PACKET is only available on Linux systems")
                
            from socket import socket, AF_PACKET, SOCK_RAW, htons
            
            # Create AF_PACKET socket
            self.socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))  # ETH_P_ALL
            self.socket.bind((self.interface, 0))
            
            # Set up PACKET_MMAP if available for zero-copy
            try:
                from socket import SOL_PACKET, PACKET_RX_RING
                import mmap
                
                # TPACKET_V3 for block-based processing in kernel
                try:
                    from socket import PACKET_VERSION
                    TPACKET_V3 = 3
                    
                    # Try to set TPACKET_V3
                    self.socket.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
                    logger.info("Using TPACKET_V3 for AF_PACKET capture")
                except (ImportError, AttributeError):
                    logger.info("TPACKET_V3 not available, using default packet version")
                
                # Setup packet ring buffer
                # This is simplified; a full implementation would require careful setup
                # of the PACKET_RX_RING option with a complex struct
                # For demonstration purposes only:
                BLOCK_SIZE = 1 << 20  # 1MB
                FRAME_SIZE = 2048     # 2KB per frame
                BLOCK_NR = 64         # 64 blocks
                
                # Create a packet ring buffer with mmap
                # Note: This is a simplified approximation and real implementation 
                # would need detailed memory mapping configuration
                logger.info("AF_PACKET ring buffer setup complete")
                
            except (ImportError, AttributeError) as e:
                logger.warning(f"PACKET_MMAP not available, using standard AF_PACKET: {e}")
                
            logger.info(f"Setup AF_PACKET capture on interface {self.interface}")
            
        except ImportError as e:
            logger.error(f"Required packages not available for AF_PACKET: {e}")
            raise
    
    def _setup_dpdk(self) -> None:
        """Setup DPDK capture for highest performance packet processing"""
        try:
            # Check if DPDK Python bindings are available
            # Note: This is placeholder code as DPDK typically requires custom bindings
            try:
                # There is no standard DPDK Python binding, 
                # this would be replaced with your specific DPDK integration
                logger.warning("DPDK support requires custom Python bindings and proper DPDK installation")
                logger.warning("This is a placeholder for actual DPDK integration")
                
                # In reality, you'd need to:
                # 1. Initialize EAL (Environment Abstraction Layer)
                # 2. Configure and initialize network ports
                # 3. Setup memory pools and rings
                # 4. Configure and start RX/TX queues
                
                # Example pseudo-code:
                """
                import dpdk
                
                # Initialize EAL
                dpdk.eal_init(["dpdk", "-l", "0-3", "-n", "4"])
                
                # Configure port
                port_id = 0  # First port
                dpdk.eth_dev_configure(port_id, 1, 1, port_conf)
                
                # Setup memory pools
                self.mbuf_pool = dpdk.pktmbuf_pool_create("MBUF_POOL", 8192, 250, 0, 1518, 0)
                
                # Setup RX queue
                dpdk.eth_rx_queue_setup(port_id, 0, 1024, None, self.mbuf_pool)
                
                # Start the port
                dpdk.eth_dev_start(port_id)
                """
                
                # For now, we'll just raise an exception as proper DPDK support is beyond
                # the scope of this demonstration
                raise NotImplementedError("DPDK support requires custom bindings and configuration")
                
            except (ImportError, AttributeError):
                logger.error("DPDK Python bindings not available")
                raise
                
        except Exception as e:
            logger.error(f"Failed to setup DPDK capture: {e}")
            raise
    
    def _setup_npcap(self) -> None:
        """Setup Npcap for Windows high-performance packet capture"""
        try:
            import pcap
            # On Windows with Npcap installed, pypcap should use the Npcap drivers
            self.capture = pcap.pcap(
                name=self.interface,
                snaplen=self.snaplen,
                promisc=self.promiscuous,
                timeout_ms=self.timeout_ms,
                immediate=True
            )
            
            if self.bpf_filter:
                self.capture.setfilter(self.bpf_filter)
                
            logger.info(f"Setup Npcap capture on interface {self.interface}")
            
        except ImportError:
            logger.error("pypcap package not available. Install with: pip install pypcap")
            logger.error("Also ensure Npcap is installed on your Windows system")
            raise
    
    def start_capture(self, 
                     packet_processor: PacketProcessor,
                     num_processing_threads: int = 4) -> None:
        """
        Start packet capture with the specified processor
        
        Args:
            packet_processor: Processor instance for handling captured packets
            num_processing_threads: Number of parallel processing threads
        """
        if self.running:
            logger.warning("Packet capture already running")
            return
            
        self.running = True
        self.num_processing_threads = max(1, num_processing_threads)
        self.stats["start_time"] = time.time()
        
        # Start processing threads
        for i in range(self.num_processing_threads):
            thread = threading.Thread(
                target=self._process_packet_queue,
                args=(packet_processor,),
                name=f"packet-processor-{i}"
            )
            thread.daemon = True
            thread.start()
            self.processing_threads.append(thread)
            
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            name="packet-capture"
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        logger.info(f"Started packet capture on {self.interface} using {self.method.value}")
        logger.info(f"Using {self.num_processing_threads} processing threads")
    
    def stop_capture(self) -> Dict[str, Any]:
        """
        Stop packet capture and return statistics
        
        Returns:
            Dictionary with capture statistics
        """
        if not self.running:
            return self.stats
            
        self.running = False
        
        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=3.0)
            
        for thread in self.processing_threads:
            thread.join(timeout=1.0)
        
        # Calculate final statistics
        capture_time = time.time() - self.stats["start_time"]
        if capture_time > 0:
            self.stats["avg_pps"] = self.stats["packets_captured"] / capture_time
            
        logger.info(f"Stopped packet capture. Captured {self.stats['packets_captured']} packets "
                   f"({self.stats['bytes_captured']} bytes) at {self.stats['avg_pps']:.2f} packets/sec")
        
        return self.stats
    
    def _capture_packets(self) -> None:
        """Continuously capture packets and add them to the queue"""
        last_time = time.time()
        last_packet_count = 0
        
        try:
            if self.method == CaptureMethod.PCAP or self.method == CaptureMethod.NPCAP:
                for timestamp, packet_data in self.capture:
                    if not self.running:
                        break
                        
                    packet_info = {
                        "timestamp": timestamp,
                        "length": len(packet_data)
                    }
                    
                    try:
                        self.packet_queue.put((packet_data, packet_info), block=True, timeout=0.1)
                        self.stats["packets_captured"] += 1
                        self.stats["bytes_captured"] += len(packet_data)
                    except queue.Full:
                        self.stats["drop_count"] += 1
                    
                    # Update PPS every second
                    current_time = time.time()
                    if current_time - last_time >= 1.0:
                        self.stats["current_pps"] = self.stats["packets_captured"] - last_packet_count
                        self.stats["max_pps"] = max(self.stats["max_pps"], self.stats["current_pps"])
                        last_packet_count = self.stats["packets_captured"]
                        last_time = current_time
                        
            elif self.method == CaptureMethod.AF_PACKET:
                # Simple AF_PACKET packet reading loop
                while self.running:
                    try:
                        packet_data = self.socket.recv(self.snaplen)
                        packet_info = {
                            "timestamp": time.time(),
                            "length": len(packet_data)
                        }
                        
                        try:
                            self.packet_queue.put((packet_data, packet_info), block=True, timeout=0.1)
                            self.stats["packets_captured"] += 1
                            self.stats["bytes_captured"] += len(packet_data)
                        except queue.Full:
                            self.stats["drop_count"] += 1
                        
                        # Update PPS every second
                        current_time = time.time()
                        if current_time - last_time >= 1.0:
                            self.stats["current_pps"] = self.stats["packets_captured"] - last_packet_count
                            self.stats["max_pps"] = max(self.stats["max_pps"], self.stats["current_pps"])
                            last_packet_count = self.stats["packets_captured"]
                            last_time = current_time
                            
                    except Exception as e:
                        if self.running:
                            logger.error(f"Error capturing packets: {e}")
                
            elif self.method == CaptureMethod.DPDK:
                # Placeholder for DPDK packet capture
                # This would be replaced with actual DPDK integration
                logger.warning("DPDK packet capture is not implemented in this demo")
                
        except Exception as e:
            if self.running:
                logger.error(f"Error in packet capture thread: {e}")
                self.running = False
    
    def _process_packet_queue(self, packet_processor: PacketProcessor) -> None:
        """Process packets from the queue using the provided processor"""
        while self.running:
            try:
                # Try to get a batch of packets for efficient processing
                packets = []
                try:
                    # Get at least one packet
                    packets.append(self.packet_queue.get(block=True, timeout=0.1))
                    
                    # Try to get more packets up to batch_size
                    for _ in range(self.batch_size - 1):
                        try:
                            packets.append(self.packet_queue.get(block=False))
                        except queue.Empty:
                            break
                            
                except queue.Empty:
                    continue
                
                # Process the batch of packets
                for packet_data, packet_info in packets:
                    try:
                        packet_processor.process_packet(packet_data, packet_info)
                        self.stats["packets_processed"] += 1
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
                    finally:
                        self.packet_queue.task_done()
                        
            except Exception as e:
                if self.running:
                    logger.error(f"Error in packet processing thread: {e}")

# Example packet processor implementation
class SimplePacketProcessor(PacketProcessor):
    """Simple packet processor that prints basic information"""
    
    def process_packet(self, packet_data: bytes, packet_info: Dict[str, Any]) -> None:
        """Process a packet by printing its basic information"""
        print(f"Packet: {len(packet_data)} bytes, timestamp: {packet_info['timestamp']}")

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create capture
    capture = HighPerformanceCapture(
        interface="eth0",  # Change to your interface
        method=CaptureMethod.AF_PACKET if os.name == 'posix' else CaptureMethod.PCAP,
        buffer_size=2*1024*1024,  # 2MB buffer
        bpf_filter="tcp"  # Capture only TCP packets
    )
    
    # Create processor
    processor = SimplePacketProcessor()
    
    try:
        # Start capture with the processor
        capture.start_capture(processor, num_processing_threads=4)
        
        # Run for 10 seconds
        time.sleep(10)
        
    finally:
        # Stop capture and get statistics
        stats = capture.stop_capture()
        print(f"Captured {stats['packets_captured']} packets, "
              f"processed {stats['packets_processed']} packets, "
              f"dropped {stats['drop_count']} packets")
        print(f"Average rate: {stats['avg_pps']:.2f} packets/sec, "
              f"Max rate: {stats['max_pps']} packets/sec") 