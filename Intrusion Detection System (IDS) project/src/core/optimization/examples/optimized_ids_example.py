#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Optimized IDS Example
This script demonstrates how to integrate high-performance optimizations
into an Intrusion Detection System for real-time detection capabilities.
"""

import os
import sys
import time
import logging
import argparse
import numpy as np
from pathlib import Path

# Add parent directory to path so we can import the optimization modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent.parent))

# Import optimization components
from src.core.optimization import (
    CaptureMethod,
    PacketProcessor,
    HighPerformanceCapture,
    Task,
    Worker,
    ThreadPoolManager,
    AccelerationType,
    ModelFormat,
    AccelerationManager
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ids.optimized_example")

class IDSPacketProcessor(PacketProcessor):
    """Custom packet processor that detects intrusions using ML models"""
    
    def __init__(self, thread_pool, ml_accelerator, detection_threshold=0.5):
        """
        Initialize the IDS packet processor
        
        Args:
            thread_pool: Thread pool for parallel processing
            ml_accelerator: Acceleration manager for ML inference
            detection_threshold: Threshold for detection confidence
        """
        self.thread_pool = thread_pool
        self.ml_accelerator = ml_accelerator
        self.detection_threshold = detection_threshold
        self.packet_counter = 0
        self.alert_counter = 0
        self.feature_extractor = self._create_feature_extractor()
    
    def _create_feature_extractor(self):
        """Create a simple feature extractor"""
        # In a real IDS, this would be a more sophisticated method
        # to extract meaningful features from network packets
        
        def extract_features(packet_data):
            """Extract basic features from a packet"""
            # This is a simplified example - real feature extraction would be more complex
            
            # For demonstration, we'll just use packet length and first few bytes
            # as "features" - real IDS would use much more sophisticated features
            
            features = np.zeros((1, 16), dtype=np.float32)
            
            # Packet length as a feature
            features[0, 0] = len(packet_data)
            
            # First few bytes as features
            for i in range(1, min(16, len(packet_data))):
                features[0, i] = packet_data[i] / 255.0  # Normalize to [0,1]
                
            return features
            
        return extract_features
    
    def process_packet(self, packet_data, packet_info):
        """Process a packet and detect intrusions"""
        # Count the packet
        self.packet_counter += 1
        
        # Extract features from the packet (in a real IDS, this would be more complex)
        features = self.feature_extractor(packet_data)
        
        # Submit the features for ML-based detection
        task = Task(
            task_id=f"packet-{self.packet_counter}",
            data={
                "features": features,
                "packet_info": packet_info
            }
        )
        self.thread_pool.submit_task(task)
        
        # Log progress periodically
        if self.packet_counter % 1000 == 0:
            logger.info(f"Processed {self.packet_counter} packets, generated {self.alert_counter} alerts")

class IDSDetectionWorker(Worker):
    """Worker that performs intrusion detection using ML inference"""
    
    def __init__(self, ml_accelerator, detection_threshold=0.5, alert_callback=None):
        """
        Initialize the detection worker
        
        Args:
            ml_accelerator: Acceleration manager for ML inference
            detection_threshold: Threshold for detection confidence
            alert_callback: Callback function for handling alerts
        """
        self.ml_accelerator = ml_accelerator
        self.detection_threshold = detection_threshold
        self.alert_callback = alert_callback or self._default_alert_handler
        self.alert_counter = 0
    
    def process_task(self, task):
        """Process a task by running ML inference on packet features"""
        # Get the features and packet info
        features = task.data["features"]
        packet_info = task.data["packet_info"]
        
        # Run ML inference
        inputs = {"input": features}
        outputs = self.ml_accelerator.infer(inputs)
        
        # In this example, we assume the model outputs detection probabilities
        # for different attack classes (e.g., ["normal", "dos", "scan", "r2l", "u2r"])
        detection_result = next(iter(outputs.values()))
        
        # Get the predicted class and confidence
        # For simplicity, we assume a binary classification (normal vs. attack)
        attack_probability = detection_result[0][1] if detection_result.shape[1] > 1 else detection_result[0][0]
        
        # Check if it's an attack
        is_attack = attack_probability > self.detection_threshold
        
        if is_attack:
            # Generate an alert
            alert = {
                "timestamp": packet_info["timestamp"],
                "source": "ML-based IDS",
                "confidence": float(attack_probability),
                "packet_info": packet_info,
                "description": f"Potential intrusion detected with {attack_probability:.4f} confidence"
            }
            
            # Handle the alert
            self.alert_callback(alert)
            self.alert_counter += 1
        
        # Store the result in the task
        task.result = {
            "is_attack": is_attack,
            "confidence": float(attack_probability)
        }
    
    def _default_alert_handler(self, alert):
        """Default handler for alerts"""
        logger.warning(f"ALERT: {alert['description']} (confidence: {alert['confidence']:.4f})")

def run_optimized_ids(interface, model_path, duration=60):
    """
    Run an optimized IDS with high-performance components
    
    Args:
        interface: Network interface to monitor
        model_path: Path to the ML model file
        duration: Duration to run in seconds
    """
    logger.info(f"Starting optimized IDS on interface {interface}")
    logger.info(f"Using model: {model_path}")
    
    # 1. Set up GPU acceleration for ML model
    logger.info("Initializing ML acceleration...")
    try:
        # Try to use GPU acceleration if available
        model_format = ModelFormat.ONNX  # Assuming ONNX model
        
        # Check if CUDA is available
        import torch
        if torch.cuda.is_available():
            acceleration_type = AccelerationType.ONNX_CUDA
            logger.info("Using CUDA acceleration for ML inference")
        else:
            acceleration_type = AccelerationType.ONNX_CPU
            logger.info("Using CPU for ML inference (CUDA not available)")
            
    except ImportError:
        # Fall back to CPU if PyTorch/CUDA not available
        acceleration_type = AccelerationType.ONNX_CPU
        logger.info("Using CPU for ML inference (PyTorch not available)")
    
    # Create acceleration manager
    ml_accelerator = AccelerationManager(
        model_path=model_path,
        model_format=model_format,
        acceleration_type=acceleration_type,
        batch_size=1
    )
    
    # Load and optimize the model
    if not ml_accelerator.load_model():
        logger.error("Failed to load ML model. Exiting.")
        return
    
    # 2. Set up parallel processing
    logger.info("Initializing parallel processing...")
    thread_pool = ThreadPoolManager(num_workers=os.cpu_count())
    
    # 3. Create packet processor and detection worker
    packet_processor = IDSPacketProcessor(
        thread_pool=thread_pool,
        ml_accelerator=ml_accelerator,
        detection_threshold=0.7
    )
    
    detection_worker = IDSDetectionWorker(
        ml_accelerator=ml_accelerator,
        detection_threshold=0.7
    )
    
    # Start the thread pool
    thread_pool.start(detection_worker)
    
    # 4. Set up high-performance packet capture
    logger.info("Initializing high-performance packet capture...")
    
    # Choose appropriate capture method based on OS
    if os.name == 'posix':
        # Linux - use AF_PACKET if possible
        capture_method = CaptureMethod.AF_PACKET
    else:
        # Windows/Others - use regular pcap/npcap
        capture_method = CaptureMethod.PCAP if os.name != 'nt' else CaptureMethod.NPCAP
        
    logger.info(f"Using {capture_method.value} for packet capture")
    
    # Create and start the packet capture
    capture = HighPerformanceCapture(
        interface=interface,
        method=capture_method,
        buffer_size=16 * 1024 * 1024,  # 16MB buffer
        bpf_filter="ip"  # Capture only IP packets
    )
    
    # 5. Run the IDS
    try:
        logger.info(f"Starting IDS for {duration} seconds...")
        
        # Start packet capture
        capture.start_capture(packet_processor, num_processing_threads=2)
        
        # Run for specified duration
        start_time = time.time()
        while time.time() - start_time < duration:
            # Display periodic stats
            pps = capture.stats.get("current_pps", 0)
            packets_captured = capture.stats.get("packets_captured", 0)
            packets_processed = capture.stats.get("packets_processed", 0)
            drop_count = capture.stats.get("drop_count", 0)
            
            logger.info(f"Stats: {pps} packets/sec, "
                       f"total: {packets_captured}, "
                       f"processed: {packets_processed}, "
                       f"dropped: {drop_count}, "
                       f"alerts: {detection_worker.alert_counter}")
            
            # Short sleep to prevent CPU spinning
            time.sleep(1)
            
    finally:
        # 6. Cleanup
        logger.info("Stopping IDS...")
        
        # Stop packet capture
        capture_stats = capture.stop_capture()
        
        # Stop thread pool
        thread_pool_stats = thread_pool.stop()
        
        # Log final statistics
        logger.info(f"Capture stats: {capture_stats}")
        logger.info(f"Thread pool stats: {thread_pool_stats}")
        logger.info(f"ML inference stats: {ml_accelerator.get_stats()}")
        logger.info(f"Total alerts: {detection_worker.alert_counter}")
        
        logger.info("IDS stopped successfully")

def main():
    """Main entry point for the example"""
    parser = argparse.ArgumentParser(description="Run an optimized IDS")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to monitor")
    parser.add_argument("-m", "--model", required=True, help="Path to ML model file (ONNX format)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration to run in seconds")
    
    args = parser.parse_args()
    
    # Run the optimized IDS
    run_optimized_ids(args.interface, args.model, args.duration)

if __name__ == "__main__":
    main() 