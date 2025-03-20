#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Intrusion Detection System (IDS) - Main Module
This is the main entry point for the IDS system.
"""

import os
import sys
import logging
import argparse
import yaml
from datetime import datetime

# Add src directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import project modules
from src.data_preprocessing import preprocess
from src.detection import anomaly_detection, signature_detection
from src.network_monitoring import packet_capture
from src.siem_integration import alert_forwarding
from src.utils import config_loader, logger_setup

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Intrusion Detection System')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                        help='Path to configuration file')
    parser.add_argument('--mode', type=str, choices=['train', 'detect', 'analyze'],
                        default='detect', help='Operation mode')
    parser.add_argument('--interface', type=str, help='Network interface to monitor')
    parser.add_argument('--dataset', type=str, help='Path to dataset for training/analysis')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def setup_logging(verbose=False):
    """Configure logging."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f'ids_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    logger = logger_setup.setup_logger('ids', log_file, log_level)
    return logger

def load_configuration(config_path):
    """Load configuration from YAML file."""
    try:
        return config_loader.load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

def train_mode(config, args):
    """Train the anomaly detection model."""
    logger.info("Starting model training...")
    dataset_path = args.dataset or config.get('train', {}).get('dataset')
    if not dataset_path:
        logger.error("No dataset specified for training")
        sys.exit(1)
        
    # Preprocess training data
    processed_data = preprocess.preprocess_data(dataset_path)
    
    # Train anomaly detection model
    model = anomaly_detection.train_model(processed_data)
    
    # Save the trained model
    model_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'models',
        f'anomaly_model_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pkl'
    )
    anomaly_detection.save_model(model, model_path)
    logger.info(f"Model training completed and saved to {model_path}")

def detect_mode(config, args):
    """Run the IDS in detection mode."""
    logger.info("Starting detection mode...")
    
    # Load detection models
    model_path = config.get('detect', {}).get('model_path')
    if not model_path:
        logger.warning("No anomaly detection model specified, using default")
        # Try to find the latest model
        models_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'models'
        )
        model_files = [f for f in os.listdir(models_dir) if f.startswith('anomaly_model_')]
        if model_files:
            model_path = os.path.join(models_dir, sorted(model_files)[-1])
            logger.info(f"Using the latest model: {model_path}")
        else:
            logger.error("No anomaly detection model found")
            sys.exit(1)
            
    # Load anomaly detection model
    model = anomaly_detection.load_model(model_path)
    
    # Load signature rules
    signature_rules = signature_detection.load_rules(
        config.get('detect', {}).get('rules_path', 'config/signature_rules.yaml')
    )
    
    # Set up network interface for packet capture
    interface = args.interface or config.get('detect', {}).get('interface')
    if not interface:
        logger.error("No network interface specified")
        sys.exit(1)
        
    # Start packet capture and analysis
    packet_capture.start_capture(
        interface,
        lambda packet: process_packet(packet, model, signature_rules)
    )

def analyze_mode(config, args):
    """Analyze a dataset for intrusions."""
    logger.info("Starting analysis mode...")
    dataset_path = args.dataset or config.get('analyze', {}).get('dataset')
    if not dataset_path:
        logger.error("No dataset specified for analysis")
        sys.exit(1)
        
    # Preprocess data
    processed_data = preprocess.preprocess_data(dataset_path)
    
    # Load anomaly detection model
    model_path = config.get('analyze', {}).get('model_path')
    model = anomaly_detection.load_model(model_path)
    
    # Perform analysis
    results = anomaly_detection.analyze_data(model, processed_data)
    
    # Generate report
    report_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'logs',
        f'analysis_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    )
    with open(report_path, 'w') as f:
        f.write(results)
    logger.info(f"Analysis completed and report saved to {report_path}")

def process_packet(packet, model, signature_rules):
    """Process a captured packet for intrusion detection."""
    # Extract features from packet
    features = packet_capture.extract_features(packet)
    
    # Check against signature rules
    signature_match = signature_detection.check_signatures(packet, signature_rules)
    if signature_match:
        logger.warning(f"Signature-based detection triggered: {signature_match}")
        alert_forwarding.send_alert('signature', signature_match, packet)
        
    # Check against anomaly detection model
    anomaly_score = anomaly_detection.predict(model, features)
    if anomaly_detection.is_anomaly(anomaly_score):
        logger.warning(f"Anomaly detected with score: {anomaly_score}")
        alert_forwarding.send_alert('anomaly', anomaly_score, packet)

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    global logger
    logger = setup_logging(args.verbose)
    logger.info("Intrusion Detection System starting...")
    
    # Load configuration
    config = load_configuration(args.config)
    
    # Run in specified mode
    if args.mode == 'train':
        train_mode(config, args)
    elif args.mode == 'detect':
        detect_mode(config, args)
    elif args.mode == 'analyze':
        analyze_mode(config, args)
    
    logger.info("Intrusion Detection System shutting down...")

if __name__ == "__main__":
    main()
