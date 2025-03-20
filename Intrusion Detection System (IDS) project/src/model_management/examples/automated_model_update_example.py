#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example script for the Automated Model Updating system.
This example demonstrates how to configure and use the ModelUpdater 
component to automatically update anomaly detection models in an IDS.
"""

import os
import sys
import argparse
import logging
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta
from pathlib import Path

# Add the parent directory to sys.path to allow imports
parent_dir = str(Path(__file__).resolve().parent.parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import model management components
from src.model_management.model_updater import ModelUpdater

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('model_updater_example.log')
    ]
)

logger = logging.getLogger('ids.model_management.examples.automated_update')

def generate_synthetic_data(n_samples=1000, n_features=10, contamination=0.05, drift_factor=0.0):
    """
    Generate synthetic data for anomaly detection.
    
    Args:
        n_samples: Number of samples to generate
        n_features: Number of features
        contamination: Fraction of anomalies
        drift_factor: Factor to introduce data drift (0.0 = no drift, 1.0 = significant drift)
        
    Returns:
        Tuple of (data, labels)
    """
    # Generate normal samples
    n_normal = int(n_samples * (1 - contamination))
    n_anomalies = n_samples - n_normal
    
    # Normal data - tightly clustered
    normal_data = np.random.normal(0, 1, (n_normal, n_features))
    
    # Anomaly data - more spread out and offset
    anomaly_data = np.random.normal(4, 2, (n_anomalies, n_features))
    
    # Add drift if specified
    if drift_factor > 0:
        # Shift the mean for normal data
        normal_data += drift_factor * 2
        
        # Add noise to specific features
        drift_noise = np.random.normal(0, drift_factor * 3, (n_normal, n_features))
        feature_mask = np.random.choice([0, 1], size=n_features, p=[0.7, 0.3])
        normal_data += drift_noise * feature_mask
    
    # Combine the data
    data = np.vstack([normal_data, anomaly_data])
    labels = np.zeros(n_samples)
    labels[n_normal:] = 1  # Anomalies are labeled as 1
    
    # Shuffle the data
    indices = np.arange(n_samples)
    np.random.shuffle(indices)
    data = data[indices]
    labels = labels[indices]
    
    # Convert to DataFrame
    columns = [f'feature_{i}' for i in range(n_features)]
    df = pd.DataFrame(data, columns=columns)
    df['label'] = labels
    
    return df

def simulate_data_source(initial_data=None, drift_interval=3, max_iterations=10):
    """
    Generator function that simulates a data source with gradually increasing drift.
    
    Args:
        initial_data: Initial dataset (will be generated if None)
        drift_interval: How many iterations before introducing drift
        max_iterations: Maximum number of iterations
        
    Yields:
        Tuple of (training_data, validation_data) for each iteration
    """
    if initial_data is None:
        initial_data = generate_synthetic_data(n_samples=2000, n_features=15)
    
    # Split initial data into reference and validation
    reference_indices = np.random.choice(
        np.arange(len(initial_data)), 
        size=int(len(initial_data) * 0.7), 
        replace=False
    )
    validation_indices = np.setdiff1d(np.arange(len(initial_data)), reference_indices)
    
    reference_data = initial_data.iloc[reference_indices].copy()
    validation_data = initial_data.iloc[validation_indices].copy()
    
    current_data = reference_data.copy()
    
    for i in range(max_iterations):
        # Calculate drift factor (0 initially, then gradually increasing)
        if i > 0 and i % drift_interval == 0:
            drift_factor = min(0.8, (i / drift_interval) * 0.2)
            logger.info(f"Iteration {i}: Introducing drift factor of {drift_factor:.2f}")
        else:
            drift_factor = 0.0
            
        # Generate new data with potential drift
        new_data = generate_synthetic_data(
            n_samples=1000, 
            n_features=15, 
            contamination=0.05 + drift_factor * 0.1,  # More anomalies as drift increases
            drift_factor=drift_factor
        )
        
        # Add timestamp to track when the data was generated
        new_data['timestamp'] = datetime.now().isoformat()
        
        # Update current dataset with some history
        current_data = pd.concat([current_data, new_data]).reset_index(drop=True)
        
        # Keep only the most recent data to avoid unbounded growth
        if len(current_data) > 5000:
            current_data = current_data.iloc[-5000:].reset_index(drop=True)
        
        # Generate some validation data with the same drift characteristics
        # but different random samples
        current_validation = generate_synthetic_data(
            n_samples=500, 
            n_features=15, 
            contamination=0.05 + drift_factor * 0.1,
            drift_factor=drift_factor
        )
        current_validation['timestamp'] = datetime.now().isoformat()
        
        # Combine with original validation to keep some consistency
        combined_validation = pd.concat(
            [validation_data.sample(min(200, len(validation_data))), current_validation]
        ).reset_index(drop=True)
        
        yield (current_data.copy(), combined_validation.copy())

def run_model_updater_example(
    experiment_name="ids_anomaly_detection",
    model_name="example_anomaly_detector",
    mlflow_tracking_uri=None,
    metadata_dir="./model_metadata",
    n_iterations=10,
    update_check_interval=1  # in seconds for demo purpose (would be hours in real deployment)
):
    """Run the model updater example."""
    logger.info("Starting automated model update example")
    
    # Ensure the metadata directory exists
    os.makedirs(metadata_dir, exist_ok=True)
    
    # Create the model updater
    model_updater = ModelUpdater(
        experiment_name=experiment_name,
        model_name=model_name,
        mlflow_tracking_uri=mlflow_tracking_uri,
        metadata_dir=metadata_dir,
        update_frequency=1,  # Check every hour (simulated)
        min_samples_for_update=500,
        min_update_interval=1,  # Allow updates after 1 hour (simulated)
        max_update_interval=6,  # Force update after 6 hours (simulated)
        performance_threshold=0.85,
        drift_threshold=0.15,
        confidence_threshold=0.95,
        uncertainty_threshold=0.2,
        config={
            'min_samples_per_class': 50,
            'max_samples_to_label': 500,
            'drift_window_size': 500,
            'min_samples_for_drift': 300
        }
    )
    
    # Initialize a data source
    data_generator = simulate_data_source(
        drift_interval=3,
        max_iterations=n_iterations
    )
    
    # Main simulation loop
    update_count = 0
    drift_detected_count = 0
    
    for i, (train_data, val_data) in enumerate(data_generator):
        logger.info(f"\nIteration {i+1}/{n_iterations}")
        logger.info(f"Training data: {len(train_data)} samples, Validation data: {len(val_data)} samples")
        
        # Record the distribution of labels
        normal_count = (train_data['label'] == 0).sum()
        anomaly_count = (train_data['label'] == 1).sum()
        logger.info(f"Label distribution: {normal_count} normal samples, {anomaly_count} anomalies "
                   f"({anomaly_count/len(train_data)*100:.2f}% contamination)")
        
        # Check if model update is needed
        update_check = model_updater.check_update_needed(train_data)
        logger.info(f"Update needed: {update_check['update_needed']}")
        logger.info(f"Reasons: {update_check['reasons']}")
        
        # Perform update if needed
        if update_check['update_needed']:
            logger.info("Performing model update...")
            update_result = model_updater.update_model(train_data, val_data)
            
            if update_result['success']:
                update_count += 1
                logger.info(f"Update successful! New model version: {update_result['model_version']}")
                logger.info(f"Training samples: {update_result['training_samples']}")
                logger.info(f"Promoted to production: {update_result['promoted_to_production']}")
                
                if 'evaluation_metrics' in update_result and update_result['evaluation_metrics']:
                    logger.info(f"Evaluation metrics: {update_result['evaluation_metrics']}")
                    
                # Check if this was triggered by drift
                if any('drift' in reason.lower() for reason in update_check['reasons']):
                    drift_detected_count += 1
            else:
                logger.error(f"Update failed: {update_result.get('error', 'Unknown error')}")
        
        # Get current status
        status = model_updater.get_status()
        logger.info(f"Current status: Model available: {status['current_model_available']}")
        logger.info(f"Update history count: {status['update_count']}")
        
        # Print a summary of all updates so far
        update_history = model_updater.get_model_update_history()
        if update_history:
            logger.info(f"\nUpdate history summary ({len(update_history)} updates):")
            for idx, update in enumerate(update_history):
                logger.info(f"  {idx+1}. {update['timestamp']} - Version {update['version']} - "
                          f"{update['samples']} samples - "
                          f"Production: {update['promoted_to_production']}")
        
        # Sleep to simulate time passing (would be hours in a real system)
        if i < n_iterations - 1:
            logger.info(f"Waiting {update_check_interval} seconds before next iteration...")
            time.sleep(update_check_interval)
    
    # Print final summary
    logger.info("\n" + "="*50)
    logger.info("AUTOMATED MODEL UPDATE EXAMPLE SUMMARY")
    logger.info("=" * 50)
    logger.info(f"Total iterations: {n_iterations}")
    logger.info(f"Total model updates performed: {update_count}")
    logger.info(f"Updates triggered by drift detection: {drift_detected_count}")
    
    update_history = model_updater.get_model_update_history()
    if update_history:
        latest_metrics = update_history[-1].get('metrics', {})
        logger.info(f"Latest model metrics: {latest_metrics}")
    
    logger.info("=" * 50)
    
    return model_updater

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run automated model update example')
    parser.add_argument('--experiment-name', type=str, default='ids_anomaly_detection',
                        help='MLflow experiment name')
    parser.add_argument('--model-name', type=str, default='example_anomaly_detector',
                        help='Model name')
    parser.add_argument('--tracking-uri', type=str, default=None,
                        help='MLflow tracking URI')
    parser.add_argument('--metadata-dir', type=str, default='./model_metadata',
                        help='Directory to store model metadata')
    parser.add_argument('--iterations', type=int, default=10,
                        help='Number of iterations to run')
    parser.add_argument('--interval', type=int, default=1,
                        help='Time between iterations in seconds')
    
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    # Run the example
    run_model_updater_example(
        experiment_name=args.experiment_name,
        model_name=args.model_name,
        mlflow_tracking_uri=args.tracking_uri,
        metadata_dir=args.metadata_dir,
        n_iterations=args.iterations,
        update_check_interval=args.interval
    ) 