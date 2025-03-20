#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Automated Model Updater for Anomaly Detection
Coordinates the active learning, drift detection, and MLflow components to provide 
automated model updating for the IDS anomaly detection system.
"""

import os
import sys
import json
import time
import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional, Union, Set
from datetime import datetime, timedelta
import traceback
from pathlib import Path

# Import model management components
from src.model_management.active_learning import ActiveLearningSystem
from src.model_management.drift_detection import DriftDetector, evaluate_anomaly_detector
from src.model_management.mlflow_integration import MLflowModelManager

# Setup logging
logger = logging.getLogger('ids.model_management.model_updater')

class ModelUpdater:
    """
    Coordinates automated model updating for anomaly detection models.
    This class brings together active learning, drift detection, and model management
    to provide a complete pipeline for automatic model maintenance.
    """
    
    def __init__(
        self,
        experiment_name: str = "anomaly_detection",
        model_name: str = "ids_anomaly_detector",
        mlflow_tracking_uri: Optional[str] = None,
        update_frequency: int = 24,  # hours
        min_samples_for_update: int = 1000,
        min_update_interval: int = 12,  # hours
        max_update_interval: int = 168,  # hours (1 week)
        performance_threshold: float = 0.85,
        drift_threshold: float = 0.15,
        confidence_threshold: float = 0.95,
        uncertainty_threshold: float = 0.2,
        metadata_dir: Optional[str] = None,
        config: Dict[str, Any] = None
    ):
        """
        Initialize the model updater.
        
        Args:
            experiment_name: Name of the MLflow experiment
            model_name: Name of the model to manage
            mlflow_tracking_uri: URI for MLflow tracking server
            update_frequency: How often to check for updates (hours)
            min_samples_for_update: Minimum number of samples needed for retraining
            min_update_interval: Minimum time between model updates (hours)
            max_update_interval: Maximum time between model updates (hours)
            performance_threshold: Minimum acceptable model performance
            drift_threshold: Threshold for data drift to trigger retraining
            confidence_threshold: Confidence threshold for active learning
            uncertainty_threshold: Uncertainty threshold for active learning
            metadata_dir: Directory to store model metadata
            config: Additional configuration options
        """
        self.experiment_name = experiment_name
        self.model_name = model_name
        self.update_frequency = update_frequency
        self.min_samples_for_update = min_samples_for_update
        self.min_update_interval = min_update_interval
        self.max_update_interval = max_update_interval
        self.performance_threshold = performance_threshold
        self.drift_threshold = drift_threshold
        self.confidence_threshold = confidence_threshold
        self.uncertainty_threshold = uncertainty_threshold
        
        # Initialize metadata directory
        if metadata_dir is None:
            # Default to a directory in the user's home
            home_dir = Path.home()
            metadata_dir = str(home_dir / ".ids" / "model_metadata")
        
        self.metadata_dir = metadata_dir
        os.makedirs(self.metadata_dir, exist_ok=True)
        
        # Store additional config
        self.config = config or {}
        
        # Initialize components
        self.mlflow_manager = MLflowModelManager(
            experiment_name=experiment_name,
            model_name=model_name,
            tracking_uri=mlflow_tracking_uri
        )
        
        # These will be initialized when needed
        self.active_learning = None
        self.drift_detector = None
        self.current_model = None
        self.last_update_time = None
        self.update_in_progress = False
        self.update_history = []
        
        # Load existing metadata if available
        self._load_metadata()
        
    def _load_metadata(self) -> None:
        """Load model updater metadata from disk."""
        metadata_file = os.path.join(self.metadata_dir, f"{self.model_name}_metadata.json")
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                # Load relevant fields
                self.last_update_time = metadata.get('last_update_time')
                self.update_history = metadata.get('update_history', [])
                
                logger.info(f"Loaded metadata for {self.model_name}. "
                           f"Last update: {self.last_update_time}")
            except Exception as e:
                logger.error(f"Error loading metadata: {e}")
        else:
            logger.info(f"No existing metadata found for {self.model_name}")
    
    def _save_metadata(self) -> None:
        """Save model updater metadata to disk."""
        metadata_file = os.path.join(self.metadata_dir, f"{self.model_name}_metadata.json")
        
        metadata = {
            'model_name': self.model_name,
            'last_update_time': self.last_update_time,
            'update_history': self.update_history,
            'config': {
                'update_frequency': self.update_frequency,
                'min_samples_for_update': self.min_samples_for_update,
                'min_update_interval': self.min_update_interval,
                'max_update_interval': self.max_update_interval,
                'performance_threshold': self.performance_threshold,
                'drift_threshold': self.drift_threshold
            }
        }
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.debug(f"Saved metadata for {self.model_name}")
        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
    
    def initialize_components(
        self, 
        model=None, 
        reference_data=None,
        retrain=False
    ) -> None:
        """
        Initialize or update the model management components.
        
        Args:
            model: The anomaly detection model to use (None to load from MLflow)
            reference_data: Reference data for drift detection (None to load from storage)
            retrain: Whether to force retraining the model
        """
        # Load the current production model if not provided
        if model is None and not retrain:
            try:
                model_uri, model_info = self.mlflow_manager.get_best_model(
                    metric_name="roc_auc",
                    stage="Production"
                )
                if model_uri:
                    model = self.mlflow_manager.load_model(model_uri)
                    logger.info(f"Loaded production model: {model_uri}")
                else:
                    logger.warning("No production model found. Will need to train a new one.")
                    retrain = True
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                retrain = True
        
        self.current_model = model
        
        # Initialize active learning system
        if self.active_learning is None:
            self.active_learning = ActiveLearningSystem(
                base_model=model,
                confidence_threshold=self.confidence_threshold,
                uncertainty_threshold=self.uncertainty_threshold,
                min_samples_per_class=self.config.get('min_samples_per_class', 50),
                max_samples_to_label=self.config.get('max_samples_to_label', 500)
            )
            logger.info("Initialized active learning system")
        elif model is not None:
            # Update the model in active learning
            self.active_learning.base_model = model
            logger.info("Updated model in active learning system")
        
        # Initialize or update drift detector
        if reference_data is not None:
            if self.drift_detector is None:
                self.drift_detector = DriftDetector(
                    reference_data=reference_data,
                    model_evaluator=evaluate_anomaly_detector,
                    performance_threshold=self.performance_threshold,
                    drift_threshold=self.drift_threshold,
                    window_size=self.config.get('drift_window_size', 1000),
                    min_samples_for_drift=self.config.get('min_samples_for_drift', 500)
                )
                logger.info(f"Initialized drift detector with {len(reference_data)} reference samples")
            else:
                # Reset with new reference data after retraining
                self.drift_detector.reset_baseline(reference_data)
                logger.info(f"Reset drift detector with {len(reference_data)} reference samples")
    
    def check_update_needed(self, current_data, current_labels=None) -> Dict[str, Any]:
        """
        Check if a model update is needed based on time elapsed, drift detected,
        or performance degradation.
        
        Args:
            current_data: Current data to evaluate
            current_labels: Ground truth labels if available
            
        Returns:
            Dict with update decision and reasons
        """
        result = {
            'update_needed': False,
            'reasons': [],
            'metrics': {}
        }
        
        # Skip if update is already in progress
        if self.update_in_progress:
            result['reasons'].append("Update already in progress")
            return result
        
        # Initialize components if needed
        if self.current_model is None:
            self.initialize_components()
            if self.current_model is None:
                result['update_needed'] = True
                result['reasons'].append("No current model available")
                return result
        
        # Check time-based criteria
        now = datetime.now()
        if self.last_update_time is None:
            result['update_needed'] = True
            result['reasons'].append("Initial model training needed")
        else:
            # Convert string timestamp to datetime if needed
            if isinstance(self.last_update_time, str):
                self.last_update_time = datetime.fromisoformat(self.last_update_time)
            
            # Check if max interval has elapsed
            hours_since_update = (now - self.last_update_time).total_seconds() / 3600
            result['metrics']['hours_since_update'] = hours_since_update
            
            if hours_since_update >= self.max_update_interval:
                result['update_needed'] = True
                result['reasons'].append(f"Maximum update interval exceeded: {hours_since_update:.1f} hours")
        
        # Check drift if we have enough data
        if self.drift_detector and len(current_data) >= self.drift_detector.min_samples_for_drift:
            try:
                drift_result = self.drift_detector.update(current_data, current_labels)
                result['metrics'].update(drift_result)
                
                if drift_result.get('drift_detected', False):
                    # Only trigger update if minimum interval has elapsed
                    if (self.last_update_time is None or 
                            hours_since_update >= self.min_update_interval):
                        result['update_needed'] = True
                        result['reasons'].append(
                            f"Data drift detected: {drift_result.get('drift_score', 0):.4f} > "
                            f"{self.drift_threshold}"
                        )
                
                if drift_result.get('performance_degraded', False):
                    # Performance issues should always trigger an update
                    result['update_needed'] = True
                    result['reasons'].append(
                        f"Performance degradation detected: "
                        f"{drift_result.get('current_performance', 0):.4f} < "
                        f"{self.performance_threshold}"
                    )
            except Exception as e:
                logger.error(f"Error checking drift: {e}")
                logger.debug(traceback.format_exc())
        
        # Sample size check
        result['metrics']['available_samples'] = len(current_data)
        if len(current_data) < self.min_samples_for_update and not result['update_needed']:
            result['reasons'].append(
                f"Insufficient samples for update: {len(current_data)} < "
                f"{self.min_samples_for_update}"
            )
        
        return result
    
    def update_model(
        self, 
        training_data, 
        validation_data=None,
        model_params=None,
        force=False
    ) -> Dict[str, Any]:
        """
        Perform a model update with new data.
        
        Args:
            training_data: DataFrame with training data
            validation_data: Optional validation data for evaluation
            model_params: Parameters for model training
            force: Whether to force an update regardless of criteria
            
        Returns:
            Dictionary with update results
        """
        if self.update_in_progress and not force:
            logger.warning("Model update already in progress")
            return {'success': False, 'error': 'Update already in progress'}
        
        self.update_in_progress = True
        start_time = time.time()
        
        try:
            # Start an MLflow run for this update
            run_name = f"model_update_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.mlflow_manager.start_run(run_name=run_name)
            
            # Log the input data profile
            self.mlflow_manager.log_data_profile(training_data, profile_name="training_data")
            if validation_data is not None:
                self.mlflow_manager.log_data_profile(validation_data, profile_name="validation_data")
            
            # Process data through active learning if we have enough data
            if self.active_learning and len(training_data) >= self.min_samples_for_update:
                # Get and log metrics from active learning system
                al_metrics = self.active_learning.get_metrics()
                self.mlflow_manager.log_metrics(
                    {f"active_learning_{k}": v for k, v in al_metrics.items()}
                )
                
                # Get balanced training data
                balanced_data = self.active_learning.get_training_data(training_data)
                logger.info(f"Prepared {len(balanced_data)} samples for training "
                           f"({len(training_data)} original samples)")
                
                # Log the balanced data profile
                self.mlflow_manager.log_data_profile(balanced_data, profile_name="balanced_training_data")
                
                training_data = balanced_data
            
            # Select or create model
            from sklearn.ensemble import IsolationForest
            
            # Get default parameters if none provided
            if model_params is None:
                model_params = {
                    'n_estimators': 100,
                    'max_samples': 'auto',
                    'contamination': 'auto',
                    'random_state': 42
                }
            
            # Log parameters
            self.mlflow_manager.log_params(model_params)
            
            # Train the model
            logger.info("Training new model...")
            model = IsolationForest(**model_params)
            model.fit(training_data)
            
            # Evaluate on validation data if available
            if validation_data is not None and 'label' in validation_data.columns:
                # Use our evaluator function
                evaluation_metrics = evaluate_anomaly_detector(
                    model=model,
                    data=validation_data,
                    true_labels=validation_data['label'],
                    score_column='anomaly_score'
                )
                
                # Log metrics
                self.mlflow_manager.log_metrics(evaluation_metrics)
                
                logger.info(f"Model evaluation: "
                           f"ROC AUC = {evaluation_metrics.get('roc_auc', 0):.4f}, "
                           f"PR AUC = {evaluation_metrics.get('pr_auc', 0):.4f}")
            
            # Log and register the model
            model_uri = self.mlflow_manager.log_model(model)
            
            # Create tags for the model version
            model_tags = {
                'training_samples': str(len(training_data)),
                'update_trigger': ','.join(self.check_update_needed(training_data).get('reasons', [])),
                'update_timestamp': datetime.now().isoformat()
            }
            
            # Register the model
            model_details = self.mlflow_manager.register_model(model_uri, tags=model_tags)
            logger.info(f"Registered model as version {model_details.version}")
            
            # Promote to production if evaluation is good
            promote_to_prod = force  # Force will always promote
            if validation_data is not None and 'label' in validation_data.columns:
                if evaluation_metrics.get('roc_auc', 0) >= self.performance_threshold:
                    promote_to_prod = True
            
            if promote_to_prod:
                self.mlflow_manager.promote_model(
                    version=model_details.version,
                    stage="Production"
                )
                logger.info(f"Promoted model version {model_details.version} to Production")
            else:
                self.mlflow_manager.promote_model(
                    version=model_details.version,
                    stage="Staging"
                )
                logger.info(f"Promoted model version {model_details.version} to Staging "
                           f"(did not meet threshold for Production)")
            
            # Update our current model
            self.current_model = model
            
            # Reset the drift detector with the new data as reference
            if self.drift_detector:
                self.drift_detector.reset_baseline(training_data)
            
            # Update the active learning system
            if self.active_learning:
                self.active_learning.base_model = model
            
            # Update metadata
            self.last_update_time = datetime.now().isoformat()
            self.update_history.append({
                'timestamp': self.last_update_time,
                'version': model_details.version,
                'samples': len(training_data),
                'metrics': evaluation_metrics if validation_data is not None else {},
                'promoted_to_production': promote_to_prod
            })
            self._save_metadata()
            
            # End the MLflow run
            self.mlflow_manager.end_run()
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            
            result = {
                'success': True,
                'model_version': model_details.version,
                'training_samples': len(training_data),
                'elapsed_time': elapsed_time,
                'evaluation_metrics': evaluation_metrics if validation_data is not None else {},
                'promoted_to_production': promote_to_prod
            }
            
            logger.info(f"Model update completed in {elapsed_time:.2f} seconds")
            return result
            
        except Exception as e:
            logger.error(f"Error during model update: {e}")
            logger.debug(traceback.format_exc())
            
            # End the MLflow run if active
            if self.mlflow_manager.active_run:
                self.mlflow_manager.end_run()
                
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
        finally:
            self.update_in_progress = False
    
    def schedule_updates(self, data_source=None, scheduler=None) -> None:
        """
        Schedule automatic model updates at regular intervals.
        
        Args:
            data_source: Function or object that provides data for updates
            scheduler: Scheduler to use (None for simple threading)
        """
        if scheduler is None:
            import threading
            
            def update_job():
                while True:
                    try:
                        logger.info("Checking for model updates...")
                        
                        # Get data from source
                        if data_source is not None:
                            if callable(data_source):
                                train_data, val_data = data_source()
                            else:
                                train_data = data_source.get_training_data()
                                val_data = data_source.get_validation_data()
                                
                            # Check if update is needed
                            update_check = self.check_update_needed(train_data)
                            
                            if update_check['update_needed']:
                                logger.info(f"Model update needed. Reasons: {update_check['reasons']}")
                                self.update_model(train_data, val_data)
                            else:
                                logger.info(f"No model update needed: {update_check['reasons']}")
                        
                    except Exception as e:
                        logger.error(f"Error in update job: {e}")
                        logger.debug(traceback.format_exc())
                    
                    # Sleep until next check
                    time.sleep(self.update_frequency * 3600)  # Convert hours to seconds
            
            # Start the update thread
            update_thread = threading.Thread(target=update_job, daemon=True)
            update_thread.start()
            logger.info(f"Started model update scheduler with frequency of {self.update_frequency} hours")
        else:
            # Use the provided scheduler
            scheduler.add_job(
                self.check_and_update,
                'interval',
                hours=self.update_frequency,
                args=[data_source]
            )
            logger.info(f"Scheduled model updates with frequency of {self.update_frequency} hours")
    
    def check_and_update(self, data_source) -> Dict[str, Any]:
        """
        Check if an update is needed and perform it if so.
        
        Args:
            data_source: Function or object that provides data for updates
            
        Returns:
            Dictionary with check and update results
        """
        try:
            # Get data from source
            if callable(data_source):
                train_data, val_data = data_source()
            else:
                train_data = data_source.get_training_data()
                val_data = data_source.get_validation_data()
                
            # Check if update is needed
            update_check = self.check_update_needed(train_data)
            
            if update_check['update_needed']:
                logger.info(f"Model update needed. Reasons: {update_check['reasons']}")
                update_result = self.update_model(train_data, val_data)
                return {
                    'check_result': update_check,
                    'update_performed': True,
                    'update_result': update_result
                }
            else:
                logger.info(f"No model update needed: {update_check['reasons']}")
                return {
                    'check_result': update_check,
                    'update_performed': False
                }
        except Exception as e:
            logger.error(f"Error in check_and_update: {e}")
            logger.debug(traceback.format_exc())
            return {
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    def get_model_update_history(self) -> List[Dict[str, Any]]:
        """
        Get the history of model updates.
        
        Returns:
            List of update history entries
        """
        return self.update_history
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the model updater.
        
        Returns:
            Dictionary with status information
        """
        return {
            'model_name': self.model_name,
            'last_update_time': self.last_update_time,
            'update_in_progress': self.update_in_progress,
            'update_count': len(self.update_history),
            'current_model_available': self.current_model is not None,
            'drift_detector_initialized': self.drift_detector is not None,
            'active_learning_initialized': self.active_learning is not None,
            'configuration': {
                'update_frequency': self.update_frequency,
                'min_samples_for_update': self.min_samples_for_update,
                'min_update_interval': self.min_update_interval,
                'max_update_interval': self.max_update_interval,
                'performance_threshold': self.performance_threshold,
                'drift_threshold': self.drift_threshold
            }
        } 