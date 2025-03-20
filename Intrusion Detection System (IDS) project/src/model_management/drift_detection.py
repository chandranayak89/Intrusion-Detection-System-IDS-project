#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Drift Detection Module for Anomaly Detection
Implements methods for detecting data and concept drift in anomaly detection models.
"""

import os
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Union, Callable
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc
from scipy.stats import ks_2samp, wasserstein_distance

# Setup logging
logger = logging.getLogger('ids.model_management.drift_detection')

class DriftDetector:
    """
    Drift Detector for monitoring data and concept drift in anomaly detection models.
    """
    
    def __init__(
        self,
        reference_data: pd.DataFrame,
        model_evaluator: Callable,
        features: List[str],
        performance_threshold: float = 0.7,
        drift_threshold: float = 0.1,
        window_size: int = 1000,
        min_samples_for_drift: int = 100
    ):
        """
        Initialize the drift detector.
        
        Args:
            reference_data: Reference data representing the original distribution
            model_evaluator: Function to evaluate model performance (returns score)
            features: List of feature names to monitor for drift
            performance_threshold: Threshold below which performance is considered degraded
            drift_threshold: Threshold for drift detection
            window_size: Size of sliding window for drift detection
            min_samples_for_drift: Minimum samples needed for drift assessment
        """
        self.reference_data = reference_data
        self.model_evaluator = model_evaluator
        self.features = features
        self.performance_threshold = performance_threshold
        self.drift_threshold = drift_threshold
        self.window_size = window_size
        self.min_samples_for_drift = min_samples_for_drift
        
        # Historical data for drift detection
        self.current_window = pd.DataFrame()
        
        # Reference distributions for each feature
        self.reference_distributions = self._compute_distributions(reference_data)
        
        # Performance tracking
        self.baseline_performance = None
        self.current_performance = None
        
        # Drift tracking
        self.drift_scores = {}
        self.performance_history = []
        self.last_drift_time = None
        self.drift_detected_features = set()
    
    def update(self, new_data: pd.DataFrame, labels: Optional[pd.Series] = None) -> Dict[str, Any]:
        """
        Update the drift detector with new data.
        
        Args:
            new_data: New data samples
            labels: Optional ground truth labels if available
            
        Returns:
            Dictionary with drift detection results
        """
        if new_data.empty:
            return {"drift_detected": False, "drift_score": 0, "performance_degradation": False}
        
        # Update sliding window
        self.current_window = pd.concat([self.current_window, new_data]).iloc[-self.window_size:]
        
        # Check if we have enough data
        if len(self.current_window) < self.min_samples_for_drift:
            return {"drift_detected": False, "drift_score": 0, "performance_degradation": False}
        
        # Compute current distributions
        current_distributions = self._compute_distributions(self.current_window)
        
        # Compute drift scores
        drift_scores = self._compute_drift_scores(current_distributions)
        self.drift_scores = drift_scores
        
        # Update performance if labels are available
        performance_degradation = False
        if labels is not None and not labels.empty:
            performance = self.model_evaluator(self.current_window, labels)
            self.current_performance = performance
            self.performance_history.append((datetime.now(), performance))
            
            # Keep only recent history
            if len(self.performance_history) > 20:
                self.performance_history = self.performance_history[-20:]
            
            # Set baseline if not already set
            if self.baseline_performance is None:
                self.baseline_performance = performance
            
            # Check for performance degradation
            performance_degradation = (performance < self.baseline_performance - self.drift_threshold)
        
        # Determine overall drift
        max_feature_drift = max(drift_scores.values())
        drift_detected = max_feature_drift > self.drift_threshold
        
        # Record drifted features
        self.drift_detected_features = {
            feature for feature, score in drift_scores.items() 
            if score > self.drift_threshold
        }
        
        # Record drift detection time
        if drift_detected or performance_degradation:
            self.last_drift_time = datetime.now()
        
        result = {
            "drift_detected": drift_detected,
            "drift_score": max_feature_drift,
            "performance_degradation": performance_degradation,
            "drifted_features": self.drift_detected_features,
            "feature_drift_scores": drift_scores,
            "current_performance": self.current_performance,
            "baseline_performance": self.baseline_performance,
            "last_drift_time": self.last_drift_time
        }
        
        logger.info(f"Drift detection result: Drift detected: {drift_detected}, "
                   f"Max drift score: {max_feature_drift:.4f}, "
                   f"Performance degradation: {performance_degradation}")
        
        return result
    
    def should_retrain(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Determine if model retraining is needed based on drift detection.
        
        Returns:
            Tuple of (should_retrain, reasons_dict)
        """
        if not self.drift_scores:
            return False, {"reason": "No drift information available"}
        
        # Reasons for retraining
        reasons = {}
        
        # Check if drift has been detected
        drift_detected = any(score > self.drift_threshold for score in self.drift_scores.values())
        if drift_detected:
            reasons["drift_detected"] = True
            reasons["drifted_features"] = [
                feature for feature, score in self.drift_scores.items()
                if score > self.drift_threshold
            ]
        
        # Check for performance degradation
        if self.current_performance is not None and self.baseline_performance is not None:
            performance_drop = self.baseline_performance - self.current_performance
            if performance_drop > self.drift_threshold:
                reasons["performance_degradation"] = True
                reasons["performance_drop"] = performance_drop
                reasons["current_performance"] = self.current_performance
                reasons["baseline_performance"] = self.baseline_performance
        
        # Decision to retrain
        should_retrain = len(reasons) > 0
        
        if should_retrain:
            reasons["timestamp"] = datetime.now()
        
        return should_retrain, reasons
    
    def reset_baseline(self, new_reference_data: Optional[pd.DataFrame] = None) -> None:
        """
        Reset the baseline after retraining a model.
        
        Args:
            new_reference_data: New reference data to use (if None, use current window)
        """
        # Use new reference data if provided, otherwise use current window
        if new_reference_data is not None and not new_reference_data.empty:
            self.reference_data = new_reference_data
        else:
            self.reference_data = self.current_window.copy()
        
        # Recompute reference distributions
        self.reference_distributions = self._compute_distributions(self.reference_data)
        
        # Reset drift metrics
        self.drift_scores = {}
        self.drift_detected_features = set()
        self.last_drift_time = None
        
        # Keep current performance as new baseline if available
        if self.current_performance is not None:
            self.baseline_performance = self.current_performance
        
        logger.info("Drift detector baseline has been reset")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get drift detection metrics.
        
        Returns:
            Dictionary of drift metrics
        """
        metrics = {
            "drift_scores": self.drift_scores,
            "drifted_features": list(self.drift_detected_features),
            "last_drift_time": self.last_drift_time,
            "baseline_performance": self.baseline_performance,
            "current_performance": self.current_performance,
            "window_size": len(self.current_window),
            "reference_size": len(self.reference_data)
        }
        
        # Calculate performance trend if history available
        if len(self.performance_history) >= 2:
            earliest_perf = self.performance_history[0][1]
            latest_perf = self.performance_history[-1][1]
            metrics["performance_trend"] = latest_perf - earliest_perf
        
        return metrics
    
    def _compute_distributions(self, data: pd.DataFrame) -> Dict[str, np.ndarray]:
        """
        Compute distributions for each feature in the data.
        
        Args:
            data: DataFrame containing feature data
            
        Returns:
            Dictionary mapping feature names to distribution arrays
        """
        distributions = {}
        
        for feature in self.features:
            if feature in data.columns:
                # Get feature values
                values = data[feature].dropna().values
                
                if len(values) > 0:
                    # Store sorted values as distribution
                    distributions[feature] = np.sort(values)
        
        return distributions
    
    def _compute_drift_scores(self, current_distributions: Dict[str, np.ndarray]) -> Dict[str, float]:
        """
        Compute drift scores between reference and current distributions.
        
        Args:
            current_distributions: Current feature distributions
            
        Returns:
            Dictionary mapping feature names to drift scores
        """
        drift_scores = {}
        
        for feature in self.features:
            if (feature in self.reference_distributions and 
                feature in current_distributions):
                
                ref_dist = self.reference_distributions[feature]
                curr_dist = current_distributions[feature]
                
                if len(ref_dist) > 0 and len(curr_dist) > 0:
                    # Compute KS test statistic
                    try:
                        ks_stat, _ = ks_2samp(ref_dist, curr_dist)
                        drift_scores[feature] = ks_stat
                    except Exception as e:
                        logger.warning(f"Error computing KS statistic for {feature}: {e}")
                        # Fallback to Wasserstein distance (Earth Mover's Distance)
                        try:
                            w_dist = wasserstein_distance(ref_dist, curr_dist)
                            # Normalize to [0,1] scale approximately
                            feature_range = max(np.max(ref_dist) - np.min(ref_dist), 1e-10)
                            drift_scores[feature] = min(1.0, w_dist / feature_range)
                        except Exception as e2:
                            logger.error(f"Error computing drift for {feature}: {e2}")
                            drift_scores[feature] = 0.0
        
        return drift_scores


def evaluate_anomaly_detector(
    model, data: pd.DataFrame, true_labels: pd.Series, 
    score_column: str = 'anomaly_score', 
    label_column: str = 'is_anomaly'
) -> float:
    """
    Evaluate an anomaly detection model's performance.
    
    Args:
        model: Anomaly detection model
        data: Data to evaluate
        true_labels: Ground truth labels
        score_column: Column with anomaly scores
        label_column: Column with true labels
        
    Returns:
        Performance score (AUC)
    """
    if len(data) == 0 or len(true_labels) == 0:
        return 0.0
    
    # If data already has scores, use them
    if score_column in data.columns:
        scores = data[score_column].values
    else:
        # Otherwise compute scores using the model
        feature_cols = [col for col in data.columns 
                      if col not in [score_column, label_column]]
        scores = model.predict(data[feature_cols])
    
    # Convert labels to binary format if needed
    y_true = true_labels.astype(int).values
    
    # For some anomaly detection algorithms, lower scores are more anomalous
    # Check if the model follows this convention
    if hasattr(model, 'is_anomaly') and model.is_anomaly(-1.0, threshold=0):
        scores = -scores
    
    try:
        # Compute ROC AUC
        auc_score = roc_auc_score(y_true, scores)
        
        # Compute Precision-Recall AUC
        precision, recall, _ = precision_recall_curve(y_true, scores)
        pr_auc = auc(recall, precision)
        
        # Return average of both metrics
        return (auc_score + pr_auc) / 2
    except Exception as e:
        logger.error(f"Error computing performance metrics: {e}")
        return 0.0 