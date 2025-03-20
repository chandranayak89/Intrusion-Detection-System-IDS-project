#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Active Learning Module for Anomaly Detection
Implements methods for automatic data labeling and selection of samples for model retraining.
"""

import os
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from typing import Dict, List, Tuple, Any, Optional, Union

# Setup logging
logger = logging.getLogger('ids.model_management.active_learning')

class ActiveLearningSystem:
    """
    Active Learning System for automatic data labeling and model retraining.
    """
    
    def __init__(
        self,
        base_model,
        confidence_threshold: float = 0.8,
        uncertainty_threshold: float = 0.3,
        min_samples_per_class: int = 50,
        max_samples_to_label: int = 1000
    ):
        """
        Initialize the active learning system.
        
        Args:
            base_model: The base anomaly detection model
            confidence_threshold: Threshold for high-confidence predictions
            uncertainty_threshold: Threshold for uncertain predictions
            min_samples_per_class: Minimum samples per class needed for retraining
            max_samples_to_label: Maximum number of samples to label in one iteration
        """
        self.base_model = base_model
        self.confidence_threshold = confidence_threshold
        self.uncertainty_threshold = uncertainty_threshold
        self.min_samples_per_class = min_samples_per_class
        self.max_samples_to_label = max_samples_to_label
        
        # Initialize storage for labeled and unlabeled data
        self.labeled_data = pd.DataFrame()
        self.uncertain_samples = pd.DataFrame()
        
        # Tracking metrics
        self.metrics = {
            "total_samples_processed": 0,
            "auto_labeled_normal": 0,
            "auto_labeled_anomaly": 0,
            "uncertain_samples": 0,
            "last_update_time": datetime.now()
        }
    
    def process_new_data(self, data: pd.DataFrame, features: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Process new data through the active learning pipeline.
        
        Args:
            data: DataFrame containing new data samples
            features: List of feature columns to use for prediction
            
        Returns:
            Tuple of (labeled_data, uncertain_data)
        """
        if data.empty:
            return pd.DataFrame(), pd.DataFrame()
        
        # Extract features
        X = data[features].copy()
        
        # Get anomaly scores from the base model
        scores = self.base_model.predict(X)
        
        # Classify data based on scores
        is_anomaly = np.zeros(len(scores), dtype=bool)
        is_uncertain = np.zeros(len(scores), dtype=bool)
        
        # Apply the base model's anomaly detection function
        if hasattr(self.base_model, 'is_anomaly'):
            for i, score in enumerate(scores):
                is_anomaly[i] = self.base_model.is_anomaly(score)
        else:
            # Default behavior: lower scores are more anomalous
            threshold = np.percentile(scores, self.confidence_threshold * 100)
            is_anomaly = scores < threshold
        
        # Identify uncertain samples (close to decision boundary)
        uncertainty_range = self._calculate_uncertainty_range(scores)
        lower_bound, upper_bound = uncertainty_range
        
        for i, score in enumerate(scores):
            if lower_bound <= score <= upper_bound:
                is_uncertain[i] = True
        
        # Add predictions to data
        data_with_pred = data.copy()
        data_with_pred['anomaly_score'] = scores
        data_with_pred['is_anomaly'] = is_anomaly
        data_with_pred['is_uncertain'] = is_uncertain
        
        # Separate confident and uncertain predictions
        confident_data = data_with_pred[~data_with_pred['is_uncertain']].copy()
        uncertain_data = data_with_pred[data_with_pred['is_uncertain']].copy()
        
        # Update metrics
        self.metrics["total_samples_processed"] += len(data)
        self.metrics["auto_labeled_normal"] += len(confident_data[~confident_data['is_anomaly']])
        self.metrics["auto_labeled_anomaly"] += len(confident_data[confident_data['is_anomaly']])
        self.metrics["uncertain_samples"] += len(uncertain_data)
        self.metrics["last_update_time"] = datetime.now()
        
        # Store labeled and uncertain data
        self._update_data_storage(confident_data, uncertain_data)
        
        return confident_data, uncertain_data
    
    def refine_uncertain_samples(self, manual_labels: Optional[Dict[str, int]] = None) -> pd.DataFrame:
        """
        Refine uncertain samples using clustering or manual labels.
        
        Args:
            manual_labels: Dictionary mapping sample IDs to labels (0=normal, 1=anomaly)
            
        Returns:
            DataFrame of newly labeled samples
        """
        if self.uncertain_samples.empty:
            return pd.DataFrame()
        
        newly_labeled = pd.DataFrame()
        
        # If manual labels are provided, apply them
        if manual_labels:
            labeled_indices = []
            for idx, label in manual_labels.items():
                if idx in self.uncertain_samples.index:
                    self.uncertain_samples.loc[idx, 'is_anomaly'] = bool(label)
                    self.uncertain_samples.loc[idx, 'is_uncertain'] = False
                    labeled_indices.append(idx)
            
            # Extract newly labeled samples
            newly_labeled = self.uncertain_samples.loc[labeled_indices].copy()
            
            # Remove labeled samples from uncertain set
            self.uncertain_samples = self.uncertain_samples.drop(labeled_indices)
        
        # If there are still many uncertain samples, try to cluster them
        if len(self.uncertain_samples) > self.min_samples_per_class * 2:
            feature_cols = [col for col in self.uncertain_samples.columns 
                           if col not in ['anomaly_score', 'is_anomaly', 'is_uncertain']]
            
            # Cluster uncertain samples
            clustered_labels = self._cluster_uncertain_samples(
                self.uncertain_samples[feature_cols].values
            )
            
            # Apply cluster labels to create new labeled data
            temp_df = self.uncertain_samples.copy()
            temp_df['cluster'] = clustered_labels
            
            # Identify anomaly clusters using isolation forest anomaly scores
            cluster_mean_scores = temp_df.groupby('cluster')['anomaly_score'].mean()
            anomaly_clusters = cluster_mean_scores[cluster_mean_scores < np.median(cluster_mean_scores)].index.tolist()
            
            # Update the is_anomaly field based on cluster
            for cluster in np.unique(clustered_labels):
                is_anomaly = cluster in anomaly_clusters
                indices = temp_df[temp_df['cluster'] == cluster].index
                temp_df.loc[indices, 'is_anomaly'] = is_anomaly
                temp_df.loc[indices, 'is_uncertain'] = False
            
            # Extract newly labeled samples
            newly_labeled = pd.concat([newly_labeled, temp_df])
            
            # Update uncertain samples
            self.uncertain_samples = pd.DataFrame()
        
        # Update labeled data with newly labeled samples
        if not newly_labeled.empty:
            self.labeled_data = pd.concat([self.labeled_data, newly_labeled])
            
            # Update metrics
            self.metrics["auto_labeled_normal"] += len(newly_labeled[~newly_labeled['is_anomaly']])
            self.metrics["auto_labeled_anomaly"] += len(newly_labeled[newly_labeled['is_anomaly']])
            self.metrics["uncertain_samples"] = len(self.uncertain_samples)
        
        return newly_labeled
    
    def get_training_data(self, max_samples: Optional[int] = None) -> pd.DataFrame:
        """
        Get balanced dataset for model retraining.
        
        Args:
            max_samples: Maximum number of samples to include
            
        Returns:
            DataFrame containing balanced labeled data for training
        """
        if self.labeled_data.empty:
            return pd.DataFrame()
        
        # Separate normal and anomaly samples
        normal_samples = self.labeled_data[~self.labeled_data['is_anomaly']]
        anomaly_samples = self.labeled_data[self.labeled_data['is_anomaly']]
        
        # Check if we have enough samples of each class
        if len(normal_samples) < self.min_samples_per_class or len(anomaly_samples) < self.min_samples_per_class:
            logger.warning(f"Not enough samples for retraining. Normal: {len(normal_samples)}, "
                          f"Anomaly: {len(anomaly_samples)}, Required: {self.min_samples_per_class}")
            return pd.DataFrame()
        
        # Balance the dataset
        n_samples_per_class = min(len(normal_samples), len(anomaly_samples))
        
        # Apply maximum samples limit if specified
        if max_samples and max_samples > 0:
            n_samples_per_class = min(n_samples_per_class, max_samples // 2)
        
        # Sample from each class
        balanced_normal = normal_samples.sample(n_samples_per_class, random_state=42)
        balanced_anomaly = anomaly_samples.sample(n_samples_per_class, random_state=42)
        
        # Combine samples
        balanced_data = pd.concat([balanced_normal, balanced_anomaly])
        
        # Shuffle the data
        balanced_data = balanced_data.sample(frac=1, random_state=42).reset_index(drop=True)
        
        return balanced_data
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get metrics about the active learning process.
        
        Returns:
            Dictionary of metrics
        """
        # Calculate additional metrics
        metrics = dict(self.metrics)
        metrics["total_labeled"] = metrics["auto_labeled_normal"] + metrics["auto_labeled_anomaly"]
        
        if metrics["total_samples_processed"] > 0:
            metrics["labeling_rate"] = metrics["total_labeled"] / metrics["total_samples_processed"]
        else:
            metrics["labeling_rate"] = 0.0
            
        metrics["normal_anomaly_ratio"] = (
            metrics["auto_labeled_anomaly"] / metrics["auto_labeled_normal"] 
            if metrics["auto_labeled_normal"] > 0 else float('inf')
        )
        
        return metrics
    
    def _update_data_storage(self, confident_data: pd.DataFrame, uncertain_data: pd.DataFrame) -> None:
        """
        Update the labeled and uncertain data storage.
        
        Args:
            confident_data: Data with confident predictions
            uncertain_data: Data with uncertain predictions
        """
        # Update labeled data with confident predictions
        if not confident_data.empty:
            self.labeled_data = pd.concat([self.labeled_data, confident_data])
        
        # Update uncertain samples
        if not uncertain_data.empty:
            self.uncertain_samples = pd.concat([self.uncertain_samples, uncertain_data])
        
        # If we have too many samples, keep only the most recent ones
        if len(self.labeled_data) > self.max_samples_to_label * 10:
            self.labeled_data = self.labeled_data.iloc[-self.max_samples_to_label * 10:]
            
        if len(self.uncertain_samples) > self.max_samples_to_label:
            self.uncertain_samples = self.uncertain_samples.iloc[-self.max_samples_to_label:]
    
    def _calculate_uncertainty_range(self, scores: np.ndarray) -> Tuple[float, float]:
        """
        Calculate the range of uncertainty for anomaly scores.
        
        Args:
            scores: Array of anomaly scores
            
        Returns:
            Tuple of (lower_bound, upper_bound) for uncertainty range
        """
        # Simple approach: use percentiles to define uncertainty range
        sorted_scores = np.sort(scores)
        
        # Find lower bound near anomaly threshold
        anomaly_threshold_percentile = 100 * (1 - self.confidence_threshold)
        lower_idx = max(0, int(len(sorted_scores) * anomaly_threshold_percentile / 100) - 
                        int(len(sorted_scores) * self.uncertainty_threshold / 2 / 100))
        
        # Find upper bound
        upper_idx = min(len(sorted_scores) - 1, 
                        int(len(sorted_scores) * anomaly_threshold_percentile / 100) + 
                        int(len(sorted_scores) * self.uncertainty_threshold / 2 / 100))
        
        return sorted_scores[lower_idx], sorted_scores[upper_idx]
    
    def _cluster_uncertain_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Cluster uncertain samples to assist with labeling.
        
        Args:
            X: Feature matrix of uncertain samples
            
        Returns:
            Array of cluster labels
        """
        # Determine optimal number of clusters (between 2 and 10)
        max_clusters = min(10, len(X) // 10)
        best_n_clusters = 2
        best_score = -1
        
        if max_clusters < 2:
            # Not enough samples, use a single cluster
            return np.zeros(len(X), dtype=int)
        
        # Find optimal number of clusters
        for n_clusters in range(2, max_clusters + 1):
            kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            labels = kmeans.fit_predict(X)
            
            # Skip if any cluster has too few samples
            if np.min(np.bincount(labels)) < 5:
                continue
                
            # Calculate silhouette score
            try:
                score = silhouette_score(X, labels)
                if score > best_score:
                    best_score = score
                    best_n_clusters = n_clusters
            except Exception as e:
                logger.warning(f"Error calculating silhouette score: {e}")
        
        # Cluster with optimal number of clusters
        kmeans = KMeans(n_clusters=best_n_clusters, random_state=42)
        labels = kmeans.fit_predict(X)
        
        return labels 