#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Anomaly Detection Module
This module provides machine learning-based anomaly detection for network traffic.
"""

import os
import logging
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

# Setup logging
logger = logging.getLogger('ids.anomaly_detection')

class AnomalyDetector:
    """Base class for anomaly detection models."""
    
    def __init__(self, contamination=0.1):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination (float): Expected proportion of outliers in the data
        """
        self.contamination = contamination
        self.model = None
        
    def train(self, X):
        """
        Train the anomaly detection model.
        
        Args:
            X (pd.DataFrame): Training data features
            
        Returns:
            self: The trained model
        """
        raise NotImplementedError("Subclasses must implement train()")
        
    def predict(self, X):
        """
        Predict anomaly scores for new data.
        
        Args:
            X (pd.DataFrame): Data to predict anomaly scores for
            
        Returns:
            np.ndarray: Anomaly scores
        """
        raise NotImplementedError("Subclasses must implement predict()")
        
    def is_anomaly(self, score, threshold=None):
        """
        Determine if a given score represents an anomaly.
        
        Args:
            score (float): Anomaly score
            threshold (float, optional): Threshold for anomaly detection
            
        Returns:
            bool: True if the score represents an anomaly, False otherwise
        """
        raise NotImplementedError("Subclasses must implement is_anomaly()")

class IsolationForestDetector(AnomalyDetector):
    """Anomaly detection using Isolation Forest algorithm."""
    
    def __init__(self, contamination=0.1, n_estimators=100, random_state=42):
        """
        Initialize the Isolation Forest detector.
        
        Args:
            contamination (float): Expected proportion of outliers in the data
            n_estimators (int): Number of base estimators
            random_state (int): Random seed for reproducibility
        """
        super().__init__(contamination)
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state
        )
        
    def train(self, X):
        """
        Train the Isolation Forest model.
        
        Args:
            X (pd.DataFrame): Training data features
            
        Returns:
            self: The trained model
        """
        logger.info("Training Isolation Forest model")
        self.model.fit(X)
        logger.info("Isolation Forest model training completed")
        return self
        
    def predict(self, X):
        """
        Predict anomaly scores for new data.
        
        Args:
            X (pd.DataFrame): Data to predict anomaly scores for
            
        Returns:
            np.ndarray: Anomaly scores (lower means more anomalous)
        """
        if self.model is None:
            raise ValueError("Model has not been trained yet")
        
        # Return decision function (higher = more normal, lower = more anomalous)
        return self.model.decision_function(X)
        
    def is_anomaly(self, score, threshold=0):
        """
        Determine if a given score represents an anomaly.
        For Isolation Forest, lower scores are more anomalous.
        
        Args:
            score (float): Anomaly score
            threshold (float, optional): Threshold for anomaly detection
            
        Returns:
            bool: True if the score represents an anomaly, False otherwise
        """
        return score < threshold

class DBSCANDetector(AnomalyDetector):
    """Anomaly detection using DBSCAN clustering algorithm."""
    
    def __init__(self, eps=0.5, min_samples=5):
        """
        Initialize the DBSCAN detector.
        
        Args:
            eps (float): The maximum distance between two samples for them to be considered in the same neighborhood
            min_samples (int): The number of samples in a neighborhood for a point to be considered a core point
        """
        super().__init__(contamination=None)  # DBSCAN doesn't use contamination
        self.eps = eps
        self.min_samples = min_samples
        self.model = DBSCAN(eps=eps, min_samples=min_samples)
        
    def train(self, X):
        """
        Train the DBSCAN model.
        
        Args:
            X (pd.DataFrame): Training data features
            
        Returns:
            self: The trained model
        """
        logger.info("Training DBSCAN model")
        self.model.fit(X)
        self.labels_ = self.model.labels_
        logger.info(f"DBSCAN identified {np.sum(self.labels_ == -1)} outliers out of {len(X)} samples")
        return self
        
    def predict(self, X):
        """
        Predict anomaly scores for new data.
        For DBSCAN, we calculate the distance to the nearest cluster.
        
        Args:
            X (pd.DataFrame): Data to predict anomaly scores for
            
        Returns:
            np.ndarray: Anomaly scores (higher means more anomalous)
        """
        if not hasattr(self, 'labels_'):
            raise ValueError("Model has not been trained yet")
            
        # Compute distances to all non-outlier clusters
        non_outlier_clusters = np.unique(self.labels_[self.labels_ != -1])
        if len(non_outlier_clusters) == 0:
            # All training points were outliers, so all new points are outliers
            return np.ones(len(X))
            
        distances = []
        for point in X.values:
            # Calculate distance to each cluster
            min_dist = float('inf')
            for cluster in non_outlier_clusters:
                cluster_points = self.model.components_[self.labels_ == cluster]
                if len(cluster_points) > 0:
                    # Calculate minimum distance to any point in the cluster
                    point_dists = np.linalg.norm(cluster_points - point, axis=1)
                    min_cluster_dist = np.min(point_dists)
                    min_dist = min(min_dist, min_cluster_dist)
            distances.append(min_dist)
            
        return np.array(distances)
        
    def is_anomaly(self, score, threshold=None):
        """
        Determine if a given score represents an anomaly.
        For our DBSCAN implementation, higher scores (distances) are more anomalous.
        
        Args:
            score (float): Anomaly score
            threshold (float, optional): Threshold for anomaly detection
            
        Returns:
            bool: True if the score represents an anomaly, False otherwise
        """
        if threshold is None:
            threshold = self.eps  # Use eps as default threshold
        return score > threshold

class LOFDetector(AnomalyDetector):
    """Anomaly detection using Local Outlier Factor algorithm."""
    
    def __init__(self, contamination=0.1, n_neighbors=20):
        """
        Initialize the LOF detector.
        
        Args:
            contamination (float): Expected proportion of outliers in the data
            n_neighbors (int): Number of neighbors to consider
        """
        super().__init__(contamination)
        self.n_neighbors = n_neighbors
        self.model = LocalOutlierFactor(
            contamination=contamination,
            n_neighbors=n_neighbors,
            novelty=True  # Enable predict method
        )
        
    def train(self, X):
        """
        Train the LOF model.
        
        Args:
            X (pd.DataFrame): Training data features
            
        Returns:
            self: The trained model
        """
        logger.info("Training Local Outlier Factor model")
        self.model.fit(X)
        logger.info("Local Outlier Factor model training completed")
        return self
        
    def predict(self, X):
        """
        Predict anomaly scores for new data.
        
        Args:
            X (pd.DataFrame): Data to predict anomaly scores for
            
        Returns:
            np.ndarray: Anomaly scores (lower means more anomalous)
        """
        if not hasattr(self.model, '_fit_X'):
            raise ValueError("Model has not been trained yet")
            
        # Return negative of decision function (higher = more anomalous)
        return -self.model.decision_function(X)
        
    def is_anomaly(self, score, threshold=0):
        """
        Determine if a given score represents an anomaly.
        For LOF, higher scores are more anomalous.
        
        Args:
            score (float): Anomaly score
            threshold (float, optional): Threshold for anomaly detection
            
        Returns:
            bool: True if the score represents an anomaly, False otherwise
        """
        return score > threshold

class OneClassSVMDetector(AnomalyDetector):
    """Anomaly detection using One-Class SVM algorithm."""
    
    def __init__(self, nu=0.1, kernel='rbf', gamma='scale'):
        """
        Initialize the One-Class SVM detector.
        
        Args:
            nu (float): An upper bound on the fraction of training errors and a lower bound of the fraction of support vectors
            kernel (str): Kernel type
            gamma (str or float): Kernel coefficient
        """
        super().__init__(contamination=nu)  # nu is similar to contamination
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self.model = OneClassSVM(
            nu=nu,
            kernel=kernel,
            gamma=gamma
        )
        
    def train(self, X):
        """
        Train the One-Class SVM model.
        
        Args:
            X (pd.DataFrame): Training data features
            
        Returns:
            self: The trained model
        """
        logger.info("Training One-Class SVM model")
        self.model.fit(X)
        logger.info("One-Class SVM model training completed")
        return self
        
    def predict(self, X):
        """
        Predict anomaly scores for new data.
        
        Args:
            X (pd.DataFrame): Data to predict anomaly scores for
            
        Returns:
            np.ndarray: Anomaly scores (lower means more anomalous)
        """
        if not hasattr(self.model, 'support_'):
            raise ValueError("Model has not been trained yet")
            
        # Return decision function (lower = more anomalous)
        return self.model.decision_function(X)
        
    def is_anomaly(self, score, threshold=0):
        """
        Determine if a given score represents an anomaly.
        For One-Class SVM, lower scores are more anomalous.
        
        Args:
            score (float): Anomaly score
            threshold (float, optional): Threshold for anomaly detection
            
        Returns:
            bool: True if the score represents an anomaly, False otherwise
        """
        return score < threshold

def get_detector(detector_type, **kwargs):
    """
    Get an instance of the specified detector type.
    
    Args:
        detector_type (str): Type of detector ('isolation_forest', 'dbscan', 'lof', 'one_class_svm')
        **kwargs: Additional arguments for the detector
        
    Returns:
        AnomalyDetector: An instance of the specified detector
    """
    detector_map = {
        'isolation_forest': IsolationForestDetector,
        'dbscan': DBSCANDetector,
        'lof': LOFDetector,
        'one_class_svm': OneClassSVMDetector
    }
    
    if detector_type not in detector_map:
        raise ValueError(f"Unknown detector type: {detector_type}")
        
    return detector_map[detector_type](**kwargs)

def train_model(data, detector_type='isolation_forest', **kwargs):
    """
    Train an anomaly detection model.
    
    Args:
        data (dict): Preprocessed data dictionary containing features and optionally labels
        detector_type (str): Type of detector to use
        **kwargs: Additional arguments for the detector
        
    Returns:
        AnomalyDetector: The trained anomaly detector
    """
    logger.info(f"Training {detector_type} anomaly detection model")
    
    # Get features from data
    features = data['features']
    
    # Create detector
    detector = get_detector(detector_type, **kwargs)
    
    # Train detector
    detector.train(features)
    
    return detector

def save_model(model, model_path):
    """
    Save an anomaly detection model.
    
    Args:
        model (AnomalyDetector): Model to save
        model_path (str): Path to save the model to
        
    Returns:
        str: Path to the saved model
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save the model
    joblib.dump(model, model_path)
    logger.info(f"Model saved to {model_path}")
    
    return model_path

def load_model(model_path):
    """
    Load an anomaly detection model.
    
    Args:
        model_path (str): Path to the model
        
    Returns:
        AnomalyDetector: The loaded model
    """
    try:
        model = joblib.load(model_path)
        logger.info(f"Model loaded from {model_path}")
        return model
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        raise

def predict(model, features):
    """
    Predict anomaly scores for the given features.
    
    Args:
        model (AnomalyDetector): Trained anomaly detection model
        features (pd.DataFrame): Features to predict anomaly scores for
        
    Returns:
        np.ndarray: Anomaly scores
    """
    return model.predict(features)

def is_anomaly(score, model=None, threshold=None):
    """
    Determine if a given score represents an anomaly.
    
    Args:
        score (float): Anomaly score
        model (AnomalyDetector, optional): Model to use for anomaly detection
        threshold (float, optional): Threshold for anomaly detection
        
    Returns:
        bool: True if the score represents an anomaly, False otherwise
    """
    if model is not None:
        return model.is_anomaly(score, threshold)
    else:
        # Default behavior if model is not provided
        if threshold is None:
            threshold = 0
        return score < threshold

def analyze_data(model, data):
    """
    Analyze a dataset for anomalies.
    
    Args:
        model (AnomalyDetector): Trained anomaly detection model
        data (dict): Preprocessed data dictionary containing features and optionally labels
        
    Returns:
        str: Analysis report
    """
    features = data['features']
    scores = predict(model, features)
    
    anomalies = [is_anomaly(score, model) for score in scores]
    anomaly_count = sum(anomalies)
    anomaly_percent = (anomaly_count / len(features)) * 100
    
    # Generate report
    report = [
        "Anomaly Detection Analysis Report",
        "==============================",
        f"Total samples analyzed: {len(features)}",
        f"Number of anomalies detected: {anomaly_count}",
        f"Percentage of anomalies: {anomaly_percent:.2f}%",
        "",
        "Score Distribution:",
        f"  Min score: {np.min(scores):.4f}",
        f"  Max score: {np.max(scores):.4f}",
        f"  Mean score: {np.mean(scores):.4f}",
        f"  Median score: {np.median(scores):.4f}",
        "",
    ]
    
    # Add label-based analysis if labels exist
    if 'labels' in data:
        labels = data['labels']
        label_names = np.unique(labels)
        
        report.append("Label-based Analysis:")
        for label in label_names:
            label_indices = labels == label
            label_count = np.sum(label_indices)
            label_anomalies = np.sum([anomalies[i] for i in range(len(anomalies)) if label_indices[i]])
            label_anomaly_percent = (label_anomalies / label_count) * 100 if label_count > 0 else 0
            
            report.append(f"  Label {label}:")
            report.append(f"    Count: {label_count}")
            report.append(f"    Anomalies: {label_anomalies}")
            report.append(f"    Anomaly percentage: {label_anomaly_percent:.2f}%")
    
    return "\n".join(report)

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create and train a model
    X = pd.DataFrame(np.random.randn(100, 5))
    detector = get_detector('isolation_forest')
    detector.train(X)
    
    # Predict on new data
    X_new = pd.DataFrame(np.random.randn(10, 5))
    scores = detector.predict(X_new)
    
    print("Anomaly scores:", scores)
    print("Anomalies:", [detector.is_anomaly(score) for score in scores]) 