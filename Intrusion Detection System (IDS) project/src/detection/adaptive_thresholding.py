#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adaptive Thresholding Module for Anomaly Detection
This module provides methods for dynamically adjusting anomaly detection thresholds
based on historical network traffic patterns and seasonal trends.
"""

import os
import sys
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union, Optional, Any
import threading
import time
import json
import pickle
from collections import defaultdict, deque

# Try importing statsmodels for time series decomposition
try:
    from statsmodels.tsa.seasonal import STL
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    STATSMODELS_AVAILABLE = True
except ImportError:
    STATSMODELS_AVAILABLE = False
    logging.warning("statsmodels not available. Some advanced thresholding methods will be disabled.")

# Setup logging
logger = logging.getLogger('ids.adaptive_thresholding')

class BaseThresholdModel:
    """Base class for adaptive threshold models."""
    
    def __init__(self, feature_name: str, window_size: int = 100, threshold_factor: float = 3.0):
        """
        Initialize the base threshold model.
        
        Args:
            feature_name (str): Name of the feature this model is tracking
            window_size (int): Size of the sliding window for historical data
            threshold_factor (float): Multiplier for standard deviation to determine threshold
        """
        self.feature_name = feature_name
        self.window_size = window_size
        self.threshold_factor = threshold_factor
        self.values = deque(maxlen=window_size)
        self.thresholds = deque(maxlen=window_size)
        self.last_updated = None
        
    def update(self, value: float) -> None:
        """
        Update the model with a new value.
        
        Args:
            value (float): New observed value
        """
        self.values.append(value)
        self._recalculate_threshold()
        self.last_updated = datetime.now()
        
    def _recalculate_threshold(self) -> None:
        """
        Recalculate the threshold based on historical data.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _recalculate_threshold()")
        
    def get_current_threshold(self) -> float:
        """
        Get the current threshold.
        
        Returns:
            float: Current threshold value
        """
        if not self.thresholds:
            return 0.0
        return self.thresholds[-1]
        
    def is_anomaly(self, value: float) -> bool:
        """
        Check if a value is an anomaly based on current threshold.
        
        Args:
            value (float): Value to check
            
        Returns:
            bool: True if the value exceeds the threshold, False otherwise
        """
        if not self.thresholds:
            self.update(value)
            return False
            
        return value > self.thresholds[-1]
        
    def save_state(self, filepath: str) -> bool:
        """
        Save the model state to a file.
        
        Args:
            filepath (str): Path to save the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            state = {
                'feature_name': self.feature_name,
                'window_size': self.window_size,
                'threshold_factor': self.threshold_factor,
                'values': list(self.values),
                'thresholds': list(self.thresholds),
                'last_updated': self.last_updated.isoformat() if self.last_updated else None
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(state, f)
                
            logger.info(f"Saved threshold model for {self.feature_name} to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving threshold model: {e}")
            return False
            
    def load_state(self, filepath: str) -> bool:
        """
        Load the model state from a file.
        
        Args:
            filepath (str): Path to load the model from
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filepath, 'rb') as f:
                state = pickle.load(f)
                
            self.feature_name = state['feature_name']
            self.window_size = state['window_size']
            self.threshold_factor = state['threshold_factor']
            self.values = deque(state['values'], maxlen=self.window_size)
            self.thresholds = deque(state['thresholds'], maxlen=self.window_size)
            
            if state['last_updated']:
                self.last_updated = datetime.fromisoformat(state['last_updated'])
                
            logger.info(f"Loaded threshold model for {self.feature_name} from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading threshold model: {e}")
            return False

class MovingAverageThreshold(BaseThresholdModel):
    """Threshold model based on moving average and standard deviation."""
    
    def __init__(self, feature_name: str, window_size: int = 100, threshold_factor: float = 3.0):
        """
        Initialize the moving average threshold model.
        
        Args:
            feature_name (str): Name of the feature this model is tracking
            window_size (int): Size of the sliding window for historical data
            threshold_factor (float): Multiplier for standard deviation to determine threshold
        """
        super().__init__(feature_name, window_size, threshold_factor)
        
    def _recalculate_threshold(self) -> None:
        """Recalculate threshold based on moving average and standard deviation."""
        if len(self.values) < 2:
            # Not enough data for meaningful statistics
            self.thresholds.append(float('inf') if self.values else 0.0)
            return
            
        # Calculate mean and standard deviation
        values_array = np.array(self.values)
        mean = np.mean(values_array)
        std = np.std(values_array)
        
        # Calculate threshold as mean + (factor * std)
        threshold = mean + (self.threshold_factor * std)
        self.thresholds.append(threshold)

class ExponentialWeightedMovingAverage(BaseThresholdModel):
    """Threshold model based on exponentially weighted moving average (EWMA)."""
    
    def __init__(self, feature_name: str, window_size: int = 100, threshold_factor: float = 3.0, 
                 alpha: float = 0.3):
        """
        Initialize the EWMA threshold model.
        
        Args:
            feature_name (str): Name of the feature this model is tracking
            window_size (int): Size of the sliding window for historical data
            threshold_factor (float): Multiplier for standard deviation to determine threshold
            alpha (float): Smoothing factor for EWMA (between 0 and 1)
        """
        super().__init__(feature_name, window_size, threshold_factor)
        self.alpha = alpha
        self.ewma = None
        self.ewmvar = None
        
    def update(self, value: float) -> None:
        """
        Update the model with a new value.
        
        Args:
            value (float): New observed value
        """
        self.values.append(value)
        
        # Initialize EWMA and variance if this is the first value
        if self.ewma is None:
            self.ewma = value
            self.ewmvar = 0.0
        else:
            # Update EWMA
            prev_ewma = self.ewma
            self.ewma = (self.alpha * value) + ((1 - self.alpha) * self.ewma)
            
            # Update exponentially weighted moving variance
            self.ewmvar = (1 - self.alpha) * (self.ewmvar + self.alpha * (value - prev_ewma) ** 2)
            
        self._recalculate_threshold()
        self.last_updated = datetime.now()
        
    def _recalculate_threshold(self) -> None:
        """Recalculate threshold based on EWMA and EWMVAR."""
        if self.ewma is None:
            self.thresholds.append(0.0)
            return
            
        # Calculate threshold as EWMA + (factor * sqrt(EWMVAR))
        ewmstd = np.sqrt(self.ewmvar) if self.ewmvar > 0 else 0
        threshold = self.ewma + (self.threshold_factor * ewmstd)
        self.thresholds.append(threshold)
        
    def save_state(self, filepath: str) -> bool:
        """
        Save the model state to a file, including EWMA-specific parameters.
        
        Args:
            filepath (str): Path to save the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            state = {
                'feature_name': self.feature_name,
                'window_size': self.window_size,
                'threshold_factor': self.threshold_factor,
                'alpha': self.alpha,
                'ewma': self.ewma,
                'ewmvar': self.ewmvar,
                'values': list(self.values),
                'thresholds': list(self.thresholds),
                'last_updated': self.last_updated.isoformat() if self.last_updated else None
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(state, f)
                
            logger.info(f"Saved EWMA threshold model for {self.feature_name} to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving EWMA threshold model: {e}")
            return False
            
    def load_state(self, filepath: str) -> bool:
        """
        Load the model state from a file, including EWMA-specific parameters.
        
        Args:
            filepath (str): Path to load the model from
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filepath, 'rb') as f:
                state = pickle.load(f)
                
            self.feature_name = state['feature_name']
            self.window_size = state['window_size']
            self.threshold_factor = state['threshold_factor']
            self.alpha = state['alpha']
            self.ewma = state['ewma']
            self.ewmvar = state['ewmvar']
            self.values = deque(state['values'], maxlen=self.window_size)
            self.thresholds = deque(state['thresholds'], maxlen=self.window_size)
            
            if state['last_updated']:
                self.last_updated = datetime.fromisoformat(state['last_updated'])
                
            logger.info(f"Loaded EWMA threshold model for {self.feature_name} from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading EWMA threshold model: {e}")
            return False

class SeasonalTrendDecomposition(BaseThresholdModel):
    """Threshold model based on seasonal trend decomposition (STL)."""
    
    def __init__(self, feature_name: str, window_size: int = 100, threshold_factor: float = 3.0,
                 seasonal_period: int = 24, robust: bool = True):
        """
        Initialize the STL threshold model.
        
        Args:
            feature_name (str): Name of the feature this model is tracking
            window_size (int): Size of the sliding window for historical data
            threshold_factor (float): Multiplier for residual standard deviation
            seasonal_period (int): Period of seasonality (e.g., 24 for hourly data with daily seasonality)
            robust (bool): Whether to use robust STL decomposition
        """
        if not STATSMODELS_AVAILABLE:
            raise ImportError("statsmodels is required for SeasonalTrendDecomposition")
            
        super().__init__(feature_name, window_size, threshold_factor)
        self.seasonal_period = seasonal_period
        self.robust = robust
        self.trend = deque(maxlen=window_size)
        self.seasonal = deque(maxlen=window_size)
        self.residual = deque(maxlen=window_size)
        
    def update(self, value: float) -> None:
        """
        Update the model with a new value.
        
        Args:
            value (float): New observed value
        """
        self.values.append(value)
        self._decompose()
        self._recalculate_threshold()
        self.last_updated = datetime.now()
        
    def _decompose(self) -> None:
        """Perform seasonal trend decomposition on the time series data."""
        # Need at least 2 * seasonal_period data points for meaningful decomposition
        if len(self.values) < 2 * self.seasonal_period:
            # Not enough data, just store the raw value
            if self.trend:
                self.trend.append(self.trend[-1])
            else:
                self.trend.append(0.0)
                
            if self.seasonal:
                self.seasonal.append(0.0)
            else:
                self.seasonal.append(0.0)
                
            if self.residual:
                self.residual.append(self.values[-1] - self.trend[-1])
            else:
                self.residual.append(0.0)
                
            return
            
        try:
            # Convert values to pandas Series
            ts = pd.Series(self.values)
            
            # Perform STL decomposition
            stl = STL(ts, period=self.seasonal_period, robust=self.robust)
            result = stl.fit()
            
            # Extract components
            self.trend = deque(result.trend.values, maxlen=self.window_size)
            self.seasonal = deque(result.seasonal.values, maxlen=self.window_size)
            self.residual = deque(result.resid.values, maxlen=self.window_size)
            
        except Exception as e:
            logger.error(f"Error in STL decomposition: {e}")
            # Fallback: simple decomposition
            if self.trend:
                # Use simple moving average for trend
                trend_value = np.mean(list(self.values)[-self.seasonal_period:])
                self.trend.append(trend_value)
            else:
                self.trend.append(self.values[-1])
                
            if self.seasonal:
                self.seasonal.append(0.0)  # Simplified, no seasonality estimation
            else:
                self.seasonal.append(0.0)
                
            if self.residual:
                self.residual.append(self.values[-1] - self.trend[-1])
            else:
                self.residual.append(0.0)
        
    def _recalculate_threshold(self) -> None:
        """Recalculate threshold based on trend, seasonal component, and residual variance."""
        if not self.trend or not self.seasonal or not self.residual:
            self.thresholds.append(float('inf') if self.values else 0.0)
            return
            
        # Calculate expected value based on trend and seasonality
        expected_value = self.trend[-1] + self.seasonal[-1]
        
        # Calculate threshold using residual standard deviation
        residual_std = np.std(list(self.residual))
        threshold = expected_value + (self.threshold_factor * residual_std)
        
        self.thresholds.append(threshold)
        
    def get_forecast(self, steps: int = 1) -> List[Tuple[float, float]]:
        """
        Forecast future values and thresholds.
        
        Args:
            steps (int): Number of steps to forecast
            
        Returns:
            List[Tuple[float, float]]: List of (forecast_value, threshold) tuples
        """
        if not self.trend or not self.seasonal or len(self.values) < 2 * self.seasonal_period:
            return [(self.values[-1] if self.values else 0.0, 
                    self.thresholds[-1] if self.thresholds else 0.0)] * steps
                    
        # Extract current trend and calculate trend slope
        trend_values = list(self.trend)
        trend_slope = (trend_values[-1] - trend_values[-2]) if len(trend_values) >= 2 else 0
        
        # Extract seasonal pattern
        seasonal_values = list(self.seasonal)
        season_length = min(self.seasonal_period, len(seasonal_values))
        
        # Calculate residual standard deviation
        residual_std = np.std(list(self.residual))
        
        forecasts = []
        for i in range(steps):
            # Forecast trend by adding slope
            trend_forecast = trend_values[-1] + (trend_slope * (i + 1))
            
            # Reuse the appropriate seasonal component
            season_index = (-season_length + (i % season_length))
            seasonal_forecast = seasonal_values[season_index]
            
            # Combine components
            value_forecast = trend_forecast + seasonal_forecast
            
            # Calculate threshold
            threshold = value_forecast + (self.threshold_factor * residual_std)
            
            forecasts.append((value_forecast, threshold))
            
        return forecasts
        
    def save_state(self, filepath: str) -> bool:
        """
        Save the model state to a file, including decomposition components.
        
        Args:
            filepath (str): Path to save the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            state = {
                'feature_name': self.feature_name,
                'window_size': self.window_size,
                'threshold_factor': self.threshold_factor,
                'seasonal_period': self.seasonal_period,
                'robust': self.robust,
                'values': list(self.values),
                'trend': list(self.trend),
                'seasonal': list(self.seasonal),
                'residual': list(self.residual),
                'thresholds': list(self.thresholds),
                'last_updated': self.last_updated.isoformat() if self.last_updated else None
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(state, f)
                
            logger.info(f"Saved STL threshold model for {self.feature_name} to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving STL threshold model: {e}")
            return False
            
    def load_state(self, filepath: str) -> bool:
        """
        Load the model state from a file, including decomposition components.
        
        Args:
            filepath (str): Path to load the model from
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filepath, 'rb') as f:
                state = pickle.load(f)
                
            self.feature_name = state['feature_name']
            self.window_size = state['window_size']
            self.threshold_factor = state['threshold_factor']
            self.seasonal_period = state['seasonal_period']
            self.robust = state['robust']
            self.values = deque(state['values'], maxlen=self.window_size)
            self.trend = deque(state['trend'], maxlen=self.window_size)
            self.seasonal = deque(state['seasonal'], maxlen=self.window_size)
            self.residual = deque(state['residual'], maxlen=self.window_size)
            self.thresholds = deque(state['thresholds'], maxlen=self.window_size)
            
            if state['last_updated']:
                self.last_updated = datetime.fromisoformat(state['last_updated'])
                
            logger.info(f"Loaded STL threshold model for {self.feature_name} from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading STL threshold model: {e}")
            return False

class ThresholdManager:
    """Manages multiple adaptive threshold models for different features."""
    
    def __init__(self, base_dir: Optional[str] = None, auto_save: bool = True,
                 save_interval: int = 3600):  # 1 hour interval by default
        """
        Initialize the threshold manager.
        
        Args:
            base_dir (str, optional): Directory to save model states
            auto_save (bool): Whether to automatically save models periodically
            save_interval (int): Interval in seconds for auto-saving models
        """
        self.models = {}
        
        # Set up base directory
        if base_dir:
            self.base_dir = base_dir
        else:
            # Use default directory
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.base_dir = os.path.join(base_dir, 'data', 'thresholds')
            
        os.makedirs(self.base_dir, exist_ok=True)
        
        # Auto-save settings
        self.auto_save = auto_save
        self.save_interval = save_interval
        self.last_save = datetime.now()
        
        # Auto-save thread
        self.auto_save_thread = None
        self.stop_event = threading.Event()
        
        # Start auto-save if enabled
        if self.auto_save:
            self.start_auto_save()
    
    def add_model(self, model_type: str, feature_name: str, **kwargs) -> BaseThresholdModel:
        """
        Add a new threshold model.
        
        Args:
            model_type (str): Type of model ('moving_average', 'ewma', or 'seasonal')
            feature_name (str): Name of the feature this model will track
            **kwargs: Additional arguments for the specific model
            
        Returns:
            BaseThresholdModel: The created model
        """
        # Check if model for this feature already exists
        if feature_name in self.models:
            logger.warning(f"Replacing existing threshold model for {feature_name}")
            
        # Create the appropriate model
        if model_type == 'moving_average':
            model = MovingAverageThreshold(feature_name=feature_name, **kwargs)
        elif model_type == 'ewma':
            model = ExponentialWeightedMovingAverage(feature_name=feature_name, **kwargs)
        elif model_type == 'seasonal':
            if not STATSMODELS_AVAILABLE:
                logger.warning("statsmodels not available, falling back to EWMA")
                model = ExponentialWeightedMovingAverage(feature_name=feature_name, **kwargs)
            else:
                model = SeasonalTrendDecomposition(feature_name=feature_name, **kwargs)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
            
        # Add the model to our collection
        self.models[feature_name] = model
        
        # Try to load existing state
        model_path = os.path.join(self.base_dir, f"{feature_name.replace('/', '_')}.pkl")
        if os.path.exists(model_path):
            model.load_state(model_path)
            
        return model
    
    def update(self, feature_name: str, value: float) -> None:
        """
        Update a model with a new value.
        
        Args:
            feature_name (str): Name of the feature
            value (float): New observed value
        """
        if feature_name not in self.models:
            logger.warning(f"No threshold model for {feature_name}, skipping update")
            return
            
        self.models[feature_name].update(value)
        
        # Save periodically if auto-save is enabled
        if self.auto_save and (datetime.now() - self.last_save).total_seconds() >= self.save_interval:
            self.save_all()
            
    def is_anomaly(self, feature_name: str, value: float) -> bool:
        """
        Check if a value is an anomaly for a given feature.
        
        Args:
            feature_name (str): Name of the feature
            value (float): Value to check
            
        Returns:
            bool: True if the value is an anomaly, False otherwise
        """
        if feature_name not in self.models:
            logger.warning(f"No threshold model for {feature_name}, unable to check for anomaly")
            return False
            
        return self.models[feature_name].is_anomaly(value)
        
    def get_threshold(self, feature_name: str) -> float:
        """
        Get the current threshold for a feature.
        
        Args:
            feature_name (str): Name of the feature
            
        Returns:
            float: Current threshold value
        """
        if feature_name not in self.models:
            logger.warning(f"No threshold model for {feature_name}, no threshold available")
            return 0.0
            
        return self.models[feature_name].get_current_threshold()
        
    def save_all(self) -> None:
        """Save all models."""
        for feature_name, model in self.models.items():
            model_path = os.path.join(self.base_dir, f"{feature_name.replace('/', '_')}.pkl")
            model.save_state(model_path)
            
        self.last_save = datetime.now()
        logger.info(f"Saved {len(self.models)} threshold models")
        
    def load_all(self) -> None:
        """Load all models from the base directory."""
        for filename in os.listdir(self.base_dir):
            if filename.endswith('.pkl'):
                feature_name = filename[:-4].replace('_', '/')
                model_path = os.path.join(self.base_dir, filename)
                
                if feature_name in self.models:
                    self.models[feature_name].load_state(model_path)
                else:
                    logger.warning(f"Found model for {feature_name} but no matching model exists")
                    
    def start_auto_save(self) -> None:
        """Start the auto-save thread."""
        if self.auto_save_thread is not None and self.auto_save_thread.is_alive():
            logger.warning("Auto-save thread is already running")
            return
            
        logger.info("Starting auto-save thread")
        self.stop_event.clear()
        self.auto_save_thread = threading.Thread(target=self._auto_save_worker, daemon=True)
        self.auto_save_thread.start()
        
    def stop_auto_save(self) -> None:
        """Stop the auto-save thread."""
        if self.auto_save_thread is None or not self.auto_save_thread.is_alive():
            logger.warning("Auto-save thread is not running")
            return
            
        logger.info("Stopping auto-save thread")
        self.stop_event.set()
        self.auto_save_thread.join(timeout=5.0)
        self.auto_save_thread = None
        
    def _auto_save_worker(self) -> None:
        """Worker function for the auto-save thread."""
        logger.info("Auto-save thread started")
        
        while not self.stop_event.is_set():
            time.sleep(self.save_interval)
            
            if self.stop_event.is_set():
                break
                
            try:
                self.save_all()
            except Exception as e:
                logger.error(f"Error in auto-save thread: {e}")
                
        logger.info("Auto-save thread stopped")

def get_example_data() -> List[dict]:
    """
    Generate example data for demonstrating adaptive thresholding.
    
    Returns:
        List[dict]: Example data
    """
    # Create a time series with trend, seasonality, and some anomalies
    np.random.seed(42)
    n_points = 200
    
    # Time vector (hours)
    time = np.arange(n_points)
    
    # Trend component (linear growth)
    trend = 0.1 * time
    
    # Seasonal component (daily pattern, 24-hour period)
    seasonality = 10 * np.sin(2 * np.pi * time / 24)
    
    # Baseline signal
    baseline = trend + seasonality
    
    # Add random noise
    noise = np.random.normal(0, 1, n_points)
    
    # Add some anomalies
    anomaly_indices = [50, 100, 150]
    anomalies = np.zeros(n_points)
    for idx in anomaly_indices:
        anomalies[idx] = 20  # Significant spike
        
    # Combine all components
    values = baseline + noise + anomalies
    
    # Create a list of dictionaries
    data = []
    start_time = datetime.now() - timedelta(hours=n_points)
    
    for i in range(n_points):
        timestamp = start_time + timedelta(hours=i)
        data.append({
            'timestamp': timestamp,
            'bytes_per_second': max(0, values[i]),
            'packets_per_second': max(0, values[i] / 10),
            'is_true_anomaly': i in anomaly_indices
        })
        
    return data

def demo_thresholding() -> None:
    """Demonstrate the adaptive thresholding models."""
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Get example data
    data = get_example_data()
    
    # Create threshold manager
    manager = ThresholdManager(auto_save=False)
    
    # Add models for different features
    manager.add_model('moving_average', 'bytes_per_second', window_size=50, threshold_factor=3.0)
    manager.add_model('ewma', 'packets_per_second', window_size=50, threshold_factor=3.0, alpha=0.3)
    
    if STATSMODELS_AVAILABLE:
        manager.add_model('seasonal', 'seasonal_bytes', window_size=100, threshold_factor=3.0, seasonal_period=24)
    
    # Process data and detect anomalies
    results = {
        'bytes_per_second': {'true_positives': 0, 'false_positives': 0, 'true_negatives': 0, 'false_negatives': 0},
        'packets_per_second': {'true_positives': 0, 'false_positives': 0, 'true_negatives': 0, 'false_negatives': 0}
    }
    
    if STATSMODELS_AVAILABLE:
        results['seasonal_bytes'] = {'true_positives': 0, 'false_positives': 0, 'true_negatives': 0, 'false_negatives': 0}
    
    # Process each data point
    for point in data:
        for feature in ['bytes_per_second', 'packets_per_second']:
            # Update the model and check for anomaly
            is_anomaly = manager.is_anomaly(feature, point[feature])
            manager.update(feature, point[feature])
            
            # Update evaluation metrics
            if is_anomaly and point['is_true_anomaly']:
                results[feature]['true_positives'] += 1
            elif is_anomaly and not point['is_true_anomaly']:
                results[feature]['false_positives'] += 1
            elif not is_anomaly and point['is_true_anomaly']:
                results[feature]['false_negatives'] += 1
            else:
                results[feature]['true_negatives'] += 1
                
        # Also update seasonal model if available
        if STATSMODELS_AVAILABLE:
            # For demonstration, we use the same data for both features
            is_anomaly = manager.is_anomaly('seasonal_bytes', point['bytes_per_second'])
            manager.update('seasonal_bytes', point['bytes_per_second'])
            
            # Update evaluation metrics
            if is_anomaly and point['is_true_anomaly']:
                results['seasonal_bytes']['true_positives'] += 1
            elif is_anomaly and not point['is_true_anomaly']:
                results['seasonal_bytes']['false_positives'] += 1
            elif not is_anomaly and point['is_true_anomaly']:
                results['seasonal_bytes']['false_negatives'] += 1
            else:
                results['seasonal_bytes']['true_negatives'] += 1
    
    # Print results
    print("\nAdaptive Thresholding Evaluation:")
    print("=================================")
    
    for feature, metrics in results.items():
        tp = metrics['true_positives']
        fp = metrics['false_positives']
        tn = metrics['true_negatives']
        fn = metrics['false_negatives']
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\n{feature} Model:")
        print(f"  Precision: {precision:.2f}")
        print(f"  Recall: {recall:.2f}")
        print(f"  F1 Score: {f1:.2f}")
        print(f"  True Positives: {tp}")
        print(f"  False Positives: {fp}")
        print(f"  True Negatives: {tn}")
        print(f"  False Negatives: {fn}")
    
    # Clean up
    manager.save_all()
    manager.stop_auto_save()

if __name__ == "__main__":
    # Run the demo
    demo_thresholding() 