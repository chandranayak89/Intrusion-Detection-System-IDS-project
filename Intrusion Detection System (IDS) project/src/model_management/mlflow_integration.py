#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MLflow Integration for Anomaly Detection Model Management
Implements MLflow-based experiment tracking, model versioning and performance monitoring.
"""

import os
import sys
import json
import logging
import tempfile
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional, Union
import mlflow
import mlflow.sklearn
from mlflow.tracking import MlflowClient

# Setup logging
logger = logging.getLogger('ids.model_management.mlflow_integration')

class MLflowModelManager:
    """
    MLflow-based model management for anomaly detection models.
    """
    
    def __init__(
        self,
        experiment_name: str = "anomaly_detection",
        model_name: str = "ids_anomaly_detector",
        tracking_uri: Optional[str] = None,
        artifact_location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the MLflow model manager.
        
        Args:
            experiment_name: Name of the MLflow experiment to use
            model_name: Name for the registered model
            tracking_uri: MLflow tracking server URI (None for local)
            artifact_location: Location to store artifacts (None for default)
            tags: Additional tags to apply to the experiment
        """
        self.experiment_name = experiment_name
        self.model_name = model_name
        self.tracking_uri = tracking_uri
        self.artifact_location = artifact_location
        self.tags = tags or {}
        
        # Initialize MLflow
        self._setup_mlflow()
        
        # Initialize client and experiment
        self.client = MlflowClient(tracking_uri=tracking_uri)
        self.experiment = self._get_or_create_experiment()
        
        # Current run tracking
        self.active_run = None
        self.run_id = None
        
    def _setup_mlflow(self) -> None:
        """Set up MLflow tracking."""
        if self.tracking_uri:
            mlflow.set_tracking_uri(self.tracking_uri)
            
        # Add system info to default tags
        self.tags.update({
            "platform": sys.platform,
            "python_version": sys.version.split(" ")[0],
            "mlflow_version": mlflow.__version__
        })
    
    def _get_or_create_experiment(self) -> mlflow.entities.Experiment:
        """Get or create the MLflow experiment."""
        experiment = mlflow.get_experiment_by_name(self.experiment_name)
        
        if experiment is None:
            logger.info(f"Creating new experiment: {self.experiment_name}")
            experiment_id = mlflow.create_experiment(
                name=self.experiment_name,
                artifact_location=self.artifact_location,
                tags=self.tags
            )
            experiment = mlflow.get_experiment(experiment_id)
        else:
            logger.info(f"Using existing experiment: {self.experiment_name} (ID: {experiment.experiment_id})")
            
        return experiment
    
    def start_run(self, run_name: Optional[str] = None, tags: Optional[Dict[str, str]] = None) -> str:
        """
        Start a new MLflow run.
        
        Args:
            run_name: Name for the run
            tags: Additional tags for the run
            
        Returns:
            Run ID
        """
        if self.active_run:
            logger.warning("Ending existing run before starting new one")
            self.end_run()
            
        # Generate run name if not provided
        if run_name is None:
            run_name = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
        # Combine instance tags with run-specific tags
        run_tags = dict(self.tags)
        if tags:
            run_tags.update(tags)
            
        # Start the run
        self.active_run = mlflow.start_run(
            experiment_id=self.experiment.experiment_id,
            run_name=run_name,
            tags=run_tags
        )
        self.run_id = self.active_run.info.run_id
        
        logger.info(f"Started MLflow run: {run_name} (ID: {self.run_id})")
        return self.run_id
    
    def end_run(self) -> None:
        """End the current MLflow run."""
        if self.active_run:
            mlflow.end_run()
            logger.info(f"Ended MLflow run: {self.run_id}")
            self.active_run = None
            self.run_id = None
    
    def log_params(self, params: Dict[str, Any]) -> None:
        """
        Log parameters to the current run.
        
        Args:
            params: Dictionary of parameters to log
        """
        if not self.active_run:
            self.start_run()
            
        # Convert non-string params to strings
        str_params = {}
        for key, value in params.items():
            if isinstance(value, (dict, list, tuple)):
                str_params[key] = json.dumps(value)
            else:
                str_params[key] = str(value)
                
        mlflow.log_params(str_params)
        logger.debug(f"Logged {len(params)} parameters")
    
    def log_metrics(self, metrics: Dict[str, float], step: Optional[int] = None) -> None:
        """
        Log metrics to the current run.
        
        Args:
            metrics: Dictionary of metrics to log
            step: Step number (optional)
        """
        if not self.active_run:
            self.start_run()
            
        mlflow.log_metrics(metrics, step=step)
        logger.debug(f"Logged {len(metrics)} metrics")
    
    def log_artifact(self, local_path: str, artifact_path: Optional[str] = None) -> None:
        """
        Log an artifact to the current run.
        
        Args:
            local_path: Local path to the artifact file
            artifact_path: Path within the artifact directory (optional)
        """
        if not self.active_run:
            self.start_run()
            
        mlflow.log_artifact(local_path, artifact_path)
        logger.debug(f"Logged artifact: {local_path}")
    
    def log_model(
        self, 
        model, 
        artifact_path: str = "model",
        registered_model_name: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Log a model to the current run.
        
        Args:
            model: Model object to log
            artifact_path: Path within the artifact directory
            registered_model_name: Name to register the model under (optional)
            **kwargs: Additional arguments for mlflow.sklearn.log_model
            
        Returns:
            Model URI
        """
        if not self.active_run:
            self.start_run()
            
        # Use the class model name if not provided
        if registered_model_name is None:
            registered_model_name = self.model_name
            
        # Log the model
        result = mlflow.sklearn.log_model(
            sk_model=model,
            artifact_path=artifact_path,
            registered_model_name=registered_model_name,
            **kwargs
        )
        
        logger.info(f"Logged model: {registered_model_name}")
        return result.model_uri
    
    def log_feature_importance(
        self, 
        feature_importance: Dict[str, float],
        artifact_name: str = "feature_importance.json"
    ) -> None:
        """
        Log feature importance to the current run.
        
        Args:
            feature_importance: Dictionary mapping feature names to importance scores
            artifact_name: Name of the artifact file
        """
        if not self.active_run:
            self.start_run()
            
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(feature_importance, f, indent=2)
            temp_path = f.name
            
        # Log the artifact
        self.log_artifact(temp_path, artifact_path="feature_importance")
        
        # Clean up
        os.remove(temp_path)
        logger.debug(f"Logged feature importance for {len(feature_importance)} features")
    
    def log_data_profile(self, data: pd.DataFrame, profile_name: str = "data_profile") -> None:
        """
        Log a data profile to the current run.
        
        Args:
            data: DataFrame to profile
            profile_name: Name for the profile
        """
        if not self.active_run:
            self.start_run()
            
        # Compute basic statistics
        profile = {
            "n_rows": len(data),
            "n_columns": len(data.columns),
            "column_names": list(data.columns),
            "dtypes": {col: str(dtype) for col, dtype in data.dtypes.items()}
        }
        
        # Compute statistics for numeric columns
        numeric_stats = {}
        for col in data.select_dtypes(include=np.number).columns:
            col_stats = {
                "mean": data[col].mean(),
                "std": data[col].std(),
                "min": data[col].min(),
                "25%": data[col].quantile(0.25),
                "median": data[col].median(),
                "75%": data[col].quantile(0.75),
                "max": data[col].max(),
                "missing": data[col].isnull().sum()
            }
            numeric_stats[col] = col_stats
            
        profile["numeric_stats"] = numeric_stats
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(profile, f, indent=2)
            temp_path = f.name
            
        # Log the artifact
        self.log_artifact(temp_path, artifact_path="data_profiles")
        
        # Clean up
        os.remove(temp_path)
        logger.debug(f"Logged data profile for DataFrame with {len(data)} rows")
    
    def get_best_model(
        self,
        metric_name: str = "accuracy",
        max_results: int = 5,
        stage: str = "Production"
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Get the best model based on a metric.
        
        Args:
            metric_name: Name of the metric to use
            max_results: Maximum number of runs to consider
            stage: Model stage to filter by
            
        Returns:
            Tuple of (model_uri, run_info)
        """
        # Search for runs with the metric
        query = f"metric.`{metric_name}` IS NOT NULL"
        runs = mlflow.search_runs(
            experiment_ids=[self.experiment.experiment_id],
            filter_string=query,
            max_results=max_results,
            order_by=[f"metric.`{metric_name}` DESC"]
        )
        
        if len(runs) == 0:
            logger.warning(f"No runs found with metric {metric_name}")
            return None, {}
        
        # Get the best run
        best_run_id = runs.iloc[0]["run_id"]
        best_metric_value = runs.iloc[0][f"metrics.{metric_name}"]
        
        # Get the model URI
        client = MlflowClient()
        
        try:
            # Try to get the registered model
            versions = client.get_latest_versions(self.model_name, stages=[stage])
            if versions:
                model_uri = versions[0].source
                run_info = {
                    "run_id": best_run_id,
                    "metric_name": metric_name,
                    "metric_value": best_metric_value,
                    "model_uri": model_uri,
                    "model_version": versions[0].version,
                    "model_stage": versions[0].current_stage
                }
                logger.info(f"Found best model: {model_uri} with {metric_name} = {best_metric_value}")
                return model_uri, run_info
        except Exception as e:
            logger.warning(f"Error getting registered model: {e}")
        
        # Fallback to the run's model
        model_uri = f"runs:/{best_run_id}/model"
        run_info = {
            "run_id": best_run_id,
            "metric_name": metric_name,
            "metric_value": best_metric_value,
            "model_uri": model_uri
        }
        
        logger.info(f"Found best model: {model_uri} with {metric_name} = {best_metric_value}")
        return model_uri, run_info
    
    def load_model(self, model_uri: Optional[str] = None) -> Any:
        """
        Load a model from MLflow.
        
        Args:
            model_uri: URI of the model to load (None for latest production model)
            
        Returns:
            Loaded model
        """
        # If no URI provided, get the latest production model
        if model_uri is None:
            model_uri, _ = self.get_best_model()
            if model_uri is None:
                raise ValueError("No model found in the registry")
        
        # Load the model
        model = mlflow.sklearn.load_model(model_uri)
        logger.info(f"Loaded model from {model_uri}")
        return model
    
    def register_model(
        self,
        model_uri: str,
        name: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None
    ) -> mlflow.entities.model_registry.ModelVersion:
        """
        Register a model with the MLflow Model Registry.
        
        Args:
            model_uri: URI of the model to register
            name: Name to register the model under (optional)
            tags: Additional tags for the model version
            
        Returns:
            ModelVersion object
        """
        # Use the class model name if not provided
        if name is None:
            name = self.model_name
            
        # Register the model
        model_details = mlflow.register_model(model_uri, name)
        
        # Add tags if provided
        if tags:
            for key, value in tags.items():
                self.client.set_model_version_tag(name, model_details.version, key, value)
        
        logger.info(f"Registered model {name} version {model_details.version}")
        return model_details
    
    def promote_model(
        self,
        version: Union[int, str],
        stage: str,
        name: Optional[str] = None,
        archive_existing_versions: bool = True
    ) -> mlflow.entities.model_registry.ModelVersion:
        """
        Promote a model to a new stage.
        
        Args:
            version: Model version to promote
            stage: Stage to promote to ('Staging', 'Production', 'Archived')
            name: Model name (optional)
            archive_existing_versions: Whether to archive existing versions in the target stage
            
        Returns:
            Updated ModelVersion object
        """
        # Use the class model name if not provided
        if name is None:
            name = self.model_name
        
        # Convert version to string if it's an integer
        if isinstance(version, int):
            version = str(version)
            
        # Promote the model
        client = MlflowClient()
        
        # Archive existing versions if requested
        if archive_existing_versions:
            for model_version in client.get_latest_versions(name, stages=[stage]):
                logger.info(f"Archiving {name} version {model_version.version} "
                           f"from {model_version.current_stage}")
                client.transition_model_version_stage(
                    name=name,
                    version=model_version.version,
                    stage="Archived"
                )
        
        # Transition the specified version to the target stage
        model_details = client.transition_model_version_stage(
            name=name,
            version=version,
            stage=stage
        )
        
        logger.info(f"Promoted {name} version {version} to {stage}")
        return model_details
    
    def get_model_info(
        self,
        name: Optional[str] = None,
        version: Optional[str] = None,
        stage: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get information about registered models.
        
        Args:
            name: Model name (optional)
            version: Model version (optional)
            stage: Model stage (optional)
            
        Returns:
            List of model info dictionaries
        """
        # Use the class model name if not provided
        if name is None:
            name = self.model_name
            
        client = MlflowClient()
        model_info = []
        
        try:
            # If version is specified, get that specific version
            if version is not None:
                model_version = client.get_model_version(name, version)
                model_info.append({
                    "name": model_version.name,
                    "version": model_version.version,
                    "stage": model_version.current_stage,
                    "creation_timestamp": model_version.creation_timestamp,
                    "last_updated_timestamp": model_version.last_updated_timestamp,
                    "description": model_version.description,
                    "source": model_version.source,
                    "run_id": model_version.run_id
                })
            # Otherwise, get all versions filtered by stage if provided
            else:
                stages = [stage] if stage else None
                for model_version in client.get_latest_versions(name, stages=stages):
                    model_info.append({
                        "name": model_version.name,
                        "version": model_version.version,
                        "stage": model_version.current_stage,
                        "creation_timestamp": model_version.creation_timestamp,
                        "last_updated_timestamp": model_version.last_updated_timestamp,
                        "description": model_version.description,
                        "source": model_version.source,
                        "run_id": model_version.run_id
                    })
        except Exception as e:
            logger.warning(f"Error getting model info: {e}")
            
        return model_info 