# Automated Model Updating for Anomaly Detection

This module provides a robust system for automatically updating machine learning models for anomaly detection in an Intrusion Detection System (IDS). The system detects when model performance degrades or when data drift occurs, automatically retraining models with new data.

## Features

- **Active Learning**: Automatically labels new data and selects the most informative samples for model retraining
- **Drift Detection**: Monitors data distributions and model performance to detect when retraining is needed
- **MLflow Integration**: Tracks model versions, parameters, metrics, and manages the model lifecycle
- **Automated Retraining**: Schedules and executes model retraining when necessary
- **Model Versioning**: Maintains proper versioning and staging of models (Development, Staging, Production)
- **Metadata Tracking**: Records model update history and performance metrics over time

## Components

### 1. Active Learning System (`active_learning.py`)

The Active Learning System manages the process of automatically selecting and labeling the most informative data points for model retraining, reducing the need for manual labeling.

Key features:
- Confidence-based data filtering
- Uncertainty sampling for selecting informative examples
- Clustering for refined sample selection
- Balanced dataset generation for training

### 2. Drift Detection (`drift_detection.py`)

The Drift Detection module monitors for changes in data distribution or model performance degradation that indicate the need for model retraining.

Key features:
- Statistical distribution tests (KS-test, Wasserstein distance) for detecting data drift
- Performance monitoring to detect model degradation
- Window-based analysis to reduce false positives
- Configurable thresholds for different sensitivity levels

### 3. MLflow Integration (`mlflow_integration.py`)

The MLflow Integration component provides model tracking, versioning, and lifecycle management.

Key features:
- Experiment tracking for model iterations
- Parameter and metric logging
- Model versioning (Development, Staging, Production)
- Model registry for managing the lifecycle
- Artifact storage for models and metadata

### 4. Model Updater (`model_updater.py`)

The Model Updater coordinates the active learning, drift detection, and MLflow components to manage the end-to-end process of model maintenance.

Key features:
- Automatic checks for update necessity
- Scheduled updates based on configurable intervals
- Model update execution and validation
- Update history tracking
- Metadata management

## Usage

### Basic Setup

```python
from src.model_management.model_updater import ModelUpdater

# Create a model updater instance
model_updater = ModelUpdater(
    experiment_name="anomaly_detection",
    model_name="ids_anomaly_detector",
    update_frequency=24,  # check for updates every 24 hours
    min_samples_for_update=1000,
    performance_threshold=0.85,
    drift_threshold=0.15
)

# Initialize components with existing model (if available)
model_updater.initialize_components()

# Schedule automatic updates
model_updater.schedule_updates(data_source=my_data_source)
```

### Manual Update Check

```python
# Get current data
current_data = my_data_source.get_training_data()
validation_data = my_data_source.get_validation_data()

# Check if update is needed
update_check = model_updater.check_update_needed(current_data)

if update_check['update_needed']:
    print(f"Update needed. Reasons: {update_check['reasons']}")
    result = model_updater.update_model(
        training_data=current_data,
        validation_data=validation_data
    )
    print(f"Update success: {result['success']}")
    if result['success']:
        print(f"New model version: {result['model_version']}")
```

### Integration with MLflow UI

After running the system, you can view model versions, metrics, and experiment runs in the MLflow UI:

```bash
# Start the MLflow UI
mlflow ui --port 5000
```

Then open a browser to http://localhost:5000 to access the MLflow dashboard.

## Example

See `examples/automated_model_update_example.py` for a complete demonstration of the Automated Model Updating system.

Run the example:

```bash
python -m src.model_management.examples.automated_model_update_example --iterations 10 --interval 1
```

## Configuration Options

The Model Updater can be configured with the following parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `experiment_name` | Name of the MLflow experiment | `"anomaly_detection"` |
| `model_name` | Name of the model to manage | `"ids_anomaly_detector"` |
| `update_frequency` | How often to check for updates (hours) | `24` |
| `min_samples_for_update` | Minimum samples needed for retraining | `1000` |
| `min_update_interval` | Minimum time between updates (hours) | `12` |
| `max_update_interval` | Maximum time between updates (hours) | `168` (1 week) |
| `performance_threshold` | Minimum acceptable model performance | `0.85` |
| `drift_threshold` | Threshold for data drift to trigger retraining | `0.15` |
| `confidence_threshold` | Confidence threshold for active learning | `0.95` |
| `uncertainty_threshold` | Uncertainty threshold for active learning | `0.2` |
| `metadata_dir` | Directory to store model metadata | `~/.ids/model_metadata` |

## Requirements

- Python 3.6+
- pandas
- numpy
- scikit-learn
- MLflow
- scipy 