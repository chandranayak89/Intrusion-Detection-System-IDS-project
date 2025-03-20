# High-Performance Optimization for IDS

This module provides high-performance optimizations for real-time network intrusion detection.

## Overview

When dealing with high-throughput networks, standard packet capture and processing methods may not keep up with the traffic volume. This module addresses three critical performance bottlenecks in intrusion detection systems:

1. **Packet Capture**: Optimized packet capture using high-performance techniques
2. **Parallel Processing**: Efficient multi-threaded and asynchronous event handling
3. **GPU Acceleration**: Hardware acceleration for ML-based detection models

## Components

### 1. High-Performance Packet Capture

Captures network packets at line rate using optimized methods:

- **DPDK** (Data Plane Development Kit): Bypasses the kernel for maximum throughput
- **AF_PACKET**: Linux-specific high-performance packet capture
- **NPCAP**: Windows optimized packet capture

```python
from src.core.optimization import CaptureMethod, HighPerformanceCapture, PacketProcessor

# Create a custom packet processor
class MyPacketProcessor(PacketProcessor):
    def process_packet(self, packet_data, packet_info):
        # Process the packet
        print(f"Packet: {len(packet_data)} bytes")

# Create capture instance
capture = HighPerformanceCapture(
    interface="eth0",  # Change to your interface
    method=CaptureMethod.AF_PACKET,  # Or other method
    buffer_size=4 * 1024 * 1024,  # 4MB buffer
    bpf_filter="tcp"  # Capture only TCP packets
)

# Start capture with your processor
capture.start_capture(MyPacketProcessor(), num_processing_threads=4)

# Later, stop capture and get statistics
stats = capture.stop_capture()
print(f"Captured {stats['packets_captured']} packets at {stats['avg_pps']} packets/sec")
```

### 2. Parallel Processing

Processes events efficiently using thread pools, process pools, and async processing:

- **ThreadPoolManager**: Multi-threaded processing for I/O-bound tasks
- **ProcessPoolManager**: Multi-process processing for CPU-bound tasks
- **AsyncTaskManager**: Asynchronous processing for non-blocking operations

```python
from src.core.optimization import Task, Worker, ThreadPoolManager

# Create a custom worker
class MyWorker(Worker):
    def process_task(self, task):
        # Process the task
        task.result = f"Processed: {task.data}"

# Create thread pool
pool = ThreadPoolManager(num_workers=os.cpu_count())

# Start the pool with your worker
pool.start(MyWorker())

# Submit tasks
for i in range(100):
    task = Task(f"task-{i}", f"data-{i}")
    pool.submit_task(task)

# Get results
while True:
    result = pool.get_result(block=True, timeout=1.0)
    if result:
        print(f"Result: {result.result}")
    else:
        break

# Stop the pool
stats = pool.stop()
```

### 3. GPU Acceleration

Accelerates machine learning inference using hardware optimizations:

- **TensorRT**: NVIDIA's deep learning inference optimizer
- **ONNX Runtime**: Cross-platform, high-performance inference
- **CUDA Acceleration**: Direct GPU acceleration

```python
from src.core.optimization import AccelerationType, ModelFormat, AccelerationManager
import numpy as np

# Create acceleration manager
manager = AccelerationManager(
    model_path="model.onnx",
    model_format=ModelFormat.ONNX,
    acceleration_type=AccelerationType.ONNX_CUDA,
    batch_size=1,
    precision="fp16"  # Use fp16 for faster inference
)

# Load and optimize the model
manager.load_model()

# Prepare input data
input_data = {"input": np.random.randn(1, 3, 224, 224).astype(np.float32)}

# Run inference
outputs = manager.infer(input_data)

# Benchmark performance
benchmark_results = manager.benchmark(input_data, num_runs=100)
print(f"Inference throughput: {benchmark_results['throughput_fps']} FPS")
```

## Integrated Example

For a complete example of how to integrate all three components, see [optimized_ids_example.py](examples/optimized_ids_example.py).

## Requirements

### General Requirements
- Python 3.6+
- NumPy

### Packet Capture Requirements
- **PCAP/NPCAP**: `pip install pypcap`
- **DPDK**: Custom installation required (see [DPDK documentation](https://doc.dpdk.org/))

### Parallel Processing Requirements
- No external dependencies

### GPU Acceleration Requirements
- **ONNX Runtime**: `pip install onnxruntime-gpu` (CPU-only: `pip install onnxruntime`)
- **TensorRT**: Install NVIDIA TensorRT and `pip install pycuda`
- **PyTorch**: `pip install torch`
- **TensorFlow**: `pip install tensorflow`

## Performance Considerations

- **Memory Usage**: Larger buffer sizes improve performance but consume more memory
- **Batch Processing**: Process packets in batches for better throughput
- **Precision**: Lower precision (FP16/INT8) provides faster inference with slightly reduced accuracy
- **Thread Count**: More threads aren't always better; test to find the optimal setting for your hardware

## Troubleshooting

- **DPDK Issues**: Ensure proper system configuration (hugepages, driver binding)
- **GPU Acceleration**: Verify CUDA installation with `nvidia-smi`
- **Packet Drops**: Increase buffer size if you see packet drops
- **Performance Bottlenecks**: Use profiling tools to identify bottlenecks 