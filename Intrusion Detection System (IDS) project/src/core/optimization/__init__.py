#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
High-Performance Optimization Module for IDS
This package provides optimized components for real-time intrusion detection:
1. High-speed packet capture using DPDK/AF_PACKET
2. Parallel processing for efficient event handling
3. GPU acceleration for ML-based detection
"""

import logging

# Set up package-level logger
logger = logging.getLogger("ids.optimization")
logger.setLevel(logging.INFO)

# Import components from packet capture module
from .packet_capture import (
    CaptureMethod,
    PacketProcessor,
    HighPerformanceCapture,
    SimplePacketProcessor
)

# Import components from parallel processing module
from .parallel_processing import (
    Task,
    Worker,
    ThreadPoolManager,
    ProcessPoolManager,
    AsyncTaskManager,
    ExampleWorker
)

# Import components from GPU acceleration module
from .gpu_acceleration import (
    AccelerationType,
    ModelFormat,
    AccelerationManager
)

__all__ = [
    # Packet capture
    'CaptureMethod',
    'PacketProcessor',
    'HighPerformanceCapture',
    'SimplePacketProcessor',
    
    # Parallel processing
    'Task',
    'Worker',
    'ThreadPoolManager',
    'ProcessPoolManager',
    'AsyncTaskManager',
    'ExampleWorker',
    
    # GPU acceleration
    'AccelerationType', 
    'ModelFormat',
    'AccelerationManager'
] 