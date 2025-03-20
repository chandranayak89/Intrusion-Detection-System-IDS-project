#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parallel Processing Module
This module provides optimized parallel processing capabilities using 
multi-threading and async processing for efficient event handling.
"""

import os
import sys
import time
import queue
import asyncio
import logging
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, List, Tuple, Callable, Optional, Any, Union, TypeVar, Generic

# Configure logging
logger = logging.getLogger("ids.optimization.parallel_processing")

# Type variables for generic typing
T = TypeVar('T')  # Input type
R = TypeVar('R')  # Result type

class Task(Generic[T, R]):
    """Represents a task to be processed by a worker"""
    
    def __init__(self, task_id: str, data: T):
        """
        Initialize a task
        
        Args:
            task_id: Unique identifier for the task
            data: Data to be processed
        """
        self.task_id = task_id
        self.data = data
        self.result = None
        self.error = None
        self.start_time = 0
        self.end_time = 0
        self.completed = False

class Worker:
    """Base class for task workers"""
    
    def process_task(self, task: Task) -> None:
        """
        Process a task
        
        Args:
            task: Task to process
        """
        raise NotImplementedError("Subclasses must implement process_task")

class ThreadPoolManager:
    """Thread pool for parallel task processing"""
    
    def __init__(self, num_workers: int = None, queue_size: int = 10000):
        """
        Initialize the thread pool manager
        
        Args:
            num_workers: Number of worker threads (default: CPU count * 2)
            queue_size: Maximum size of the task queue
        """
        self.num_workers = num_workers or (multiprocessing.cpu_count() * 2)
        self.task_queue = queue.Queue(maxsize=queue_size)
        self.result_queue = queue.Queue()
        self.workers = []
        self.running = False
        self.stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_processing_time": 0,
            "total_processing_time": 0
        }
    
    def start(self, worker: Worker) -> None:
        """
        Start the thread pool
        
        Args:
            worker: Worker instance for processing tasks
        """
        if self.running:
            logger.warning("Thread pool already running")
            return
            
        self.running = True
        
        # Start worker threads
        for i in range(self.num_workers):
            thread = threading.Thread(
                target=self._worker_thread,
                args=(worker,),
                name=f"worker-{i}"
            )
            thread.daemon = True
            thread.start()
            self.workers.append(thread)
            
        logger.info(f"Started thread pool with {self.num_workers} worker threads")
    
    def stop(self) -> Dict[str, Any]:
        """
        Stop the thread pool and return statistics
        
        Returns:
            Dictionary with processing statistics
        """
        if not self.running:
            return self.stats
            
        self.running = False
        
        # Put sentinel tasks to signal workers to stop
        for _ in range(self.num_workers):
            try:
                self.task_queue.put(None, block=False)
            except queue.Full:
                pass
        
        # Wait for threads to finish
        for thread in self.workers:
            thread.join(timeout=1.0)
            
        logger.info(f"Stopped thread pool. Processed {self.stats['tasks_completed']} tasks "
                   f"with {self.stats['tasks_failed']} failures")
        
        return self.stats
    
    def submit_task(self, task: Task) -> bool:
        """
        Submit a task for processing
        
        Args:
            task: Task to process
            
        Returns:
            True if the task was submitted, False otherwise
        """
        if not self.running:
            logger.warning("Thread pool not running")
            return False
            
        try:
            self.task_queue.put(task, block=True, timeout=0.1)
            self.stats["tasks_submitted"] += 1
            return True
        except queue.Full:
            logger.warning(f"Task queue full, could not submit task {task.task_id}")
            return False
    
    def get_result(self, block: bool = True, timeout: float = None) -> Optional[Task]:
        """
        Get a completed task from the result queue
        
        Args:
            block: Whether to block waiting for a result
            timeout: Timeout in seconds if blocking
            
        Returns:
            Completed task or None if no results are available
        """
        try:
            return self.result_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
    
    def _worker_thread(self, worker: Worker) -> None:
        """
        Worker thread function
        
        Args:
            worker: Worker instance for processing tasks
        """
        while self.running:
            try:
                # Get a task from the queue
                task = self.task_queue.get(block=True, timeout=0.1)
                
                # Check for sentinel task
                if task is None:
                    break
                    
                # Process the task
                task.start_time = time.time()
                try:
                    worker.process_task(task)
                    task.completed = True
                    self.stats["tasks_completed"] += 1
                except Exception as e:
                    task.error = str(e)
                    task.completed = False
                    self.stats["tasks_failed"] += 1
                    logger.error(f"Error processing task {task.task_id}: {e}")
                finally:
                    task.end_time = time.time()
                    processing_time = task.end_time - task.start_time
                    
                    # Update statistics
                    self.stats["total_processing_time"] += processing_time
                    if self.stats["tasks_completed"] > 0:
                        self.stats["avg_processing_time"] = (
                            self.stats["total_processing_time"] / self.stats["tasks_completed"]
                        )
                    
                    # Put the completed task in the result queue
                    try:
                        self.result_queue.put(task, block=True, timeout=0.1)
                    except queue.Full:
                        logger.warning(f"Result queue full, dropping completed task {task.task_id}")
                    
                    # Mark the task as done in the input queue
                    self.task_queue.task_done()
                    
            except queue.Empty:
                continue
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error in worker thread: {e}")


class ProcessPoolManager:
    """Process pool for CPU-bound parallel task processing"""
    
    def __init__(self, num_processes: int = None, max_tasks_per_child: int = 1000):
        """
        Initialize the process pool manager
        
        Args:
            num_processes: Number of worker processes (default: CPU count)
            max_tasks_per_child: Maximum number of tasks per worker before respawning
        """
        self.num_processes = num_processes or multiprocessing.cpu_count()
        self.max_tasks_per_child = max_tasks_per_child
        self.executor = None
        self.futures = {}
        self.running = False
        self.stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0
        }
    
    def start(self) -> None:
        """Start the process pool"""
        if self.running:
            logger.warning("Process pool already running")
            return
            
        self.running = True
        self.executor = ProcessPoolExecutor(
            max_workers=self.num_processes,
            max_tasks_per_child=self.max_tasks_per_child
        )
        
        logger.info(f"Started process pool with {self.num_processes} worker processes")
    
    def stop(self) -> Dict[str, Any]:
        """
        Stop the process pool and return statistics
        
        Returns:
            Dictionary with processing statistics
        """
        if not self.running:
            return self.stats
            
        self.running = False
        
        # Cancel any pending futures
        for future in self.futures.values():
            future.cancel()
            
        # Shutdown the executor
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
            
        logger.info(f"Stopped process pool. Processed {self.stats['tasks_completed']} tasks "
                   f"with {self.stats['tasks_failed']} failures")
        
        return self.stats
    
    def submit_task(self, task_id: str, func: Callable[..., R], *args, **kwargs) -> bool:
        """
        Submit a function for processing
        
        Args:
            task_id: Unique identifier for the task
            func: Function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            True if the task was submitted, False otherwise
        """
        if not self.running or not self.executor:
            logger.warning("Process pool not running")
            return False
            
        try:
            future = self.executor.submit(func, *args, **kwargs)
            self.futures[task_id] = future
            self.stats["tasks_submitted"] += 1
            
            # Add a callback to update statistics when the task completes
            future.add_done_callback(
                lambda f, tid=task_id: self._task_completed(tid, f)
            )
            
            return True
        except Exception as e:
            logger.error(f"Error submitting task {task_id} to process pool: {e}")
            return False
    
    def get_result(self, task_id: str, timeout: float = None) -> Optional[R]:
        """
        Get the result of a task
        
        Args:
            task_id: Unique identifier of the task
            timeout: Timeout in seconds
            
        Returns:
            Task result or None if not available
        """
        if task_id not in self.futures:
            logger.warning(f"No task found with ID {task_id}")
            return None
            
        future = self.futures[task_id]
        
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            logger.warning(f"Timeout waiting for result of task {task_id}")
            return None
        except Exception as e:
            logger.error(f"Error getting result of task {task_id}: {e}")
            return None
    
    def _task_completed(self, task_id: str, future) -> None:
        """
        Callback for when a task completes
        
        Args:
            task_id: Unique identifier of the task
            future: Future object
        """
        try:
            # Check if the task completed successfully
            if future.exception() is None:
                self.stats["tasks_completed"] += 1
            else:
                self.stats["tasks_failed"] += 1
                logger.error(f"Task {task_id} failed: {future.exception()}")
                
            # Remove the future from the tracking dict
            self.futures.pop(task_id, None)
            
        except Exception as e:
            logger.error(f"Error in task completion callback for task {task_id}: {e}")


class AsyncTaskManager:
    """Asynchronous task manager for non-blocking event processing"""
    
    def __init__(self, max_concurrent: int = 1000):
        """
        Initialize the async task manager
        
        Args:
            max_concurrent: Maximum number of concurrent tasks
        """
        self.max_concurrent = max_concurrent
        self.semaphore = None
        self.tasks = {}
        self.loop = None
        self.running = False
        self.stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_processing_time": 0,
            "total_processing_time": 0
        }
    
    async def _initialize(self) -> None:
        """Initialize the async task manager"""
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.running = True
    
    def start(self) -> None:
        """Start the async task manager"""
        if self.running:
            logger.warning("Async task manager already running")
            return
            
        # Get or create an event loop
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
        # Initialize
        self.loop.run_until_complete(self._initialize())
        
        logger.info(f"Started async task manager with max {self.max_concurrent} concurrent tasks")
    
    def stop(self) -> Dict[str, Any]:
        """
        Stop the async task manager and return statistics
        
        Returns:
            Dictionary with processing statistics
        """
        if not self.running:
            return self.stats
            
        self.running = False
        
        # Cancel any pending tasks
        if self.loop and self.tasks:
            for task in self.tasks.values():
                task.cancel()
            
            # Wait for tasks to cancel
            pending = [t for t in self.tasks.values() if not t.done()]
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                
        logger.info(f"Stopped async task manager. Processed {self.stats['tasks_completed']} tasks "
                   f"with {self.stats['tasks_failed']} failures")
        
        return self.stats
    
    async def _run_task(self, task_id: str, coro) -> Any:
        """
        Run a coroutine with the semaphore
        
        Args:
            task_id: Unique identifier for the task
            coro: Coroutine to run
            
        Returns:
            Result of the coroutine
        """
        start_time = time.time()
        
        try:
            async with self.semaphore:
                result = await coro
                self.stats["tasks_completed"] += 1
                return result
                
        except asyncio.CancelledError:
            logger.warning(f"Task {task_id} was cancelled")
            raise
            
        except Exception as e:
            self.stats["tasks_failed"] += 1
            logger.error(f"Error in async task {task_id}: {e}")
            raise
            
        finally:
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Update statistics
            self.stats["total_processing_time"] += processing_time
            if self.stats["tasks_completed"] > 0:
                self.stats["avg_processing_time"] = (
                    self.stats["total_processing_time"] / self.stats["tasks_completed"]
                )
                
            # Remove task from tracking
            self.tasks.pop(task_id, None)
    
    def submit_task(self, task_id: str, coro) -> bool:
        """
        Submit a coroutine for execution
        
        Args:
            task_id: Unique identifier for the task
            coro: Coroutine to execute
            
        Returns:
            True if the task was submitted, False otherwise
        """
        if not self.running or not self.loop:
            logger.warning("Async task manager not running")
            return False
            
        try:
            # Create and schedule the task
            task = self.loop.create_task(self._run_task(task_id, coro))
            self.tasks[task_id] = task
            self.stats["tasks_submitted"] += 1
            
            return True
        except Exception as e:
            logger.error(f"Error submitting async task {task_id}: {e}")
            return False
    
    def run_until_complete(self, coro) -> Any:
        """
        Run a coroutine to completion
        
        Args:
            coro: Coroutine to run
            
        Returns:
            Result of the coroutine
        """
        if not self.loop:
            raise RuntimeError("Async task manager not started")
            
        return self.loop.run_until_complete(coro)


# Example worker implementation
class ExampleWorker(Worker):
    """Example worker that processes tasks"""
    
    def process_task(self, task: Task) -> None:
        """Process a task by setting its result"""
        # Simulate processing time
        time.sleep(0.01)
        
        # Set the result
        task.result = f"Processed task {task.task_id}: {task.data}"

# Example async task
async def example_async_task(task_id: str, data: Any) -> str:
    """
    Example async task
    
    Args:
        task_id: Task identifier
        data: Input data
        
    Returns:
        Processed result
    """
    # Simulate async processing
    await asyncio.sleep(0.01)
    
    # Return the result
    return f"Processed async task {task_id}: {data}"

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example with thread pool
    def thread_pool_example():
        # Create thread pool
        pool = ThreadPoolManager(num_workers=4)
        
        # Create worker
        worker = ExampleWorker()
        
        # Start the pool
        pool.start(worker)
        
        try:
            # Submit some tasks
            for i in range(100):
                task = Task(f"task-{i}", f"data-{i}")
                pool.submit_task(task)
                
            # Get results
            completed = 0
            while completed < 100:
                result = pool.get_result(block=True, timeout=1.0)
                if result:
                    print(f"Got result: {result.result}")
                    completed += 1
                    
        finally:
            # Stop the pool
            stats = pool.stop()
            print(f"Thread pool stats: {stats}")
    
    # Example with process pool
    def process_pool_example():
        # Create process pool
        pool = ProcessPoolManager(num_processes=2)
        
        # Start the pool
        pool.start()
        
        try:
            # Example function for the process pool
            def process_data(data):
                import time
                time.sleep(0.01)  # Simulate processing
                return f"Processed {data} in process {os.getpid()}"
                
            # Submit some tasks
            for i in range(10):
                pool.submit_task(f"task-{i}", process_data, f"data-{i}")
                
            # Get results
            for i in range(10):
                result = pool.get_result(f"task-{i}", timeout=2.0)
                print(f"Process result for task-{i}: {result}")
                
        finally:
            # Stop the pool
            stats = pool.stop()
            print(f"Process pool stats: {stats}")
    
    # Example with async tasks
    def async_example():
        # Create async manager
        async_mgr = AsyncTaskManager(max_concurrent=10)
        
        # Start the manager
        async_mgr.start()
        
        try:
            async def run_tasks():
                # Submit some tasks
                for i in range(10):
                    async_mgr.submit_task(f"task-{i}", example_async_task(f"task-{i}", f"data-{i}"))
                    
                # Wait for all tasks to complete
                pending_tasks = list(async_mgr.tasks.values())
                results = await asyncio.gather(*pending_tasks)
                
                for result in results:
                    print(f"Async result: {result}")
            
            # Run the tasks
            async_mgr.run_until_complete(run_tasks())
            
        finally:
            # Stop the manager
            stats = async_mgr.stop()
            print(f"Async manager stats: {stats}")
    
    # Run the examples
    print("\n=== Thread Pool Example ===")
    thread_pool_example()
    
    print("\n=== Process Pool Example ===")
    process_pool_example()
    
    print("\n=== Async Task Example ===")
    async_example() 