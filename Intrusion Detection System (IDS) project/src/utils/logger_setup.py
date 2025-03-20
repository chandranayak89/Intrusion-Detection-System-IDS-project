#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logger Setup Module
This module provides functions for setting up logging for the IDS.
"""

import os
import sys
import logging
import logging.handlers
from datetime import datetime

# Default log format
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Map string log levels to logging constants
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

def setup_logger(name='ids', log_level='INFO', log_file=None, log_format=None):
    """
    Set up the logger for the IDS.
    
    Args:
        name (str): Logger name
        log_level (str): Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        log_file (str, optional): Path to log file. If None, logs will only go to console.
        log_format (str, optional): Format string for log messages.
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Convert string log level to logging constant
    level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # Set format
    formatter = logging.Formatter(log_format or DEFAULT_LOG_FORMAT)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up log file: {e}")
    
    return logger

def setup_rotating_logger(name='ids', log_level='INFO', log_file=None, log_format=None, 
                         max_bytes=10485760, backup_count=5):
    """
    Set up a rotating logger for the IDS.
    
    Args:
        name (str): Logger name
        log_level (str): Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        log_file (str, optional): Path to log file. If None, logs will only go to console.
        log_format (str, optional): Format string for log messages.
        max_bytes (int): Maximum size of each log file in bytes (default 10MB)
        backup_count (int): Number of backup files to keep (default 5)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Convert string log level to logging constant
    level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # Set format
    formatter = logging.Formatter(log_format or DEFAULT_LOG_FORMAT)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add rotating file handler if specified
    if log_file:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up rotating log file: {e}")
    
    return logger

def setup_timed_rotating_logger(name='ids', log_level='INFO', log_file=None, log_format=None,
                              when='midnight', interval=1, backup_count=7):
    """
    Set up a time-rotating logger for the IDS.
    
    Args:
        name (str): Logger name
        log_level (str): Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        log_file (str, optional): Path to log file. If None, logs will only go to console.
        log_format (str, optional): Format string for log messages.
        when (str): Type of interval ('S', 'M', 'H', 'D', 'midnight')
        interval (int): Interval count
        backup_count (int): Number of backup files to keep
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Convert string log level to logging constant
    level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()
    
    # Set format
    formatter = logging.Formatter(log_format or DEFAULT_LOG_FORMAT)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add timed rotating file handler if specified
    if log_file:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.handlers.TimedRotatingFileHandler(
                log_file, when=when, interval=interval, backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up timed rotating log file: {e}")
    
    return logger

def setup_logger_from_config(config):
    """
    Set up logger from a configuration dictionary.
    
    Args:
        config (dict): Configuration dictionary with logging settings
        
    Returns:
        logging.Logger: Configured logger instance
    """
    log_config = config.get('logging', {})
    
    log_level = log_config.get('level', 'INFO')
    log_file = log_config.get('file')
    log_format = log_config.get('format', DEFAULT_LOG_FORMAT)
    rotation = log_config.get('rotation', {})
    
    if rotation.get('enabled', False):
        if rotation.get('type') == 'timed':
            return setup_timed_rotating_logger(
                name='ids',
                log_level=log_level,
                log_file=log_file,
                log_format=log_format,
                when=rotation.get('when', 'midnight'),
                interval=rotation.get('interval', 1),
                backup_count=rotation.get('backup_count', 7)
            )
        else:  # Default to size-based rotation
            return setup_rotating_logger(
                name='ids',
                log_level=log_level,
                log_file=log_file,
                log_format=log_format,
                max_bytes=rotation.get('max_bytes', 10485760),
                backup_count=rotation.get('backup_count', 5)
            )
    else:
        return setup_logger(
            name='ids',
            log_level=log_level,
            log_file=log_file,
            log_format=log_format
        )

class IDSLogger:
    """
    IDS Logger class that maintains a hierarchy of loggers for different components.
    """
    
    def __init__(self, config=None):
        """
        Initialize the IDS logger.
        
        Args:
            config (dict, optional): Configuration dictionary with logging settings
        """
        self.config = config or {}
        self.log_config = self.config.get('logging', {})
        
        # Set up the root logger
        self.root_logger = setup_logger_from_config(self.config)
        self.loggers = {'ids': self.root_logger}
    
    def get_logger(self, name):
        """
        Get or create a logger for a specific component.
        
        Args:
            name (str): Logger name (e.g., 'ids.detection', 'ids.network')
            
        Returns:
            logging.Logger: Logger instance
        """
        if name in self.loggers:
            return self.loggers[name]
            
        # Make sure the name is prefixed with 'ids.'
        if not name.startswith('ids.'):
            name = f'ids.{name}'
            
        logger = logging.getLogger(name)
        
        # Set level from config or inherit from parent
        log_level = self.log_config.get('level', 'INFO')
        level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
        logger.setLevel(level)
        
        self.loggers[name] = logger
        return logger
        
    def reset_loggers(self):
        """
        Reset all loggers to their default state.
        """
        for name, logger in self.loggers.items():
            if logger.handlers:
                logger.handlers.clear()
                
        # Re-setup the root logger
        self.root_logger = setup_logger_from_config(self.config)
        self.loggers = {'ids': self.root_logger}
        
def create_audit_logger(audit_file, log_format=None):
    """
    Create a special logger for audit purposes.
    
    Args:
        audit_file (str): Path to the audit log file
        log_format (str, optional): Format string for log messages
        
    Returns:
        logging.Logger: Audit logger instance
    """
    # Ensure audit directory exists
    audit_dir = os.path.dirname(audit_file)
    if audit_dir and not os.path.exists(audit_dir):
        os.makedirs(audit_dir)
        
    # Create logger
    audit_logger = logging.getLogger('ids.audit')
    audit_logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    if audit_logger.handlers:
        audit_logger.handlers.clear()
        
    # Set format
    formatter = logging.Formatter(log_format or '%(asctime)s - %(message)s')
    
    # Add file handler
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            audit_file, maxBytes=52428800, backupCount=10  # 50MB, 10 backups
        )
        file_handler.setFormatter(formatter)
        audit_logger.addHandler(file_handler)
    except Exception as e:
        logging.error(f"Failed to set up audit log file: {e}")
        
    # Make sure audit logs don't propagate to parent loggers
    audit_logger.propagate = False
    
    return audit_logger

if __name__ == "__main__":
    # Example usage
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Example 1: Basic logger
    logger = setup_logger(log_file=os.path.join(logs_dir, 'ids.log'))
    logger.info("Basic logger test")
    
    # Example 2: Rotating logger
    rotating_logger = setup_rotating_logger(
        name='ids.rotating',
        log_file=os.path.join(logs_dir, 'ids_rotating.log')
    )
    rotating_logger.info("Rotating logger test")
    
    # Example 3: Timed rotating logger
    timed_logger = setup_timed_rotating_logger(
        name='ids.timed',
        log_file=os.path.join(logs_dir, 'ids_timed.log')
    )
    timed_logger.info("Timed rotating logger test")
    
    # Example 4: Logger from config
    config = {
        'logging': {
            'level': 'DEBUG',
            'file': os.path.join(logs_dir, 'ids_config.log'),
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'rotation': {
                'enabled': True,
                'type': 'size',
                'max_bytes': 1048576,  # 1MB
                'backup_count': 3
            }
        }
    }
    config_logger = setup_logger_from_config(config)
    config_logger.debug("Config logger test")
    
    # Example 5: IDS Logger hierarchy
    ids_logger = IDSLogger(config)
    detection_logger = ids_logger.get_logger('detection')
    network_logger = ids_logger.get_logger('network')
    
    detection_logger.info("Detection module test")
    network_logger.info("Network module test")
    
    # Example 6: Audit logger
    audit_logger = create_audit_logger(os.path.join(logs_dir, 'audit.log'))
    audit_logger.info(f"User action: System started at {datetime.now()}") 