#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Config Loader Module
This module handles loading and validating configuration files.
"""

import os
import yaml
import logging
import json

# Setup logging
logger = logging.getLogger('ids.config_loader')

def load_config(config_path):
    """
    Load configuration from a file.
    
    Args:
        config_path (str): Path to the configuration file
        
    Returns:
        dict: Loaded configuration
        
    Raises:
        FileNotFoundError: If the config file is not found
        ValueError: If the config file is invalid
    """
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        raise FileNotFoundError(f"Config file not found: {config_path}")
        
    try:
        # Determine file type from extension
        _, ext = os.path.splitext(config_path)
        
        if ext.lower() in ('.yaml', '.yml'):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        elif ext.lower() == '.json':
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            logger.error(f"Unsupported config file format: {ext}")
            raise ValueError(f"Unsupported config file format: {ext}")
            
        if not isinstance(config, dict):
            logger.error("Invalid config file format: root must be a dictionary")
            raise ValueError("Invalid config file format: root must be a dictionary")
            
        logger.info(f"Loaded configuration from {config_path}")
        return config
        
    except Exception as e:
        logger.error(f"Error loading config file: {e}")
        raise

def validate_config(config, schema=None):
    """
    Validate configuration against a schema.
    
    Args:
        config (dict): Configuration to validate
        schema (dict, optional): Schema to validate against
        
    Returns:
        bool: True if valid, False otherwise
    """
    if schema is None:
        # No schema provided, assume valid
        return True
        
    try:
        # Basic validation
        if not isinstance(config, dict):
            logger.error("Invalid config format: must be a dictionary")
            return False
            
        # Check required fields
        for key, spec in schema.items():
            if spec.get('required', False) and key not in config:
                logger.error(f"Missing required config field: {key}")
                return False
                
            if key in config:
                # Type validation
                if 'type' in spec:
                    if spec['type'] == 'dict' and not isinstance(config[key], dict):
                        logger.error(f"Invalid type for config field {key}: expected dict")
                        return False
                    elif spec['type'] == 'list' and not isinstance(config[key], list):
                        logger.error(f"Invalid type for config field {key}: expected list")
                        return False
                    elif spec['type'] == 'int' and not isinstance(config[key], int):
                        logger.error(f"Invalid type for config field {key}: expected int")
                        return False
                    elif spec['type'] == 'str' and not isinstance(config[key], str):
                        logger.error(f"Invalid type for config field {key}: expected str")
                        return False
                    elif spec['type'] == 'bool' and not isinstance(config[key], bool):
                        logger.error(f"Invalid type for config field {key}: expected bool")
                        return False
                        
                # Recursive validation for nested dictionaries
                if spec.get('type') == 'dict' and 'schema' in spec:
                    if not validate_config(config[key], spec['schema']):
                        return False
                        
                # Validation for lists of dictionaries
                if spec.get('type') == 'list' and 'item_schema' in spec:
                    for item in config[key]:
                        if not validate_config(item, spec['item_schema']):
                            return False
                            
        return True
        
    except Exception as e:
        logger.error(f"Error validating config: {e}")
        return False

def get_default_config():
    """
    Get the default configuration.
    
    Returns:
        dict: Default configuration
    """
    return {
        'logging': {
            'level': 'INFO',
            'file': None,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'network': {
            'interface': None,
            'bpf_filter': '',
            'use_pyshark': False
        },
        'detection': {
            'signature_rules_file': 'config/signature_rules.yaml',
            'anomaly_detector': {
                'type': 'isolation_forest',
                'contamination': 0.1,
                'model_path': None
            }
        },
        'alerts': {
            'forwarders': [
                {
                    'type': 'file',
                    'log_file': 'logs/alerts.log'
                }
            ]
        }
    }

def merge_configs(default_config, user_config):
    """
    Merge user configuration with default configuration.
    
    Args:
        default_config (dict): Default configuration
        user_config (dict): User-provided configuration
        
    Returns:
        dict: Merged configuration
    """
    if not user_config:
        return default_config.copy()
        
    result = default_config.copy()
    
    # Helper function for recursive merging
    def _merge_dict(target, source):
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                _merge_dict(target[key], value)
            else:
                target[key] = value
                
    _merge_dict(result, user_config)
    return result

def create_default_config(config_path):
    """
    Create a default configuration file.
    
    Args:
        config_path (str): Path to save the configuration file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        directory = os.path.dirname(config_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
        # Determine file format from extension
        _, ext = os.path.splitext(config_path)
        config = get_default_config()
        
        if ext.lower() in ('.yaml', '.yml'):
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        elif ext.lower() == '.json':
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        else:
            logger.error(f"Unsupported config file format: {ext}")
            return False
            
        logger.info(f"Created default configuration at {config_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error creating default config: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create default config
    config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config')
    os.makedirs(config_dir, exist_ok=True)
    
    config_path = os.path.join(config_dir, 'config.yaml')
    if not os.path.exists(config_path):
        create_default_config(config_path)
        
    # Load config
    config = load_config(config_path)
    print(json.dumps(config, indent=2)) 