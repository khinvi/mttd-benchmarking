"""
Utility functions for the MTTD Benchmarking Framework.
"""

import logging
import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def configure_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: Optional[str] = None
) -> None:
    """
    Configure logging settings.
    
    Args:
        log_level: Logging level
        log_file: Path to log file
        log_format: Log message format
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Default log format
    log_format = log_format or "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configure root logger
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))
    handlers.append(console_handler)
    
    # File handler if specified
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=handlers
    )
    
    logger.info(f"Logging initialized at level {log_level}")


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: Optional[str] = None
) -> None:
    """
    Set up logging configuration (alias for configure_logging).
    
    Args:
        log_level: Logging level
        log_file: Path to log file
        log_format: Log message format
    """
    return configure_logging(log_level, log_file, log_format)


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a JSON file.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
        
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        logger.info(f"Loaded configuration from {config_path}")
        return config
    
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {str(e)}")
        raise
    
    except Exception as e:
        logger.error(f"Error loading config file: {str(e)}")
        raise


def save_config(config: Dict[str, Any], config_path: str) -> None:
    """
    Save configuration to a JSON file.
    
    Args:
        config: Configuration dictionary
        config_path: Path to save the config file
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
            
        logger.info(f"Saved configuration to {config_path}")
    
    except Exception as e:
        logger.error(f"Error saving config file: {str(e)}")
        raise


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 0:
        return "N/A"
        
    if seconds < 1:
        return f"{seconds*1000:.2f} ms"
    
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    
    if seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    
    hours = seconds / 3600
    return f"{hours:.2f} hours"


def format_timestamp(timestamp: datetime) -> str:
    """
    Format a timestamp to a human-readable string.
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse a timestamp string to a datetime object.
    
    Args:
        timestamp_str: Timestamp string
        
    Returns:
        Datetime object
    """
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except ValueError:
        # Try other common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
                
        # If all formats fail, raise the error
        raise ValueError(f"Unsupported timestamp format: {timestamp_str}")


def validate_json_schema(data: Any, schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate data against a JSON schema.
    
    Args:
        data: Data to validate
        schema: JSON schema
        
    Returns:
        Dictionary with validation results
    """
    try:
        import jsonschema
        jsonschema.validate(instance=data, schema=schema)
        return {"valid": True, "errors": []}
    
    except ImportError:
        logger.warning("jsonschema package not installed, skipping schema validation")
        return {"valid": True, "errors": ["jsonschema package not installed"]}
    
    except jsonschema.exceptions.ValidationError as e:
        return {"valid": False, "errors": [str(e)]}
    
    except Exception as e:
        return {"valid": False, "errors": [f"Validation error: {str(e)}"]}


def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two configuration dictionaries, with override_config taking precedence.
    
    Args:
        base_config: Base configuration
        override_config: Override configuration
        
    Returns:
        Merged configuration
    """
    result = base_config.copy()
    
    for key, value in override_config.items():
        # If both configs have this key and both values are dictionaries, recursively merge
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            # Otherwise, override or add the key
            result[key] = value
            
    return result