"""Configuration and constants utilities for CVE Research Toolkit."""

from pathlib import Path
from typing import Any, Dict

# Optional imports with fallbacks
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False

# Constants
DEFAULT_CONFIG = "research_toolkit.yaml"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


def load_config(config_path: str = DEFAULT_CONFIG) -> Dict[str, Any]:
    """Load configuration from YAML file with fallback handling.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing configuration data, empty if file doesn't exist or YAML unavailable
    """
    config_data: Dict[str, Any] = {}
    
    if Path(config_path).exists() and YAML_AVAILABLE and yaml is not None:
        with open(config_path) as f:
            config_data = yaml.safe_load(f) or {}
    elif Path(config_path).exists():
        print(f"Warning: YAML not available, skipping config file {config_path}")
    
    return config_data


def get_default_config() -> Dict[str, Any]:
    """Get default configuration values.
    
    Returns:
        Dictionary with default configuration values
    """
    return {
        "max_concurrent": 10,
        "timeout_seconds": 30,
        "retry_attempts": 3
    }