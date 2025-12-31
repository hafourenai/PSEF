import yaml
import os
from typing import Dict, Any

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file"""
    if not os.path.exists(config_path):
        return {}
    
    with open(config_path, 'r') as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError:
            return {}

def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration structure"""
    # Simple validation for now
    required_keys = ['http', 'exploitation']
    return all(key in config for key in required_keys)
