import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional

def setup_logging(level: str = "INFO", log_file: Optional[str] = "psef.log"):
    """Setup framework-wide logging configuration"""
    
    # Map string level to logging constants
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=10*1024*1024, 
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

def get_logger(name: str):
    """Get a named logger"""
    return logging.getLogger(name)
