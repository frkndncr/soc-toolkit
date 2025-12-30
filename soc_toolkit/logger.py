"""
Logging configuration for SOC Toolkit
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from .config import Config


def get_logger(name: str = "soc_toolkit") -> logging.Logger:
    """Get configured logger instance"""
    
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG)
    
    # Console handler - INFO and above
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_format = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler - DEBUG and above
    try:
        log_dir = Path.home() / ".soc-toolkit" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"soc-toolkit_{datetime.now().strftime('%Y%m%d')}.log"
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
        
    except Exception:
        # If we can't create log file, just use console
        pass
    
    return logger


def set_log_level(level: str):
    """Set log level for all handlers"""
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }
    
    log_level = level_map.get(level.lower(), logging.INFO)
    
    logger = logging.getLogger("soc_toolkit")
    logger.setLevel(log_level)
    
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(log_level)


def enable_verbose():
    """Enable verbose console output"""
    logger = logging.getLogger("soc_toolkit")
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(logging.DEBUG)


class LogCapture:
    """Context manager to capture logs"""
    
    def __init__(self):
        self.logs = []
        self.handler = None
        
    def __enter__(self):
        self.handler = logging.Handler()
        self.handler.emit = lambda record: self.logs.append(record)
        logging.getLogger("soc_toolkit").addHandler(self.handler)
        return self
        
    def __exit__(self, *args):
        logging.getLogger("soc_toolkit").removeHandler(self.handler)
        
    def get_errors(self):
        return [r for r in self.logs if r.levelno >= logging.ERROR]
        
    def get_warnings(self):
        return [r for r in self.logs if r.levelno >= logging.WARNING]
