"""
Configuration management for SOC Toolkit
"""

import os
from pathlib import Path


class Config:
    """Configuration settings"""
    
    VERSION = "2.0.0"
    TIMEOUT = 15
    USER_AGENT = "SOC-Toolkit/2.0 (https://github.com/frkndncr/soc-toolkit)"
    MAX_WORKERS = 10
    
    # API Keys - Free providers (no key needed for basic use)
    GREYNOISE_API_KEY: str = ""
    PULSEDIVE_API_KEY: str = ""
    MALTIVERSE_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    IPINFO_API_KEY: str = ""
    
    # API Keys - Premium (free tier available)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    HYBRID_ANALYSIS_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    OTX_API_KEY: str = ""
    
    # API Keys - abuse.ch (free key required since May 2025)
    THREATFOX_API_KEY: str = ""
    URLHAUS_API_KEY: str = ""
    MALWAREBAZAAR_API_KEY: str = ""
    
    # API Keys - Additional premium
    BINARYEDGE_API_KEY: str = ""
    CRIMINALIP_API_KEY: str = ""
    IPQUALITYSCORE_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""
    
    # Cache settings
    CACHE_DIR = Path.home() / ".soc-toolkit" / "cache"
    CACHE_EXPIRY_HOURS = 24
    CACHE_ENABLED = True
    
    # Config file
    CONFIG_FILE = Path.home() / ".soc-toolkit" / "config.ini"
    LOG_DIR = Path.home() / ".soc-toolkit" / "logs"
    
    @classmethod
    def load_from_env(cls):
        """Load API keys from environment variables"""
        # Free tier enhanced
        cls.GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY", "")
        cls.PULSEDIVE_API_KEY = os.environ.get("PULSEDIVE_API_KEY", "")
        cls.MALTIVERSE_API_KEY = os.environ.get("MALTIVERSE_API_KEY", "")
        cls.URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
        cls.IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY", "")
        
        # Premium providers
        cls.VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
        cls.ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
        cls.HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
        cls.CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
        cls.CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
        cls.OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
        
        # abuse.ch services (free key from auth.abuse.ch)
        cls.THREATFOX_API_KEY = os.environ.get("THREATFOX_API_KEY", "")
        cls.URLHAUS_API_KEY = os.environ.get("URLHAUS_API_KEY", "")
        cls.MALWAREBAZAAR_API_KEY = os.environ.get("MALWAREBAZAAR_API_KEY", "")
        
        # Additional
        cls.BINARYEDGE_API_KEY = os.environ.get("BINARYEDGE_API_KEY", "")
        cls.CRIMINALIP_API_KEY = os.environ.get("CRIMINALIP_API_KEY", "")
        cls.IPQUALITYSCORE_API_KEY = os.environ.get("IPQUALITYSCORE_API_KEY", "")
        cls.SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
        cls.PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", "")
        
    @classmethod
    def load_from_file(cls):
        """Load config from file"""
        if cls.CONFIG_FILE.exists():
            import configparser
            config = configparser.ConfigParser()
            config.read(cls.CONFIG_FILE)
            
            if 'api_keys' in config:
                for key in ['virustotal', 'abuseipdb', 'shodan', 'otx', 'greynoise', 
                           'urlscan', 'hybrid_analysis', 'censys_id', 'censys_secret',
                           'pulsedive', 'maltiverse', 'phishtank']:
                    env_key = f"{key.upper()}_API_KEY" if 'censys' not in key else f"CENSYS_API_{key.split('_')[1].upper()}"
                    if key == 'censys_id':
                        env_key = 'CENSYS_API_ID'
                    elif key == 'censys_secret':
                        env_key = 'CENSYS_API_SECRET'
                    value = config['api_keys'].get(key, "")
                    if value:
                        setattr(cls, env_key, value)
                        
            if 'settings' in config:
                cls.CACHE_ENABLED = config['settings'].getboolean('cache_enabled', True)
                cls.CACHE_EXPIRY_HOURS = config['settings'].getint('cache_expiry_hours', 24)
                cls.TIMEOUT = config['settings'].getint('timeout', 15)
                cls.MAX_WORKERS = config['settings'].getint('max_workers', 10)
                
    @classmethod
    def save_config(cls):
        """Save config to file"""
        import configparser
        
        cls.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        config = configparser.ConfigParser()
        config['api_keys'] = {
            'virustotal': cls.VIRUSTOTAL_API_KEY,
            'abuseipdb': cls.ABUSEIPDB_API_KEY,
            'shodan': cls.SHODAN_API_KEY,
            'otx': cls.OTX_API_KEY,
            'greynoise': cls.GREYNOISE_API_KEY,
            'urlscan': cls.URLSCAN_API_KEY,
            'hybrid_analysis': cls.HYBRID_ANALYSIS_API_KEY,
            'censys_id': cls.CENSYS_API_ID,
            'censys_secret': cls.CENSYS_API_SECRET,
            'pulsedive': cls.PULSEDIVE_API_KEY,
            'maltiverse': cls.MALTIVERSE_API_KEY,
            'phishtank': cls.PHISHTANK_API_KEY,
        }
        config['settings'] = {
            'cache_enabled': str(cls.CACHE_ENABLED),
            'cache_expiry_hours': str(cls.CACHE_EXPIRY_HOURS),
            'timeout': str(cls.TIMEOUT),
            'max_workers': str(cls.MAX_WORKERS),
        }
        
        with open(cls.CONFIG_FILE, 'w') as f:
            config.write(f)
            
    @classmethod
    def init(cls):
        """Initialize configuration"""
        cls.load_from_file()
        cls.load_from_env()
        
        # Create directories
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)


Config.init()
