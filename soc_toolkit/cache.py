"""
Cache module for SOC Toolkit
Caches IOC lookup results to reduce API calls and improve speed
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Optional, Any
from datetime import datetime, timedelta

from .config import Config
from .logger import get_logger

logger = get_logger(__name__)


class Cache:
    """Simple file-based cache for IOC lookups"""
    
    def __init__(self, cache_dir: Path = None, expiry_hours: int = None):
        self.cache_dir = cache_dir or Config.CACHE_DIR
        self.expiry_hours = expiry_hours or Config.CACHE_EXPIRY_HOURS
        self.enabled = Config.CACHE_ENABLED
        
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_key(self, ioc: str, provider: str) -> str:
        """Generate cache key from IOC and provider"""
        key = f"{provider}:{ioc}".lower()
        return hashlib.sha256(key.encode()).hexdigest()[:32]
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get file path for cache key"""
        # Use subdirectories to avoid too many files in one dir
        subdir = cache_key[:2]
        return self.cache_dir / subdir / f"{cache_key}.json"
    
    def get(self, ioc: str, provider: str) -> Optional[dict]:
        """
        Get cached result
        
        Returns:
            Cached data dict or None if not found/expired
        """
        if not self.enabled:
            return None
            
        cache_key = self._get_cache_key(ioc, provider)
        cache_path = self._get_cache_path(cache_key)
        
        if not cache_path.exists():
            return None
            
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Check expiry
            cached_time = datetime.fromisoformat(data.get('_cached_at', '2000-01-01'))
            expiry_time = cached_time + timedelta(hours=self.expiry_hours)
            
            if datetime.now() > expiry_time:
                logger.debug(f"Cache expired for {provider}:{ioc}")
                cache_path.unlink(missing_ok=True)
                return None
                
            logger.debug(f"Cache hit for {provider}:{ioc}")
            return data.get('result')
            
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
            return None
    
    def set(self, ioc: str, provider: str, result: dict) -> bool:
        """
        Store result in cache
        
        Returns:
            True if cached successfully
        """
        if not self.enabled:
            return False
            
        cache_key = self._get_cache_key(ioc, provider)
        cache_path = self._get_cache_path(cache_key)
        
        try:
            # Create subdirectory
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                '_cached_at': datetime.now().isoformat(),
                '_ioc': ioc,
                '_provider': provider,
                'result': result
            }
            
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
                
            logger.debug(f"Cached result for {provider}:{ioc}")
            return True
            
        except Exception as e:
            logger.warning(f"Cache write error: {e}")
            return False
    
    def delete(self, ioc: str, provider: str) -> bool:
        """Delete cached entry"""
        cache_key = self._get_cache_key(ioc, provider)
        cache_path = self._get_cache_path(cache_key)
        
        try:
            cache_path.unlink(missing_ok=True)
            return True
        except Exception:
            return False
    
    def clear(self) -> int:
        """
        Clear all cached entries
        
        Returns:
            Number of entries cleared
        """
        count = 0
        try:
            for file in self.cache_dir.rglob("*.json"):
                file.unlink()
                count += 1
            logger.info(f"Cleared {count} cached entries")
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
        return count
    
    def clear_expired(self) -> int:
        """
        Clear only expired entries
        
        Returns:
            Number of entries cleared
        """
        count = 0
        try:
            expiry_threshold = datetime.now() - timedelta(hours=self.expiry_hours)
            
            for file in self.cache_dir.rglob("*.json"):
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)
                    cached_time = datetime.fromisoformat(data.get('_cached_at', '2000-01-01'))
                    if cached_time < expiry_threshold:
                        file.unlink()
                        count += 1
                except Exception:
                    continue
                    
            logger.info(f"Cleared {count} expired entries")
        except Exception as e:
            logger.error(f"Error clearing expired cache: {e}")
        return count
    
    def stats(self) -> dict:
        """Get cache statistics"""
        total_files = 0
        total_size = 0
        oldest = None
        newest = None
        
        try:
            for file in self.cache_dir.rglob("*.json"):
                total_files += 1
                total_size += file.stat().st_size
                
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)
                    cached_time = datetime.fromisoformat(data.get('_cached_at', '2000-01-01'))
                    
                    if oldest is None or cached_time < oldest:
                        oldest = cached_time
                    if newest is None or cached_time > newest:
                        newest = cached_time
                except Exception:
                    continue
                    
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            
        return {
            "enabled": self.enabled,
            "directory": str(self.cache_dir),
            "total_entries": total_files,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "expiry_hours": self.expiry_hours,
            "oldest_entry": oldest.isoformat() if oldest else None,
            "newest_entry": newest.isoformat() if newest else None
        }


# Global cache instance
_cache = None

def get_cache() -> Cache:
    """Get global cache instance"""
    global _cache
    if _cache is None:
        _cache = Cache()
    return _cache
