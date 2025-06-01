from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Callable, TypeVar, Awaitable
import functools
import hashlib
import json

T = TypeVar('T')

class CacheItem:
    def __init__(self, value: Any, expires_at: datetime):
        self.value = value
        self.expires_at = expires_at
        
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

# In-memory cache store
_cache: Dict[str, CacheItem] = {}

def generate_cache_key(prefix: str, *args, **kwargs) -> str:
    """Generate a unique cache key based on function arguments"""
    # Convert args and kwargs to a string representation
    key_parts = [prefix]
    
    if args:
        for arg in args:
            key_parts.append(str(arg))
    
    if kwargs:
        # Sort kwargs for consistent keys
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}:{v}")
    
    # Join and hash to create fixed-length key
    key_str = ":".join(key_parts)
    return hashlib.md5(key_str.encode()).hexdigest()

def cache_result(ttl_seconds: int = 300):
    """Decorator for caching function results in memory"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            prefix = f"{func.__module__}.{func.__name__}"
            cache_key = generate_cache_key(prefix, *args, **kwargs)
            
            # Check cache
            cache_item = _cache.get(cache_key)
            if cache_item and not cache_item.is_expired():
                return cache_item.value
            
            # Call function
            result = await func(*args, **kwargs)
            
            # Store in cache
            expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
            _cache[cache_key] = CacheItem(result, expires_at)
            
            return result
        return wrapper
    return decorator

def invalidate_cache(prefix: str, *args, **kwargs) -> None:
    """Invalidate specific cache entries"""
    if not args and not kwargs:
        # Invalidate all entries with prefix
        for key in list(_cache.keys()):
            if key.startswith(prefix):
                del _cache[key]
    else:
        # Invalidate specific entry
        cache_key = generate_cache_key(prefix, *args, **kwargs)
        if cache_key in _cache:
            del _cache[cache_key]

def clear_cache() -> None:
    """Clear the entire cache"""
    _cache.clear()
