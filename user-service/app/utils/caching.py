import redis
import json
from datetime import timedelta
import os
from typing import Any, Callable, TypeVar, Awaitable
import functools
import hashlib

T = TypeVar('T')

# Initialize Redis client (local development)
redis_client = redis.Redis(
    host="localhost",
    port=6379,
    decode_responses=True
)

def generate_cache_key(prefix: str, *args, **kwargs) -> str:
    """Generate a unique cache key based on function arguments"""
    key_parts = [prefix]
    
    if args:
        for arg in args:
            key_parts.append(str(arg))
    
    if kwargs:
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}:{v}")
    
    key_str = ":".join(key_parts)
    return hashlib.md5(key_str.encode()).hexdigest()

def cache_result(ttl_seconds: int = 300):
    """Decorator for caching function results in Redis"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            prefix = f"{func.__module__}.{func.__name__}"
            cache_key = generate_cache_key(prefix, *args, **kwargs)
            
            # Check Redis cache
            cached_data = redis_client.get(cache_key)
            if cached_data is not None:
                return json.loads(cached_data)
            
            result = await func(*args, **kwargs)
            
            # Store in Redis with TTL
            redis_client.setex(cache_key, timedelta(seconds=ttl_seconds), json.dumps(result))
            return result
        return wrapper
    return decorator

def invalidate_cache(prefix: str, *args, **kwargs) -> None:
    """Invalidate specific cache entries in Redis"""
    if not args and not kwargs:
        # Invalidate all keys with prefix
        keys = redis_client.keys(f"{prefix}*")
        if keys:
            redis_client.delete(*keys)
    else:
        # Invalidate specific key
        cache_key = generate_cache_key(prefix, *args, **kwargs)
        redis_client.delete(cache_key)

def clear_cache() -> None:
    """Clear the entire Redis cache"""
    redis_client.flushdb()
