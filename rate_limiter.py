import time
import logging
try:
    import redis
except ImportError:
    redis = None
import os

logger = logging.getLogger("soar-engine.rate-limiter")

class RedisTokenBucketRateLimiter:
    """
    Redis-backed thread-safe Token Bucket Rate Limiter for microservices.
    Falls back to in-memory token bucket if Redis is unavailable.
    """

    def __init__(self, redis_url: str = None):
        self.redis_client = None
        if redis_url and redis:
            try:
                self.redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
                logger.info(f"[RATE LIMITER] Configured Redis-backed rate limiting using {redis_url}")
            except Exception as e:
                logger.warning(f"[RATE LIMITER] Failed to initialize Redis client: {e}. Falling back to in-memory limits.")
        else:
            logger.warning("[RATE LIMITER] Redis library not installed or url missing. Using in-memory fallback mode.")

        # In-memory fallback states: {system_name: (last_tokens, last_updated_time)}
        self._local_buckets = {}

        # Default rate limit configurations: (max_tokens_capacity, leak_rate_per_second)
        self.limits = {
            "fortinet": (5, 5 / 60.0),        # 5 requests per minute max, refilling 5/60 tokens/sec
            "crowdstrike": (10, 10 / 60.0),   # 10 requests per minute max
            "active_directory": (10, 10 / 60.0), # 10 requests per minute max
            "aws_waf": (15, 15 / 60.0)        # 15 requests per minute max
        }

    def _acquire_local(self, system: str, capacity: int, refill_rate: float) -> bool:
        """Acquires a token using in-memory state."""
        now = time.time()
        if system not in self._local_buckets:
            self._local_buckets[system] = (capacity - 1.0, now)
            return True

        tokens, last_update = self._local_buckets[system]
        elapsed = now - last_update
        new_tokens = min(capacity, tokens + elapsed * refill_rate)
        
        if new_tokens >= 1.0:
            self._local_buckets[system] = (new_tokens - 1.0, now)
            return True
        return False

    def _acquire_redis(self, system: str, capacity: int, refill_rate: float) -> bool:
        """Acquires a token using Redis keys with transaction-based safety."""
        key = f"aegis:ratelimit:{system}"
        now = time.time()
        
        try:
            with self.redis_client.pipeline() as pipe:
                pipe.watch(key)
                state = pipe.hgetall(key)
                
                if not state:
                    tokens = float(capacity)
                    last_update = now
                else:
                    tokens = float(state.get("tokens", capacity))
                    last_update = float(state.get("last_update", now))

                elapsed = now - last_update
                new_tokens = min(capacity, tokens + elapsed * refill_rate)
                
                if new_tokens >= 1.0:
                    pipe.multi()
                    pipe.hset(key, mapping={
                        "tokens": str(new_tokens - 1.0),
                        "last_update": str(now)
                    })
                    pipe.execute()
                    return True
                else:
                    return False
        except redis.WatchError:
            return False
        except Exception as e:
            logger.error(f"[RATE LIMITER ERROR] Redis check failed: {e}")
            return self._acquire_local(system, capacity, refill_rate)

    def acquire_token(self, system: str, timeout_seconds: float = 10.0) -> bool:
        """
        Attempts to acquire a token for the given system.
        If no token is available, blocks/sleeps until a token is acquired or timeout_seconds is reached.
        Returns True if token acquired, False if timeout reached.
        """
        system = system.lower()
        if system not in self.limits:
            return True
            
        capacity, refill_rate = self.limits[system]
        start_time = time.time()
        
        while True:
            if self.redis_client:
                acquired = self._acquire_redis(system, capacity, refill_rate)
            else:
                acquired = self._acquire_local(system, capacity, refill_rate)
                
            if acquired:
                return True
                
            elapsed = time.time() - start_time
            if elapsed >= timeout_seconds:
                logger.warning(f"[RATE LIMITER] Timeout reached waiting for token on system: {system}")
                return False
                
            sleep_time = min(1.0, (1.0 / refill_rate) * 0.5)
            time.sleep(max(0.1, sleep_time))
