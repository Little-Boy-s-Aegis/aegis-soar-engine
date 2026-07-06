import unittest
import time
from rate_limiter import RedisTokenBucketRateLimiter

class TestRateLimiter(unittest.TestCase):
    def test_local_token_bucket(self):
        # Initialize in-memory mode
        limiter = RedisTokenBucketRateLimiter(redis_url=None)
        
        # Configure a very fast limit for testing: capacity=2, rate=1 token/sec
        limiter.limits["test_sys"] = (2, 1.0)
        
        # 1. First 2 requests should be allowed immediately
        self.assertTrue(limiter.acquire_token("test_sys", timeout_seconds=0.1))
        self.assertTrue(limiter.acquire_token("test_sys", timeout_seconds=0.1))
        
        # 2. Third request should block and fail immediately (timeout=0.1s is less than 1.0s refill time)
        start_time = time.time()
        acquired = limiter.acquire_token("test_sys", timeout_seconds=0.1)
        duration = time.time() - start_time
        
        self.assertFalse(acquired)
        self.assertGreaterEqual(duration, 0.1)

    def test_local_token_bucket_refill(self):
        limiter = RedisTokenBucketRateLimiter(redis_url=None)
        # capacity=1, rate=10 tokens/sec (0.1s wait for refill)
        limiter.limits["test_sys_fast"] = (1, 10.0)
        
        self.assertTrue(limiter.acquire_token("test_sys_fast", timeout_seconds=0.01))
        
        # Should be able to acquire again if we wait for refill (e.g. timeout=0.15s)
        self.assertTrue(limiter.acquire_token("test_sys_fast", timeout_seconds=0.2))

if __name__ == "__main__":
    unittest.main()
