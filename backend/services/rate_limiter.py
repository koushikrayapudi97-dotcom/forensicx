import os
import threading
import time
from collections import defaultdict


class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.monotonic()

    def check(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        """Check if key has exceeded limit in window_seconds.

        Returns:
            (is_allowed, retry_after_seconds)
            is_allowed is True if request is permitted.
            retry_after_seconds is 0 if allowed, else seconds until next available slot.
        """
        # Bypass during automated test runs unless rate-limiting is explicitly being tested
        if os.getenv("FX_DISABLE_RATE_LIMIT") == "1" or (
            os.getenv("PYTEST_CURRENT_TEST") and not os.getenv("FX_TEST_RATE_LIMIT")
        ):
            return True, 0

        now = time.monotonic()
        with self._lock:
            # Periodic cleanup of keys older than 5 minutes
            if now - self._last_cleanup > 300:
                self._cleanup(now)

            timestamps = self._requests[key]
            # Discard timestamps outside window
            cutoff = now - window_seconds
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._requests[key] = valid_timestamps

            if len(valid_timestamps) >= limit:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(window_seconds - (now - oldest)))
                return False, retry_after

            valid_timestamps.append(now)
            return True, 0

    def _cleanup(self, now: float) -> None:
        """Evict stale keys to prevent memory growth."""
        cutoff = now - 300
        keys_to_delete = [
            k for k, v in self._requests.items()
            if not v or v[-1] <= cutoff
        ]
        for k in keys_to_delete:
            del self._requests[k]
        self._last_cleanup = now

    def reset(self) -> None:
        """Clear all rate limit records (useful for testing)."""
        with self._lock:
            self._requests.clear()


limiter = SlidingWindowRateLimiter()

