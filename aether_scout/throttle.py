from __future__ import annotations

import time


class RateLimiter:
    def __init__(
        self,
        requests_per_minute: int,
        *,
        monotonic=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        if requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be greater than 0")
        self.interval_seconds = 60.0 / requests_per_minute
        self._monotonic = monotonic
        self._sleep = sleep
        self._next_at: float | None = None

    def wait(self) -> None:
        now = self._monotonic()
        if self._next_at is not None and now < self._next_at:
            self._sleep(self._next_at - now)
            now = self._monotonic()
        self._next_at = now + self.interval_seconds


class NullRateLimiter:
    def wait(self) -> None:
        return None
