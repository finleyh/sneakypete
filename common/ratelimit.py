import time
from collections import defaultdict, deque


class PerIpLimiter:
    """Simple in-memory sliding-window + cooldown-ban limiter, keyed by source IP.

    Not distributed, not persisted across restarts -- fine for a single-process
    honeypot listener whose only goal is to stop one noisy scanner from
    exhausting connections/CPU, not to be a real WAF.
    """

    def __init__(
        self,
        *,
        max_attempts: int = 20,
        window_seconds: float = 60.0,
        ban_seconds: float = 300.0,
        max_concurrent_per_ip: int = 5,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.ban_seconds = ban_seconds
        self.max_concurrent_per_ip = max_concurrent_per_ip

        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._banned_until: dict[str, float] = {}
        self._concurrent: dict[str, int] = defaultdict(int)

    def is_banned(self, ip: str) -> bool:
        until = self._banned_until.get(ip)
        if until is None:
            return False
        if time.monotonic() >= until:
            del self._banned_until[ip]
            return False
        return True

    def allow_connection(self, ip: str) -> bool:
        """Call when a new connection/attempt arrives. Returns False if it should be dropped."""
        if self.is_banned(ip):
            return False

        if self._concurrent[ip] >= self.max_concurrent_per_ip:
            return False

        now = time.monotonic()
        window = self._attempts[ip]
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        window.append(now)

        if len(window) > self.max_attempts:
            self._banned_until[ip] = now + self.ban_seconds
            return False

        return True

    def connection_opened(self, ip: str) -> None:
        self._concurrent[ip] += 1

    def connection_closed(self, ip: str) -> None:
        if self._concurrent[ip] <= 1:
            self._concurrent.pop(ip, None)
        else:
            self._concurrent[ip] -= 1
