import json
import os
from typing import Any, Dict, Optional

try:
    import redis.asyncio as redis
except ImportError:
    redis = None  # type: ignore

DEFAULT_TRUSTED_DOMAINS: Dict[str, str] = {
    "stanford.edu": "Trusted University Domain (Verified Institution)",
    "mit.edu": "Trusted University Domain (Verified Institution)",
    "berkeley.edu": "Trusted University Domain (Verified Institution)",
    "ox.ac.uk": "Trusted University Domain (Verified Institution)",
    "github.com": "Developer Platform (Verified)",
    "google.com": "Cloud & Identity Provider (Verified)",
    "accounts.google.com": "Google Identity (Verified)",
    "paypal.com": "Financial Services (Protected Brand)",
    "microsoft.com": "Enterprise Cloud (Protected Brand)",
    "stripe.com": "Payments Infrastructure (Protected Brand)",
    "acme-corp.internal": "Internal Enterprise / Institution Domain",
}


class TrustedDomainRedisStore:
    """
    Backed by `redis-py` (redis.asyncio) to store Trusted Domains and URL Scan caches.
    Automatically falls back to an in-memory Redis-compatible store if a local Redis
    daemon is not reachable during prototyping demos.
    """

    REDIS_HASH_KEY = "phishing_agent:trusted_domains"
    URL_CACHE_PREFIX = "phishing_agent:url_scan:"

    def __init__(self) -> None:
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client: Optional[Any] = None
        self._using_fallback: bool = False
        self._fallback_domains: Dict[str, str] = dict(DEFAULT_TRUSTED_DOMAINS)
        self._fallback_url_cache: Dict[str, dict] = {}

    async def initialize(self) -> None:
        if redis is None:
            self._client = None
            self._using_fallback = True
            return
        try:
            client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=0.75,
                socket_timeout=0.75,
            )
            await client.ping()
            self._client = client
            self._using_fallback = False
            # Seed default trusted domains if empty
            existing = await self._client.hlen(self.REDIS_HASH_KEY)
            if existing == 0:
                await self._client.hset(self.REDIS_HASH_KEY, mapping=DEFAULT_TRUSTED_DOMAINS)
        except Exception:
            self._client = None
            self._using_fallback = True

    @property
    def backend_mode(self) -> str:
        return "redis-py (live server)" if not self._using_fallback and self._client else "redis-py (in-memory demo fallback)"

    async def lookup_domain(self, domain: str) -> Optional[str]:
        clean = domain.strip().lower()
        if not clean:
            return None
        if not self._using_fallback and self._client:
            try:
                return await self._client.hget(self.REDIS_HASH_KEY, clean)
            except Exception:
                self._using_fallback = True
        return self._fallback_domains.get(clean)

    async def list_trusted_domains(self) -> Dict[str, str]:
        if not self._using_fallback and self._client:
            try:
                return await self._client.hgetall(self.REDIS_HASH_KEY)
            except Exception:
                self._using_fallback = True
        return dict(self._fallback_domains)

    async def add_trusted_domain(self, domain: str, category: str = "Custom Trusted Domain") -> Dict[str, str]:
        clean = domain.strip().lower()
        if not self._using_fallback and self._client:
            try:
                await self._client.hset(self.REDIS_HASH_KEY, clean, category)
                return await self.list_trusted_domains()
            except Exception:
                self._using_fallback = True
        self._fallback_domains[clean] = category
        return dict(self._fallback_domains)

    async def remove_trusted_domain(self, domain: str) -> Dict[str, str]:
        clean = domain.strip().lower()
        if not self._using_fallback and self._client:
            try:
                await self._client.hdel(self.REDIS_HASH_KEY, clean)
                return await self.list_trusted_domains()
            except Exception:
                self._using_fallback = True
        self._fallback_domains.pop(clean, None)
        return dict(self._fallback_domains)

    async def get_cached_url_scan(self, url_sha256: str) -> Optional[dict]:
        key = f"{self.URL_CACHE_PREFIX}{url_sha256}"
        if not self._using_fallback and self._client:
            try:
                raw = await self._client.get(key)
                return json.loads(raw) if raw else None
            except Exception:
                self._using_fallback = True
        return self._fallback_url_cache.get(url_sha256)

    async def set_cached_url_scan(self, url_sha256: str, verdict_data: dict, ttl_seconds: int = 1800) -> None:
        key = f"{self.URL_CACHE_PREFIX}{url_sha256}"
        if not self._using_fallback and self._client:
            try:
                await self._client.setex(key, ttl_seconds, json.dumps(verdict_data))
                return
            except Exception:
                self._using_fallback = True
        self._fallback_url_cache[url_sha256] = verdict_data


redis_store = TrustedDomainRedisStore()
