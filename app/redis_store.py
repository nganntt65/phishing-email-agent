import json
import os
from typing import Any, Dict, Optional

from app import config

try:
    import redis.asyncio as redis
except ImportError:
    redis = None  # type: ignore

# Official domains of real universities. CampusGuard AI is for university students, so the built-in trusted list is
# universities plus a few sign-in and coursework services. Subdomains count too: lms.ntpu.edu.tw is
# trusted because ntpu.edu.tw is. The list is a starting point, not complete: add your own university in the
# "Trusted domains" window, or set CAMPUS_DOMAINS. Check a domain on the university's own website before adding it.
_UNIVERSITIES = {
    "Taiwan": (
        "ntpu.edu.tw", "ntu.edu.tw", "nccu.edu.tw", "nthu.edu.tw", "nycu.edu.tw", "ncku.edu.tw", "ntnu.edu.tw",
        "ntust.edu.tw", "ntut.edu.tw", "tku.edu.tw", "fju.edu.tw", "scu.edu.tw", "cgu.edu.tw", "ncu.edu.tw",
        "nsysu.edu.tw", "nchu.edu.tw", "ccu.edu.tw", "ntou.edu.tw", "yzu.edu.tw", "cycu.edu.tw", "fcu.edu.tw",
        "thu.edu.tw", "pccu.edu.tw", "mcu.edu.tw",
    ),
    "Indonesia": (
        "ui.ac.id", "ugm.ac.id", "itb.ac.id", "its.ac.id", "unair.ac.id", "ipb.ac.id", "undip.ac.id", "unpad.ac.id",
        "ub.ac.id", "binus.ac.id", "telkomuniversity.ac.id", "uns.ac.id", "unhas.ac.id", "usu.ac.id", "petra.ac.id",
        "uajy.ac.id", "trisakti.ac.id", "uny.ac.id", "unej.ac.id", "unud.ac.id", "unsri.ac.id", "unand.ac.id",
        "upi.edu", "uii.ac.id", "umy.ac.id", "ums.ac.id",
    ),
    "United States": (
        "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu", "yale.edu", "princeton.edu", "columbia.edu",
        "cornell.edu", "upenn.edu", "caltech.edu", "umich.edu", "nyu.edu", "ucla.edu", "cmu.edu", "illinois.edu",
        "utexas.edu", "wisc.edu", "duke.edu", "northwestern.edu", "uchicago.edu", "jhu.edu", "brown.edu",
        "gatech.edu", "purdue.edu", "washington.edu", "ucsd.edu", "usc.edu", "bu.edu", "umd.edu", "osu.edu",
        "psu.edu", "asu.edu", "ufl.edu",
    ),
    "United Kingdom": (
        "ox.ac.uk", "cam.ac.uk", "imperial.ac.uk", "ucl.ac.uk", "ed.ac.uk", "manchester.ac.uk", "kcl.ac.uk",
        "lse.ac.uk", "warwick.ac.uk", "bristol.ac.uk", "durham.ac.uk", "glasgow.ac.uk", "leeds.ac.uk",
    ),
    "East and Southeast Asia": (
        "nus.edu.sg", "ntu.edu.sg", "smu.edu.sg", "hku.hk", "cuhk.edu.hk", "ust.hk", "polyu.edu.hk",
        "u-tokyo.ac.jp", "kyoto-u.ac.jp", "osaka-u.ac.jp", "keio.ac.jp", "waseda.jp",
        "snu.ac.kr", "kaist.ac.kr", "yonsei.ac.kr", "korea.ac.kr", "postech.ac.kr",
        "tsinghua.edu.cn", "pku.edu.cn", "fudan.edu.cn", "sjtu.edu.cn", "zju.edu.cn",
        "um.edu.my", "utm.my", "ukm.edu.my", "usm.my", "upm.edu.my",
        "chula.ac.th", "mahidol.ac.th", "up.edu.ph", "ateneo.edu", "dlsu.edu.ph", "vnu.edu.vn",
    ),
    "Australia, India and elsewhere": (
        "unimelb.edu.au", "sydney.edu.au", "unsw.edu.au", "anu.edu.au", "monash.edu", "uq.edu.au", "auckland.ac.nz",
        "iitb.ac.in", "iitd.ac.in", "iisc.ac.in",
        "utoronto.ca", "ubc.ca", "mcgill.ca", "uwaterloo.ca",
        "ethz.ch", "epfl.ch", "tum.de", "uva.nl", "tudelft.nl", "ku.dk", "kth.se", "helsinki.fi",
    ),
}

# Services students use to sign in or hand in work. (github.io, googleapis.com and docs.google.com are deliberately
# NOT trusted: anyone can host pages there, including scammers.)
STUDENT_SERVICES: Dict[str, str] = {
    "microsoftonline.com": "Microsoft 365 sign-in (used by most universities)",
    "microsoft.com": "Microsoft (Office, Teams, account pages)",
    "accounts.google.com": "Google sign-in (used by many universities)",
    "github.com": "GitHub (coursework and code hosting)",
}

DEFAULT_TRUSTED_DOMAINS: Dict[str, str] = {
    **{domain: f"University, {region} (official domain)" for region, domains in _UNIVERSITIES.items() for domain in domains},
    **STUDENT_SERVICES,
}


def _campus_trusted_domains() -> Dict[str, str]:
    return {d: f"Official campus domain ({config.CAMPUS_NAME})" for d in config.CAMPUS_DOMAINS}


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
        self._fallback_domains: Dict[str, str] = {**DEFAULT_TRUSTED_DOMAINS, **_campus_trusted_domains()}
        self._fallback_url_cache: Dict[str, dict] = {}

    async def initialize(self) -> None:
        # REDIS_DISABLED=1 forces the in-memory store (used by tests and the evaluation harness
        # so results never depend on whatever a local Redis server happens to contain).
        if redis is None or os.getenv("REDIS_DISABLED", "").strip() in ("1", "true", "yes"):
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
            for domain, category in _campus_trusted_domains().items():
                await self._client.hsetnx(self.REDIS_HASH_KEY, domain, category)
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
