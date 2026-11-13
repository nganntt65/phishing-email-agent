"""Test isolation.

Before this file existed, tests wrote to the real campaign_memory.db, so every second run saw its
own earlier results as a "known campaign" (+15 points) and the HIGH-risk sample became CRITICAL.
Each test session now gets a fresh database, the in-memory trusted-domain store, no live Gemini
calls, and the default campus configuration.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="scamshield-tests-")
os.environ["SCAMSHIELD_SKIP_DOTENV"] = "1"  # a developer's own .env must not change test results
os.environ["CAMPAIGN_DB_PATH"] = os.path.join(_tmp, "campaign_memory.db")
os.environ["EVAL_ADDED_DIR"] = os.path.join(_tmp, "eval-added")
os.environ["REDIS_DISABLED"] = "1"
os.environ["GEMINI_API_KEY"] = ""
os.environ.pop("LLM_CACHE_DIR", None)
os.environ.pop("SAFE_BROWSING_API_KEY", None)
for _var in ("CAMPUS_NAME", "CAMPUS_DOMAINS", "CAMPUS_PORTAL_URL", "PHISHING_THRESHOLD"):
    os.environ.pop(_var, None)
