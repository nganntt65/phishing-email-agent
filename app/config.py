"""Runtime configuration read from environment variables.

CampusGuard AI is generic: it serves students of any university and knows no campus by default.
A university that deploys it can optionally tell it which domains are official, which turns on
"looks like OUR login domain" detection and an "Open official campus portal" button:

    $env:CAMPUS_NAME = "My University"
    $env:CAMPUS_DOMAINS = "myuni.ac.id"
    $env:CAMPUS_PORTAL_URL = "https://portal.myuni.ac.id"

Leave them unset for the generic behaviour.
"""

import os
from typing import List


def _split_domains(value: str) -> List[str]:
    return [d.strip().lower().lstrip(".") for d in value.split(",") if d.strip()]


CAMPUS_NAME: str = os.getenv("CAMPUS_NAME", "").strip()
CAMPUS_DOMAINS: List[str] = _split_domains(os.getenv("CAMPUS_DOMAINS", ""))
CAMPUS_PORTAL_URL: str = os.getenv("CAMPUS_PORTAL_URL", "").strip()

# Score at or above which a scan counts as "phishing" for evaluation and the live scoreboard.
PHISHING_THRESHOLD: int = int(os.getenv("PHISHING_THRESHOLD", "60"))
