"""Phishing Email Agentic AI System Backend."""

import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def load_env_file(path: Path = ENV_FILE) -> bool:
    """Read settings such as GEMINI_API_KEY from the project's .env file, so pasting a key there is enough.

    Variables already set in the shell win over the file. Tests set SCAMSHIELD_SKIP_DOTENV so a developer's
    own .env can't change their results. Returns True when a file was read.
    """
    if os.getenv("SCAMSHIELD_SKIP_DOTENV") or not path.is_file():
        return False
    try:
        from dotenv import load_dotenv
    except ImportError:  # python-dotenv is in requirements.txt; without it, shell variables still work
        return False
    return load_dotenv(path, override=False, encoding="utf-8-sig")


load_env_file()
