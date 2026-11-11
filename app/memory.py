import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.schemas import CampaignMatchResult, SanitizedEmailPayload


class CampaignHistoryMemory:
    """
    MEMORY Layer: Campaign history / Historical outputs.
    Persists email analysis outputs in SQLite and computes campaign fingerprints
    (based on normalized subject template + sender domain + URL domains) to correlate
    recurring phishing waves across recipients.
    """

    def __init__(self, db_path: str | None = None) -> None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = db_path or os.path.join(base_dir, "campaign_memory.db")
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS campaign_clusters (
                    fingerprint TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    sender_domain TEXT,
                    subject_pattern TEXT,
                    seen_count INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_risk_score INTEGER DEFAULT 0,
                    last_risk_level TEXT DEFAULT 'LOW',
                    last_action TEXT DEFAULT 'ALLOW'
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS historical_outputs (
                    request_id TEXT PRIMARY KEY,
                    analyzed_at TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    sender_address TEXT,
                    subject TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    escalated_action TEXT,
                    short_analysis TEXT,
                    full_json TEXT
                )
                """
            )
            # Seed a known active phishing campaign so first-time demo runs can also showcase campaign correlation
            cur = conn.execute("SELECT COUNT(*) FROM campaign_clusters")
            if cur.fetchone()[0] == 0:
                now_iso = datetime.now(timezone.utc).isoformat()
                seed_fp = self._compute_fingerprint_raw(
                    sender_domain="paypai-support.com",
                    subject="URGENT: Your account will be suspended in 24 hours",
                    urls=["https://paypaI-support.com/login?session=89234"],
                )
                conn.execute(
                    """
                    INSERT INTO campaign_clusters (
                        fingerprint, campaign_id, sender_domain, subject_pattern,
                        seen_count, first_seen, last_seen, last_risk_score, last_risk_level, last_action
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        seed_fp,
                        "camp_paypal_lure_01",
                        "paypai-support.com",
                        "urgent: your account will be suspended in # hours",
                        14,
                        "2026-11-10T08:15:00+00:00",
                        now_iso,
                        95,
                        "CRITICAL",
                        "QUARANTINE_AND_BLOCK",
                    ),
                )
            conn.commit()

    @staticmethod
    def _compute_fingerprint_raw(sender_domain: str, subject: str, urls: List[str]) -> str:
        norm_subj = re.sub(r"\d+", "#", subject.lower().strip())
        norm_subj = re.sub(r"\s+", " ", norm_subj)
        url_hosts = sorted(
            {
                (urlparse(u).hostname or "").lower()
                for u in urls
                if urlparse(u).hostname
            }
        )
        raw_key = f"{sender_domain.lower().strip()}|{norm_subj}|{','.join(url_hosts)}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    def compute_fingerprint(self, payload: SanitizedEmailPayload) -> str:
        return self._compute_fingerprint_raw(
            sender_domain=payload.headers.from_domain,
            subject=payload.headers.subject,
            urls=payload.extracted_urls,
        )

    def lookup_campaign(self, payload: SanitizedEmailPayload) -> CampaignMatchResult:
        fp = self.compute_fingerprint(payload)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM campaign_clusters WHERE fingerprint = ?", (fp,)
            ).fetchone()

        if not row:
            return CampaignMatchResult(
                matched=False,
                fingerprint=fp,
                seen_count=0,
                campaign_boost_score=0,
                summary="No prior matching campaign fingerprint in Campaign History DB.",
            )

        prior_level = row["last_risk_level"]
        boost = 15 if prior_level in ("HIGH", "CRITICAL") else 0
        return CampaignMatchResult(
            matched=True,
            campaign_id=row["campaign_id"],
            fingerprint=fp,
            seen_count=row["seen_count"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            prior_risk_level=prior_level,
            campaign_boost_score=boost,
            summary=(
                f"Matched active campaign '{row['campaign_id']}' seen {row['seen_count']} times "
                f"(prior verdict: {prior_level} / {row['last_action']})."
            ),
        )

    def record_analysis_output(
        self,
        payload: SanitizedEmailPayload,
        fingerprint: str,
        risk_score: int,
        risk_level: str,
        escalated_action: str,
        short_analysis: str,
        full_response_dict: Dict[str, Any],
    ) -> str:
        now_iso = datetime.now(timezone.utc).isoformat()
        norm_subj = re.sub(r"\d+", "#", payload.headers.subject.lower().strip())

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            existing = conn.execute(
                "SELECT campaign_id, seen_count FROM campaign_clusters WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

            if existing:
                campaign_id = existing["campaign_id"]
                conn.execute(
                    """
                    UPDATE campaign_clusters
                    SET seen_count = seen_count + 1,
                        last_seen = ?,
                        last_risk_score = ?,
                        last_risk_level = ?,
                        last_action = ?
                    WHERE fingerprint = ?
                    """,
                    (now_iso, risk_score, risk_level, escalated_action, fingerprint),
                )
            else:
                campaign_id = f"camp_{fingerprint[:8]}"
                conn.execute(
                    """
                    INSERT INTO campaign_clusters (
                        fingerprint, campaign_id, sender_domain, subject_pattern,
                        seen_count, first_seen, last_seen, last_risk_score, last_risk_level, last_action
                    ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        fingerprint,
                        campaign_id,
                        payload.headers.from_domain,
                        norm_subj,
                        now_iso,
                        now_iso,
                        risk_score,
                        risk_level,
                        escalated_action,
                    ),
                )

            conn.execute(
                """
                INSERT OR REPLACE INTO historical_outputs (
                    request_id, analyzed_at, campaign_id, sender_address, subject,
                    risk_score, risk_level, escalated_action, short_analysis, full_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.request_id,
                    now_iso,
                    campaign_id,
                    payload.headers.from_address,
                    payload.headers.subject,
                    risk_score,
                    risk_level,
                    escalated_action,
                    short_analysis,
                    json.dumps(full_response_dict),
                ),
            )
            conn.commit()
        return campaign_id

    def list_recent_history(self, limit: int = 15) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            campaigns = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM campaign_clusters ORDER BY last_seen DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]
            history = [
                {
                    k: r[k]
                    for k in (
                        "request_id",
                        "analyzed_at",
                        "campaign_id",
                        "sender_address",
                        "subject",
                        "risk_score",
                        "risk_level",
                        "escalated_action",
                        "short_analysis",
                    )
                }
                for r in conn.execute(
                    "SELECT * FROM historical_outputs ORDER BY analyzed_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]
        return {"campaigns": campaigns, "recent_analyses": history}


campaign_memory = CampaignHistoryMemory()

