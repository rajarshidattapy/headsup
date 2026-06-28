"""Anakin — emerging threat-intelligence ingestion for HeadsUp.

Pulls the latest malware campaigns / advisories from the web via the Anakin API
(CISA, CVE feeds, Microsoft Security Blog, BleepingComputer, The Hacker News,
Reddit), summarises each into the ``threat_intelligence`` schema (optionally with
Gemma), and stores them in HydraDB.

Without ``ANAKIN_API_KEY`` it falls back to a bundled set of recent real-world
campaigns (``data/sample_intel.json``) so HeadsUp always has intel to correlate
against. Local machine behaviour can then be matched against these campaigns to
surface "this looks like the X campaign (NN% similarity)".
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Optional

try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    _HAS_REQUESTS = False

_SAMPLE_PATH = Path(__file__).parent / "data" / "sample_intel.json"
_ANAKIN_URL = os.environ.get("ANAKIN_API_URL", "https://api.anakin.ai/v1/threat-intel")
_STOPWORDS = {"the", "a", "an", "of", "to", "and", "for", "via", "with", "from", "on"}


def _tokenize(text: str) -> set[str]:
    toks = re.split(r"[^a-z0-9]+", (text or "").lower())
    return {t for t in toks if t and t not in _STOPWORDS and len(t) > 2}


class Anakin:
    def __init__(self, db, analyst=None) -> None:
        self.db = db
        self.analyst = analyst
        self.api_key = os.environ.get("ANAKIN_API_KEY", "")
        self._campaigns: list[dict] = []   # in-memory copy for fast matching
        self._lock = threading.Lock()

    @property
    def source(self) -> str:
        return "Anakin API" if (self.api_key and _HAS_REQUESTS) else "bundled sample feed"

    # ── ingestion ─────────────────────────────────────────────────────────────

    def ingest(self) -> int:
        """Fetch + store intel. Returns the number of newly-stored campaigns."""
        items = self._fetch()
        existing = {r["threat_name"].lower() for r in self.db.recent_intel(limit=500)}
        stored = 0
        for item in items:
            name = item.get("threat_name", "").strip()
            if not name:
                continue
            with self._lock:
                if not any(c["threat_name"] == name for c in self._campaigns):
                    self._campaigns.append(item)
            if name.lower() in existing:
                continue
            self.db.store_intel(
                threat_name=name,
                ioc_domains=item.get("ioc_domains", []),
                ioc_hashes=item.get("ioc_hashes", []),
                behaviors=item.get("behaviors", []),
                severity=item.get("severity", ""),
                source=item.get("source", ""),
                published_at=item.get("published_at", ""),
            )
            stored += 1
        return stored

    def start_background(self, interval_sec: int = 1800) -> None:
        """Ingest now, then refresh periodically in the background."""
        def _loop():
            while True:
                try:
                    self.ingest()
                except Exception:
                    pass
                time.sleep(interval_sec)
        threading.Thread(target=_loop, daemon=True, name="hu-anakin").start()

    # ── fetching ──────────────────────────────────────────────────────────────

    def _fetch(self) -> list[dict]:
        if self.api_key and _HAS_REQUESTS:
            try:
                raw = self._fetch_anakin()
                if raw:
                    return [self._normalize(x) for x in raw]
            except Exception:
                pass  # fall back to bundled feed
        return self._fetch_bundled()

    def _fetch_anakin(self) -> list[dict]:
        """Call the Anakin API. Endpoint shape is configurable via env.

        Expected to return a JSON list (or {"items": [...]}) of threat reports.
        Each report is summarised into our schema by :meth:`_normalize` (which
        uses Gemma when available).
        """
        resp = requests.get(
            _ANAKIN_URL,
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Accept": "application/json"},
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            data = data.get("items") or data.get("data") or data.get("results") or []
        return data if isinstance(data, list) else []

    def _fetch_bundled(self) -> list[dict]:
        try:
            with open(_SAMPLE_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _normalize(self, item: dict) -> dict:
        """Coerce an arbitrary Anakin item into the threat_intelligence schema.

        If the item is raw text and Gemma is available, ask it to extract the
        structured fields; otherwise best-effort map common keys.
        """
        if all(k in item for k in ("threat_name", "behaviors")):
            return item
        if self.analyst is not None and getattr(self.analyst, "available", False):
            blob = json.dumps(item)[:2000]
            prompt = (
                "Extract a threat-intel record as JSON with keys threat_name, "
                "ioc_domains[], ioc_hashes[], behaviors[], severity, source, "
                "published_at from this report:\n" + blob)
            out = self.analyst._chat(
                "You output only strict JSON for threat intelligence extraction.",
                prompt, 300)
            s, e = out.find("{"), out.rfind("}") + 1
            if s >= 0 and e > s:
                try:
                    return json.loads(out[s:e])
                except Exception:
                    pass
        # best-effort fallback mapping
        return {
            "threat_name": item.get("title") or item.get("name") or "Unknown campaign",
            "ioc_domains": item.get("domains") or item.get("ioc_domains") or [],
            "ioc_hashes": item.get("hashes") or item.get("ioc_hashes") or [],
            "behaviors": item.get("behaviors") or item.get("tags") or [],
            "severity": item.get("severity", ""),
            "source": item.get("source", "Anakin"),
            "published_at": item.get("published_at") or item.get("date", ""),
        }

    # ── matching ──────────────────────────────────────────────────────────────

    def _campaign_pool(self) -> list[dict]:
        with self._lock:
            if self._campaigns:
                return list(self._campaigns)
        # lazy-load from DB or bundled feed if we haven't ingested yet
        pool = self.db.recent_intel(limit=200) or self._fetch_bundled()
        with self._lock:
            self._campaigns = pool
        return pool

    def match(self, behaviors: list[str], domains: Optional[list[str]] = None,
              hashes: Optional[list[str]] = None) -> Optional[dict]:
        """Return the best-matching campaign with a similarity score, or None.

        {threat_name, similarity (0-100), severity, source, matched[]}.
        """
        domains = domains or []
        hashes = hashes or []
        local_tokens = set()
        for b in behaviors:
            local_tokens |= _tokenize(b)
        if not local_tokens and not domains and not hashes:
            return None

        best: Optional[dict] = None
        for c in self._campaign_pool():
            c_beh = c.get("behaviors", [])
            if isinstance(c_beh, str):
                try:
                    c_beh = json.loads(c_beh)
                except Exception:
                    c_beh = [c_beh]
            c_tokens = set()
            for b in c_beh:
                c_tokens |= _tokenize(b)

            matched = sorted(local_tokens & c_tokens)
            # Jaccard over behaviour tokens
            union = local_tokens | c_tokens
            sim = (len(matched) / len(union)) if union else 0.0

            # hard IOC matches dominate
            c_domains = c.get("ioc_domains", [])
            c_hashes = c.get("ioc_hashes", [])
            if isinstance(c_domains, str):
                try:
                    c_domains = json.loads(c_domains)
                except Exception:
                    c_domains = []
            if isinstance(c_hashes, str):
                try:
                    c_hashes = json.loads(c_hashes)
                except Exception:
                    c_hashes = []
            ioc_hit = bool(set(domains) & set(c_domains)) or bool(set(hashes) & set(c_hashes))
            if ioc_hit:
                sim = max(sim, 0.95)

            pct = round(sim * 100)
            if pct >= 35 and (best is None or pct > best["similarity"]):
                best = {
                    "threat_name": c.get("threat_name", "?"),
                    "similarity": pct,
                    "severity": c.get("severity", ""),
                    "source": c.get("source", ""),
                    "matched": matched + (["IOC match"] if ioc_hit else []),
                }
        return best


if __name__ == "__main__":
    from hydradb import HydraDB

    db = HydraDB()
    anakin = Anakin(db)
    n = anakin.ingest()
    print(f"source: {anakin.source} | newly stored: {n}")
    for intel in db.recent_intel(5):
        print(" -", intel["threat_name"], intel["severity"], intel["source"])
    m = anakin.match(["downloaded executable", "registry persistence",
                      "foreign network connection", "browser credential theft"])
    print("match:", m)
