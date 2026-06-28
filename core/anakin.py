"""Anakin — AI-powered web search + emerging threat-intelligence for HeadsUp.

Anakin's ``/v1/search`` endpoint performs an AI-powered web search and returns
ranked results with snippets and citations. HeadsUp uses it two ways:

1. **Threat-intel ingestion** — query the web for the latest malware campaigns /
   advisories (CISA, CVE feeds, Microsoft, BleepingComputer, The Hacker News,
   Reddit), then summarise the results into the ``threat_intelligence`` schema
   (with Gemma when available) and store them in HydraDB.
2. **Copilot web search** — answer live security questions ("explain this malware
   campaign", "search for …") grounded in fresh, cited web sources.

Without ``ANAKIN_API_KEY`` it falls back to a bundled set of recent real-world
campaigns (``data/sample_intel.json``) so HeadsUp always has intel to correlate
against. Local machine behaviour is matched against these campaigns to surface
"this looks like the X campaign (NN% similarity)".
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
_ANAKIN_URL = os.environ.get("ANAKIN_API_URL", "https://api.anakin.io/v1/search")
_THREAT_PROMPT = (
    "Latest malware campaigns, ransomware, infostealers, and actively exploited "
    "CVEs reported in the last two weeks by CISA, Microsoft Security, "
    "BleepingComputer and The Hacker News — include the threat name, affected "
    "software, indicators of compromise, and observed behaviors."
)
_STOPWORDS = {"the", "a", "an", "of", "to", "and", "for", "via", "with", "from", "on"}


def _tokenize(text: str) -> set[str]:
    toks = re.split(r"[^a-z0-9]+", (text or "").lower())
    return {t for t in toks if t and t not in _STOPWORDS and len(t) > 2}


def _domain_of(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url or "")
    return m.group(1).replace("www.", "") if m else ""


class Anakin:
    def __init__(self, db, analyst=None) -> None:
        self.db = db
        self.analyst = analyst
        self.api_key = os.environ.get("ANAKIN_API_KEY", "")
        self._campaigns: list[dict] = []   # in-memory copy for fast matching
        self._lock = threading.Lock()

    @property
    def web_search_available(self) -> bool:
        return bool(self.api_key and _HAS_REQUESTS)

    @property
    def source(self) -> str:
        return "Anakin web search" if self.web_search_available else "bundled sample feed"

    # ── AI-powered web search (Anakin /v1/search) ─────────────────────────────

    def search(self, prompt: str, limit: int = 5) -> dict:
        """AI-powered web search. Returns {"id", "results"[], "summary"}.

        Empty dict-shape when no API key / requests is unavailable.
        """
        if not self.web_search_available:
            return {"id": "", "results": [], "summary": ""}
        resp = requests.post(
            _ANAKIN_URL,
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
            json={"prompt": prompt, "limit": limit},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return {"id": "", "results": [], "summary": ""}
        return {
            "id": data.get("id", ""),
            "results": data.get("results") or [],
            "summary": data.get("summary") or data.get("answer") or "",
        }

    def web_answer(self, question: str, limit: int = 5) -> str:
        """Search the web via Anakin and return a cited, Gemma-synthesised answer.

        Returns "" when web search is unavailable (caller decides the fallback).
        """
        if not self.web_search_available:
            return ""
        try:
            res = self.search(question, limit=limit)
        except Exception as exc:
            return f"Anakin web search failed: {str(exc)[:80]}"
        results = res.get("results", [])
        summary = res.get("summary", "")
        if not results and not summary:
            return "No web results found."
        sources = "\n".join(
            f"[{i+1}] {r.get('title', '')} — {r.get('url', '')}\n    "
            f"{(r.get('snippet') or '')[:200]}"
            for i, r in enumerate(results))
        cite_list = "\n".join(f"[{i+1}] {r.get('url', '')}" for i, r in enumerate(results))

        if summary:
            return summary + (f"\n\nSources:\n{cite_list}" if cite_list else "")
        if self.analyst is not None and getattr(self.analyst, "available", False):
            ans = self.analyst._chat(
                "You are a security research assistant. Answer using ONLY the "
                "provided web sources and cite them inline as [n]. Be concise.",
                f"Question: {question}\n\nWeb sources:\n{sources}", 600)
            if ans and not ans.startswith("[AI error"):
                return ans + (f"\n\nSources:\n{cite_list}" if cite_list else "")
        return "Top web results:\n" + sources

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
        if self.web_search_available:
            try:
                campaigns = self._fetch_anakin()
                if campaigns:
                    return campaigns
            except Exception:
                pass  # fall back to bundled feed
        return self._fetch_bundled()

    def _fetch_anakin(self) -> list[dict]:
        """Web-search the latest threats via Anakin and structure the results."""
        results = self.search(_THREAT_PROMPT, limit=8).get("results", [])
        if not results:
            return []
        return self._extract_campaigns(results)

    def _extract_campaigns(self, results: list[dict]) -> list[dict]:
        """Turn raw web search results into threat_intelligence records.

        Uses Gemma to extract structured, named campaigns from the snippets when
        available; otherwise maps one record per search result.
        """
        if self.analyst is not None and getattr(self.analyst, "available", False):
            digest = "\n\n".join(
                f"TITLE: {r.get('title', '')}\nURL: {r.get('url', '')}\n"
                f"DATE: {r.get('date', '')}\nSNIPPET: {r.get('snippet', '')}"
                for r in results[:8])[:6000]
            prompt = (
                "From these web search results about cybersecurity threats, extract "
                "distinct, named malware campaigns or advisories as a JSON array. "
                "Each item: {threat_name, ioc_domains[], ioc_hashes[], behaviors[], "
                "severity (LOW|MEDIUM|HIGH|CRITICAL), source, published_at}. Only "
                "include real, named threats. Return ONLY the JSON array.\n\n" + digest)
            out = self.analyst._chat(
                "You output only strict JSON arrays for threat-intelligence extraction.",
                prompt, 900)
            s, e = out.find("["), out.rfind("]") + 1
            if s >= 0 and e > s:
                try:
                    arr = json.loads(out[s:e])
                    if isinstance(arr, list):
                        campaigns = [self._coerce(x) for x in arr if isinstance(x, dict)]
                        campaigns = [c for c in campaigns if c["threat_name"]]
                        if campaigns:
                            return campaigns
                except Exception:
                    pass
        # fallback: one record per search result (no Gemma)
        return [self._result_to_campaign(r) for r in results]

    @staticmethod
    def _coerce(item: dict) -> dict:
        """Fill schema defaults on a Gemma-extracted record."""
        def _aslist(v):
            return v if isinstance(v, list) else ([v] if v else [])
        return {
            "threat_name": (item.get("threat_name") or item.get("name") or "").strip(),
            "ioc_domains": _aslist(item.get("ioc_domains") or item.get("domains")),
            "ioc_hashes": _aslist(item.get("ioc_hashes") or item.get("hashes")),
            "behaviors": _aslist(item.get("behaviors") or item.get("tags")),
            "severity": (item.get("severity") or "").upper(),
            "source": item.get("source") or "Anakin",
            "published_at": item.get("published_at") or item.get("date", ""),
        }

    def _result_to_campaign(self, r: dict) -> dict:
        """Map a single web search result to a loose threat_intelligence record."""
        title = (r.get("title") or "").strip() or "Web threat report"
        snippet = (r.get("snippet") or "").strip()
        return {
            "threat_name": title[:80],
            "ioc_domains": [], "ioc_hashes": [],
            "behaviors": [snippet] if snippet else [],
            "severity": "",
            "source": _domain_of(r.get("url", "")) or "Anakin",
            "published_at": r.get("date") or r.get("last_updated") or "",
        }

    def _fetch_bundled(self) -> list[dict]:
        try:
            with open(_SAMPLE_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

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
            union = local_tokens | c_tokens
            jaccard = (len(matched) / len(union)) if union else 0.0
            # campaign coverage: how many of THIS campaign's behaviours we exhibit
            coverage = (len(matched) / len(c_tokens)) if c_tokens else 0.0
            sim = max(jaccard, coverage)

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
