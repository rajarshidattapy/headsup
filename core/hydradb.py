"""HydraDB — long-term threat memory for HeadsUp.

The persistent memory layer that "never forgets". Stores every observed system
event, the threat intelligence ingested from the web, the incidents HeadsUp
opens, and the predictions Gemma makes.

Backends
--------
* **SQLite** (default) — zero-setup file at ``~/.headsup/headsup.db``. Works on
  any machine with no services running.
* **Hydra / Postgres** — used automatically when ``HYDRA_URL`` is set (e.g.
  ``postgresql://user:pass@localhost:5432/headsup``). Falls back to SQLite if
  the driver/connection is unavailable.

Schema (mirrors the PRD)
------------------------
* ``process_events``      timestamp, pid, process_name, parent_process, path, risk_score
* ``network_events``      timestamp, process_name, remote_ip, remote_domain, country, risk_score
* ``system_events``       generic startup/registry/file/download/dns observations
* ``threat_intelligence`` threat_name, ioc_domains, ioc_hashes, behaviors, severity, source, published_at
* ``incidents``           incident_id, summary, confidence, prediction, resolved
* ``predictions``         AI predictions tied to an incident
"""
from __future__ import annotations

import json
import os
import queue
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

# Optional Postgres / Hydra driver
try:  # pragma: no cover - optional dependency
    import psycopg2  # type: ignore
    import psycopg2.extras  # type: ignore
    _HAS_PG = True
except ImportError:  # pragma: no cover
    _HAS_PG = False

# Optional HTTP client for the HydraDB cloud memory backend
try:  # pragma: no cover - optional dependency
    import requests  # type: ignore
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    _HAS_REQUESTS = False

_DEFAULT_PATH = Path.home() / ".headsup" / "headsup.db"


def now_iso() -> str:
    """UTC timestamp, sortable as a string."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def severity_for(score: int) -> str:
    """Map a 0-4 risk score to a HydraDB severity label."""
    s = int(score or 0)
    if s >= 4:
        return "CRITICAL"
    return {0: "SAFE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}.get(s, "MEDIUM")


def _clean_meta(d: dict) -> dict:
    """Drop empty values but keep 0 / False (they are meaningful metadata)."""
    return {k: v for k, v in d.items() if v is not None and v != "" and v != []}


def _extract_texts(data: Any, limit: int) -> list[str]:
    """Best-effort pull of memory snippets out of a recall response."""
    out: list[str] = []

    def walk(node):
        if len(out) >= limit:
            return
        if isinstance(node, dict):
            for key in ("memory", "text", "content", "chunk", "summary"):
                val = node.get(key)
                if isinstance(val, str) and val.strip():
                    out.append(val.strip())
                    break
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return out[:limit]


# ════════════════════════════════════════════════════════════════════════════
#  HydraDB cloud memory backend (usecortex — https://api.hydradb.com)
# ════════════════════════════════════════════════════════════════════════════

class _HydraCloud:
    """Long-term semantic memory in HydraDB.

    Active when ``HYDRADB_API_KEY`` + ``HYDRADB_TENANT_ID`` are set. Every event
    HeadsUp records is also ingested here with structured ``tenant_metadata``
    (matching ``hydradb.tenant-schema.json``), so memory survives across machines
    and sessions and can be filtered/recalled. Writes are queued and sent on a
    background worker so they never block the 1-second monitor loop.
    """

    INGEST_PATH = "/memories/add_memory"
    RECALL_PATH = "/recall/recall_preferences"

    def __init__(self) -> None:
        self.api_key = os.environ.get("HYDRADB_API_KEY", "")
        self.tenant_id = os.environ.get("HYDRADB_TENANT_ID", "")
        self.sub_tenant_id = os.environ.get("HYDRADB_SUB_TENANT_ID", "")
        self.base = os.environ.get("HYDRADB_API_BASE", "https://api.hydradb.com").rstrip("/")
        self._timeout = float(os.environ.get("HYDRADB_REQUEST_TIMEOUT_MS", "8000")) / 1000.0
        self.available = bool(self.api_key and self.tenant_id and _HAS_REQUESTS)
        self._q: queue.Queue = queue.Queue(maxsize=500)
        self._session = None
        if self.available:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
            threading.Thread(target=self._worker, daemon=True, name="hydradb-ingest").start()

    # ── ingestion (non-blocking) ────────────────────────────────────────────
    def ingest(self, text: str, metadata: dict, source_id: str = "", infer: bool = False) -> None:
        if not self.available:
            return
        try:
            self._q.put_nowait((text, metadata, source_id, infer))
        except queue.Full:
            pass  # best-effort; drop under pressure rather than block monitoring

    def _worker(self) -> None:
        while True:
            text, metadata, source_id, infer = self._q.get()
            try:
                self._post_memory(text, metadata, source_id, infer)
            except Exception:
                pass

    def _post_memory(self, text: str, metadata: dict, source_id: str, infer: bool) -> None:
        item: dict = {"text": text, "infer": bool(infer),
                      "tenant_metadata": json.dumps(_clean_meta(metadata))}
        if source_id:
            item["source_id"] = source_id
        body: dict = {"memories": [item], "tenant_id": self.tenant_id, "upsert": True}
        if self.sub_tenant_id:
            body["sub_tenant_id"] = self.sub_tenant_id
        self._session.post(self.base + self.INGEST_PATH, json=body, timeout=self._timeout)

    # ── recall (best-effort, short timeout) ─────────────────────────────────
    def recall(self, query: str, metadata_filters: Optional[dict] = None,
               max_results: int = 4) -> list[str]:
        if not self.available:
            return []
        body: dict = {"tenant_id": self.tenant_id, "query": query or "suspicious activity",
                      "mode": "fast", "max_results": max_results}
        if self.sub_tenant_id:
            body["sub_tenant_id"] = self.sub_tenant_id
        if metadata_filters:
            body["metadata_filters"] = _clean_meta(metadata_filters)
        try:
            r = self._session.post(self.base + self.RECALL_PATH, json=body, timeout=self._timeout)
            r.raise_for_status()
            return _extract_texts(r.json(), max_results)
        except Exception:
            return []


# ── DDL ─────────────────────────────────────────────────────────────────────

_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS process_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    pid            INTEGER,
    process_name   TEXT,
    parent_process TEXT,
    path           TEXT,
    risk_score     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS network_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    process_name   TEXT,
    remote_ip      TEXT,
    remote_domain  TEXT,
    country        TEXT,
    risk_score     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS system_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    kind           TEXT,
    source         TEXT,
    summary        TEXT,
    detail         TEXT,
    risk_score     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_name    TEXT,
    ioc_domains    TEXT,
    ioc_hashes     TEXT,
    behaviors      TEXT,
    severity       TEXT,
    source         TEXT,
    published_at   TEXT,
    ingested_at    TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id    TEXT UNIQUE,
    timestamp      TEXT,
    summary        TEXT,
    confidence     REAL,
    prediction     TEXT,
    severity       TEXT,
    resolved       INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS predictions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT,
    incident_id    TEXT,
    subject        TEXT,
    prediction     TEXT,
    confidence     REAL
);
CREATE INDEX IF NOT EXISTS ix_proc_ts ON process_events(timestamp);
CREATE INDEX IF NOT EXISTS ix_net_ts  ON network_events(timestamp);
CREATE INDEX IF NOT EXISTS ix_net_ip  ON network_events(remote_ip);
CREATE INDEX IF NOT EXISTS ix_sys_ts  ON system_events(timestamp);
"""


class HydraDB:
    """Threat-memory store. Thread-safe; one connection guarded by a lock."""

    def __init__(self, path: Optional[Path] = None, hydra_url: str = "") -> None:
        self._lock = threading.Lock()
        self._url = hydra_url or os.environ.get("HYDRA_URL", "")
        self._pg = False
        self._conn = None

        if self._url and _HAS_PG:
            try:
                self._conn = psycopg2.connect(self._url)
                self._conn.autocommit = True
                self._pg = True
            except Exception:
                self._conn = None  # fall through to sqlite

        if self._conn is None:
            self._path = Path(path) if path else _DEFAULT_PATH
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row

        self._init_schema()

        # Long-term cloud memory (HydraDB) — additive; SQLite/Postgres stays the
        # local store that powers the live dashboard and the offline fallback.
        self._host = socket.gethostname()
        self._cloud = _HydraCloud()

    # ── backend label ───────────────────────────────────────────────────────

    @property
    def backend(self) -> str:
        return "hydra/postgres" if self._pg else "sqlite"

    @property
    def cloud_active(self) -> bool:
        return bool(getattr(self, "_cloud", None) and self._cloud.available)

    @property
    def memory_mode(self) -> str:
        """Short label for the banner: reflects HydraDB cloud + local store."""
        local = "Postgres" if self._pg else "SQLite"
        if self.cloud_active:
            return f"cloud + {local}"
        return "Hydra/Postgres" if self._pg else "local SQLite"

    @property
    def location(self) -> str:
        return self._url if self._pg else str(getattr(self, "_path", "?"))

    # ── low-level helpers ─────────────────────────────────────────────────────

    def _q(self, sql: str) -> str:
        """Translate '?' placeholders to '%s' for psycopg2."""
        return sql.replace("?", "%s") if self._pg else sql

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self._pg:
                # Postgres: SERIAL/auto-increment differs slightly; reuse the
                # same DDL but swap the autoincrement clause.
                ddl = _SCHEMA_SQLITE.replace(
                    "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"
                )
                for stmt in ddl.split(";"):
                    if stmt.strip():
                        try:
                            cur.execute(stmt)
                        except Exception:
                            pass
            else:
                cur.executescript(_SCHEMA_SQLITE)
                self._conn.commit()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._q(sql), params)
            if not self._pg:
                self._conn.commit()

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._q(sql), params)
            rows = cur.fetchall()
            if self._pg:
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, r)) for r in rows]
            return [dict(r) for r in rows]

    # ── writers ───────────────────────────────────────────────────────────────

    def store_process_event(
        self, pid: Optional[int], process_name: str, parent_process: str = "",
        path: str = "", risk_score: int = 0, ts: str = "",
    ) -> None:
        self._exec(
            "INSERT INTO process_events "
            "(timestamp, pid, process_name, parent_process, path, risk_score) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts or now_iso(), pid, process_name, parent_process, path, int(risk_score)),
        )
        parent = f" (parent {parent_process})" if parent_process else ""
        self._cloud.ingest(
            f"[process] {process_name} started{parent} from {path or 'unknown path'}",
            {"event_type": "process", "source": "monitor",
             "severity": severity_for(risk_score), "risk_score": int(risk_score),
             "host": self._host, "process_name": process_name, "pid": pid},
        )

    def store_network_event(
        self, process_name: str, remote_ip: str, remote_domain: str = "",
        country: str = "", risk_score: int = 0, ts: str = "",
    ) -> None:
        self._exec(
            "INSERT INTO network_events "
            "(timestamp, process_name, remote_ip, remote_domain, country, risk_score) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts or now_iso(), process_name, remote_ip, remote_domain, country, int(risk_score)),
        )
        tgt = remote_domain or remote_ip
        self._cloud.ingest(
            f"[network] {process_name} connected to {tgt}"
            + (f" ({country})" if country else ""),
            {"event_type": "network", "source": "monitor",
             "severity": severity_for(risk_score), "risk_score": int(risk_score),
             "host": self._host, "process_name": process_name,
             "remote_ip": remote_ip, "remote_domain": remote_domain, "country": country},
        )

    def store_system_event(
        self, kind: str, summary: str, source: str = "", detail: Any = None,
        risk_score: int = 0, ts: str = "",
    ) -> None:
        """Generic observation: startup / registry / file / download / dns / log."""
        self._exec(
            "INSERT INTO system_events "
            "(timestamp, kind, source, summary, detail, risk_score) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts or now_iso(), kind, source, summary,
             json.dumps(detail) if detail is not None else "", int(risk_score)),
        )
        self._cloud.ingest(
            f"[{kind}] {summary}",
            {"event_type": kind, "source": "monitor",
             "severity": severity_for(risk_score), "risk_score": int(risk_score),
             "host": self._host},
        )

    def store_intel(
        self, threat_name: str, ioc_domains: list[str] | None = None,
        ioc_hashes: list[str] | None = None, behaviors: list[str] | None = None,
        severity: str = "", source: str = "", published_at: str = "",
    ) -> None:
        self._exec(
            "INSERT INTO threat_intelligence "
            "(threat_name, ioc_domains, ioc_hashes, behaviors, severity, source, "
            " published_at, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                threat_name,
                json.dumps(ioc_domains or []),
                json.dumps(ioc_hashes or []),
                json.dumps(behaviors or []),
                severity, source, published_at, now_iso(),
            ),
        )
        beh = ", ".join(behaviors or []) or "n/a"
        doms = ", ".join(ioc_domains or []) or "n/a"
        self._cloud.ingest(
            f"Threat intelligence: {threat_name} ({severity}) from {source}. "
            f"Behaviors: {beh}. IOC domains: {doms}.",
            {"event_type": "intel", "source": "anakin", "severity": severity,
             "host": self._host, "threat_name": threat_name},
            source_id=f"intel:{threat_name}",
        )

    def open_incident(
        self, incident_id: str, summary: str, confidence: float = 0.0,
        prediction: str = "", severity: str = "MEDIUM",
    ) -> None:
        sql = (
            "INSERT INTO incidents "
            "(incident_id, timestamp, summary, confidence, prediction, severity, resolved) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)"
        )
        if self._pg:
            sql += " ON CONFLICT (incident_id) DO NOTHING"
        else:
            sql = sql.replace("INSERT INTO", "INSERT OR IGNORE INTO")
        self._exec(sql, (incident_id, now_iso(), summary, confidence, prediction, severity))
        self._cloud.ingest(
            f"Incident {incident_id}: {summary}. Prediction: {prediction}",
            {"event_type": "incident", "source": "analyst", "severity": severity,
             "host": self._host, "incident_id": incident_id,
             "confidence": round(float(confidence), 3), "resolved": False},
            source_id=incident_id, infer=True,
        )

    def resolve_incident(self, incident_id: str) -> None:
        self._exec("UPDATE incidents SET resolved = 1 WHERE incident_id = ?", (incident_id,))
        self._cloud.ingest(
            f"Incident {incident_id} resolved.",
            {"event_type": "incident", "source": "user", "host": self._host,
             "incident_id": incident_id, "resolved": True},
            source_id=incident_id,
        )

    def store_prediction(
        self, subject: str, prediction: str, confidence: float = 0.0,
        incident_id: str = "",
    ) -> None:
        self._exec(
            "INSERT INTO predictions (timestamp, incident_id, subject, prediction, confidence) "
            "VALUES (?, ?, ?, ?, ?)",
            (now_iso(), incident_id, subject, prediction, confidence),
        )
        self._cloud.ingest(
            f"Prediction for {subject}: {prediction}",
            {"event_type": "prediction", "source": "analyst",
             "host": self._host, "incident_id": incident_id,
             "confidence": round(float(confidence), 3)},
        )

    # ── readers ───────────────────────────────────────────────────────────────

    def timeline(self, limit: int = 40) -> list[dict]:
        """Unified, newest-first event timeline across all observation tables.

        Each entry: {ts, kind, summary, risk_score}.
        """
        rows: list[dict] = []
        for r in self._query(
            "SELECT timestamp, pid, process_name, path, risk_score "
            "FROM process_events ORDER BY id DESC LIMIT ?", (limit,)
        ):
            rows.append({
                "ts": r["timestamp"], "kind": "process",
                "summary": f"{r['process_name']} started"
                           + (f" (pid {r['pid']})" if r.get("pid") else ""),
                "risk_score": r.get("risk_score", 0),
            })
        for r in self._query(
            "SELECT timestamp, process_name, remote_ip, remote_domain, country, risk_score "
            "FROM network_events ORDER BY id DESC LIMIT ?", (limit,)
        ):
            tgt = r.get("remote_domain") or r.get("remote_ip") or "?"
            rows.append({
                "ts": r["timestamp"], "kind": "network",
                "summary": f"{r['process_name']} → {tgt}"
                           + (f" ({r['country']})" if r.get("country") else ""),
                "risk_score": r.get("risk_score", 0),
            })
        for r in self._query(
            "SELECT timestamp, kind, summary, risk_score "
            "FROM system_events ORDER BY id DESC LIMIT ?", (limit,)
        ):
            rows.append({
                "ts": r["timestamp"], "kind": r.get("kind", "system"),
                "summary": r.get("summary", ""), "risk_score": r.get("risk_score", 0),
            })
        rows.sort(key=lambda e: e["ts"], reverse=True)
        return rows[:limit]

    def correlate(self, ip: str = "", process: str = "", domain: str = "") -> dict:
        """Have I seen this before? Returns hit counts + worst risk per source."""
        out: dict[str, Any] = {"hits": 0, "first_seen": "", "last_seen": "", "worst": 0}
        clauses = []
        if ip:
            clauses.append(("network_events", "remote_ip = ?", (ip,)))
        if domain:
            clauses.append(("network_events", "remote_domain = ?", (domain,)))
        if process:
            clauses.append(("network_events", "process_name LIKE ?", (f"%{process}%",)))
            clauses.append(("process_events", "process_name LIKE ?", (f"%{process}%",)))
        seen_ts: list[str] = []
        for table, where, params in clauses:
            for r in self._query(
                f"SELECT timestamp, risk_score FROM {table} WHERE {where} "
                f"ORDER BY id DESC LIMIT 100", params
            ):
                out["hits"] += 1
                seen_ts.append(r["timestamp"])
                out["worst"] = max(out["worst"], r.get("risk_score", 0) or 0)
        if seen_ts:
            seen_ts.sort()
            out["first_seen"] = seen_ts[0]
            out["last_seen"] = seen_ts[-1]
        return out

    def recent_intel(self, limit: int = 10) -> list[dict]:
        rows = self._query(
            "SELECT threat_name, severity, source, behaviors, ioc_domains, "
            "published_at, ingested_at FROM threat_intelligence "
            "ORDER BY id DESC LIMIT ?", (limit,)
        )
        for r in rows:
            for col in ("behaviors", "ioc_domains"):
                try:
                    r[col] = json.loads(r.get(col) or "[]")
                except Exception:
                    r[col] = []
        return rows

    def intel_count(self, since_hours: int = 24) -> int:
        cutoff = (datetime.utcnow() - timedelta(hours=since_hours)).isoformat() + "Z"
        rows = self._query(
            "SELECT COUNT(*) AS n FROM threat_intelligence WHERE ingested_at >= ?", (cutoff,)
        )
        return int(rows[0]["n"]) if rows else 0

    def recent_incidents(self, limit: int = 10, unresolved_only: bool = False) -> list[dict]:
        where = "WHERE resolved = 0 " if unresolved_only else ""
        return self._query(
            f"SELECT incident_id, timestamp, summary, confidence, prediction, severity, "
            f"resolved FROM incidents {where}ORDER BY id DESC LIMIT ?", (limit,)
        )

    def count(self, table: str, since_hours: int = 0) -> int:
        if table not in ("process_events", "network_events", "system_events",
                         "threat_intelligence", "incidents", "predictions"):
            return 0
        if since_hours:
            cutoff = (datetime.utcnow() - timedelta(hours=since_hours)).isoformat() + "Z"
            col = "ingested_at" if table == "threat_intelligence" else "timestamp"
            rows = self._query(f"SELECT COUNT(*) AS n FROM {table} WHERE {col} >= ?", (cutoff,))
        else:
            rows = self._query(f"SELECT COUNT(*) AS n FROM {table}")
        return int(rows[0]["n"]) if rows else 0

    def health_score(self) -> tuple[int, str]:
        """0–100 machine health score derived from recent risk activity.

        Higher == healthier. Returns (score, label).
        """
        rows = self._query(
            "SELECT risk_score FROM network_events ORDER BY id DESC LIMIT 200"
        ) + self._query(
            "SELECT risk_score FROM process_events ORDER BY id DESC LIMIT 200"
        ) + self._query(
            "SELECT risk_score FROM system_events ORDER BY id DESC LIMIT 200"
        )
        scores = [r.get("risk_score", 0) or 0 for r in rows]
        unresolved = self.count_unresolved_incidents()
        penalty = sum(s for s in scores if s >= 3) * 4 + sum(
            1 for s in scores if s == 2) * 2 + unresolved * 12
        score = max(0, 100 - penalty)
        if score >= 80:
            label = "HEALTHY"
        elif score >= 55:
            label = "ELEVATED"
        elif score >= 30:
            label = "MEDIUM"
        else:
            label = "CRITICAL"
        return score, label

    def count_unresolved_incidents(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM incidents WHERE resolved = 0")
        return int(rows[0]["n"]) if rows else 0

    # ── memory context for the AI prompt (used by analyst) ─────────────────────

    def memory_context(self, ip: str = "", process: str = "", domain: str = "") -> str:
        c = self.correlate(ip=ip, process=process, domain=domain)
        lines: list[str] = []
        if c["hits"]:
            lines.append(f"[MEMORY] Seen {c['hits']}x before (worst risk {c['worst']}).")
            if c["last_seen"]:
                lines.append(f"[MEMORY] Last seen {c['last_seen']}, first seen {c['first_seen']}.")
        # Cross-session / cross-machine recall from HydraDB cloud memory.
        if self.cloud_active:
            query = " ".join(x for x in (process, domain, ip) if x)
            for snippet in self._cloud.recall(query, max_results=3):
                lines.append(f"[HYDRADB] {snippet[:160]}")
        return "\n".join(lines)

    def recall(self, query: str, metadata_filters: Optional[dict] = None,
               max_results: int = 5) -> list[str]:
        """Semantic recall from HydraDB cloud memory (empty when not configured)."""
        if not self.cloud_active:
            return []
        return self._cloud.recall(query, metadata_filters, max_results)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ── module-level singleton helper ──────────────────────────────────────────────

_DB: Optional[HydraDB] = None
_DB_LOCK = threading.Lock()


def get_db() -> HydraDB:
    global _DB
    with _DB_LOCK:
        if _DB is None:
            _DB = HydraDB()
        return _DB


if __name__ == "__main__":  # tiny smoke test
    db = HydraDB()
    print("backend:", db.backend, "@", db.location)
    db.store_process_event(1234, "powershell.exe", "explorer.exe",
                           r"C:\Windows\System32\powershell.exe", risk_score=2)
    db.store_network_event("powershell.exe", "45.33.32.156", "evil.example",
                           "US", risk_score=4)
    db.store_system_event("registry", "Run key modified: Updater",
                          source="HKCU\\...\\Run", risk_score=3)
    print("health:", db.health_score())
    for ev in db.timeline(10):
        print(" ", ev["ts"], ev["kind"], ev["summary"], ev["risk_score"])
