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

_DEFAULT_PATH = Path.home() / ".headsup" / "headsup.db"


def now_iso() -> str:
    """UTC timestamp, sortable as a string."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


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

    # ── backend label ───────────────────────────────────────────────────────

    @property
    def backend(self) -> str:
        return "hydra/postgres" if self._pg else "sqlite"

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

    def resolve_incident(self, incident_id: str) -> None:
        self._exec("UPDATE incidents SET resolved = 1 WHERE incident_id = ?", (incident_id,))

    def store_prediction(
        self, subject: str, prediction: str, confidence: float = 0.0,
        incident_id: str = "",
    ) -> None:
        self._exec(
            "INSERT INTO predictions (timestamp, incident_id, subject, prediction, confidence) "
            "VALUES (?, ?, ?, ?, ?)",
            (now_iso(), incident_id, subject, prediction, confidence),
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
        if not c["hits"]:
            return ""
        lines = [f"[MEMORY] Seen {c['hits']}x before (worst risk {c['worst']})."]
        if c["last_seen"]:
            lines.append(f"[MEMORY] Last seen {c['last_seen']}, first seen {c['first_seen']}.")
        return "\n".join(lines)

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
