"""HeadsUp monitoring engine.

Watches the *whole machine* (not just the network) on a 1-second poll plus an
event-driven file watcher, normalises every observation, scores its risk, and
writes it into HydraDB — the persistent threat memory.

Sources
-------
* processes      — new process executions (name / pid / parent / path)
* network        — outbound/listening connections (+ GeoIP, reverse-DNS domain)
* startup        — Windows Run keys + Startup-folder changes
* registry       — Run-key value diffs (Windows)
* downloads      — new files landing in the Downloads folder
* files          — created/modified executables & scripts (watchdog)

This module also exports the *pure* network/risk helpers reused by the TUI, so
the UI layer never has to import the engine's stateful pieces.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.request
import json
from pathlib import Path
from typing import Callable, NamedTuple, Optional

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore

# watchdog is optional — file-change collector silently disables without it
try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    _HAS_WATCHDOG = True
except ImportError:  # pragma: no cover
    _HAS_WATCHDOG = False
    FileSystemEventHandler = object  # type: ignore

# winreg is Windows-only
try:
    import winreg  # type: ignore
    _HAS_WINREG = True
except ImportError:  # pragma: no cover
    _HAS_WINREG = False


# ════════════════════════════════════════════════════════════════════════════
#  Pure helpers (shared with the TUI)
# ════════════════════════════════════════════════════════════════════════════

RISK_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "red"), 22: ("SSH", "yellow"), 23: ("Telnet", "bold red"),
    25: ("SMTP", "yellow"), 53: ("DNS", "cyan"), 80: ("HTTP", "white"),
    443: ("HTTPS", "green"), 3306: ("MySQL", "bold yellow"),
    3389: ("RDP", "bold red"), 4444: ("ShellPort", "bold red"),
    5432: ("PostgreSQL", "bold yellow"), 8080: ("HTTP-Alt", "white"),
    8443: ("HTTPS-Alt", "green"), 27017: ("MongoDB", "bold yellow"),
    6379: ("Redis", "bold yellow"),
}

_PORT_SCORE: dict[int, int] = {
    23: 4, 21: 4, 4444: 4, 3389: 3,
    22: 2, 25: 2, 3306: 2, 5432: 2, 27017: 2, 6379: 2,
    80: 1, 8080: 1, 443: 0, 8443: 0, 53: 0,
}

_SUSPICIOUS_PATHS = (
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\temp\\",
    "\\downloads\\", "\\desktop\\", "c:\\temp\\", "c:\\windows\\temp\\",
    "\\$recycle.bin\\", "/tmp/", "/var/tmp/", "/downloads/", "/desktop/",
)

_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3",
    "192.168.", "127.", "::1", "fe80",
)

_EXECUTABLE_EXT = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                   ".js", ".jar", ".msi", ".com", ".pif", ".sh", ".apk")


def is_external(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::"):
        return False
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# backwards-compatible private alias used by some callers
_is_external = is_external


def resolve_host(ip: str, timeout: float = 0.4) -> str:
    if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return ip
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def port_label(port: int) -> str:
    if port in RISK_PORTS:
        name, _ = RISK_PORTS[port]
        return f"{port} [dim]({name})[/dim]"
    return str(port) if port else "—"


def port_style(port: int) -> str:
    return RISK_PORTS[port][1] if port in RISK_PORTS else "white"


def is_suspicious_path(path: str) -> bool:
    p = (path or "").lower()
    return any(s in p for s in _SUSPICIOUS_PATHS)


def calc_risk(conn, suspicious_path: bool = False) -> tuple[str, str]:
    """Return (label, rich_style) for a connection — HIGH / MED / LOW."""
    rip = conn.raddr.ip if conn.raddr else ""
    rport = conn.raddr.port if conn.raddr else 0
    laddr = conn.laddr
    status = getattr(conn, "status", "NONE") or "NONE"
    eff = rport or (laddr.port if laddr else 0)
    score = _PORT_SCORE.get(eff, 1)
    if is_external(rip) and status == "ESTABLISHED":
        score += 1
    if status == "LISTEN" and laddr and laddr.ip in ("0.0.0.0", "::"):
        score += 1
    if status == "SYN_SENT" and is_external(rip):
        score += 1
    if suspicious_path:
        score += 2
    if score >= 4:
        return "● HIGH", "bold red"
    if score >= 2:
        return "◆ MED", "bold yellow"
    return "○ LOW", "dim green"


def risk_to_score(label: str) -> int:
    """Map a HIGH/MED/LOW label to a 0–4 integer for HydraDB."""
    if "HIGH" in label:
        return 4
    if "MED" in label:
        return 2
    return 1


def get_proc_info(pid: Optional[int]) -> tuple[str, str, bool]:
    """(display_name, exe_path, is_suspicious)."""
    if pid is None or psutil is None:
        return "—", "", False
    try:
        p = psutil.Process(pid)
        exe = p.exe()
        return p.name(), exe, is_suspicious_path(exe)
    except Exception:
        return f"pid:{pid}", "", False


# ── GeoIP cache ────────────────────────────────────────────────────────────────

_geo_cache: dict[str, str] = {}
_geo_lock = threading.Lock()


def _fetch_geo(ip: str) -> None:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
        result = f"{d.get('countryCode', '?')}  {d.get('country', '?')}"
    except Exception:
        result = "?"
    with _geo_lock:
        _geo_cache[ip] = result


def get_geo(ip: str) -> str:
    if not ip or not is_external(ip):
        return "[dim]local[/dim]"
    with _geo_lock:
        cached = _geo_cache.get(ip)
    if cached is not None:
        return cached
    with _geo_lock:
        _geo_cache[ip] = "…"
    threading.Thread(target=_fetch_geo, args=(ip,), daemon=True).start()
    return "…"


def geo_country(ip: str) -> str:
    """Plain (un-markup) country string for storage."""
    with _geo_lock:
        return _geo_cache.get(ip, "?") if ip else ""


# ── connection enumeration ─────────────────────────────────────────────────────

class _Conn(NamedTuple):
    fd: int
    family: int
    type: int
    laddr: object
    raddr: object
    status: str
    pid: Optional[int]


def get_connections() -> list:
    if psutil is None:
        return []
    try:
        return psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []
        for proc in psutil.process_iter(["pid"]):
            try:
                for c in proc.net_connections(kind="inet"):
                    conns.append(_Conn(c.fd, c.family, c.type,
                                       c.laddr, c.raddr, c.status, proc.pid))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        return conns


def conn_key(conn) -> tuple:
    la = (conn.laddr.ip, conn.laddr.port) if conn.laddr else None
    ra = (conn.raddr.ip, conn.raddr.port) if conn.raddr else None
    return (la, ra, conn.pid)


_conn_key = conn_key  # alias


# ════════════════════════════════════════════════════════════════════════════
#  Watchdog file handler
# ════════════════════════════════════════════════════════════════════════════

class _FileHandler(FileSystemEventHandler):  # type: ignore
    def __init__(self, engine: "MonitoringEngine") -> None:
        self._engine = engine

    def on_created(self, event):  # noqa: D401
        if not getattr(event, "is_directory", False):
            self._engine._on_file_event(event.src_path, "created")

    def on_moved(self, event):
        dest = getattr(event, "dest_path", "")
        if dest and not getattr(event, "is_directory", False):
            self._engine._on_file_event(dest, "moved")


# ════════════════════════════════════════════════════════════════════════════
#  Monitoring engine
# ════════════════════════════════════════════════════════════════════════════

class MonitoringEngine:
    """Runs all collectors and persists observations into HydraDB.

    The TUI reads live state from :meth:`snapshot`; everything else is written
    straight to memory (HydraDB) and optionally pushed to an ``on_event``
    callback for live alerting.
    """

    def __init__(self, db, on_event: Optional[Callable[[dict], None]] = None,
                 poll_interval: float = 1.0) -> None:
        self.db = db
        self.on_event = on_event
        self.poll = poll_interval
        self._stop = threading.Event()
        self._lock = threading.Lock()

        # live state for the TUI
        self.connections: list = []
        self.new_keys: set = set()
        self.suspicious_processes: dict[int, str] = {}
        self.recent_events: list[dict] = []  # in-memory tail of normalised events

        # de-dup state
        self._seen_conns: dict[tuple, float] = {}
        self._seen_pids: set[int] = set()
        self._seen_downloads: set[str] = set()
        self._startup_baseline: dict[str, str] = {}
        self._stored_net: set[tuple] = set()
        self._observer = None

        home = Path.home()
        self._watch_dirs = [d for d in (
            home / "Downloads", home / "Desktop",
            Path(os.environ.get("TEMP", "")) if os.environ.get("TEMP") else None,
        ) if d and Path(d).exists()]
        self._downloads_dir = home / "Downloads"

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._snapshot_startup_baseline()
        # seed PID baseline so we don't dump every running process on launch
        if psutil is not None:
            self._seen_pids = {p.pid for p in psutil.process_iter()}
        threading.Thread(target=self._poll_loop, daemon=True, name="hu-poll").start()
        self._start_file_watcher()

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            try:
                self._observer.stop()
            except Exception:
                pass

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "connections": list(self.connections),
                "new_keys": set(self.new_keys),
                "suspicious_processes": dict(self.suspicious_processes),
                "active_connections": len(self.connections),
                "suspicious_count": len(self.suspicious_processes),
            }

    # ── poll loop ─────────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._collect_network()
                self._collect_processes()
                self._collect_startup()
                self._collect_downloads()
            except Exception:
                pass
            self._stop.wait(self.poll)

    # ── emit ──────────────────────────────────────────────────────────────────

    def _emit(self, event: dict) -> None:
        with self._lock:
            self.recent_events.append(event)
            if len(self.recent_events) > 200:
                self.recent_events = self.recent_events[-200:]
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

    # ── network collector ─────────────────────────────────────────────────────

    def _collect_network(self) -> None:
        conns = get_connections()
        now = time.time()
        keys = {conn_key(c) for c in conns}
        with self._lock:
            for k in keys:
                self._seen_conns.setdefault(k, now)
            for k in list(self._seen_conns):
                if k not in keys:
                    del self._seen_conns[k]
            new_keys = {k for k, ts in self._seen_conns.items() if now - ts < 6.0}
            self.connections = conns
            self.new_keys = new_keys

        for conn in conns:
            rip = conn.raddr.ip if conn.raddr else ""
            if not rip or not is_external(rip):
                continue
            store_key = (conn_key(conn), rip)
            if store_key in self._stored_net:
                continue
            self._stored_net.add(store_key)
            name, exe, suspicious = get_proc_info(conn.pid)
            label, _ = calc_risk(conn, suspicious_path=suspicious)
            score = risk_to_score(label)
            get_geo(rip)  # warm the cache for the country column
            domain = resolve_host(rip)
            self.db.store_network_event(
                process_name=name, remote_ip=rip,
                remote_domain=domain if domain != rip else "",
                country=geo_country(rip), risk_score=score,
            )
            self._emit({
                "kind": "network", "risk_score": score,
                "summary": f"{name} → {domain if domain != rip else rip}",
                "process": name, "remote_ip": rip, "pid": conn.pid,
                "exe": exe, "suspicious": suspicious,
            })

    # ── process collector ─────────────────────────────────────────────────────

    def _collect_processes(self) -> None:
        if psutil is None:
            return
        suspicious: dict[int, str] = {}
        for proc in psutil.process_iter(["pid", "name", "ppid", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                exe = info.get("exe") or ""
                name = info.get("name") or f"pid:{pid}"
                sus = is_suspicious_path(exe)
                if sus:
                    suspicious[pid] = name
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)
                parent = ""
                try:
                    ppid = info.get("ppid")
                    if ppid:
                        parent = psutil.Process(ppid).name()
                except Exception:
                    pass
                score = 3 if sus else 0
                self.db.store_process_event(
                    pid=pid, process_name=name, parent_process=parent,
                    path=exe, risk_score=score,
                )
                self._emit({
                    "kind": "process", "risk_score": score,
                    "summary": f"{name} started"
                               + (" [suspicious path]" if sus else ""),
                    "process": name, "pid": pid, "exe": exe, "suspicious": sus,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # prune dead PIDs occasionally so the set doesn't grow unbounded
        if len(self._seen_pids) > 4000:
            alive = {p.pid for p in psutil.process_iter()}
            self._seen_pids &= alive
        with self._lock:
            self.suspicious_processes = suspicious

    # ── startup / registry collector ───────────────────────────────────────────

    def _read_run_keys(self) -> dict[str, str]:
        items: dict[str, str] = {}
        if not _HAS_WINREG:
            return items
        roots = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for root, sub in roots:
            try:
                with winreg.OpenKey(root, sub) as key:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            items[f"{sub}\\{name}"] = str(val)
                            i += 1
                        except OSError:
                            break
            except OSError:
                continue
        # Startup folder
        startup = (Path(os.environ.get("APPDATA", "")) /
                   "Microsoft/Windows/Start Menu/Programs/Startup")
        if startup.exists():
            for f in startup.iterdir():
                items[f"StartupFolder\\{f.name}"] = str(f)
        return items

    def _snapshot_startup_baseline(self) -> None:
        self._startup_baseline = self._read_run_keys()

    def _collect_startup(self) -> None:
        if not _HAS_WINREG:
            return
        current = self._read_run_keys()
        if not self._startup_baseline:
            self._startup_baseline = current
            return
        for name, val in current.items():
            if self._startup_baseline.get(name) != val:
                kind = "startup" if "StartupFolder" in name else "registry"
                summary = f"Startup item added/changed: {name.split(chr(92))[-1]}"
                self.db.store_system_event(
                    kind=kind, summary=summary, source=name,
                    detail={"value": val}, risk_score=3,
                )
                self._emit({"kind": kind, "risk_score": 3, "summary": summary,
                            "detail": val})
        self._startup_baseline = current

    # ── downloads collector ────────────────────────────────────────────────────

    def _collect_downloads(self) -> None:
        d = self._downloads_dir
        if not d.exists():
            return
        try:
            entries = list(d.iterdir())
        except Exception:
            return
        for f in entries:
            try:
                if not f.is_file():
                    continue
                key = str(f)
                if key in self._seen_downloads:
                    continue
                # only flag freshly-arrived files (last 5 min) to avoid backfill spam
                if time.time() - f.stat().st_mtime > 300:
                    self._seen_downloads.add(key)
                    continue
                self._seen_downloads.add(key)
                ext = f.suffix.lower()
                if ext in (".crdownload", ".part", ".tmp"):
                    continue
                executable = ext in _EXECUTABLE_EXT
                score = 3 if executable else 1
                summary = f"Downloaded {'executable ' if executable else ''}{f.name}"
                self.db.store_system_event(
                    kind="download", summary=summary, source=str(f),
                    detail={"size": f.stat().st_size}, risk_score=score,
                )
                self._emit({"kind": "download", "risk_score": score,
                            "summary": summary, "path": str(f),
                            "suspicious": executable})
            except Exception:
                continue

    # ── file watcher (event-driven) ────────────────────────────────────────────

    def _start_file_watcher(self) -> None:
        if not _HAS_WATCHDOG or not self._watch_dirs:
            return
        try:
            self._observer = Observer()
            handler = _FileHandler(self)
            for d in self._watch_dirs:
                self._observer.schedule(handler, str(d), recursive=False)
            self._observer.daemon = True
            self._observer.start()
        except Exception:
            self._observer = None

    def _on_file_event(self, path: str, action: str) -> None:
        try:
            p = Path(path)
            ext = p.suffix.lower()
            if ext not in _EXECUTABLE_EXT:
                return  # only care about executables/scripts landing on disk
            key = f"file:{path}"
            if key in self._seen_downloads:
                return
            self._seen_downloads.add(key)
            summary = f"Executable {action}: {p.name}"
            self.db.store_system_event(
                kind="file", summary=summary, source=path, risk_score=3,
            )
            self._emit({"kind": "file", "risk_score": 3, "summary": summary,
                        "path": path, "suspicious": True})
        except Exception:
            pass


if __name__ == "__main__":  # smoke test — watch for ~6s and print events
    from hydradb import HydraDB

    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    db = HydraDB()
    eng = MonitoringEngine(db, on_event=lambda e: print("EVENT:", e["kind"], e["summary"]))
    eng.start()
    print("Monitoring for 6s… (watchdog:", _HAS_WATCHDOG, "winreg:", _HAS_WINREG, ")")
    time.sleep(6)
    snap = eng.snapshot()
    print("active connections:", snap["active_connections"],
          "suspicious procs:", snap["suspicious_count"])
    eng.stop()
