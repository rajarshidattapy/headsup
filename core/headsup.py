#!/usr/bin/env python3
"""HeadsUp — terminal-native AI threat memory engine.

A live security command center in the terminal. Monitors the whole machine,
remembers everything in HydraDB, reasons with Gemma 4 on Cerebras, ingests
emerging threat intelligence via Anakin, and predicts attacks before they
fully execute.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import queue
import re
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── env loader ────────────────────────────────────────────────────────────────
_env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

# ── imports ───────────────────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    print("pip install psutil rich openai watchdog requests send2trash")
    sys.exit(1)

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markup import escape as _markup_escape
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("pip install rich"); sys.exit(1)

try:
    import send2trash as _send2trash
    _HAS_SEND2TRASH = True
except ImportError:
    _HAS_SEND2TRASH = False

# HeadsUp engine modules (work both as `core.x` and top-level `x`)
try:
    from monitor import (MonitoringEngine, calc_risk, conn_key, get_connections,
                         get_geo, geo_country, get_proc_info, is_external,
                         port_label, port_style, resolve_host, risk_to_score)
    from hydradb import get_db, HydraDB
    from analyst import HeadsUpAnalyst
    from anakin import Anakin
except ImportError:  # pragma: no cover
    from core.monitor import (MonitoringEngine, calc_risk, conn_key, get_connections,
                             get_geo, geo_country, get_proc_info, is_external,
                             port_label, port_style, resolve_host, risk_to_score)
    from core.hydradb import get_db, HydraDB
    from core.analyst import HeadsUpAnalyst
    from core.anakin import Anakin

try:
    from telegram_alert import TelegramAlert, TelegramMock, PendingAction
except ImportError:
    try:
        from core.telegram_alert import TelegramAlert, TelegramMock, PendingAction
    except ImportError:
        TelegramAlert = None  # type: ignore
        TelegramMock = None  # type: ignore
        PendingAction = None  # type: ignore

console = Console()

BANNER = r"""
 ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██╗   ██╗██████╗
 ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║   ██║██╔══██╗
 ███████║█████╗  ███████║██║  ██║███████╗██║   ██║██████╔╝
 ██╔══██║██╔══╝  ██╔══██║██║  ██║╚════██║██║   ██║██╔═══╝
 ██║  ██║███████╗██║  ██║██████╔╝███████║╚██████╔╝██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚═╝
"""

STATUS_STYLE = {
    "ESTABLISHED": "bold green", "LISTEN": "bold cyan", "TIME_WAIT": "yellow",
    "CLOSE_WAIT": "bold yellow", "SYN_SENT": "bold magenta", "SYN_RECV": "magenta",
    "FIN_WAIT1": "dim yellow", "FIN_WAIT2": "dim yellow", "LAST_ACK": "dim red",
    "CLOSING": "dim red", "CLOSE": "dim white", "NONE": "dim white",
}

_THREAT_STYLE = {
    "HEALTHY": "bold green", "ELEVATED": "bold yellow", "MEDIUM": "bold yellow",
    "CRITICAL": "bold red",
}

# ── shared state ──────────────────────────────────────────────────────────────

@dataclass
class HeadsUpState:
    page: int = 0
    per_page: int = 10
    chat_mode: bool = False
    chat_input: str = ""
    chat_thinking: bool = False
    chat_history: deque = field(default_factory=lambda: deque(maxlen=200))
    chat_scroll: int = 0
    chat_queue: queue.Queue = field(default_factory=queue.Queue)
    action_log: deque = field(default_factory=lambda: deque(maxlen=6))
    predictions: deque = field(default_factory=lambda: deque(maxlen=4))
    intel_match: Optional[dict] = None
    alerted_keys: set = field(default_factory=set)
    actioned: set = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

# ── cursor blink ──────────────────────────────────────────────────────────────

_cur_on = True
_cur_ts = 0.0


def _blink() -> str:
    global _cur_on, _cur_ts
    now = time.monotonic()
    if now - _cur_ts > 0.5:
        _cur_on = not _cur_on
        _cur_ts = now
    return "▋" if _cur_on else " "

# ── Windows / system helpers ──────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_vpn_status() -> tuple[str, str]:
    _VPN_KW = ("vpn", "tap-windows", "wireguard", "tun", "ppp", "cisco",
               "nordlynx", "mullvad", "expressvpn", "openconnect", "protonvpn",
               "surfshark")
    ifaces = list(psutil.net_if_addrs().keys())
    active = [i for i in ifaces if any(kw in i.lower() for kw in _VPN_KW)]
    if active:
        return f"● ACTIVE  ({active[0]})", "bold green"
    return "✗ NONE", "bold red"


def get_wifi_ssid() -> str:
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                             capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("SSID") and "BSSID" not in s:
                p = s.split(":", 1)
                if len(p) == 2:
                    return p[1].strip() or "—"
    except Exception:
        pass
    return "—"


def get_default_gateway() -> str:
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            if "Default Gateway" in line:
                p = line.split(":", 1)
                if len(p) == 2 and p[1].strip():
                    return p[1].strip()
    except Exception:
        pass
    return "—"


def get_dns_servers() -> str:
    try:
        out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=3).stdout
        servers: list[str] = []
        for line in out.splitlines():
            s = line.strip()
            if "DNS Servers" in s:
                p = s.split(":", 1)
                if len(p) == 2 and p[1].strip():
                    servers.append(p[1].strip())
        return "  ".join(servers[:2]) if servers else "—"
    except Exception:
        return "—"

# ── remediation actions ───────────────────────────────────────────────────────

def kill_process(pid: int) -> bool:
    try:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def suspend_process(pid: int) -> bool:
    try:
        psutil.Process(pid).suspend()
        return True
    except Exception:
        return False


def block_ip(ip: str) -> bool:
    try:
        rule = f"HeadsUp-Block-{ip}"
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=out", "action=block",
            f"remoteip={ip}", "protocol=any", "enable=yes",
        ], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def close_port(port: int) -> list[int]:
    killed: list[int] = []
    for conn in psutil.net_connections():
        if conn.laddr and conn.laddr.port == port and conn.pid:
            if kill_process(conn.pid):
                killed.append(conn.pid)
    return killed


def quarantine_file(path: str) -> bool:
    if not _HAS_SEND2TRASH:
        return False
    try:
        _send2trash.send2trash(path)
        return True
    except Exception:
        return False


def inspect_file(path: str) -> dict:
    try:
        stat = os.stat(path)
        sha256 = "?"
        try:
            with open(path, "rb") as f:
                sha256 = hashlib.sha256(f.read(2 * 1024 * 1024)).hexdigest()
        except Exception:
            pass
        return {"path": path, "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "sha256": sha256}
    except Exception as e:
        return {"error": str(e)}


def execute_action(action_type: str, pid: Optional[int], remote_ip: str,
                   state: "HeadsUpState") -> str:
    ts = datetime.now().strftime("%H:%M:%S")
    msg = ""
    if action_type in ("kill_process", "kill_and_block") and pid:
        ok = kill_process(pid)
        msg = f"[{ts}] {'✓' if ok else '✗'} KILLED  pid {pid}"
        with state.lock:
            state.action_log.append(msg)
    if action_type in ("block_ip", "kill_and_block", "block") and remote_ip:
        ok = block_ip(remote_ip)
        msg = f"[{ts}] {'✓' if ok else '✗'} BLOCKED {remote_ip}"
        with state.lock:
            state.action_log.append(msg)
    return msg or "done"

# ── system info (public IP) ───────────────────────────────────────────────────

_pub_ip_cache: dict = {"value": "fetching…", "ts": 0.0}
_pub_ip_lock = threading.Lock()


def _fetch_public_ip() -> None:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            ip = r.read().decode().strip()
    except Exception:
        ip = "unavailable"
    with _pub_ip_lock:
        _pub_ip_cache.update({"value": ip, "ts": time.time()})


def get_public_ip() -> str:
    now = time.time()
    with _pub_ip_lock:
        stale = now - _pub_ip_cache["ts"] > 60
    if stale:
        with _pub_ip_lock:
            _pub_ip_cache["ts"] = now
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
    return _pub_ip_cache["value"]


def get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"
    finally:
        try:
            s.close()
        except Exception:
            pass


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"

# ── command parser (copilot) ──────────────────────────────────────────────────

def parse_command(text: str) -> tuple[str, dict]:
    t = text.strip()
    for pat, name, key, cast in [
        (r'(?:kill\s+(?:pid\s+)?|/kill\s+)(\d+)', "kill", "pid", int),
        (r'(?:suspend\s+(?:pid\s+)?|/suspend\s+)(\d+)', "suspend", "pid", int),
        (r'(?:block\s+(?:ip\s+)?|/block\s+)([\d.a-fA-F:]+)', "block", "ip", str),
        (r'close\s+port\s+(\d+)', "close_port", "port", int),
        (r'quarantine\s+(.+)', "quarantine", "path", str),
        (r'inspect\s+(.+)', "inspect", "path", str),
    ]:
        m = re.match(pat, t, re.I)
        if m:
            return name, {key: cast(m.group(1).strip() if cast is str else m.group(1))}
    if re.match(r'show\s+(?:all\s+)?foreign', t, re.I):
        return "show_foreign", {}
    if re.match(r'show\s+(?:high|critical)', t, re.I):
        return "show_high", {}
    if re.search(r'\b(today|changed|summar)', t, re.I):
        return "summary", {}
    if re.search(r'\b(predict|next|going to happen)', t, re.I):
        return "predict", {}
    if re.search(r'\b(intel|campaign|malware feed|threat feed)', t, re.I):
        return "intel", {}
    m = re.search(r'\b(seen|history of)\b.*?([\d]{1,3}(?:\.\d{1,3}){3})', t, re.I)
    if m:
        return "seen", {"ip": m.group(2)}
    return "ai", {"text": t}

# ── AI context builder ────────────────────────────────────────────────────────

def build_ai_context(db: "HydraDB", engine: "MonitoringEngine") -> str:
    snap = engine.snapshot()
    conns = snap["connections"]
    score, label = db.health_score()
    header = (
        f"Host: {socket.gethostname()}  Local IP: {get_primary_ip()}  "
        f"Public IP: {get_public_ip()}\n"
        f"VPN: {get_vpn_status()[0]}  Health: {score}/100 ({label})\n"
        f"Active connections: {snap['active_connections']}  "
        f"Suspicious processes: {snap['suspicious_count']}\n"
    )
    rows = ["Active connections (top 20):",
            f"{'Process':<20} {'Status':<12} {'Remote IP':<18} {'Country':<14} Risk"]
    for conn in conns[:20]:
        proc, _, sus = get_proc_info(conn.pid)
        rip = conn.raddr.ip if conn.raddr else ""
        status = getattr(conn, "status", "NONE") or "NONE"
        risk, _ = calc_risk(conn, suspicious_path=sus)
        rows.append(f"{proc:<20} {status:<12} {rip:<18} {geo_country(rip):<14} {risk}")
    tl = ["", "Recent memory timeline:"]
    for ev in db.timeline(15):
        tl.append(f"  {ev['ts'][11:19]} [{ev['kind']}] {ev['summary']}")
    intel = ["", "Recent threat intelligence:"]
    for it in db.recent_intel(5):
        intel.append(f"  {it['threat_name']} ({it['severity']}) — {it['source']}")
    return "\n".join([header] + rows + tl + intel)

# ── chat command processor ────────────────────────────────────────────────────

def _run_chat_command(state, db, engine, analyst, anakin, msg: str) -> str:
    cmd, args = parse_command(msg)
    ts = datetime.now().strftime("%H:%M:%S")

    if cmd == "kill":
        ok = kill_process(args["pid"])
        r = f"✓ Killed PID {args['pid']}" if ok else f"✗ Failed to kill PID {args['pid']}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r
    if cmd == "block":
        ok = block_ip(args["ip"])
        r = f"✓ Blocked {args['ip']} via firewall" if ok else f"✗ Failed to block {args['ip']}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r
    if cmd == "suspend":
        ok = suspend_process(args["pid"])
        r = f"✓ Suspended PID {args['pid']}" if ok else f"✗ Failed to suspend PID {args['pid']}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r
    if cmd == "close_port":
        killed = close_port(args["port"])
        return (f"✓ Closed port {args['port']} — killed PID(s): {', '.join(map(str, killed))}"
                if killed else f"No processes on port {args['port']}")
    if cmd == "quarantine":
        if not _HAS_SEND2TRASH:
            return "send2trash not installed — pip install send2trash"
        ok = quarantine_file(args["path"])
        r = f"✓ Moved to Recycle Bin: {args['path']}" if ok else f"✗ Quarantine failed: {args['path']}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r
    if cmd == "inspect":
        info = inspect_file(args["path"])
        if "error" in info:
            return f"✗ {info['error']}"
        return (f"Path:     {info['path']}\nSize:     {fmt_bytes(info['size'])}\n"
                f"Modified: {info['modified']}\nSHA256:   {info['sha256'][:32]}…")
    if cmd == "seen":
        c = db.correlate(ip=args["ip"])
        if not c["hits"]:
            return f"I have no memory of {args['ip']} — first time seen."
        return (f"Yes — {args['ip']} seen {c['hits']}x before (worst risk {c['worst']}). "
                f"First {c['first_seen']}, last {c['last_seen']}.")
    if cmd == "summary":
        return analyst.summarize(db.timeline(40))
    if cmd == "predict":
        chain = [f"{ev['kind']}: {ev['summary']}" for ev in db.timeline(20)
                 if (ev.get("risk_score", 0) or 0) >= 2]
        if not chain:
            chain = [f"{ev['kind']}: {ev['summary']}" for ev in db.timeline(8)]
        return analyst.predict(chain[:6])
    if cmd == "intel":
        lines = ["Latest threat intelligence:"]
        for it in db.recent_intel(8):
            lines.append(f"  • {it['threat_name']} [{it['severity']}] — {it['source']}")
        with state.lock:
            m = state.intel_match
        if m:
            lines.append(f"\n⚠ Your machine resembles {m['threat_name']} "
                         f"({m['similarity']}% similarity).")
        return "\n".join(lines)
    if cmd == "show_foreign":
        conns = engine.snapshot()["connections"]
        foreign = [c for c in conns if c.raddr and is_external(c.raddr.ip)]
        if not foreign:
            return "No foreign IP connections right now."
        lines = [f"Found {len(foreign)} foreign connections:"]
        for c in foreign[:12]:
            name, _, _ = get_proc_info(c.pid)
            lines.append(f"  {name:<18} → {c.raddr.ip:<16} ({geo_country(c.raddr.ip)})")
        return "\n".join(lines)
    if cmd == "show_high":
        conns = engine.snapshot()["connections"]
        high = [c for c in conns if calc_risk(c)[0] == "● HIGH"]
        if not high:
            return "No HIGH risk connections right now."
        lines = [f"Found {len(high)} HIGH risk connections:"]
        for c in high[:12]:
            name, _, _ = get_proc_info(c.pid)
            lines.append(f"  {name:<18} → {c.raddr.ip if c.raddr else '—'}")
        return "\n".join(lines)

    return analyst.copilot(msg, build_ai_context(db, engine))


def _chat_worker(state, db, engine, analyst, anakin) -> None:
    while True:
        try:
            msg = state.chat_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        with state.lock:
            state.chat_thinking = True
        try:
            response = _run_chat_command(state, db, engine, analyst, anakin, msg)
        except Exception as exc:
            response = f"Error: {exc}"
        with state.lock:
            state.chat_history.append(("AI", response))
            state.chat_thinking = False
            state.chat_scroll = 0

# ── keyboard input ────────────────────────────────────────────────────────────

def _input_thread(state, live_ref: list) -> None:
    try:
        import msvcrt
    except ImportError:
        return
    while True:
        if not msvcrt.kbhit():
            time.sleep(0.03)
            continue
        ch = msvcrt.getch()
        ch2 = None
        if ch in (b"\xe0", b"\x00"):
            ch2 = msvcrt.getch()
        changed = False
        with state.lock:
            if state.chat_mode:
                if ch == b"\r":
                    m = state.chat_input.strip()
                    state.chat_input = ""
                    if m:
                        state.chat_history.append(("YOU", m))
                        state.chat_scroll = 0
                        state.chat_queue.put(m)
                    changed = True
                elif ch == b"\x1b":
                    state.chat_mode = False
                    state.chat_input = ""
                    changed = True
                elif ch == b"\x08":
                    state.chat_input = state.chat_input[:-1]
                    changed = True
                elif ch in (b"\xe0", b"\x00"):
                    if ch2 == b"H":
                        state.chat_scroll += 1
                    elif ch2 == b"P":
                        state.chat_scroll = max(0, state.chat_scroll - 1)
                    elif ch2 == b"I":
                        state.chat_scroll += 5
                    elif ch2 == b"Q":
                        state.chat_scroll = max(0, state.chat_scroll - 5)
                    changed = True
                else:
                    try:
                        c = ch.decode("utf-8")
                        if c.isprintable():
                            state.chat_input += c
                            changed = True
                    except UnicodeDecodeError:
                        pass
            else:
                if ch in (b"t", b"T"):
                    state.chat_mode = True
                    state.chat_input = ""
                    changed = True
                elif ch == b"j":
                    state.page += 1
                    changed = True
                elif ch == b"k":
                    state.page = max(0, state.page - 1)
                    changed = True
                elif ch in (b"\xe0", b"\x00"):
                    if ch2 == b"P":
                        state.page += 1
                        changed = True
                    elif ch2 == b"H":
                        state.page = max(0, state.page - 1)
                        changed = True
        if changed:
            live = live_ref[0]
            if live is not None:
                try:
                    live.refresh()
                except Exception:
                    pass

# ── predictive engine + alerting (event callback) ─────────────────────────────

class _Predictor:
    """Tracks recent risky behaviour and raises predictions/incidents."""

    def __init__(self, state, db, analyst, anakin, tg=None) -> None:
        self.state = state
        self.db = db
        self.analyst = analyst
        self.anakin = anakin
        self.tg = tg
        self._recent: deque = deque(maxlen=12)
        self._last_pred = 0.0

    def on_event(self, ev: dict) -> None:
        score = ev.get("risk_score", 0) or 0
        if score >= 2:
            self._recent.append(ev)
        if score < 3:
            return
        kinds = {e["kind"] for e in self._recent}
        # behaviour chain that warrants a prediction
        download = bool(kinds & {"download", "file"})
        persist = bool(kinds & {"registry", "startup"})
        netw = "network" in kinds
        if not ((download and netw) or (persist and netw)):
            return
        now = time.time()
        if now - self._last_pred < 20:   # throttle predictions
            return
        self._last_pred = now

        chain = [e["summary"] for e in self._recent]
        behaviors = [e.get("summary", "") for e in self._recent]
        match = self.anakin.match(behaviors)
        prediction = self.analyst.predict(chain[-6:])
        conf = (match["similarity"] / 100.0) if match else 0.6
        inc_id = f"INC-{int(now)}"
        summary = "Correlated suspicious chain: " + " → ".join(
            sorted(kinds & {"download", "file", "registry", "startup", "network"}))
        self.db.open_incident(inc_id, summary, confidence=conf,
                              prediction=prediction.split(chr(10))[0],
                              severity="HIGH" if not match else match.get("severity", "HIGH"))
        self.db.store_prediction("machine behaviour", prediction, conf, inc_id)
        with self.state.lock:
            self.state.predictions.appendleft({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "text": prediction, "match": match,
            })
            if match:
                self.state.intel_match = match
        if self.tg and getattr(self.tg, "ready", False):
            try:
                extra = (f"\nResembles {match['threat_name']} ({match['similarity']}%)"
                         if match else "")
                self.tg.send_alert(
                    f"🔴 <b>HeadsUp Prediction</b>\n{summary}{extra}\n"
                    f"{_markup_escape(prediction)[:300]}")
            except Exception:
                pass


def maybe_request_analysis(engine, analyst) -> None:
    snap = engine.snapshot()
    new_keys = snap["new_keys"]
    for conn in snap["connections"]:
        ck = conn_key(conn)
        proc_name, exe, suspicious = get_proc_info(conn.pid)
        risk_label, _ = calc_risk(conn, suspicious_path=suspicious)
        if ck not in new_keys and risk_label != "● HIGH" and not suspicious:
            continue
        rip = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else None
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        analyst.request(ck, {
            "process": proc_name, "exe": exe or "unknown", "proto": proto,
            "status": getattr(conn, "status", "NONE") or "NONE",
            "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
            "remote": rip, "rport": rport or "",
            "country": geo_country(rip) if rip else "local",
            "suspicious": suspicious, "risk": risk_label, "pid": conn.pid,
        })

# ── UI panels ─────────────────────────────────────────────────────────────────

def build_security_center(state, db, engine) -> Panel:
    """The PRD 'HeadsUp Security Center' summary box + system facts."""
    snap = engine.snapshot()
    score, label = db.health_score()
    threat_style = _THREAT_STYLE.get(label, "white")
    vpn_label, vpn_style = get_vpn_status()
    intel_new = db.intel_count(24)
    incidents = db.count_unresolved_incidents()

    def f(lbl, val, vs="white"):
        return f"[bold bright_green]{lbl}[/]  [{vs}]{val}[/]"

    left = "\n".join([
        f("ACTIVE CONNS", str(snap["active_connections"]), "bright_cyan"),
        f("SUSPICIOUS PROC", str(snap["suspicious_count"]),
          "bold red" if snap["suspicious_count"] else "green"),
        f("OPEN INCIDENTS", str(incidents), "bold red" if incidents else "green"),
        f("NEW INTEL (24h)", str(intel_new), "bright_magenta"),
    ])
    right = "\n".join([
        f"[bold bright_green]THREAT SCORE[/]  [{threat_style}]{label}[/]  [dim]{score}/100[/]",
        f"[bold bright_green]VPN[/]  [{vpn_style}]{vpn_label}[/]",
        f("HOST", socket.gethostname()),
        f("PUBLIC IP", get_public_ip()),
    ])
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(Text.from_markup(left), Text.from_markup(right))
    border = "bold red" if label == "CRITICAL" else (
        "yellow" if label in ("MEDIUM", "ELEVATED") else "bright_cyan")
    return Panel(grid, title="[bold bright_cyan]◈ HEADSUP SECURITY CENTER[/]",
                 subtitle="[dim]T=copilot  j/k=scroll  Ctrl+C=quit[/dim]",
                 border_style=border, padding=(0, 1))


def _ai_flag(analyst, ck) -> tuple[str, str]:
    a = analyst.get(ck)
    if a is None:
        return "", ""
    if a.pending:
        return "~", "dim"
    return {"CRITICAL": ("C", "bold bright_red"), "SUSPICIOUS": ("S", "bold yellow"),
            "SAFE": ("✓", "dim green")}.get(a.level, ("?", "dim"))


def build_table(connections, analyst, new_keys, resolve=False, row_offset=0) -> Table:
    table = Table(box=box.HEAVY_HEAD, border_style="bright_black",
                  header_style="bold bright_cyan", show_lines=True,
                  title=f"[bold bright_cyan]ACTIVE CONNECTIONS[/]  "
                        f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]")
    table.add_column("№", style="dim", width=4, justify="right")
    table.add_column("FLAGS", width=6, justify="center")
    table.add_column("RISK", width=8)
    table.add_column("PROTO", style="bright_white", width=6)
    table.add_column("STATUS", width=12)
    table.add_column("REMOTE", min_width=20)
    table.add_column("COUNTRY", min_width=14)
    table.add_column("PORT", width=16)
    table.add_column("PROCESS", min_width=16)
    table.add_column("PID", style="dim", width=7, justify="right")

    for i, conn in enumerate(connections, row_offset + 1):
        rip = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else None
        if resolve and rip:
            rhost = resolve_host(rip)
            remote = f"{rhost}\n[dim]{rip}[/]" if rhost != rip else rip
        else:
            remote = rip or "[dim]—[/dim]"
        status = getattr(conn, "status", "NONE") or "NONE"
        status_txt = Text(status, style=STATUS_STYLE.get(status, "white"))
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        pid_str = str(conn.pid) if conn.pid else "—"
        port_txt = (Text.from_markup(port_label(rport), style=port_style(rport))
                    if rport else Text("—", style="dim"))
        proc_name, _, suspicious = get_proc_info(conn.pid)
        proc_display = Text()
        if suspicious:
            proc_display.append("⚠ ", style="bold red")
        proc_display.append(proc_name, style="bold red" if suspicious else "bright_magenta")
        country_txt = Text.from_markup(get_geo(rip) if rip else "[dim]—[/dim]")
        risk_label, risk_style = calc_risk(conn, suspicious_path=suspicious)
        ck = conn_key(conn)
        is_new = ck in new_keys
        ai_ch, ai_st = _ai_flag(analyst, ck)
        flags = Text()
        if is_new:
            flags.append("★", style="bold yellow")
        if suspicious:
            flags.append("⚠", style="bold red")
        if ai_ch:
            flags.append(ai_ch, style=ai_st)
        table.add_row(str(i), flags, Text(risk_label, style=risk_style), proto,
                      status_txt, remote, country_txt, port_txt, proc_display, pid_str,
                      style="on grey7" if is_new else "")
    return table


def build_connections_panel(state, engine, analyst, resolve) -> Panel:
    snap = engine.snapshot()
    conns = snap["connections"]
    new_keys = snap["new_keys"]
    with state.lock:
        page, per_page = state.page, state.per_page
    total = len(conns)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages - 1)
    with state.lock:
        state.page = page
    start = page * per_page
    end = min(start + per_page, total)
    table = build_table(conns[start:end], analyst, new_keys, resolve=resolve, row_offset=start)
    nav = (f"[dim]Showing [bold]{start+1 if total else 0}–{end}[/bold] of [bold]{total}[/bold]  │  "
           f"Page [bold]{page+1}[/bold]/[bold]{total_pages}[/bold]  │  "
           f"[bright_cyan]j[/]/[bright_cyan]k[/] scroll  [bright_cyan]T[/] copilot[/dim]")
    return Panel(Group(table, Align.center(Text.from_markup(nav))),
                 border_style="bright_black", padding=(0, 0))


_TL_ICON = {"process": "▸", "network": "→", "registry": "✎", "startup": "⏻",
            "download": "▼", "file": "≡", "dns": "◇"}


def build_timeline_panel(db) -> Panel:
    lines = []
    for ev in db.timeline(9):
        icon = _TL_ICON.get(ev["kind"], "•")
        score = ev.get("risk_score", 0) or 0
        col = "bold red" if score >= 3 else ("yellow" if score == 2 else "dim")
        t = ev["ts"][11:19]
        lines.append(f"[dim]{t}[/] [{col}]{icon}[/] {_markup_escape(ev['summary'][:54])}")
    if not lines:
        lines = ["[dim]No events recorded yet — monitoring…[/dim]"]
    return Panel("\n".join(lines), title="[bold bright_cyan]⏱ THREAT TIMELINE[/]",
                 border_style="bright_black", padding=(0, 1))


def build_intel_panel(db, state) -> Panel:
    lines = []
    with state.lock:
        match = state.intel_match
    if match:
        lines.append(f"[bold red]⚠ Resembles {match['threat_name']} "
                     f"({match['similarity']}% similarity)[/]")
        lines.append("")
    for it in db.recent_intel(6):
        sev = it.get("severity", "")
        col = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        lines.append(f"[{col}]●[/] {_markup_escape(it['threat_name'][:34])} "
                     f"[dim]{it['source'][:18]}[/]")
    if not lines:
        lines = ["[dim]No threat intel ingested yet…[/dim]"]
    return Panel("\n".join(lines), title="[bold bright_magenta]🌐 THREAT INTEL FEED[/]",
                 border_style="bright_black", padding=(0, 1))


def build_intelligence_panel(state, db, analyst, tg) -> Panel:
    title = "[bold bright_red]⚡ AI THREAT INTELLIGENCE[/]"
    lines: list[str] = [f"[dim]Reasoning engine: {analyst.label}[/dim]"]

    analyses = analyst.all_analyses()
    critical = [a for a in analyses if not a.pending and a.level == "CRITICAL"]
    suspicious = [a for a in analyses if not a.pending and a.level == "SUSPICIOUS"]
    analyzing = sum(1 for a in analyses if a.pending)
    if analyzing:
        lines.append(f"[dim]Analyzing {analyzing} connection(s)…[/dim]")
    for a in critical[:4]:
        remote = f" → [dim]{a.remote}[/dim]" if a.remote else ""
        lines.append(f"[bold bright_red]● CRITICAL[/] [bold]{a.process}[/]{remote}\n"
                     f"  [dim]{_markup_escape(a.reason)}[/]  [red]→ {a.action}[/red]")
    for a in suspicious[:2]:
        remote = f" → [dim]{a.remote}[/dim]" if a.remote else ""
        lines.append(f"[yellow]◆ SUSPICIOUS[/] [bold]{a.process}[/]{remote}\n"
                     f"  [dim]{_markup_escape(a.reason)}[/]")
    if not analyses:
        lines.append("[dim]Waiting for connections to analyze…[/dim]")
    elif not critical and not suspicious and not analyzing:
        lines.append("[dim green]✓ No active threats[/dim green]")

    with state.lock:
        preds = list(state.predictions)
        log = list(state.action_log)
    if preds:
        lines.append("")
        lines.append("[bold bright_yellow]🔮 PREDICTION[/]")
        p = preds[0]
        for ln in p["text"].split("\n")[:5]:
            lines.append(f"  [yellow]{_markup_escape(ln)}[/]")
    if log:
        lines.append("")
        lines.append("[bold bright_cyan]REMEDIATION LOG[/]")
        lines += [f"  [bold cyan]{_markup_escape(e)}[/]" for e in log[-3:]]

    border = "bold red" if critical else ("yellow" if suspicious or preds else "bright_black")
    if tg is not None:
        if not getattr(tg, "ready", False) and getattr(tg, "available", False):
            lines.append("[dim yellow]Telegram: send /start to your bot to enable alerts[/dim yellow]")
    return Panel("\n".join(lines), title=title, border_style=border, padding=(0, 1))


_CHAT_HIST_ROWS = 9


def _wrap_chat_msg(role, text, inner_width):
    label = "YOU" if role == "YOU" else " AI"
    color = "bright_cyan" if role == "YOU" else "bright_green"
    prefix = f"[bold {color}]  {label}[/]  "
    indent = "       "
    avail = max(20, inner_width - len(indent) - 2)
    out = []
    for line in (text.split("\n") if "\n" in text else [text]):
        wrapped = textwrap.wrap(line, width=avail, break_long_words=True) or [""]
        for i, w in enumerate(wrapped):
            safe = _markup_escape(w)
            out.append(f"{prefix}{safe}" if (i == 0 and not out) else f"{indent}{safe}")
    return out


def build_chat_panel(state, inner_width=76) -> Panel:
    with state.lock:
        history = list(state.chat_history)
        inp = state.chat_input
        mode = state.chat_mode
        thinking = state.chat_thinking
        scroll = state.chat_scroll

    all_lines: list[str] = []
    for role, text in history:
        all_lines.extend(_wrap_chat_msg(role, text, inner_width))
        all_lines.append("")
    if thinking:
        all_lines.append("[dim yellow]   ⠿  thinking…[/dim yellow]")

    total = len(all_lines)
    max_scroll = max(0, total - _CHAT_HIST_ROWS)
    scroll = min(scroll, max_scroll)
    if total <= _CHAT_HIST_ROWS:
        visible = all_lines + [""] * (_CHAT_HIST_ROWS - total)
    else:
        end = total - scroll
        start = max(0, end - _CHAT_HIST_ROWS)
        visible = all_lines[start:end]
        while len(visible) < _CHAT_HIST_ROWS:
            visible.append("")

    sep = "[bright_black]" + "─" * max(10, inner_width) + "[/]"
    visible.append(sep)
    if mode:
        visible.append(f"[bold bright_cyan]  >[/]  {_markup_escape(inp)}[bright_cyan]{_blink()}[/]")
        visible.append("[dim]  ENTER send  ·  ESC cancel  ·  ↑/↓ history[/dim]")
    else:
        hint = ("[dim]  Ask: \"what changed today?\" · \"have I seen 1.2.3.4?\" · "
                "\"predict\" · \"show foreign\"[/dim]")
        visible.append("[dim]  [bold bright_cyan]T[/] open AI copilot[/dim]")
        visible.append(hint)

    border = "bright_cyan" if mode else "bright_black"
    title = "[bold bright_cyan]● AI COPILOT[/]" if mode else "[dim]  AI COPILOT  [/dim]"
    return Panel(Text.from_markup("\n".join(visible)), title=title,
                 border_style=border, padding=(0, 1))

# ── branded stack line ────────────────────────────────────────────────────────

def _stack_subtitle(db, analyst, anakin) -> str:
    """The product-stack banner: names HydraDB · Gemma/Cerebras · Anakin with a
    compact, honest mode indicator for each."""
    mem_mode = db.memory_mode
    if analyst.provider == "cerebras":
        ai_mode = analyst.model
    elif analyst.provider == "openai":
        ai_mode = f"via OpenAI {analyst.model}"
    else:
        ai_mode = "offline"
    intel_mode = "sample feed" if "sample" in anakin.source else "live"
    return (
        "[dim]Threat Memory Engine[/dim]   "
        f"[bold bright_cyan]HydraDB[/] [dim]{mem_mode}[/]   "
        f"[bold bright_magenta]Gemma 4 · Cerebras[/] [dim]{ai_mode}[/]   "
        f"[bold bright_green]Anakin[/] [dim]{intel_mode}[/]"
    )

# ── Telegram bootstrap ────────────────────────────────────────────────────────

def _execute_tg_action(state, action) -> None:
    execute_action(action.action_type, action.pid, action.remote_ip, state)

# ── main monitor ──────────────────────────────────────────────────────────────

def run_monitor(resolve: bool = False, auto: bool = False, once: bool = False) -> None:
    admin = is_admin()
    state = HeadsUpState()

    db = get_db()
    analyst = HeadsUpAnalyst(db)
    anakin = Anakin(db, analyst)

    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    tg = None
    if TelegramAlert is not None and tg_token:
        tg = TelegramAlert(tg_token, os.environ.get("TELEGRAM_CHAT_ID", ""))
        tg.set_execute_callback(lambda a: _execute_tg_action(state, a))
        if TelegramMock is not None and os.environ.get("TELEGRAM_MOCK_ENABLED", "1").lower() in ("1", "true", "yes"):
            TelegramMock(tg).start()

    predictor = _Predictor(state, db, analyst, anakin, tg)
    engine = MonitoringEngine(db, on_event=predictor.on_event)

    # ingest threat intel up-front (start_background runs its first ingest
    # immediately) so the feed is populated, then refresh periodically.
    anakin.start_background(interval_sec=1800)

    engine.start()
    threading.Thread(target=_fetch_public_ip, daemon=True).start()

    live_ref: list = [None]
    threading.Thread(target=_input_thread, args=(state, live_ref), daemon=True).start()
    threading.Thread(target=_chat_worker, args=(state, db, engine, analyst, anakin), daemon=True).start()

    def _analysis_loop():
        while True:
            try:
                maybe_request_analysis(engine, analyst)
            except Exception:
                pass
            time.sleep(2)
    threading.Thread(target=_analysis_loop, daemon=True).start()

    console.print(Panel(Align.center(Text(BANNER, style="bold bright_cyan")),
                        border_style="bright_cyan",
                        subtitle=_stack_subtitle(db, analyst, anakin),
                        padding=(0, 0)))
    if not admin:
        console.print(Panel(
            "[yellow]Running without Administrator rights — some process info may be hidden.\n"
            "Run as Administrator for full visibility and action capabilities.[/yellow]",
            border_style="yellow", padding=(0, 1)))

    if once:
        time.sleep(3)  # let collectors gather a first batch
        console.print(_render(state, db, engine, analyst, tg, resolve))
        console.print(f"[dim]HydraDB: {db.location}[/dim]")
        engine.stop()
        return

    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            live_ref[0] = live
            while True:
                live.update(_render(state, db, engine, analyst, tg, resolve))
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        console.print("\n[bold bright_cyan]HeadsUp terminated. Memory preserved.[/]")


def _render(state, db, engine, analyst, tg, resolve) -> Group:
    top = Table.grid(expand=True, padding=(0, 1))
    top.add_column(ratio=1)
    top.add_column(ratio=1)
    top.add_row(build_timeline_panel(db), build_intel_panel(db, state))
    return Group(
        build_security_center(state, db, engine),
        build_connections_panel(state, engine, analyst, resolve),
        top,
        build_intelligence_panel(state, db, analyst, tg),
        build_chat_panel(state, inner_width=max(40, console.width - 6)),
    )

# ── copilot mode ──────────────────────────────────────────────────────────────

def run_copilot() -> None:
    db = get_db()
    analyst = HeadsUpAnalyst(db)
    anakin = Anakin(db, analyst)
    anakin.ingest()
    state = HeadsUpState()
    engine = MonitoringEngine(db)
    engine.start()

    console.print(Panel(Align.center(Text(BANNER, style="bold bright_cyan")),
                        border_style="bright_cyan",
                        subtitle="[dim]AI Copilot Mode  |  type 'exit' to quit[/dim]",
                        padding=(0, 0)))
    console.print(_stack_subtitle(db, analyst, anakin))
    console.print(f"[dim]HydraDB @ {db.location}[/dim]")
    console.print("[dim]Gathering a machine snapshot (3 s)…[/dim]")
    threading.Thread(target=_fetch_public_ip, daemon=True).start()
    time.sleep(3)
    console.print(Rule("[bold bright_cyan]HeadsUp Copilot[/]"))
    console.print('[dim]Ask anything. Examples:\n'
                  '  "What changed today?"   "Have I seen 45.33.32.156 before?"\n'
                  '  "Predict what happens next"   "Show foreign"   "kill pid 1234"[/dim]\n')
    while True:
        try:
            q = Prompt.ask("[bold bright_cyan]>[/]")
        except (KeyboardInterrupt, EOFError):
            break
        if q.strip().lower() in ("exit", "quit", "q"):
            break
        if not q.strip():
            continue
        console.print("[dim]Thinking…[/dim]")
        ans = _run_chat_command(state, db, engine, analyst, anakin, q)
        console.print(Panel(ans, border_style="bright_cyan", title="[bold]HeadsUp[/]"))
    engine.stop()
    console.print("\n[bold bright_cyan]Copilot session ended. Memory preserved.[/]")


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--copilot" in args:
        run_copilot()
    else:
        run_monitor(resolve="--resolve" in args, auto="--auto" in args,
                    once="--once" in args)
