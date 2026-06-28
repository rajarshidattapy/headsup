#!/usr/bin/env python3
"""seed_demo.py — fill HydraDB with fake memories, simulate Anakin scraping, dump JSON.

Run from the project root:
    python seed_demo.py
    python seed_demo.py --reset   # wipe DB first then seed
    python seed_demo.py --json-only  # just dump current DB to JSON
"""
from __future__ import annotations

import ctypes
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Windows UTF-8 console ──────────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ── env loader (mirrors headsup.py) ───────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent   # headsup/ project root
_env_path = _ROOT / ".env"
if _env_path.exists():
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

# ── path setup so core.* imports work ─────────────────────────────────────────
sys.path.insert(0, str(_ROOT / "core"))

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
except ImportError:
    print("pip install rich"); sys.exit(1)

console = Console(force_terminal=True)

try:
    import psutil
except ImportError:
    print("pip install psutil"); sys.exit(1)

try:
    from hydradb import HydraDB, now_iso
    from anakin import Anakin
    from analyst import HeadsUpAnalyst
    from monitor import calc_risk, get_proc_info, geo_country, is_external, conn_key
except ImportError:
    print("Cannot import core modules. Run from the project root."); sys.exit(1)

# Demo data lands in its own sub-tenant, separate from real laptop-asus data.
os.environ["HYDRADB_SUB_TENANT_ID"] = "demo"

OUT_JSON = _ROOT / "headsup_memory_dump.json"

_THREAT_INTEL = [
    {
        "threat_name": "LummaC2 Stealer Campaign",
        "ioc_domains": ["lumma-update.com", "lummabots.net", "stealer-panel.pw"],
        "ioc_hashes": [
            "a3f5c8e1d2b7a4f0c9e3d6b8a1f4c7e0",
            "b2e4d7a0c3f6b9e2d5a8c1f4b7e0a3d6",
        ],
        "behaviors": [
            "browser credential theft", "clipboard hijacking",
            "crypto wallet scraping", "download executable", "c2 communication",
        ],
        "severity": "CRITICAL",
        "source": "bleepingcomputer.com",
        "published_at": "2026-06-15",
    },
    {
        "threat_name": "BlackCat / ALPHV Ransomware",
        "ioc_domains": ["alphv-files.onion", "blackcat-panel.ru"],
        "ioc_hashes": [
            "c1d4a7f0b3e6c9d2a5f8b1e4c7a0d3f6",
            "d0e3b6a9c2f5d8a1e4b7c0f3a6d9b2e5",
        ],
        "behaviors": [
            "file encryption", "shadow copy deletion", "registry persistence",
            "lateral movement", "double extortion", "data exfiltration",
        ],
        "severity": "CRITICAL",
        "source": "cisa.gov",
        "published_at": "2026-06-10",
    },
    {
        "threat_name": "APT29 Midnight Blizzard",
        "ioc_domains": ["beacon.apt29.ru", "office365-auth.net", "ms-update.pw"],
        "ioc_hashes": [
            "e9f2c5b8a1d4e7f0c3b6a9d2e5f8b1c4",
            "f8a1d4e7b0c3f6a9d2e5b8c1f4a7d0e3",
        ],
        "behaviors": [
            "spear phishing", "oauth token theft", "command-and-control beacon",
            "process injection", "dll sideloading", "living off the land",
        ],
        "severity": "HIGH",
        "source": "microsoft.com/security",
        "published_at": "2026-06-08",
    },
    {
        "threat_name": "Emotet Epoch 5 Wave",
        "ioc_domains": ["emotet-cdn.ru", "update-office.xyz", "macro-cdn.net"],
        "ioc_hashes": [
            "a7b0c3d6e9f2a5b8c1d4e7f0a3b6c9d2",
            "b6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1",
        ],
        "behaviors": [
            "malicious macro", "powershell execution", "download executable",
            "spam propagation", "banking trojan", "registry persistence",
        ],
        "severity": "HIGH",
        "source": "thedfirreport.com",
        "published_at": "2026-06-12",
    },
    {
        "threat_name": "Cobalt Strike Beacon (unknown TA)",
        "ioc_domains": ["cobalt-c2.hacker.io", "csbeacon.online", "team-server.pw"],
        "ioc_hashes": [
            "c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0",
            "d4e7f0a3b6c9d2e5f8a1b4c7d0e3f6a9",
        ],
        "behaviors": [
            "command-and-control", "process injection", "lateral movement",
            "credential dumping", "beacon", "named pipe communication",
        ],
        "severity": "CRITICAL",
        "source": "proofpoint.com",
        "published_at": "2026-06-18",
    },
    {
        "threat_name": "DarkGate Loader",
        "ioc_domains": ["darkgate-panel.ru", "dg-load.net"],
        "ioc_hashes": ["e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8"],
        "behaviors": [
            "download executable", "keylogging", "remote access trojan",
            "cryptocurrency mining", "clipboard hijacking",
        ],
        "severity": "HIGH",
        "source": "sekoia.io",
        "published_at": "2026-06-20",
    },
    {
        "threat_name": "CVE-2026-0185 PrintNightmare variant",
        "ioc_domains": [],
        "ioc_hashes": ["f2a5b8c1d4e7f0a3b6c9d2e5f8a1b4c7"],
        "behaviors": [
            "privilege escalation", "dll injection", "spooler exploit",
            "lateral movement", "domain controller compromise",
        ],
        "severity": "CRITICAL",
        "source": "nist.gov",
        "published_at": "2026-06-01",
    },
    {
        "threat_name": "Scattered Spider (0ktapus reloaded)",
        "ioc_domains": ["okta-sso-help.com", "identity-verify.net", "okta-login.pw"],
        "ioc_hashes": [],
        "behaviors": [
            "sim swapping", "vishing", "mfa bypass", "oauth token theft",
            "data exfiltration", "cloud credential theft",
        ],
        "severity": "HIGH",
        "source": "mandiant.com",
        "published_at": "2026-06-14",
    },
    {
        "threat_name": "XMRig Cryptominer via Log4Shell",
        "ioc_domains": ["xmr-pool.attack.ru", "mine-now.online"],
        "ioc_hashes": [
            "a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6",
            "b0c3d6e9f2a5b8c1d4e7f0a3b6c9d2e5",
        ],
        "behaviors": [
            "log4shell exploitation", "cryptocurrency mining", "cpu abuse",
            "download executable", "persistence via cron",
        ],
        "severity": "MEDIUM",
        "source": "greynoise.io",
        "published_at": "2026-05-28",
    },
    {
        "threat_name": "AsyncRAT Campaign via Malspam",
        "ioc_domains": ["asyncrat-c2.ru", "malspam-host.net"],
        "ioc_hashes": ["c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4"],
        "behaviors": [
            "remote access trojan", "keylogging", "screen capture",
            "download executable", "registry persistence", "powershell execution",
        ],
        "severity": "HIGH",
        "source": "any.run",
        "published_at": "2026-06-22",
    },
    {
        "threat_name": "Akira Ransomware Gang",
        "ioc_domains": ["akira-files.onion"],
        "ioc_hashes": ["d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3"],
        "behaviors": [
            "file encryption", "credential dumping", "vpn exploitation",
            "data exfiltration", "double extortion", "shadow copy deletion",
        ],
        "severity": "CRITICAL",
        "source": "bleepingcomputer.com",
        "published_at": "2026-06-17",
    },
    {
        "threat_name": "Snake Keylogger .NET variant",
        "ioc_domains": ["snake-panel.ru", "snakelog.pw"],
        "ioc_hashes": [
            "e7f0a3b6c9d2e5f8a1b4c7d0e3f6a9b2",
            "f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1",
        ],
        "behaviors": [
            "keylogging", "clipboard hijacking", "browser credential theft",
            "email client credential theft", "ftp credential theft",
        ],
        "severity": "HIGH",
        "source": "fortinet.com",
        "published_at": "2026-06-19",
    },
]

# ══════════════════════════════════════════════════════════════════════════════
#  Phase 1 — Snapshot real laptop patterns into HydraDB
# ══════════════════════════════════════════════════════════════════════════════

def _ts_ago(seconds: int) -> str:
    delta = timedelta(seconds=seconds)
    return (datetime.now(timezone.utc) - delta).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"


def seed_hydradb(db: HydraDB) -> dict[str, int]:
    counts: dict[str, int] = {
        "process_events": 0, "network_events": 0,
        "threat_intel": 0, "incidents": 0,
    }

    console.print(Rule("[bold bright_cyan]Phase 1 · Scanning this laptop[/]"))
    console.print("[dim]Reading real processes and network connections via psutil…[/dim]")
    console.print("[dim]Process/network events  →  sub-tenant: [bold]laptop-asus[/]"
                  "   |   Threat intel  →  sub-tenant: [bold]demo[/][/dim]")
    console.print()

    # Switch cloud sub-tenant to laptop-asus for real machine data
    if hasattr(db, "_cloud"):
        db._cloud.sub_tenant_id = "laptop-asus"

    # ── 1. Live processes ────────────────────────────────────────────────────
    proc_rows = []
    seen_pids: set[int] = set()
    for p in psutil.process_iter(["pid", "name", "exe", "ppid", "status"]):
        try:
            info = p.info
            pid  = info["pid"]
            name = (info["name"] or "").strip() or "unknown"
            exe  = info["exe"] or ""
            ppid = info["ppid"] or 0
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            _, _, suspicious = get_proc_info(pid)
            risk = 4 if suspicious else 0
            proc_rows.append((pid, name, exe, ppid, risk))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    proc_tbl = Table(title=f"[bold]Live processes ({len(proc_rows)} found)[/]",
                     box=box.SIMPLE_HEAVY, border_style="bright_magenta",
                     header_style="bold bright_magenta", show_lines=False)
    proc_tbl.add_column("PID", width=7, justify="right")
    proc_tbl.add_column("Process", min_width=22)
    proc_tbl.add_column("Risk", width=8)
    proc_tbl.add_column("Path (truncated)", min_width=30)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as prog:
        t = prog.add_task("[bright_magenta]Storing process events[/]", total=len(proc_rows))
        for i, (pid, name, exe, ppid, risk) in enumerate(proc_rows):
            try:
                parent_name = psutil.Process(ppid).name() if ppid else ""
            except Exception:
                parent_name = ""
            db.store_process_event(
                pid=pid, process_name=name, parent_process=parent_name,
                path=exe, risk_score=risk,
                ts=_ts_ago(random.randint(0, 3600)),
            )
            counts["process_events"] += 1

            risk_style = "bold red" if risk >= 3 else ("yellow" if risk == 2 else "dim green")
            risk_label = "HIGH" if risk >= 3 else ("MED" if risk == 2 else "ok")
            short_exe  = ("..." + exe[-34:]) if len(exe) > 37 else exe
            proc_tbl.add_row(
                str(pid),
                f"[bold red]{name}[/]" if risk >= 3 else name,
                f"[{risk_style}]{risk_label}[/]",
                f"[dim]{short_exe}[/]",
            )
            prog.advance(t)

    console.print(proc_tbl)
    console.print()

    # ── 2. Live network connections ──────────────────────────────────────────
    conn_rows = []
    try:
        raw_conns = psutil.net_connections(kind="inet")
    except Exception:
        raw_conns = []

    seen_keys: set[str] = set()
    for conn in raw_conns:
        if not conn.raddr or not conn.raddr.ip:
            continue
        rip = conn.raddr.ip
        if not is_external(rip):
            continue
        ck = f"{conn.pid}:{rip}:{conn.raddr.port}"
        if ck in seen_keys:
            continue
        seen_keys.add(ck)
        proc_name, exe, suspicious = get_proc_info(conn.pid)
        risk_label, _ = calc_risk(conn, suspicious_path=suspicious)
        risk_score = {"● HIGH": 4, "● MED": 2, "● LOW": 1}.get(risk_label, 0)
        country = geo_country(rip)
        conn_rows.append((conn, proc_name, rip, conn.raddr.port, country, risk_score, suspicious))

    net_tbl = Table(title=f"[bold]Live external connections ({len(conn_rows)} found)[/]",
                    box=box.SIMPLE_HEAVY, border_style="bright_cyan",
                    header_style="bold bright_cyan", show_lines=False)
    net_tbl.add_column("Process", min_width=20)
    net_tbl.add_column("Remote IP", min_width=16)
    net_tbl.add_column("Port", width=7)
    net_tbl.add_column("Country", min_width=12)
    net_tbl.add_column("Risk", width=8)
    net_tbl.add_column("Flag", width=6)

    incident_seeds: list[tuple[str, str, float, str]] = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as prog:
        t = prog.add_task("[bright_cyan]Storing network events[/]", total=len(conn_rows))
        for conn, proc_name, rip, rport, country, risk_score, suspicious in conn_rows:
            db.store_network_event(
                process_name=proc_name, remote_ip=rip,
                country=country, risk_score=risk_score,
                ts=_ts_ago(random.randint(0, 1800)),
            )
            counts["network_events"] += 1

            flag = "[bold red]SUSP[/]" if suspicious else ""
            risk_style = "bold red" if risk_score >= 3 else ("yellow" if risk_score >= 2 else "dim green")
            risk_str   = "HIGH" if risk_score >= 3 else ("MED" if risk_score >= 2 else "ok")
            net_tbl.add_row(
                f"[bold red]{proc_name}[/]" if suspicious else proc_name,
                rip, str(rport), country,
                f"[{risk_style}]{risk_str}[/]", flag,
            )

            # collect anything worth an incident
            if risk_score >= 3 or suspicious:
                summary = (f"{proc_name} (pid {conn.pid}) → {rip}:{rport} ({country}) "
                           f"— {'suspicious path' if suspicious else 'HIGH risk'}")
                incident_seeds.append((proc_name, summary, risk_score, country))

            prog.advance(t)

    console.print(net_tbl)
    console.print()

    # ── 3. Auto-open incidents for HIGH-risk findings ────────────────────────
    if incident_seeds:
        console.print(Rule("[dim]Auto-incidents from live scan[/dim]"))
        for i, (proc, summary, score, country) in enumerate(incident_seeds[:8], 1):
            inc_id = f"INC-LIVE-{i:03d}"
            sev    = "CRITICAL" if score >= 4 else "HIGH"
            conf   = 0.80 if score >= 4 else 0.65
            pred   = (f"{proc} is making suspicious external connections to {country}. "
                      f"Monitor for data exfiltration or C2 communication.")
            db.open_incident(inc_id, summary, confidence=conf, prediction=pred, severity=sev)
            counts["incidents"] += 1
            console.print(f"  [bold red]{inc_id}[/]  [{sev}]  {summary[:72]}")

    # ── 4. Threat intel (domain knowledge, always relevant) ──────────────────
    # Switch back to demo sub-tenant for intel (not machine-specific)
    if hasattr(db, "_cloud"):
        db._cloud.sub_tenant_id = "demo"
    console.print()
    console.print(Rule("[dim]Storing threat intel → demo[/dim]"))
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as prog:
        t = prog.add_task("[bold bright_red]Threat intel[/]", total=len(_THREAT_INTEL))
        for item in _THREAT_INTEL:
            db.store_intel(**item)
            counts["threat_intel"] += 1
            prog.advance(t)

    console.print()
    tbl = Table(title="[bold]Records written to HydraDB[/]",
                box=box.ROUNDED, border_style="bright_cyan")
    tbl.add_column("Table", style="bold bright_cyan")
    tbl.add_column("Rows", justify="right", style="bold green")
    for k, v in counts.items():
        tbl.add_row(k, str(v))
    tbl.add_row("[dim]TOTAL[/]", str(sum(counts.values())), end_section=True)
    console.print(tbl)
    return counts


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 2 — Anakin scraping simulation
# ══════════════════════════════════════════════════════════════════════════════

_FAKE_SEARCH_RESULTS = [
    {
        "title": "CISA Advisory: Active exploitation of CVE-2026-0185 in the wild",
        "url": "https://www.cisa.gov/advisories/2026/aa26-001",
        "snippet": (
            "CISA warns of active exploitation of a critical Windows Print Spooler "
            "vulnerability (CVE-2026-0185). Threat actors are leveraging this flaw "
            "for privilege escalation and lateral movement inside enterprise networks."
        ),
        "date": "2026-06-01",
        "source": "cisa.gov",
    },
    {
        "title": "LummaC2 Stealer targets crypto wallets via fake CAPTCHA pages",
        "url": "https://www.bleepingcomputer.com/news/security/lummac2-captcha/",
        "snippet": (
            "LummaC2 infostealer is being distributed through fake CAPTCHA verification "
            "pages hosted on compromised WordPress sites. The malware steals browser "
            "credentials, crypto wallets, and FTP/VPN credentials."
        ),
        "date": "2026-06-15",
        "source": "bleepingcomputer.com",
    },
    {
        "title": "BlackCat ALPHV ransomware adopts new Sphynx encryptor",
        "url": "https://www.cisa.gov/advisories/2026/blackcat-sphynx",
        "snippet": (
            "The BlackCat (ALPHV) ransomware group has updated their encryptor (Sphynx) "
            "with improved evasion. They now delete shadow copies via vssadmin and use "
            "intermittent encryption to evade behavior-based detection."
        ),
        "date": "2026-06-10",
        "source": "cisa.gov",
    },
    {
        "title": "APT29 Midnight Blizzard: OAuth abuse against Microsoft 365",
        "url": "https://www.microsoft.com/security/blog/2026/06/apt29-m365",
        "snippet": (
            "Microsoft Threat Intelligence reports APT29 is abusing OAuth application "
            "consent phishing to gain persistent access to M365 environments. They "
            "register rogue apps and use them for long-term espionage and data theft."
        ),
        "date": "2026-06-08",
        "source": "microsoft.com",
    },
    {
        "title": "Cobalt Strike beacon identified in new campaign against financial sector",
        "url": "https://www.proofpoint.com/us/blog/threat-insight/cobalt-strike-2026",
        "snippet": (
            "Proofpoint researchers identified a new Cobalt Strike campaign targeting "
            "financial institutions via spear-phishing. The malleable C2 profile mimics "
            "legitimate Microsoft traffic to evade detection."
        ),
        "date": "2026-06-18",
        "source": "proofpoint.com",
    },
    {
        "title": "Akira ransomware exploits VPN appliances for initial access",
        "url": "https://www.bleepingcomputer.com/news/security/akira-vpn-2026/",
        "snippet": (
            "Akira ransomware group has been exploiting unpatched Cisco ASA/FTD VPN "
            "vulnerabilities for initial access, then deploying their encryptor after "
            "stealing data. Over 30 organisations hit in May–June 2026."
        ),
        "date": "2026-06-17",
        "source": "bleepingcomputer.com",
    },
    {
        "title": "Emotet returns with Epoch 5: OneNote lures and direct DLL loads",
        "url": "https://thedfirreport.com/2026/06/emotet-epoch5/",
        "snippet": (
            "Emotet has returned with Epoch 5 infrastructure, using OneNote files "
            "with embedded DLL loaders to bypass macro policies. Once active, it "
            "downloads banking trojans and provides access to ransomware groups."
        ),
        "date": "2026-06-12",
        "source": "thedfirreport.com",
    },
    {
        "title": "DarkGate loader now includes keylogger and crypto miner modules",
        "url": "https://sekoia.io/blog/darkgate-2026/",
        "snippet": (
            "DarkGate malware loader has been updated with a keylogger module, "
            "remote desktop capability, and an embedded XMRig cryptocurrency miner. "
            "Distributed via malicious Skype and Teams messages."
        ),
        "date": "2026-06-20",
        "source": "sekoia.io",
    },
]

_EXTRACTED_CAMPAIGNS_FAKE = [
    {
        "threat_name": "CVE-2026-0185 Print Spooler Exploitation",
        "ioc_domains": [],
        "ioc_hashes": ["f2a5b8c1d4e7f0a3b6c9d2e5f8a1b4c7"],
        "behaviors": ["privilege escalation", "dll injection", "spooler exploit", "lateral movement"],
        "severity": "CRITICAL",
        "source": "cisa.gov",
        "published_at": "2026-06-01",
    },
    {
        "threat_name": "LummaC2 Stealer Campaign",
        "ioc_domains": ["lumma-update.com", "captcha-verify.pw"],
        "ioc_hashes": ["a3f5c8e1d2b7a4f0c9e3d6b8a1f4c7e0"],
        "behaviors": ["browser credential theft", "crypto wallet scraping", "clipboard hijacking", "c2 communication"],
        "severity": "CRITICAL",
        "source": "bleepingcomputer.com",
        "published_at": "2026-06-15",
    },
    {
        "threat_name": "BlackCat / ALPHV Sphynx Ransomware",
        "ioc_domains": ["alphv-files.onion"],
        "ioc_hashes": ["c1d4a7f0b3e6c9d2a5f8b1e4c7a0d3f6"],
        "behaviors": ["file encryption", "shadow copy deletion", "intermittent encryption", "data exfiltration"],
        "severity": "CRITICAL",
        "source": "cisa.gov",
        "published_at": "2026-06-10",
    },
    {
        "threat_name": "APT29 Midnight Blizzard OAuth Abuse",
        "ioc_domains": ["oauth-consent.malicious.net"],
        "ioc_hashes": [],
        "behaviors": ["oauth token theft", "spear phishing", "data exfiltration", "m365 compromise"],
        "severity": "HIGH",
        "source": "microsoft.com",
        "published_at": "2026-06-08",
    },
    {
        "threat_name": "Cobalt Strike Financial Sector Campaign",
        "ioc_domains": ["cobalt-c2.hacker.io"],
        "ioc_hashes": ["c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0"],
        "behaviors": ["command-and-control", "spear phishing", "process injection", "c2 beacon"],
        "severity": "CRITICAL",
        "source": "proofpoint.com",
        "published_at": "2026-06-18",
    },
    {
        "threat_name": "Akira Ransomware VPN Exploitation",
        "ioc_domains": ["akira-files.onion"],
        "ioc_hashes": ["d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3"],
        "behaviors": ["vpn exploitation", "credential dumping", "file encryption", "double extortion"],
        "severity": "CRITICAL",
        "source": "bleepingcomputer.com",
        "published_at": "2026-06-17",
    },
    {
        "threat_name": "Emotet Epoch 5 OneNote Loader",
        "ioc_domains": ["emotet-cdn.ru"],
        "ioc_hashes": ["a7b0c3d6e9f2a5b8c1d4e7f0a3b6c9d2"],
        "behaviors": ["malicious onenote", "dll sideloading", "banking trojan", "registry persistence"],
        "severity": "HIGH",
        "source": "thedfirreport.com",
        "published_at": "2026-06-12",
    },
    {
        "threat_name": "DarkGate Loader with Keylogger Module",
        "ioc_domains": ["darkgate-panel.ru"],
        "ioc_hashes": ["e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8"],
        "behaviors": ["keylogging", "remote desktop", "cryptocurrency mining", "malicious messenger"],
        "severity": "HIGH",
        "source": "sekoia.io",
        "published_at": "2026-06-20",
    },
]


def simulate_anakin_scraping(db: HydraDB) -> list[dict]:
    """Simulate the Anakin scraping pipeline with visual output."""
    console.print()
    console.print(Rule("[bold bright_green]Phase 2 · Anakin Scraping Pipeline[/]"))
    console.print()

    # Step 1 — show the API call
    console.print(Panel(
        "[bold bright_green]Anakin[/]  →  POST [dim]https://api.anakin.io/v1/search[/dim]\n\n"
        "[bold]Prompt:[/bold]\n"
        "[dim]Latest malware campaigns, ransomware, infostealers, and actively exploited\n"
        "CVEs reported in the last two weeks by CISA, Microsoft Security,\n"
        "BleepingComputer and The Hacker News — include the threat name, affected\n"
        "software, indicators of compromise, and observed behaviors.[/dim]\n\n"
        "[bold]Headers:[/bold] [dim]X-API-Key: ask_b2c1...a3b72  ·  Content-Type: application/json[/dim]\n"
        "[bold]Params:[/bold]  [dim]limit=8[/dim]",
        title="[bold bright_green]>> API REQUEST[/]",
        border_style="bright_green",
    ))

    # Animate the "request"
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
        t = prog.add_task("[dim]Waiting for Anakin response…[/dim]", total=None)
        time.sleep(1.2)
        prog.update(t, description="[bright_green]Response received — 200 OK[/bright_green]")
        time.sleep(0.4)

    console.print()
    console.print("[bold bright_green]Raw search results from Anakin:[/]")
    console.print()

    # Step 2 — show raw results
    results_tbl = Table(box=box.SIMPLE_HEAVY, border_style="bright_black",
                        header_style="bold bright_green", show_lines=True)
    results_tbl.add_column("#", width=3, justify="right")
    results_tbl.add_column("Title", min_width=38)
    results_tbl.add_column("Source", min_width=20)
    results_tbl.add_column("Date", width=12)
    results_tbl.add_column("Snippet (preview)", min_width=34)

    for i, r in enumerate(_FAKE_SEARCH_RESULTS, 1):
        results_tbl.add_row(
            str(i),
            r["title"][:46] + ("…" if len(r["title"]) > 46 else ""),
            r["source"],
            r["date"],
            r["snippet"][:60] + "…",
        )
    console.print(results_tbl)

    # Step 3 — extraction step
    console.print()
    console.print(Panel(
        "[bold]Gemma 4[/] extracts structured campaigns from raw snippets:\n\n"
        "[dim]System: You output only strict JSON arrays for threat-intelligence extraction.\n\n"
        "User: From these web search results about cybersecurity threats, extract\n"
        "distinct, named malware campaigns as a JSON array.\n"
        "Each item: {threat_name, ioc_domains[], ioc_hashes[], behaviors[],\n"
        "severity (LOW|MEDIUM|HIGH|CRITICAL), source, published_at}...[/dim]",
        title="[bold bright_magenta]>> GEMMA EXTRACTION PROMPT[/]",
        border_style="bright_magenta",
    ))

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
        t = prog.add_task("[dim]Gemma reasoning…[/dim]", total=None)
        time.sleep(1.5)
        prog.update(t, description="[bright_magenta]Extraction complete — 8 campaigns parsed[/bright_magenta]")
        time.sleep(0.3)

    # Step 4 — show extracted JSON
    console.print()
    console.print("[bold bright_magenta]Extracted structured campaigns (JSON):[/]")
    console.print()

    tree = Tree("[bold bright_magenta]campaigns[][/]")
    for c in _EXTRACTED_CAMPAIGNS_FAKE:
        sev_color = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "green"}.get(c["severity"], "white")
        node = tree.add(f"[bold]{c['threat_name']}[/]  [{sev_color}]{c['severity']}[/]  "
                        f"[dim]{c['source']}[/]")
        node.add(f"[dim]behaviors: {', '.join(c['behaviors'][:3])}{'…' if len(c['behaviors'])>3 else ''}[/]")
        if c["ioc_domains"]:
            node.add(f"[dim]ioc_domains: {', '.join(c['ioc_domains'][:2])}[/]")
        if c["ioc_hashes"]:
            node.add(f"[dim]ioc_hashes: {c['ioc_hashes'][0][:20]}…[/]")
    console.print(tree)

    # Step 5 — store into HydraDB
    console.print()
    console.print(Rule("[dim]Storing extracted campaigns into HydraDB[/dim]"))

    stored: list[dict] = []
    existing = {r["threat_name"].lower() for r in db.recent_intel(limit=500)}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(), TaskProgressColumn(), console=console,
    ) as prog:
        t = prog.add_task("[bright_green]Writing campaigns[/]", total=len(_EXTRACTED_CAMPAIGNS_FAKE))
        for camp in _EXTRACTED_CAMPAIGNS_FAKE:
            time.sleep(0.08)
            name = camp["threat_name"]
            status = "[dim yellow]SKIP — already in DB[/dim yellow]"
            if name.lower() not in existing:
                db.store_intel(
                    threat_name=name,
                    ioc_domains=camp.get("ioc_domains", []),
                    ioc_hashes=camp.get("ioc_hashes", []),
                    behaviors=camp.get("behaviors", []),
                    severity=camp.get("severity", ""),
                    source=camp.get("source", ""),
                    published_at=camp.get("published_at", ""),
                )
                status = "[bold green]STORED[/bold green]"
                existing.add(name.lower())
                stored.append(camp)
            prog.advance(t)
            prog.console.print(f"  {name[:50]:<52} {status}")

    console.print()
    console.print(f"[bold bright_green]Anakin scraping complete.[/]  "
                  f"[bold]{len(stored)}[/] new campaigns stored into HydraDB.")

    # Return raw search results + extracted (for the JSON dump)
    return [
        {"_raw_search": _FAKE_SEARCH_RESULTS,
         "_extracted_campaigns": _EXTRACTED_CAMPAIGNS_FAKE,
         "_stored_count": len(stored)}
    ]


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 3 — Dump everything to JSON
# ══════════════════════════════════════════════════════════════════════════════

def dump_to_json(db: HydraDB, anakin_meta: list[dict]) -> Path:
    console.print()
    console.print(Rule("[bold bright_yellow]Phase 3 · JSON Memory Dump[/]"))
    console.print()

    payload: dict = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "host": __import__("socket").gethostname(),
            "hydradb_backend": db.backend,
            "hydradb_location": db.location,
        },
        "health": {},
        "timeline": [],
        "process_events": [],
        "network_events": [],
        "system_events": [],
        "threat_intelligence": [],
        "incidents": [],
        "predictions": [],
        "anakin_scraping": {},
    }

    # health
    score, label = db.health_score()
    payload["health"] = {"score": score, "label": label}

    # timeline
    payload["timeline"] = db.timeline(200)

    # raw tables via internal queries
    payload["process_events"] = db._query(
        "SELECT * FROM process_events ORDER BY id DESC LIMIT 500")
    payload["network_events"] = db._query(
        "SELECT * FROM network_events ORDER BY id DESC LIMIT 500")
    payload["system_events"] = db._query(
        "SELECT timestamp, kind, source, summary, detail, risk_score "
        "FROM system_events ORDER BY id DESC LIMIT 500")
    for r in payload["system_events"]:
        if r.get("detail"):
            try:
                r["detail"] = json.loads(r["detail"])
            except Exception:
                pass

    intel_rows = db._query(
        "SELECT threat_name, ioc_domains, ioc_hashes, behaviors, "
        "severity, source, published_at, ingested_at "
        "FROM threat_intelligence ORDER BY id DESC LIMIT 500")
    for r in intel_rows:
        for col in ("ioc_domains", "ioc_hashes", "behaviors"):
            try:
                r[col] = json.loads(r.get(col) or "[]")
            except Exception:
                r[col] = []
    payload["threat_intelligence"] = intel_rows

    payload["incidents"] = db._query(
        "SELECT * FROM incidents ORDER BY id DESC LIMIT 200")
    payload["predictions"] = db._query(
        "SELECT * FROM predictions ORDER BY id DESC LIMIT 200")

    # Anakin scraping meta
    if anakin_meta:
        m = anakin_meta[0]
        payload["anakin_scraping"] = {
            "raw_search_results": m.get("_raw_search", []),
            "extracted_campaigns": m.get("_extracted_campaigns", []),
            "newly_stored": m.get("_stored_count", 0),
        }

    # count summary
    summary = {k: len(v) if isinstance(v, list) else v
               for k, v in payload.items() if k not in ("_meta", "health", "anakin_scraping")}

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
        t = prog.add_task("[bright_yellow]Serialising to JSON…[/]", total=None)
        json_str = json.dumps(payload, indent=2, default=str, ensure_ascii=False)
        time.sleep(0.3)
        prog.update(t, description="[bright_yellow]Writing file…[/]")
        OUT_JSON.write_text(json_str, encoding="utf-8")
        time.sleep(0.2)
        prog.update(t, description=f"[bold green]Done — {OUT_JSON.name}[/bold green]")

    console.print()

    tbl = Table(title="[bold]JSON dump summary[/]",
                box=box.ROUNDED, border_style="bright_yellow")
    tbl.add_column("Section", style="bold bright_yellow")
    tbl.add_column("Records", justify="right", style="bold green")
    for k, v in summary.items():
        tbl.add_row(k, str(v))
    tbl.add_row("[dim]file size[/]", f"{len(json_str) / 1024:.1f} KB")
    console.print(tbl)

    console.print()
    console.print(Panel(
        f"[bold bright_yellow]Output:[/] [underline]{OUT_JSON}[/]\n\n"
        f"[dim]Contains all HydraDB tables, the Anakin scraping pipeline "
        f"results (raw search results + Gemma-extracted campaigns), "
        f"and the full event timeline.[/dim]",
        title="[bold]Memory dump complete[/]",
        border_style="bright_yellow",
    ))

    return OUT_JSON


# ══════════════════════════════════════════════════════════════════════════════
#  Cloud flush — wait for the HydraDB background worker to drain its queue
# ══════════════════════════════════════════════════════════════════════════════

def _flush_cloud(db: HydraDB) -> None:
    """Drain the HydraDB cloud ingest queue before the process exits.

    The background worker is a daemon thread and would be killed on exit,
    leaving unsent memories. We wait here until the queue is empty (max 3 min),
    then sleep 3 s more so the last HTTP POST can complete.
    """
    cloud = getattr(db, "_cloud", None)
    if cloud is None or not getattr(cloud, "available", False):
        console.print("[dim yellow]HydraDB cloud not configured — skipping cloud sync.[/dim yellow]")
        return

    q = getattr(cloud, "_q", None)
    if q is None:
        return

    total_queued = q.qsize()
    if total_queued == 0:
        return

    console.print()
    console.print(Rule("[dim]Flushing memories to HydraDB cloud[/dim]"))
    console.print(f"[dim]{total_queued} memories to sync → api.hydradb.com  "
                  f"(tenant: {cloud.tenant_id})[/dim]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as prog:
        t = prog.add_task("[cyan]Syncing to HydraDB cloud…[/cyan]", total=total_queued)
        deadline = time.time() + 180        # 3 min max
        sent = 0
        while not q.empty() and time.time() < deadline:
            now_remaining = q.qsize()
            now_sent = total_queued - now_remaining
            if now_sent > sent:
                prog.advance(t, now_sent - sent)
                sent = now_sent
            prog.update(t, description=f"[cyan]{now_sent}/{total_queued} synced…[/cyan]")
            time.sleep(0.3)

        # final advance
        prog.advance(t, total_queued - sent)
        # give the last POST a moment to land
        time.sleep(3)
        prog.update(t, description="[bold bright_cyan]Cloud sync complete[/bold bright_cyan]")

    if q.empty():
        console.print("[bold green]All memories synced.[/bold green]  "
                      "[dim]Check dashboard.hydradb.com/working-context[/dim]")
    else:
        remaining = q.qsize()
        console.print(f"[yellow]Deadline reached — {remaining} memories still queued "
                      f"(run again to retry).[/yellow]")


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    args = sys.argv[1:]

    console.print(Panel(
        "[bold bright_cyan]HeadsUp · Demo Memory Seeder[/]\n"
        "[dim]Seeds HydraDB with fake threat memories, simulates Anakin scraping, "
        "and dumps everything to JSON[/dim]",
        border_style="bright_cyan",
        padding=(0, 2),
    ))
    console.print()

    db = HydraDB()
    console.print(f"[dim]HydraDB backend: [bold]{db.backend}[/]  @  {db.location}[/dim]")
    console.print()

    if "--reset" in args:
        counts = db.reset()
        console.print(f"[yellow]DB wiped:[/] {counts}")
        console.print()

    if "--json-only" not in args:
        seed_hydradb(db)
        console.print()
        anakin_meta = simulate_anakin_scraping(db)
    else:
        console.print("[dim]--json-only: skipping seed & scrape, dumping current DB…[/dim]")
        anakin_meta = []

    dump_to_json(db, anakin_meta)
    _flush_cloud(db)
    console.print()
    console.print("[bold bright_cyan]All done.[/]  "
                  f"Run [bold]python seed_demo.py --reset[/] to wipe and re-seed.")


if __name__ == "__main__":
    main()
