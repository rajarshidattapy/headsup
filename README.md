# HeadsUp
<img width="1378" height="168" alt="image" src="https://github.com/user-attachments/assets/f11adf85-3a4b-474c-9ed7-bd22e0399164" />


<p align="center">
  <h3 align="center">Terminal-native AI Threat Memory Engine for Your Computer</h3>
  <p align="center">
    Learns your machine, remembers every anomaly, ingests live threat intel, and predicts attacks before they become attacks.
  </p>
</p>

<p align="center">
  <b>Terminal-first</b> · <b>Memory-driven</b> · <b>AI-native</b> · <b>Explainable</b><br>
  Python · Rich TUI · Gemma 4 on Cerebras · HydraDB · Anakin web search
</p>

---

## What is HeadsUp?

Traditional antivirus tools detect a threat in the moment and immediately forget it. They flood
you with alerts but rarely explain *why* something happened, how it relates to past incidents, or
what is likely to happen next.

**HeadsUp** is different. It runs as a live **Rich terminal dashboard** that continuously watches
your computer's processes, files, network, startup items and registry, stores **everything
suspicious** in a long-term memory (**HydraDB**), reasons over that memory with **Gemma 4 on
Cerebras**, ingests **emerging malware campaigns from the web** via **Anakin**, and **predicts**
attacks before they fully execute.

It behaves like a personal security analyst that never sleeps and never forgets.

---

## Why HeadsUp?

Most security tools answer:

> "What just happened?"

HeadsUp answers:

* What happened?
* **Why** did it happen?
* **Have I seen this before?** (long-term memory)
* **Is this similar to a new malware campaign?** (live threat intel)
* **What is likely to happen next?** (prediction)

---

## Quickstart

```bash
git clone <repo> && cd headsup
pip install -e .            # or: pip install psutil rich watchdog openai requests send2trash
cp .env.example .env        # optional — add API keys if you have them (see Configuration)

headsup                     # live threat-memory dashboard (Rich TUI)
```

> 💡 Run the terminal **as Administrator** for full process/connection visibility and for the
> remediation actions (kill / block / quarantine). Without admin, some process info is hidden.

**HeadsUp runs fully offline** with graceful fallbacks — no API keys required:

| Capability | With keys | Without keys |
|---|---|---|
| Threat memory (**HydraDB**) | HydraDB cloud (`HYDRADB_API_KEY` + `HYDRADB_TENANT_ID`); optional Postgres via `HYDRA_URL` | local SQLite at `~/.headsup/headsup.db` |
| AI reasoning (**Gemma/Cerebras**) | Gemma 4 on Cerebras (`CEREBRAS_API_KEY`) → OpenAI fallback (`OPENAI_API_KEY`) | deterministic heuristics |
| Threat intel (**Anakin**) | live AI web search (`ANAKIN_API_KEY`) | bundled sample campaign feed |
| Alerts (**Telegram**) | push alerts (`TELEGRAM_BOT_TOKEN`) | on-screen only |

The banner reflects what's active, e.g.
`HydraDB cloud + SQLite · Gemma 4 · Cerebras gemma-3-12b-it · Anakin live`.

---

## Command-line interface

```bash
headsup                  # live threat-memory dashboard (Rich TUI)
headsup --copilot        # natural-language AI security copilot (REPL)
headsup --resolve        # dashboard with reverse-DNS on remote IPs
headsup --auto           # auto-execute remediation on CRITICAL verdicts
headsup --once           # render one snapshot and exit (CI / smoke test)
headsup timeline [N]     # print the recent memory timeline and exit
headsup intel            # ingest + list the latest threat intelligence
headsup reset [-y]       # clear local HydraDB memory (asks to confirm; -y skips)
```

---

## The terminal dashboard

```text
┌──────────────────── ◈ HEADSUP SECURITY CENTER ────────────────────┐
│ ACTIVE CONNS  193          THREAT SCORE  HEALTHY  98/100           │
│ SUSPICIOUS PROC  0         VPN  ✗ NONE                             │
│ OPEN INCIDENTS  0          HOST  LAPTOP-…                          │
│ NEW INTEL (24h)  5         PUBLIC IP  …                            │
└───────────────────────────────────────────────────────────────────┘
  ACTIVE CONNECTIONS   · risk · flags (★ new ⚠ suspicious C/S AI verdict)
  ⏱ THREAT TIMELINE          🌐 THREAT INTEL FEED
  ⚡ AI THREAT INTELLIGENCE   (live verdicts · 🔮 prediction · 🌐 web intel)
  ● AI COPILOT  (press T to chat)
```

| Panel | What it shows |
|---|---|
| **Security Center** | Active connections, suspicious processes, open incidents, new intel, a 0–100 **threat score** (HEALTHY / ELEVATED / MEDIUM / CRITICAL), VPN/host/IP |
| **Active Connections** | Live connections with risk, GeoIP country, port labels, process, and flags: `★` new, `⚠` suspicious path, `C`/`S` AI verdict (critical/suspicious) |
| **Threat Timeline** | Newest-first stream of every observed event (process / network / registry / startup / download / file) |
| **Threat Intel Feed** | Latest campaigns from Anakin (or the bundled feed) + a "resembles X (NN%)" banner when your machine matches one |
| **AI Threat Intelligence** | Live per-connection verdicts, the **🔮 prediction** for the current behavior chain, **🌐 live web intel** on the matched campaign, and a remediation log |
| **AI Copilot** | Natural-language chat — press `T` to open |

**Keyboard:** `T` open copilot · `j`/`k` or `↑`/`↓` scroll connections · in chat: `Enter` send, `Esc` cancel, `↑`/`↓` scroll history · `Ctrl+C` quit.

---

## AI Copilot

Press `T` in the dashboard, or run `headsup --copilot`. Ask plain-English questions or issue
commands — answers are grounded in the live machine state **plus** your HydraDB memory.

| Ask / command | What it does |
|---|---|
| `what changed today?` | Summarizes today's activity and flags anything risky |
| `have I seen 45.33.32.156 before?` / `seen <ip>` | Correlates an IP/process against long-term memory |
| `predict` / `what happens next?` | Predicts the next attack stages for the current behavior chain |
| `search latest ransomware` / `web <topic>` | **Anakin AI web search** with cited sources |
| `intel` | Lists the latest ingested threat intelligence |
| `show foreign` / `show high` | Lists foreign / high-risk connections right now |
| `is this process dangerous?` (free text) | Gemma explanation grounded in context + memory |
| `kill <pid>` · `suspend <pid>` · `block <ip>` · `close port <n>` | Remediation actions |
| `quarantine <path>` · `inspect <path>` | Move a file to the Recycle Bin / hash & inspect it |

---

## How it works

```text
        ┌─────────────────────────────┐
        │     Rich Terminal UI        │  panels · copilot · alerts
        └──────────────┬──────────────┘
                       ▼
        ┌─────────────────────────────┐
        │     Monitoring Engine       │  psutil + watchdog + winreg (1s poll)
        └──────────────┬──────────────┘
                       ▼
        ┌─────────────────────────────┐      ┌────────────────────┐
        │          HydraDB            │◀────▶│  HydraDB Cloud      │  long-term,
        │  local SQLite / Postgres    │      │  (usecortex)        │  cross-session
        └──────────────┬──────────────┘      └────────────────────┘  memory
                       ▼
        ┌─────────────────────────────┐
        │      Gemma 4 (Cerebras)     │  explain · correlate · predict · summarize
        └──────────────┬──────────────┘
                       ▼
        ┌─────────────────────────────┐      Internet threat sources
        │ Predictions & Explanations  │◀──── Anakin AI web search ──┐
        └─────────────────────────────┘                            │
                       ▲                                            ▼
                       └──────────── matched campaign ◀──── threat_intelligence
```

**The predictive flow** — when correlated suspicious activity is detected:

```text
Downloaded executable
        ↓
New registry / startup entry              →  HydraDB stores every step
        ↓
Foreign network connection                →  correlate with machine history
        ↓
Anakin matches a malware campaign  ──────►  "resembles Lumma Stealer (83%)"
        ↓
Gemma reasons over the evidence    ──────►  opens an Incident + Prediction:
                                              • Persistence likely
                                              • Browser credential theft likely
                                              • Data exfiltration possible
        ↓
Anakin web search on the campaign  ──────►  fresh, cited intel attached to the
                                              incident (and pushed to Telegram)
```

---

## Monitoring engine

A 1-second poll plus an event-driven file watcher normalizes every observation, scores its risk,
and writes it to HydraDB.

| Source | Detail |
|---|---|
| **Processes** | New executions — name / pid / parent / path; flags binaries in temp/download paths |
| **Network** | Outbound/listening connections, GeoIP country, reverse-DNS domain, risk scoring |
| **Startup** | Windows Startup-folder changes |
| **Registry** | `HKCU/HKLM …\Run` key diffs (persistence) |
| **Downloads** | New files landing in the Downloads folder (executables flagged) |
| **Files** | Created/moved executables & scripts (via `watchdog`) |

---

## HydraDB — the threat memory

HydraDB is the layer that **never forgets**. It runs in two cooperating tiers:

* **Local store** — zero-setup **SQLite** at `~/.headsup/headsup.db` (or **Postgres** via
  `HYDRA_URL`). Powers the live dashboard's fast queries (timeline, health score, correlation) and
  is the offline fallback.
* **HydraDB cloud** (usecortex) — when `HYDRADB_API_KEY` + `HYDRADB_TENANT_ID` are set, every event
  is also ingested into HydraDB as durable, **cross-session / cross-machine** semantic memory with
  structured metadata, and the AI copilot recalls from it.

**Tables:** `process_events`, `network_events`, `system_events`, `threat_intelligence`,
`incidents`, `predictions`.

**Cloud metadata schema:** events are tagged with structured `tenant_metadata`
(`event_type`, `severity`, `risk_score`, `process_name`, `remote_ip`, `threat_name`,
`incident_id`, `resolved`, …) so recalls can be filtered. Paste
[`hydradb.tenant-schema.json`](hydradb.tenant-schema.json) into the **Metadata Schema** field when
you create your HydraDB tenant.

---

## Gemma 4 on Cerebras — the reasoning engine

The analyst uses the OpenAI-compatible Cerebras endpoint (`CEREBRAS_API_KEY`, model via
`GEMMA_MODEL`), falls back to OpenAI (`OPENAI_API_KEY`), then to deterministic offline heuristics.
It provides:

* **Explain** — "Why is this process suspicious?"
* **Correlate** — "Have I seen this behavior before?" (queries HydraDB)
* **Predict** — "What is likely to happen next?" (next-stage attack chain)
* **Summarize** — "What happened on my computer today?"
* **Recommend** — delete / quarantine / monitor / ignore / block

---

## Anakin — AI web search & emerging threat intel

HeadsUp uses Anakin's AI-powered web search (`https://api.anakin.io/v1/search`) two ways:

1. **Threat-intel ingestion** — searches the web for the latest campaigns, CVEs and advisories
   (CISA, Microsoft, BleepingComputer, The Hacker News, …), structures the results (with Gemma)
   into the `threat_intelligence` schema, and stores them in HydraDB.
2. **Copilot web search** — `search <topic>` returns a concise, **cited** answer.

Local behavior is matched against known campaigns to surface lines like:

> This activity resembles the recently reported **Lumma Stealer** campaign — **83% similarity**.

When an incident fires on a matched campaign, HeadsUp automatically runs a background Anakin web
search on that campaign and attaches the fresh, cited intel to the prediction.

Without an `ANAKIN_API_KEY`, HeadsUp uses a bundled sample feed
([`core/data/sample_intel.json`](core/data/sample_intel.json)) so matching always works.

---

## Configuration

All settings are optional and read from `.env` (see [`.env.example`](.env.example)).

| Variable | Purpose |
|---|---|
| `CEREBRAS_API_KEY` | Gemma 4 reasoning on Cerebras (primary AI) |
| `GEMMA_MODEL` | Cerebras model id (default `gemma-3-12b-it`) |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | Fallback reasoning provider |
| `HYDRADB_API_KEY` / `HYDRADB_TENANT_ID` | HydraDB cloud long-term memory |
| `HYDRADB_SUB_TENANT_ID` / `HYDRADB_API_BASE` | Optional sub-tenant / self-hosted endpoint |
| `HYDRA_URL` | Use Postgres for the local store instead of SQLite |
| `ANAKIN_API_KEY` | Anakin AI web search + live threat intel |
| `ANAKIN_API_URL` | Anakin endpoint (default `https://api.anakin.io/v1/search`) |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Optional push alerts |

---

## Project structure

```text
headsup/
├─ headsup.py                  # CLI launcher (dashboard / copilot / timeline / intel / reset)
├─ hydradb.tenant-schema.json  # HydraDB cloud metadata schema (paste at tenant creation)
├─ .env.example                # configuration template
└─ core/
   ├─ headsup.py               # Rich TUI, orchestration & predictive engine
   ├─ monitor.py               # multi-source monitoring engine (1s poll + watchdog)
   ├─ hydradb.py               # threat memory: SQLite/Postgres + HydraDB cloud
   ├─ analyst.py               # Gemma-on-Cerebras reasoning (+ OpenAI / offline fallback)
   ├─ anakin.py                # Anakin AI web search + threat-intel ingestion
   ├─ telegram_alert.py        # optional Telegram alerts
   └─ data/sample_intel.json   # bundled threat-intel fallback feed
```

---

## Tech stack

| Layer | Tech |
|---|---|
| Language | Python 3.10+ |
| Terminal UI | [Rich](https://github.com/Textualize/rich) |
| Monitoring | `psutil`, `watchdog`, `winreg` |
| AI reasoning | Gemma 4 on Cerebras Inference (OpenAI-compatible client) |
| Memory | HydraDB cloud + SQLite / Postgres |
| Threat intel | Anakin AI web search |
| Alerts | Telegram (optional) |

> Terminal-first by design — there is no web frontend. The terminal *is* the security command center.

---

## Privacy & safety

* All monitoring and the local memory database stay **on your machine**. Cloud features (HydraDB,
  Cerebras, Anakin, Telegram) only activate when you provide the corresponding keys.
* `.env` and `~/.headsup/` are git-ignored. `headsup reset` wipes local memory on demand.
* Remediation actions (kill / block / quarantine) require Administrator privileges and are only
  taken on your command (or on `CRITICAL` verdicts when you opt in with `--auto`).

---

## Roadmap

* **SkillMake.xyz security skills** — pluggable IOC extraction, malware summarization, risk scoring
  and report generation to extend HeadsUp without changing the core.
* Optional **FastAPI / REST** surface for remote dashboards and integrations.
* More collectors (DNS sniffing, scheduled tasks, services, browser-extension changes).
* macOS / Linux collector parity.

---

## Vision

HeadsUp is a new category of cybersecurity software:

> A memory-powered security analyst for personal computers.

Instead of detecting malware after the damage is done, HeadsUp **remembers, learns, and predicts**.

---

## One-line pitch

**HeadsUp is a terminal-native AI security analyst that remembers everything your computer does,
learns from emerging cyber threats across the web, and predicts attacks before they fully execute.**
