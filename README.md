# HeadsUp
<img width="1378" height="168" alt="image" src="https://github.com/user-attachments/assets/f11adf85-3a4b-474c-9ed7-bd22e0399164" />


<p align="center">
  <h3 align="center">AI-Powered Threat Memory Engine for Your Computer</h3>
  <p align="center">
    Learns your machine, remembers every anomaly, and predicts threats before they become attacks.
  </p>
</p>

---

## What is HeadsUp?

Traditional antivirus tools detect threats and immediately forget them.

**HeadsUp** is different.

HeadsUp continuously monitors your computer's apps, files, processes, and network activity, builds a long-term memory of everything suspicious, learns what is normal for your machine, and warns you when small anomalies start looking like real attacks.

It acts like a personal security analyst that never sleeps and never forgets.

---

## Quickstart

```bash
pip install -e .            # or: pip install psutil rich watchdog openai requests send2trash
cp .env.example .env        # optional — add CEREBRAS_API_KEY / ANAKIN_API_KEY if you have them

headsup                     # live threat-memory dashboard (Rich TUI)
headsup --copilot           # natural-language AI security copilot
headsup --resolve           # dashboard with reverse-DNS on remote IPs
headsup timeline 20         # print the recent memory timeline and exit
headsup intel               # ingest + list the latest threat intelligence
```

HeadsUp runs **fully offline** with sensible fallbacks — no API keys required:

| Capability | With keys | Without keys |
|---|---|---|
| Threat memory (HydraDB) | Hydra/Postgres via `HYDRA_URL` | local SQLite at `~/.headsup/headsup.db` |
| AI reasoning | Gemma 4 on Cerebras (`CEREBRAS_API_KEY`) → OpenAI fallback | deterministic heuristics |
| Threat intel (Anakin) | live web feeds (`ANAKIN_API_KEY`) | bundled sample campaign feed |

> Run the terminal **as Administrator** for full process/connection visibility and
> remediation actions (kill / block / quarantine).

---

## Why HeadsUp?

Most security tools answer:

> "What just happened?"

HeadsUp answers:

* What happened?
* Why did it happen?
* Have I seen this before?
* Is this similar to a new malware campaign?
* What is likely to happen next?

---

# Architecture

```text
                ┌──────────────────┐
                │   Monitoring     │
                │      Agent       │
                └────────┬─────────┘
                         │
                         ▼
              ┌──────────────────┐
              │     HydraDB      │
              │ Threat Memory DB │
              └────────┬─────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Gemma 4 on Cerebras  │
            │  Reasoning Engine    │
            └────────┬─────────────┘
                     │
                     ▼
              ┌─────────────────┐
              │ Predictions and │
              │ Explanations    │
              └─────────────────┘


Internet Threat Intelligence
        │
        ▼
     Anakin API
        │
        ▼
     HydraDB
```

---

# Features

## Live System Monitoring

HeadsUp continuously watches:

* Running processes
* Network connections
* Browser downloads
* Startup applications
* File changes
* Registry changes
* System logs

---

## Threat Memory Engine (HydraDB)

HydraDB acts as the long-term memory layer.

It stores:

* Historical incidents
* Process activity
* Network behavior
* Threat signatures
* AI predictions
* Emerging malware intelligence

Nothing is forgotten.

The system can answer:

> "Have I seen this behavior before?"

> "Did this executable appear before another attack?"

> "Which applications repeatedly cause issues?"

---

## AI Security Analyst (Gemma 4 + Cerebras)

Powered by **Gemma 4 running on Cerebras inference**.

Gemma provides:

### Explanations

> Why is this process dangerous?

### Correlation

> Is this connected to previous incidents?

### Prediction

> What is likely to happen next?

### Recommendations

* Delete
* Monitor
* Ignore
* Block

---

## Emerging Threat Intelligence (Anakin API)

HeadsUp continuously ingests cybersecurity information from the web.

Sources include:

* CISA advisories
* CVE feeds
* Microsoft Security Blog
* BleepingComputer
* The Hacker News
* Reddit cybersecurity communities

Threat information is summarized and stored inside HydraDB.

When local activity resembles an emerging malware campaign, HeadsUp alerts the user.

Example:

> This behavior resembles the recently reported Lumma Stealer campaign with 82% similarity.

---

## Security Skills (SkillMake.xyz)

HeadsUp uses **SkillMake.xyz security skills** to extend its capabilities.

Skills can include:

* IOC extraction
* Malware behavior summarization
* Threat classification
* Incident explanation
* Risk scoring
* Security report generation

This allows HeadsUp to become more capable over time without changing the core application.

---

# Example Workflow

```text
Downloaded executable
          ↓
New registry entry
          ↓
Foreign network connection
          ↓
HydraDB finds similar historical patterns
          ↓
Anakin finds matching malware campaign
          ↓
Gemma reasons over the evidence
          ↓
HeadsUp predicts:
Credential theft likely.
Persistence likely.
Data exfiltration possible.
```

---

# Tech Stack

## Monitoring

* Python
* psutil
* watchdog

## AI

* Gemma 4
* Cerebras Inference API

## Memory

* HydraDB

## Threat Intelligence

* Anakin API

## Skills

* SkillMake.xyz Security Skills

## Backend

* FastAPI

## Frontend

* React
* TailwindCSS

---

# Vision

HeadsUp is building a new category of cybersecurity software:

> A memory-powered security analyst for personal computers.

Instead of detecting malware after the damage is done, HeadsUp remembers, learns, and predicts.

---

# One-Line Pitch

**HeadsUp is an AI-powered threat memory engine that combines long-term machine memory, real-time threat intelligence, and reasoning AI to detect, explain, and predict cyber threats before they fully execute.**
