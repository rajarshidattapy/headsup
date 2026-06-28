# HeadsUp PRD

### AI-Powered Threat Memory Engine for Personal Computers

---

# Vision

Modern antivirus tools detect threats in the moment and then forget them. They flood users with alerts but rarely explain why something happened, how it relates to previous incidents, or what could happen next.

**HeadsUp** is an AI-powered threat memory engine and terminal security analyst that continuously watches your computer, remembers every suspicious event, learns what is normal for your machine, ingests emerging cyber threats from the web, and predicts attacks before they fully execute.

Instead of acting like another antivirus, HeadsUp behaves like a security analyst that never forgets.

---

# Problem Statement

Current endpoint security tools suffer from several limitations:

* No long-term memory of threats.
* No correlation between seemingly unrelated events.
* No understanding of a user's normal machine behavior.
* No awareness of newly emerging malware campaigns.
* Poor explanations that are difficult for non-security users to understand.
* Heavy GUI applications that hide useful information.

Users need a system that can:

1. Remember
2. Learn
3. Correlate
4. Predict
5. Explain

---

# Product Philosophy

```text
Terminal-first.
Memory-driven.
AI-native.
Explainable.
```

HeadsUp is intentionally built as a **Python Rich TUI application**.

The terminal becomes a live security command center:

* Real-time monitoring
* AI explanations
* Threat timelines
* Interactive investigation
* Natural language security assistant

---

# Solution

HeadsUp continuously monitors:

* Running processes
* Network activity
* DNS requests
* Startup applications
* Browser downloads
* File changes
* Registry changes
* System logs

Everything observed is stored inside **HydraDB**, creating a persistent memory of your machine's behavior.

**Gemma 4 running on Cerebras** reasons over this memory to:

* Detect anomalies
* Explain suspicious behavior
* Correlate incidents
* Predict future actions
* Recommend remediation

**Anakin API** continuously ingests the latest malware campaigns and threat intelligence from the web and stores them inside the memory engine.

**SkillMake.xyz Security Skills** provide modular security capabilities such as IOC extraction, incident summarization, risk scoring, and threat classification.

---

# Product Architecture

```text
┌─────────────────────────────┐
│     Rich Terminal UI        │
│      (HeadsUp TUI)          │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│     Monitoring Engine       │
│ psutil + watchdog + logs    │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│          HydraDB            │
│      Threat Memory DB       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│      Gemma 4 (Cerebras)     │
│      Reasoning Engine       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Predictions & Explanations  │
└─────────────────────────────┘


Internet Threat Sources
        │
        ▼
     Anakin API
        │
        ▼
  Threat Intelligence
        │
        ▼
      HydraDB
```

---

# Core Components

# 1. Monitoring Engine

Collects:

* Process execution
* Network connections
* DNS requests
* File modifications
* Startup modifications
* Registry modifications
* Browser downloads

Polling Interval:

* Every 1 second.

---

# 2. HydraDB Integration

HydraDB acts as the long-term threat memory.

Responsibilities:

* Store system events
* Store incident history
* Store threat intelligence
* Store anomaly timelines
* Store AI predictions
* Store threat fingerprints

Example tables:

## process_events

```sql
timestamp
pid
process_name
parent_process
path
risk_score
```

## network_events

```sql
timestamp
process_name
remote_ip
remote_domain
country
risk_score
```

## threat_intelligence

```sql
threat_name
ioc_domains
ioc_hashes
behaviors
severity
source
published_at
```

## incidents

```sql
incident_id
summary
confidence
prediction
resolved
```

---

# 3. Cerebras + Gemma 4

Gemma acts as the reasoning engine.

Responsibilities:

### Explain

Why is this suspicious?

### Correlate

Have I seen this behavior before?

### Predict

What is likely to happen next?

### Summarize

What happened today?

### Recommend

* Delete
* Quarantine
* Ignore
* Monitor

---

# Prediction Example

Input:

```text
Downloaded executable
↓
Registry modification
↓
Foreign network connection
```

Gemma:

```text
This behavior resembles credential-stealing malware.

Likely next actions:

• Persistence
• Browser credential theft
• Data exfiltration
```

---

# 4. Anakin API Integration

Anakin continuously gathers:

* CISA advisories
* CVE feeds
* Microsoft Security Blog
* BleepingComputer
* The Hacker News
* Reddit cybersecurity communities

Pipeline:

```text
Threat Sources
↓
Anakin API
↓
Threat Summarization
↓
HydraDB
```

---

# 5. SkillMake.xyz Security Skills

Modular security capabilities:

* IOC extraction
* Threat classification
* Incident explanation
* Malware summarization
* Risk scoring
* Security report generation

---

# Rich TUI Experience

## Main Screen

```text
┌──────────────────────────────────────┐
│ HeadsUp Security Center              │
├──────────────────────────────────────┤
│ Active Connections : 36              │
│ Suspicious Processes : 2             │
│ Threat Score : MEDIUM                │
│ New Threat Intel : 4                 │
└──────────────────────────────────────┘
```

---

## Timeline View

```text
14:32 powershell.exe started
14:33 startup registry modified
14:35 outbound connection detected
14:36 AI prediction generated
```

---

## AI Copilot

```bash
headsup --copilot
```

Ask:

* Why is my laptop slow?
* Have I seen this IP before?
* What changed today?
* Is this process dangerous?
* Explain this malware campaign.

---

# User Flow

1. User installs HeadsUp.
2. Background monitoring starts.
3. HydraDB begins building machine memory.
4. Anakin imports new threats.
5. Gemma correlates machine events with historical incidents and global threats.
6. HeadsUp displays:

* Alert
* Explanation
* Prediction
* Recommended action

---

# Non-Goals

Removed from original ClawNet:

❌ Kubernetes defense

❌ Multi-agent orchestration

❌ Docker sandbox

❌ Blockchain audit

❌ Chaos engineering

❌ Human approval workflows

❌ Container security

---

# Tech Stack

Backend

* Python
* FastAPI

Monitoring

* psutil
* watchdog

AI

* Cerebras Inference
* Gemma 4

Memory

* HydraDB

Threat Intelligence

* Anakin API

Security Skills

* SkillMake.xyz

Terminal UI

* Rich

---

# One-Line Pitch

**HeadsUp is a terminal-native AI security analyst that remembers everything your computer does, learns from emerging cyber threats across the web, and predicts attacks before they fully execute.**
