"""HeadsUp AI analyst — Gemma 4 reasoning on Cerebras inference.

The reasoning engine. Given the machine's memory (HydraDB) and live events it can
**explain**, **correlate**, **predict**, **summarize** and **recommend**.

Provider selection (first available wins):
1. **Cerebras** — ``CEREBRAS_API_KEY`` (Gemma model, OpenAI-compatible endpoint)
2. **OpenAI**   — ``OPENAI_API_KEY`` (fallback, gpt-4o-mini)
3. **Offline**  — deterministic heuristics so the TUI stays useful with no keys.
"""
from __future__ import annotations

import json
import os
import queue
import threading
from dataclasses import dataclass
from typing import Optional

try:
    import openai as _openai  # OpenAI SDK is also used for the Cerebras endpoint
    _HAS_OPENAI = True
except ImportError:  # pragma: no cover
    _HAS_OPENAI = False

_CEREBRAS_BASE = "https://api.cerebras.ai/v1"

_SYSTEM_ANALYZE = """\
You are HeadsUp, an embedded AI security analyst running in a terminal threat-memory engine.
Analyze the observation for threats. Be concise.
Respond ONLY with valid JSON — no prose, no markdown fences.

Format:
{"level": "SAFE"|"SUSPICIOUS"|"CRITICAL", "reason": "<one sentence, max 16 words>", \
"action": "ignore"|"monitor"|"quarantine"|"delete"|"block"|"kill_process"|"block_ip"|"kill_and_block"}

Focus on: processes from temp/download paths, C2 beaconing, connections to high-risk foreign
ASNs, high-risk ports (Telnet/RDP/raw DB), startup/registry persistence, unsigned binaries."""

_SYSTEM_COPILOT = """\
You are HeadsUp, a terminal-native AI security analyst with long-term memory of this machine.
Answer the user's security question concisely and technically, grounded in the provided context
(live machine state + memory + threat intelligence). Plain English. No JSON."""

_SYSTEM_PREDICT = """\
You are HeadsUp's predictive threat engine powered by Gemma. Given a chain of recent suspicious
behaviors, predict the malware family it resembles and the likely NEXT actions. Be specific and
brief. Format:
<one-line assessment>
Likely next actions:
• ...
• ...
• ..."""


@dataclass
class Analysis:
    level: str = "?"
    reason: str = ""
    action: str = "ignore"
    process: str = ""
    remote: str = ""
    pid: Optional[int] = None
    pending: bool = False


class HeadsUpAnalyst:
    """Gemma-on-Cerebras reasoning engine with graceful degradation."""

    def __init__(self, db=None) -> None:
        self.db = db
        self._cache: dict[tuple, Analysis] = {}
        self._lock = threading.Lock()
        self._q: queue.Queue = queue.Queue(maxsize=40)

        self.provider = "offline"
        self.model = ""
        self._client = None

        cerebras_key = os.environ.get("CEREBRAS_API_KEY", "")
        openai_key = os.environ.get("OPENAI_API_KEY", "")

        if _HAS_OPENAI and cerebras_key:
            try:
                self._client = _openai.OpenAI(api_key=cerebras_key, base_url=_CEREBRAS_BASE)
                self.model = os.environ.get("GEMMA_MODEL", "gemma-3-12b-it")
                self.provider = "cerebras"
            except Exception:
                self._client = None
        if self._client is None and _HAS_OPENAI and openai_key:
            try:
                self._client = _openai.OpenAI(api_key=openai_key)
                self.model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
                self.provider = "openai"
            except Exception:
                self._client = None

        if self._client is not None:
            threading.Thread(target=self._worker, daemon=True, name="hu-analyst").start()

    # ── status ────────────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        return self._client is not None

    @property
    def label(self) -> str:
        if self.provider == "cerebras":
            return f"Gemma · Cerebras ({self.model})"
        if self.provider == "openai":
            return f"OpenAI ({self.model})"
        return "offline heuristics"

    # ── raw chat ──────────────────────────────────────────────────────────────

    def _chat(self, system: str, user: str, max_tokens: int = 400) -> str:
        if not self.available:
            return ""
        # Reasoning models (e.g. gpt-oss, GLM, deepseek) spend completion tokens
        # "thinking" before any visible content, so a small budget yields an empty
        # answer. Enforce a floor so short prompts still produce real output.
        mt = max(int(max_tokens), 768)
        try:
            r = self._client.chat.completions.create(
                model=self.model,
                max_tokens=mt,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return (r.choices[0].message.content or "").strip()
        except Exception as exc:
            return f"[AI error: {str(exc)[:80]}]"

    # ── high-level reasoning ──────────────────────────────────────────────────

    def copilot(self, question: str, context: str) -> str:
        if self.available:
            out = self._chat(_SYSTEM_COPILOT, f"Context:\n{context}\n\nQuestion: {question}", 600)
            if out and not out.startswith("[AI error"):
                return out
        return self._offline_copilot(question, context)

    def explain(self, subject: str, context: str = "") -> str:
        if self.available:
            out = self._chat(
                _SYSTEM_COPILOT,
                f"Context:\n{context}\n\nExplain why this is or isn't suspicious: {subject}", 400)
            if out and not out.startswith("[AI error"):
                return out
        return f"{subject}: insufficient AI backend — review path, signer, and remote IP manually."

    def predict(self, behavior_chain: list[str]) -> str:
        chain = "\n↓\n".join(behavior_chain)
        if self.available:
            out = self._chat(_SYSTEM_PREDICT, f"Recent behavior chain:\n{chain}", 300)
            if out and not out.startswith("[AI error"):
                return out
        return self._offline_predict(behavior_chain)

    def summarize(self, events: list[dict]) -> str:
        if not events:
            return "No notable activity recorded yet."
        lines = [f"- [{e.get('kind','?')}] {e.get('summary','')}" for e in events[:40]]
        body = "\n".join(lines)
        if self.available:
            out = self._chat(
                _SYSTEM_COPILOT,
                f"Summarize today's machine activity for the user and flag anything risky:\n{body}",
                500)
            if out and not out.startswith("[AI error"):
                return out
        return self._offline_summary(events)

    def recommend(self, level: str, suspicious: bool) -> str:
        if level == "CRITICAL":
            return "block" if not suspicious else "quarantine"
        if level == "SUSPICIOUS":
            return "monitor"
        return "ignore"

    # ── live connection scoring (async cache, like the old OpenClaw) ───────────

    def request(self, key: tuple, info: dict) -> None:
        with self._lock:
            if key in self._cache:
                return
            self._cache[key] = Analysis(
                pending=True, reason="Analyzing…",
                process=info.get("process", "?"),
                remote=info.get("remote", ""), pid=info.get("pid"),
            )
        if not self.available:
            # produce an immediate offline verdict instead of leaving it pending
            with self._lock:
                self._cache[key] = self._offline_verdict(info)
            return
        try:
            self._q.put_nowait((key, info))
        except queue.Full:
            pass

    def get(self, key: tuple) -> Optional[Analysis]:
        with self._lock:
            return self._cache.get(key)

    def all_analyses(self) -> list[Analysis]:
        with self._lock:
            return list(self._cache.values())

    def evict(self, active: set) -> None:
        with self._lock:
            for k in [k for k in self._cache if k not in active]:
                del self._cache[k]

    # ── worker ────────────────────────────────────────────────────────────────

    def _worker(self) -> None:
        while True:
            key, info = self._q.get()
            try:
                result = self._call(info)
            except Exception as exc:
                result = Analysis(level="?", reason=str(exc)[:60], action="monitor",
                                  process=info.get("process", "?"),
                                  remote=info.get("remote", ""), pid=info.get("pid"))
            with self._lock:
                self._cache[key] = result

    def _call(self, info: dict) -> Analysis:
        mem_ctx = ""
        if self.db is not None:
            try:
                mem_ctx = self.db.memory_context(
                    ip=info.get("remote", ""), process=info.get("process", ""))
            except Exception:
                mem_ctx = ""
        prompt = (
            f"Process: {info.get('process')} | Path: {info.get('exe', 'unknown')}\n"
            f"Proto: {info.get('proto')} | Status: {info.get('status')}\n"
            f"Local: {info.get('local')} | Remote: {info.get('remote')}:{info.get('rport', '?')}\n"
            f"Country: {info.get('country', '?')} | Suspicious path: {info.get('suspicious')}\n"
            f"Heuristic risk: {info.get('risk')}"
        )
        if mem_ctx:
            prompt = mem_ctx + "\n" + prompt
        text = self._chat(_SYSTEM_ANALYZE, prompt, 150)
        s, e = text.find("{"), text.rfind("}") + 1
        if s >= 0 and e > s:
            try:
                d = json.loads(text[s:e])
                return Analysis(
                    level=d.get("level", "?"), reason=d.get("reason", ""),
                    action=d.get("action", "monitor"),
                    process=info.get("process", "?"),
                    remote=info.get("remote", ""), pid=info.get("pid"),
                )
            except Exception:
                pass
        return self._offline_verdict(info)

    # ════════════════════════════════════════════════════════════════════════
    #  Offline heuristics (no API key needed)
    # ════════════════════════════════════════════════════════════════════════

    def _offline_verdict(self, info: dict) -> Analysis:
        risk = info.get("risk", "")
        suspicious = info.get("suspicious")
        if suspicious:
            level, action = "CRITICAL", "quarantine"
            reason = "Process running from a suspicious path with external connection"
        elif "HIGH" in risk:
            level, action, reason = "SUSPICIOUS", "monitor", "High-risk connection (heuristic)"
        else:
            level, action, reason = "SAFE", "ignore", "No heuristic indicators"
        return Analysis(level=level, reason=reason, action=action,
                        process=info.get("process", "?"),
                        remote=info.get("remote", ""), pid=info.get("pid"))

    def _offline_predict(self, chain: list[str]) -> str:
        joined = " ".join(chain).lower()
        has_dl = "download" in joined or "executable" in joined
        has_persist = "registry" in joined or "startup" in joined
        has_net = "→" in joined or "network" in joined or "connection" in joined
        if has_dl and has_persist and has_net:
            return ("This behavior resembles credential-stealing malware.\n"
                    "Likely next actions:\n"
                    "• Persistence via registry/startup\n"
                    "• Browser credential theft\n"
                    "• Data exfiltration to a foreign host")
        if has_persist and has_net:
            return ("This resembles a persistence + beaconing pattern.\n"
                    "Likely next actions:\n"
                    "• Scheduled re-execution on boot\n"
                    "• Command-and-control polling")
        if has_dl and has_net:
            return ("Freshly downloaded binary opening network connections.\n"
                    "Likely next actions:\n"
                    "• Second-stage payload download\n"
                    "• Outbound data staging")
        return ("Not enough correlated signal for a confident prediction yet — "
                "HeadsUp will keep watching this chain.")

    def _offline_summary(self, events: list[dict]) -> str:
        by_kind: dict[str, int] = {}
        risky = []
        for e in events:
            by_kind[e.get("kind", "?")] = by_kind.get(e.get("kind", "?"), 0) + 1
            if (e.get("risk_score", 0) or 0) >= 3:
                risky.append(e.get("summary", ""))
        parts = [f"{n} {k} event(s)" for k, n in sorted(by_kind.items(), key=lambda x: -x[1])]
        out = "Today: " + ", ".join(parts) + "."
        if risky:
            out += "\nNotable: " + "; ".join(risky[:5])
        else:
            out += "\nNo high-risk activity detected."
        return out

    def _offline_copilot(self, question: str, context: str) -> str:
        q = question.lower()
        if any(k in q for k in ("today", "changed", "happen")):
            return ("AI backend offline. From memory/context:\n" + context[-1200:]
                    if context else "AI backend offline and no context available.")
        if "predict" in q or "next" in q:
            return self._offline_predict([context])
        return ("HeadsUp AI is offline (set CEREBRAS_API_KEY for Gemma reasoning). "
                "Here is the current context you can review:\n" + context[-1000:])


# Backwards-compatibility alias (old name used elsewhere during transition)
OpenClaw = HeadsUpAnalyst


if __name__ == "__main__":
    a = HeadsUpAnalyst()
    print("provider:", a.label, "| available:", a.available)
    print(a.predict(["Downloaded executable", "Registry modification",
                     "Foreign network connection"]))
