---
name: one-password
description: "Use when working with 1Password/op: service-account first, targeted secret read/store/inject, tmux from steipete/agent-scripts."
source: https://github.com/steipete/agent-scripts/tree/main/skills/one-password
generated: 2026-05-27T20:56:09.839Z
category: security
audience: engineers
---

## When to use

- Using the one-password skill's upstream workflow, guardrails, and local-tool assumptions.
- Auditing commands or operational steps before changing one password behavior.
- Needing a compact agent reference for 1Password/op: service-account first, targeted secret read/store/inject, tmux.

## Key concepts

### References

Official docs: https://developer.1password.com/docs/cli/get-started/ references/get-started.md (install + app integration + sign-in flow) references/cli-examples.md (real op examples, including safe item create/edit patterns).

### Workflow

1. Check OS + shell. 2. Verify CLI present inside tmux: op --version. 3. REQUIRED: create exactly one persistent named tmux session for the whole secret task. 4. Try scoped service-account access first when a matching token/workflow exists; no dialogs. 5. If service-account access is missing or lacks the exact item/field needed, stop and ask before desktop-app sign-in. 6. Desktop fallback: confirm app integration/unlock, then op signin once inside the same session. 7. Verify chosen access...

### Default Account

Default account for personal/work secrets is my.1password.com. Do not silently use my.1password.eu / Titan unless explicitly asked. Pass --account my.1password.com on every op command when storing or reading secrets. Do not rely on ambient account selection. op account list is metadata-only, but still must run inside tmux. Use it to confirm account names when routing is unclear. op signin --account my.1password.com can return status 0 with no useful output and still not make a later shell...

### Service account tokens

Prefer service-account tokens before any interactive 1Password flow. User dialogs are fallback only. 1Password service accounts are non-interactive tokens for a specific vault/scope, useful for automation without unlocking the desktop app. Peter's default service-account token is exported from ~/.profile as OPSERVICEACCOUNTTOKEN in a Codex-managed block. It is scoped to the restricted Molty vault. Older shells may expose the same value as MOLTYOPSERVICEACCOUNTTOKEN; treat that as a fallback...

### Required Persistent Tmux Session

The shell tool uses a fresh TTY per command. Run op inside one dedicated tmux session and keep using that same session until the whole secret task is done. Service-account commands still run here, but must not trigger app prompts. Example: Do not create a new tmux session after a quoting, item-name, or command failure. Send a corrected command into the existing session. Target the session as $SESSION: instead of assuming window 0; older sessions may have window indexes starting at 1.

### Service-Specific Workflows

Keep service-specific auth details in the owning skill. For npm registry/package work, use $npm; it documents the npmjs item, username/password/TOTP flow, and package reservation helper. This skill owns only the generic 1Password rules: tmux-only op, targeted reads, one persistent session, no broad enumeration, no secret output.

## API reference

```
npx skills add steipete/agent-scripts --skill one-password
```

Install the one-password skill from steipete/agent-scripts.

```
npx skills add steipete/agent-scripts --skill one-password
```

```
SOCKETDIR="${CLAWDBOTTMUXSOCKETDIR:-${TMPDIR:-/tmp}/clawdbot-tmux-sockets}".
```

Command or snippet documented by the upstream one-password skill.

```
SOCKET_DIR="${CLAWDBOT_TMUX_SOCKET_DIR:-${TMPDIR:-/tmp}/clawdbot-tmux-sockets}"
mkdir -p "$SOCKET_DIR"
SOCKET="$SOCKET_DIR/clawdbot-op.sock"
SESSION="op-work"

tmux -S "$SOCKET" has-session -t "$SESSION" 2>/dev/null ||
  tmux -S "$SOCKET" new -d -s "$SESSION" -n shell
tmux -S "$SOCKET" send-keys -t "$SESSION:" -- "op signin --account my.1password.com" Enter
tmux -S "$SOCKET" send-keys -t "$SESSION:" -- "op whoami" Enter
tmux -S "$SOCKET" capture-pane -p -J -t "$SESSION:" -S -200
```

```
SOCKETDIR="${CLAWDBOTTMUXSOCKETDIR:-${TMPDIR:-/tmp}/clawdbot-tmux-sockets}".
```

Command or snippet documented by the upstream one-password skill.

```
SOCKET_DIR="${CLAWDBOT_TMUX_SOCKET_DIR:-${TMPDIR:-/tmp}/clawdbot-tmux-sockets}"
SOCKET="$SOCKET_DIR/clawdbot-op.sock"
SESSION="op-work"
tmux -S "$SOCKET" has-session -t "$SESSION" 2>/dev/null ||
  tmux -S "$SOCKET" new -d -s "$SESSION" -n shell

cat > /tmp/op-store-secret.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
set +x
ACCOUNT="my.1password.com"
ITEM_TITLE="Service API Tokens"
FIELD_NAME="api_token"
EXPECTED_PREFIX=""
NOTES="Created via tmux-safe op workflow"
TOKEN="$(pbpaste)"
if [ -n "$EXPECTED_PREFIX" ]; then
  case "$TOKEN" in "$EXPECTED_PREFIX"*) ;; *) echo "clipboard value does not match expected prefix" >&2; exit 2;; esac
fi
op item create --account "$ACCOUNT" --category "API Credential" --title "$ITEM_TITLE" "$FIELD_NAME[password]=$TOKEN" "notesPlain=$NOTES" >/dev/null
op item get "$ITEM_TITLE" --account "$ACCOUNT" --fields "label=$FIELD_NAME" >/dev/null
echo "stored and verified secret field without printing it"
SCRIPT
chmod 700 /tmp/op-store-secret.sh
tmux -S "$SOCKET" send-keys -t "$SESSION" -- "bash /tmp/op-store-secret.sh; rm -f /tmp/op-store-secret.sh" C-m
```

```
cat > /tmp/op-read-field.sh <<'SCRIPT'.
```

Command or snippet documented by the upstream one-password skill.

```
cat > /tmp/op-read-field.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
set +x
ITEM_TITLE="Known API Credential Item"
FIELD_LABEL="api_token"
VAULT="Molty"
value="$(
  OP_SERVICE_ACCOUNT_TOKEN="$OP_SERVICE_ACCOUNT_TOKEN" \
    op item get "$ITEM_TITLE" --vault "$VAULT" --format json |
    FIELD_LABEL="$FIELD_LABEL" node -e 'let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{const item=JSON.parse(s); const f=(item.fields||[]).find(x=>x.label===process.env.FIELD_LABEL); if(!f?.value) process.exit(2); process.stdout.write(f.value);})'
)"
echo "field_len:${#value}"
case "$value" in sk-*) echo "field_prefix:sk" ;; *) echo "field_prefix:other" ;; esac
echo "field_has_newline:$(printf %s "$value" | wc -l | tr -d ' ')"
SCRIPT
chmod 700 /tmp/op-read-field.sh
tmux -S "$SOCKET" send-keys -t "$SESSION:" -- "bash /tmp/op-read-field.sh; rm -f /tmp/op-read-field.sh" C-m
```

```
cat > /tmp/op-find-item.sh <<'SCRIPT'.
```

Command or snippet documented by the upstream one-password skill.

```
cat > /tmp/op-find-item.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
set +x
VAULT="Molty"
QUERY="minimax"
OP_SERVICE_ACCOUNT_TOKEN="$OP_SERVICE_ACCOUNT_TOKEN" \
  op item list --vault "$VAULT" --format json |
  QUERY="$QUERY" VAULT="$VAULT" node -e '
let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{
  const q=process.env.QUERY.toLowerCase();
  const vault=process.env.VAULT;
  const items=JSON.parse(s).filter(x => [
    x.title, x.id, x.category, ...(x.tags || [])
  ].filter(Boolean).join("\n").toLowerCase().includes(q));
  for (const item of items.slice(0, 10)) {
    console.log(`title:${item.title} id:${item.id} category:${item.category || ""} vault:${vault}`);
  }
  console.log(`matches:${items.length}`);
})'
SCRIPT
chmod 700 /tmp/op-find-item.sh
tmux -S "$SOCKET" send-keys -t "$SESSION:" -- "bash /tmp/op-find-item.sh; rm -f /tmp/op-find-item.sh" C-m
```

```
cat > /tmp/op-debug.sh <<'SCRIPT'.
```

Command or snippet documented by the upstream one-password skill.

```
cat > /tmp/op-debug.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
set +x
SIGNIN_OUTPUT="$(op signin --account my.1password.com 2>&1 || true)"
echo "signin output bytes: ${#SIGNIN_OUTPUT}"
op account list 2>&1 | sed -E "s/(xox[baprs]-)[A-Za-z0-9-]+/\\1REDACTED/g; s/(xapp-)[A-Za-z0-9-]+/\\1REDACTED/g"
SCRIPT
chmod 700 /tmp/op-debug.sh
tmux -S "$SOCKET" send-keys -t "$SESSION" -- "bash /tmp/op-debug.sh; rm -f /tmp/op-debug.sh" C-m
```

## Gotchas

- Do not silently use my.1password.eu / Titan unless explicitly asked.
- Prefer service-account tokens before any interactive 1Password flow. User dialogs are fallback only.
- Do not enumerate vaults/items with service accounts by default. If the user explicitly asks to search, gives a screenshot/listing, or gives only a fuzzy item name, use the safe metadata search below before asking.
- Do not create a new tmux session after a quoting, item-name, or command failure. Send a corrected command into the existing session.
- Never paste secrets into logs, chat, or code.
- Prefer op run / op inject over writing secrets to disk.
- Do not run op outside tmux; stop and ask if tmux is unavailable.

---
Generated by SkillMake from https://github.com/steipete/agent-scripts/tree/main/skills/one-password on 2026-05-27T20:56:09.839Z.
Verify against source before relying on details.