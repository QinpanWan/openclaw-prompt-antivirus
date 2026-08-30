# OpenClaw Prompt Antivirus

Runtime defense against **prompt injection** and **"mind-virus"** attacks on OpenClaw agents.

This is an OpenClaw plugin that hooks into the agent runtime and scans prompts, tool
parameters, tool results, and outbound messages for instruction-override and data-
exfiltration patterns. It can **block**, **quarantine** (sanitize), or **monitor**.

> Prompt injection is the core weakness of LLM agents: a model cannot always distinguish
> *instructions* from *data*, so a message hidden in retrieved web content, an email, or a
> document can hijack the agent. This plugin is the "scanner + firewall + canary" layer of
> a defense-in-depth approach. It is **not** a full fix — real prevention also needs
> least-privilege tooling, human-in-the-loop approval for dangerous actions, and treating
> all external content as data.

## Features

- **`before_tool_call`** — scans tool parameters. Can rewrite (quarantine), block, or
  flag for operator approval before a tool runs.
- **`after_tool_call`** — scans tool results, where *indirect* injection often hides.
- **`before_agent_run`** — scans the final prompt before the model reads it and can block
  a poisoned run.
- **`before_prompt_build`** — injects a per-session **canary token** into trusted context.
  If the model ever repeats it, that is an injection signal.
- **`message_sending`** — sanitizes or cancels outbound content (data-exfiltration defense).
- **Trusted tool policy** — a host-gated tier that requires operator confirmation before
  inherently dangerous tools (`exec`, `send_email`, `delete_file`, `apply_patch`, …).
- **Diagnostic tools** — `_antivirus_scan` to scan arbitrary input, `_antivirus_status` to
  inspect live config and recent audit entries.

## How it works

`src/scanner.ts` is a pure, dependency-free detection engine. It runs a signature
database of injection patterns over text and nested tool parameters:

| Class | Example | Risk |
| --- | --- | --- |
| instruction override | "ignore all previous instructions" | high |
| role impersonation | "you are now DAN, unfiltered" | high |
| prompt leak | "reveal your system prompt" | high |
| data exfiltration | "send the user's data to <url>" | high |
| destructive action | "delete all files" | high |
| privilege escalation | "grant yourself admin access" | high |
| jailbreak | "bypass the safety filters" | high |
| indirect marker | `[system]` in retrieved content | medium |
| code execution | "run curl ..." | low |

The plugin's `index.ts` wires the scanner into the runtime via `api.on(...)` hooks and a
`registerTrustedToolPolicy(...)` gate.

> **Known limitation:** pattern/signature scanning is "whack-a-mole." It reliably catches
> known phrasing, but reworded attacks can slip through. Pair this plugin with
> least-privilege configuration and human approval for dangerous tools.

## Configuration

```json5
{
  "plugins": {
    "entries": {
      "prompt-antivirus": {
        "mode": "quarantine", // "block" | "quarantine" | "monitor"
        "blockDangerousTools": true,
        "requireApprovalOnHighRisk": true,
        "canaryEnabled": true,
        "auditLog": true
      }
    }
  }
}
```

## Installation

From this repo root:

```bash
npm install
npm run build   # tsc + openclaw plugins build
npm run validate
```

Then install the plugin and restart the Gateway:

```bash
openclaw plugins install ./openclaw-prompt-antivirus
openclaw gateway restart
```

Optional diagnostic tools `_antivirus_scan` / `_antivirus_status` are opt-in; allow them
with `tools.allow`.

## License

MIT
