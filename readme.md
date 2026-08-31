<div align="center">

# 🛡️ OpenClaw Prompt Antivirus

**Runtime defense against prompt injection & "mind-virus" attacks on OpenClaw agents.**

*Scan · Sanitize · Canary-trap · Human-in-the-loop — in one zero-config plugin.*

[![GitHub Stars](https://img.shields.io/github/stars/QinpanWan/openclaw-prompt-antivirus?style=social&label=Star)](https://github.com/QinpanWan/openclaw-prompt-antivirus)
[![MIT License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://github.com/QinpanWan/openclaw-prompt-antivirus/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ESM-blue.svg)](https://github.com/QinpanWan/openclaw-prompt-antivirus)
[![OpenClaw Plugin](https://img.shields.io/badge/OpenClaw-plugin-9146FF.svg)](#)
[![Zero-config](https://img.shields.io/badge/zero--config-yes-brightgreen.svg)](#)

**Give it a ⭐ if it helps you avoid a hijacked agent.**

</div>

---

## 🤔 The problem

> Prompt injection is the **core weakness of LLM agents**. A model can't always tell *instructions* from *data* — so a message hidden in retrieved web content, an email, or a document can quietly **hijack the agent**, leak data, or run destructive actions.

`prompt-antivirus` is the **"scanner + firewall + canary"** layer of a defense-in-depth approach. It sits inside the OpenClaw agent runtime and watches every surface where hostile text can enter or exit.

## ✨ What it does

```
untrusted input ──▶ Scanner ──▶ Sanitizer ──▶ safe context
        │
untrusted tool output ──▶ Scanner ──▶ Guard ──▶ human approval gate ──▶ agent
        │
system prompt (trusted) ──▶ CanaryTrap ──▶ model ──▶ check() ──▶ leak?
```

- **`before_tool_call`** — scans tool params. Blocks, rewrites (quarantine), or flags for approval *before* a tool runs.
- **`after_tool_call`** — scans tool results, where **indirect** injection hides.
- **`before_agent_run`** — scans the final prompt before the model reads it; can block a poisoned run.
- **`before_prompt_build`** — injects a per-session **canary token**. If the model ever repeats it → injection confirmed.
- **`message_sending`** — sanitizes or cancels outbound content (data-exfiltration defense).
- **Trusted tool policy** — host-gated tier requiring operator confirmation for inherently dangerous tools (`exec`, `send_email`, `delete_file`, `apply_patch`, …).
- **Diagnostic tools** — `_antivirus_scan` (scan anything) and `_antivirus_status` (live config + audit trail).

## 🚀 Quick start

```bash
npm install
npm run build        # tsc + openclaw plugins build
npm run validate

openclaw plugins install ./openclaw-prompt-antivirus
openclaw gateway restart
```

That's it. The plugin auto-loads and starts scanning.

## 🧠 How it works

`src/scanner.ts` is a pure, **dependency-free** detection engine running a signature database over text and nested tool params:

| Risk class | What it catches | Risk |
| --- | --- | --- |
| instruction override | attempts to discard earlier system rules | 🔴 high |
| role impersonation | tries to adopt a special or unrestricted persona | 🔴 high |
| prompt leak | tries to expose the hidden system prompt | 🔴 high |
| data exfiltration | tries to move confidential data to an external target | 🔴 high |
| destructive action | tries to wipe or overwrite files and data | 🔴 high |
| privilege escalation | tries to gain elevated access or permissions | 🔴 high |
| jailbreak | attempts to evade the model's safety guardrails | 🔴 high |
| indirect marker | `[system]`-style tags riding along in retrieved content | 🟠 medium |
| code execution | tries to spawn a subprocess or pull a remote artifact | 🟡 low |

`src/index.ts` wires the scanner into the runtime via `api.on(...)` hooks and a `registerTrustedToolPolicy(...)` gate.

## ⚙️ Configuration

```json5
{
  "plugins": {
    "entries": {
      "prompt-antivirus": {
        "mode": "quarantine",          // "block" | "quarantine" | "monitor"
        "blockDangerousTools": true,
        "requireApprovalOnHighRisk": true,
        "canaryEnabled": true,
        "auditLog": true
      }
    }
  }
}
```

> ⚠️ **Honest limitation:** pattern/signature scanning is "whack-a-mole." It reliably catches known phrasing, but reworded attacks can slip through. Pair this plugin with **least-privilege tooling** and **human approval for dangerous actions**. Real prevention is architectural — this is one strong layer, not a silver bullet.

## 🤝 Contributing

PRs welcome. Small, scoped, green.

- Open an issue for a bug, feature, or suggestion
- Help us extend the signature database in `src/scanner.ts`
- Improve docs or examples

**Like it? Star the repo** ⭐ — it means a lot for open-source projects.

## 📄 License

MIT — free to use, modify, and share.
