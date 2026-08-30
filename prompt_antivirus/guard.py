"""Guard: intercept tool calls; enforce least-privilege + human approval.

The "real antivirus" for agent behavior. Scanners reduce the attack surface;
the most effective control is putting a human in the loop for privileged actions
and treating every tool result as untrusted data.
"""
from __future__ import annotations

import json
from typing import Callable, Dict

from .scanner import Scanner, ScanResult


class Guard:
    BLOCKED_KEYWORDS = (
        "send_email",
        "publish",
        "delete_file",
        "shell",
        "exec",
        "transfer",
    )

    def __init__(self, canary, require_approval: Callable[[str], bool]):
        self.canary = canary
        # human-in-the-loop callback; returns True to allow, False to deny
        self.require_approval = require_approval

    def allow_tool(self, tool_name: str, args: Dict) -> bool:
        name = tool_name.lower()
        # Hard gate: never let injected instructions reach dangerous tools silently.
        if any(k in name for k in self.BLOCKED_KEYWORDS):
            return self.require_approval(
                f"TOOL {tool_name} (args={json.dumps(args)[:200]})"
            )
        return True

    def check_tool_output(self, output_text: str) -> ScanResult:
        # Tool results are untrusted data. Scan before it reaches model context.
        return Scanner().scan(output_text)
