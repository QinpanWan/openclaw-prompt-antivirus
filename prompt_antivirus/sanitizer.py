"""Sanitizer: neutralize (not just flag) injected instructions."""
from __future__ import annotations

import re
from typing import List

from .scanner import Scanner
from .signatures import SIGNATURES


class Sanitizer:
    def __init__(self, scanner: Scanner | None = None):
        self.scanner = scanner or Scanner()
        self._replaces: List[tuple] = [(p, r) for p, _, _, r in SIGNATURES]

    def neutralize(self, text: str) -> str:
        out = text
        for pat, repl in self._replaces:
            if repl == "":
                out = re.sub(
                    pat,
                    "[REDACTED:potentially-malicious-instruction]",
                    out,
                    flags=re.IGNORECASE,
                )
            else:
                out = re.sub(pat, repl, out, flags=re.IGNORECASE)
        return out
