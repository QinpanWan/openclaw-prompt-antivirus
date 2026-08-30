"""Scanner: signal/classification-based detection of injection patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from .signatures import SIGNATURES


@dataclass
class Finding:
    start: int
    end: int
    severity: int
    category: str
    matched_text: str


@dataclass
class ScanResult:
    text: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def risk(self) -> int:
        return max([f.severity for f in self.findings] or [0])

    @property
    def risk_label(self) -> str:
        return {0: "CLEAN", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[self.risk]


class Scanner:
    """Runs the signature rules over untrusted text and collects findings."""

    def scan(self, text: str) -> ScanResult:
        res = ScanResult(text=text)
        for pat, sev, cat, _ in SIGNATURES:
            for m in re.finditer(pat, text, re.IGNORECASE):
                res.findings.append(Finding(m.start(), m.end(), sev, cat, m.group(0)))
        # Overlapping findings are intentionally returned as-is; dedup is out of scope.
        return res
