"""openclaw-prompt-antivirus: defense toolkit against prompt injection for LLM agents."""

from .scanner import Finding, ScanResult, Scanner
from .sanitizer import Sanitizer
from .canary import CanaryTrap
from .guard import Guard

__all__ = [
    "Finding",
    "ScanResult",
    "Scanner",
    "Sanitizer",
    "CanaryTrap",
    "Guard",
]

__version__ = "0.1.0"
