"""Signature database.

Each entry is a tuple:
    (regex_pattern, severity, category, neutralized_replacement)

Severity levels:
    0 = clean
    1 = LOW
    2 = MEDIUM
    3 = HIGH

If `neutralized_replacement` is empty, the matched span is replaced with a
generic placeholder; otherwise it is replaced with the given text.
"""
from __future__ import annotations

from typing import List, Tuple

Signature = Tuple[str, int, str, str]

SIGNATURES: List[Signature] = [
    # --- instruction override ---
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", 3, "instruction_override", ""),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", 3, "instruction_override", ""),
    (r"forget\s+(everything|all|your)\s+(instructions|rules|training)", 3, "instruction_override", ""),

    # --- role impersonation ---
    (r"you\s+are\s+now\s+(?!.*\b(an? (AI|assistant))).*", 3, "role_impersonation", "You are an AI assistant."),
    (r"act\s+as\s+(if\s+you\s+were|an?\s+)?(hacker|jailbreak|developer|admin|god|unfiltered|uncensored|no.?filter)", 3, "role_impersonation", ""),

    # --- prompt leak ---
    (r"reveal\s+(your\s+)?(system|hidden|secret)\s+(prompt|instructions|rules)", 3, "prompt_leak", ""),
    (r"print\s+(your\s+)?(system|developer|hidden)\s+prompt", 3, "prompt_leak", ""),
    (r"<\|?system\|?>|\[system\]|system:", 2, "system_marker", ""),

    # --- data exfiltration ---
    (r"(send|post|email|publish|exfiltrate|upload|transmit)\s+(this|the|all|any)\s+(data|info|contents|password|token|key|confidential)", 3, "data_exfiltration", ""),

    # --- destructive action ---
    (r"(delete|remove|erase|overwrite|destroy)\s+(all|everything|the)\s+(files|emails|messages|data)", 3, "destructive_action", ""),

    # --- privilege escalation ---
    (r"(grant|give)\s+(yourself|me)\s+(admin|root|elevated|unrestricted|more)\s+(access|permissions|privileges)", 3, "privilege_escalation", ""),

    # --- jailbreak ---
    (r"bypass\s+(the\s+)?(safety|security|policy|filter|guardrails)", 3, "jailbreak", ""),
    (r"you\s+have\s+no\s+(restrictions|limits|rules|constraints)", 2, "jailbreak", ""),

    # --- concealment ---
    (r"(do|just|please)\s+((not |don'?t )?(mention|tell|reveal|say)\s+(this|that|anything|it))", 2, "concealment", ""),

    # --- policy override ---
    (r"(ignore|don'?t follow|skip)\s+(the\s+)?(above|security|safety|policy)", 3, "policy_override", ""),

    # --- urgent command (urgency + action combo) ---
    (r"\b(urgent|important|critical|act now|immediately)\b.{0,60}\b(run|execute|call|send|install|download)\b", 2, "urgent_command", ""),

    # --- code execution ---
    (r"(install|run|execute|invoke|curl|wget)\s+[^\s]{2,}", 1, "code_execution", ""),
]
