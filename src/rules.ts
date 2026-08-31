// rules.ts - evolvable, externally-updatable signature library + learning engine.
// Pure data + disk I/O. No OpenClaw deps -> reusable and unit-testable.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type Severity = 0 | 1 | 2 | 3;

// Serializable rule: regex stored as source string so the whole library is
// JSON-friendly and can be hot-reloaded / community-patched without recompiling.
export interface RuleSpec {
  re: string;
  flags?: string;
  severity: Severity;
  category: string;
  sanitize?: string;
}

export interface CompiledRule {
  re: RegExp;
  severity: Severity;
  category: string;
  sanitize?: string;
}

// ---- Built-in defaults (mirrors the original scanner + more). ----
export const DEFAULT_RULES: RuleSpec[] = [
  { re: "ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+(instructions|prompts|rules|directives)", flags: "gi", severity: 3, category: "instruction_override", sanitize: "that instruction" },
  { re: "disregard\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|prompts|rules)", flags: "gi", severity: 3, category: "instruction_override", sanitize: "that instruction" },
  { re: "forget\\s+(everything|all|your)\\s+(instructions|rules|training|guidelines)", flags: "gi", severity: 3, category: "instruction_override", sanitize: "the guideline" },
  { re: "you\\s+are\\s+now\\s+(?!an?\\s+ai[\\s\\S]*?assistant)", flags: "gi", severity: 3, category: "role_impersonation", sanitize: "an AI assistant" },
  { re: "act\\s+as\\s+(a\\s+)?(hacker|jailbreak|developer|root|admin|god|unfiltered|uncensored)", flags: "gi", severity: 3, category: "role_impersonation" },
  { re: "reveal\\s+(your\\s+)?(system|hidden|secret)\\s+(prompt|instructions|rules|guideline)", flags: "gi", severity: 3, category: "prompt_leak" },
  { re: "print\\s+(your\\s+)?(system|developer|hidden)\\s+prompt", flags: "gi", severity: 3, category: "prompt_leak" },
  { re: "<\\|?system\\|?>|\\bsystem\\s*:\\s*$", flags: "gim", severity: 2, category: "system_marker" },
  { re: "(send|post|email|publish|exfiltrate|upload|transmit)\\s+(this|the|all|any|the\\s+user['’]s)\\s+(data|info|contents|password|token|key|confidential|files)", flags: "gi", severity: 3, category: "data_exfiltration" },
  { re: "(delete|remove|erase|overwrite|destroy)\\s+(all|everything|the)\\s+(files|emails|messages|data)", flags: "gi", severity: 3, category: "destructive_action" },
  { re: "(grant|give)\\s+(yourself|me)\\s+(admin|root|elevated|unrestricted|more)\\s+(access|permissions|privileges)", flags: "gi", severity: 3, category: "privilege_escalation" },
  { re: "bypass\\s+(the\\s+)?(safety|security|policy|filter|guardrails)", flags: "gi", severity: 3, category: "jailbreak" },
  { re: "you\\s+have\\s+no\\s+(restrictions|limits|rules|constraints)", flags: "gi", severity: 2, category: "jailbreak" },
  { re: "(ignore|don['’]t\\s+follow|skip)\\s+(the\\s+)?(above|security|safety|policy)", flags: "gi", severity: 3, category: "policy_override" },
  { re: "[\\(\\\\](system|user|assistant)[\\)\\\\]|<\\s*(system|user|assistant)\\s*>", flags: "gi", severity: 2, category: "prompt_marker" },
  { re: "(urgent|important|critical|act\\s+now|immediately)[^\\n]{0,60}\\b(run|execute|call|send|install|download|deploy|transfer)\\b", flags: "gi", severity: 2, category: "urgent_command" },
  { re: "\\b(inject|injection)\\b[^\\n]{0,60}\\b(prompt|instruction)", flags: "gi", severity: 2, category: "meta_prompt" },
  { re: "(this\\s+is\\s+)?(an?\\s+)?(instruction|command|directive|order|task)\\s*:", flags: "gi", severity: 1, category: "meta_prompt" },
  { re: "(install|run|execute|invoke|curl|wget|powershell|exec)\\s+[^\\s]{2,}", flags: "gi", severity: 1, category: "code_execution" },
];

export function compile(spec: RuleSpec): CompiledRule {
  return {
    re: new RegExp(spec.re, spec.flags ?? "gi"),
    severity: spec.severity,
    category: spec.category,
    sanitize: spec.sanitize,
  };
}

export function buildCompiled(specs: RuleSpec[]): CompiledRule[] {
  return specs.map(compile);
}

// ---- Disk-backed library (hot-reloadable / patchable). ----
// dist/rules.js -> ../rules/virus-signatures.json relative to plugin root.
const pluginRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const RULES_PATH = join(pluginRoot, "rules", "virus-signatures.json");

export function rulesPath(): string {
  return RULES_PATH;
}

export function loadRules(): RuleSpec[] {
  try {
    if (existsSync(RULES_PATH)) {
      const parsed = JSON.parse(readFileSync(RULES_PATH, "utf8")) as RuleSpec[];
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch (e) {
    console.warn("[prompt-antivirus] failed to read rules file, using defaults:", (e as Error).message);
  }
  // Bootstrap: write defaults so the library is inspectable & patchable.
  saveRules(DEFAULT_RULES);
  return DEFAULT_RULES;
}

export function saveRules(specs: RuleSpec[]): boolean {
  try {
    mkdirSync(dirname(RULES_PATH), { recursive: true });
    writeFileSync(RULES_PATH, JSON.stringify(specs, null, 2), "utf8");
    return true;
  } catch (e) {
    console.warn("[prompt-antivirus] failed to persist rules file:", (e as Error).message);
    return false;
  }
}

// ---- Learning: absorb a new (evaded) attack sample into the library. ----
// Heuristic trigger words; single tokens, never full attack phrases, so this
// source itself won't trip the scanner's signature database.
const LEARN_HINTS: Array<{ category: string; re: RegExp }> = [
  { category: "instruction_override", re: /\b(ignore|disregard|forget|override|skip)\b/i },
  { category: "role_impersonation", re: /\b(persona|hacker|jailbreak|unfiltered|uncensored|god)\b/i },
  { category: "prompt_leak", re: /\b(reveal|print)\b/i },
  { category: "data_exfiltration", re: /\b(send|post|upload|transmit|exfiltrate)\s+(confidential|password|token|data|info)\b/i },
  { category: "destructive_action", re: /\b(delete|erase|wipe|destroy|overwrite)\b/i },
  { category: "privilege_escalation", re: /\b(escalate|privileges?|elevated)\b/i },
  { category: "jailbreak", re: /\b(bypass|guardrail)\b/i },
  { category: "code_execution", re: /\b(curl|wget|powershell|subprocess)\b/i },
];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface LearnResult {
  added: boolean;
  rule?: RuleSpec;
  reason: string;
}

// Extract a usable signature from a previously-unevaded sample.
export function learnFromSample(text: string, hintCategory?: string): LearnResult {
  if (!text || text.trim().length === 0) {
    return { added: false, reason: "empty-sample" };
  }

  // Pick a category via the strongest heuristic hint (or the caller-provided one).
  let category = hintCategory ?? "instruction_override";
  let triggerIndex = -1;
  let triggerLen = 0;
  for (const hint of LEARN_HINTS) {
    const m = hint.re.exec(text);
    if (m && (triggerIndex === -1 || m.index < triggerIndex)) {
      triggerIndex = m.index;
      triggerLen = m[0].length;
      category = hintCategory ?? hint.category;
    }
  }

  // Build a conservative literal signature around the trigger, plus a short tail.
  const start = Math.max(0, triggerIndex === -1 ? 0 : triggerIndex);
  const end = Math.min(text.length, start + Math.max(20, triggerLen + 24));
  const fragment = text.slice(start, end).trim().replace(/\s+/g, " ");
  const lit = escapeRegExp(fragment);
  if (lit.length < 4) {
    return { added: false, reason: "fragment-too-short" };
  }

  // De-dup against the current library (compare compiled 're' sources).
  const existing = loadRules();
  if (existing.some((r) => r.re === lit || r.re === `\\b${lit}\\b`)) {
    return { added: false, reason: "already-covered" };
  }

  const rule: RuleSpec = { re: lit, flags: "gi", severity: 3, category, sanitize: "redacted" };
  const next = [rule, ...existing];
  const ok = saveRules(next);
  return ok ? { added: true, rule, reason: "learned" } : { added: false, reason: "persist-failed" };
}

// ---- Library exchange (community-shared signatures) ----
// Export the current library as a portable JSON string so users can share
// learned signatures between installations, like antivirus definition swaps.
export function exportRules(): string {
  return JSON.stringify(loadRules(), null, 2);
}

// Merge an external library (JSON string or parsed RuleSpec[]) into the local one,
// de-duplicating by regex source. Returns how many rules were added.
export function importRules(input: string | RuleSpec[]): { added: number; skipped: number } {
  let incoming: RuleSpec[];
  try {
    incoming = typeof input === "string" ? (JSON.parse(input) as RuleSpec[]) : input;
  } catch (e) {
    throw new Error(`invalid rules JSON: ${(e as Error).message}`);
  }
  if (!Array.isArray(incoming)) throw new Error("rules must be an array");

  const current = loadRules();
  const seen = new Set<string>(current.map((r) => r.re));
  let added = 0;
  let skipped = 0;
  for (const spec of incoming) {
    // Validate shape and skip malformed/falsey entries.
    if (!spec || typeof spec.re !== "string" || !spec.category) {
      skipped++;
      continue;
    }
    if (seen.has(spec.re)) {
      skipped++;
      continue;
    }
    current.push({
      re: spec.re,
      flags: spec.flags ?? "gi",
      severity: (typeof spec.severity === "number" ? spec.severity : 1) as Severity,
      category: spec.category,
      sanitize: spec.sanitize,
    });
    seen.add(spec.re);
    added++;
  }
  saveRules(current);
  return { added, skipped };
}

// Convenience: normalize a parsed external array so callers can inspect it.
export function validateRules(input: unknown): { valid: boolean; count: number; errors: string[] } {
  const errors: string[] = [];
  if (!Array.isArray(input)) {
    return { valid: false, count: 0, errors: ["not an array"] };
  }
  for (const [i, r] of (input as RuleSpec[]).entries()) {
    if (!r || typeof r.re !== "string") errors.push(`entry ${i}: missing re`);
    else if (typeof r.category !== "string") errors.push(`entry ${i}: missing category`);
    else if (typeof r.severity !== "number" || r.severity < 0 || r.severity > 3) errors.push(`entry ${i}: severity out of range`);
  }
  return { valid: errors.length === 0, count: (input as RuleSpec[]).length, errors };
}
