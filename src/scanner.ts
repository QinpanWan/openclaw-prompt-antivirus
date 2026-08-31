// scanner.ts - detection engine for prompt-injection / "mind-virus" defenses.
// Pure, no OpenClaw deps -> unit-testable and reusable. Rules come from the
// evolvable library (rules.ts) and can be swapped at runtime.

import { buildCompiled, DEFAULT_RULES, type CompiledRule } from "./rules.js";

export type Severity = 0 | 1 | 2 | 3;

export interface Finding {
  start: number;
  end: number;
  severity: Severity;
  category: string;
  matched: string;
}

export interface ScanResult {
  risk: Severity;
  label: "CLEAN" | "LOW" | "MEDIUM" | "HIGH";
  findings: Finding[];
  categories: string[];
}

// Active rule set. Starts from the built-in library; can be replaced by
// loading a hot-updated / learned library from disk at runtime.
let activeRules: CompiledRule[] = buildCompiled(DEFAULT_RULES);

export function setActiveRules(rules: CompiledRule[]): void {
  activeRules = rules;
}

export function getRuleCount(): number {
  return activeRules.length;
}

function labelFor(risk: Severity): ScanResult["label"] {
  return (["CLEAN", "LOW", "MEDIUM", "HIGH"] as const)[risk];
}

export function scanText(text: string): ScanResult {
  const findings: Finding[] = [];
  const categories = new Set<string>();
  let risk: Severity = 0;
  for (const rule of activeRules) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(text)) !== null) {
      const sev = rule.severity;
      findings.push({ start: m.index, end: m.index + m[0].length, severity: sev, category: rule.category, matched: m[0] });
      categories.add(rule.category);
      if (sev > risk) risk = sev;
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // avoid infinite loop on empty matches
    }
  }
  return { risk, label: labelFor(risk), findings, categories: [...categories] };
}

export function sanitizeText(text: string): string {
  let out = text;
  for (const rule of activeRules) {
    if (!rule.sanitize) continue;
    out = out.replace(rule.re, rule.sanitize);
  }
  return out;
}

export function scanToolParams(params: Record<string, unknown>): ScanResult {
  let risk: Severity = 0;
  const categories = new Set<string>();
  const findings: Finding[] = [];
  const visit = (v: unknown): void => {
    if (typeof v === "string") {
      const r = scanText(v);
      if (r.risk > risk) risk = r.risk;
      r.categories.forEach((c) => categories.add(c));
      findings.push(...r.findings);
    } else if (Array.isArray(v)) {
      v.forEach(visit);
    } else if (v && typeof v === "object") {
      Object.values(v as Record<string, unknown>).forEach(visit);
    }
  };
  visit(params);
  return { risk, label: labelFor(risk), findings, categories: [...categories] };
}

export interface ToolRiskRule {
  // Tools whose params should NEVER be influenced by retrieved/injected data.
  name: RegExp;
  reason: string;
}

// Host-trusted policy: tools whose effects are irreversible or externally visible.
export const DANGEROUS_TOOLS: ToolRiskRule[] = [
  { name: /send_email|email|mail|smtp|gmail/i, reason: "outbound communication" },
  { name: /\bexec\b|shell|command|run(?:_)?script|wsl|powershell|terminal/i, reason: "code execution" },
  { name: /delete|rm|remove|destroy|overwrite|unlink/i, reason: "destructive filesystem action" },
  { name: /update|patch|write|apply_patch|write_file|transact/i, reason: "persistent filesystem write" },
  { name: /transfer|pay|purchase|order|invoice|webhook|publish|release/i, reason: "external side effect / money" },
  { name: /push|deploy|upload|ftp|s3|cdn/i, reason: "external publishing" },
  { name: /approval|approve/i, reason: "self-approval escalation" },
];
