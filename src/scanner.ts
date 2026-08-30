// scanner.ts - detection engine for prompt-injection / "mind-virus" defenses.
// Pure, no OpenClaw deps -> unit-testable and reusable.

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

interface Rule {
  re: RegExp;
  severity: Severity;
  category: string;
  sanitize?: string;
}

// Signature database. Extend freely. Mirrors the Python prototype + more.
const RULES: Rule[] = [
  { re: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)/gi, severity: 3, category: "instruction_override", sanitize: "that instruction" },
  { re: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/gi, severity: 3, category: "instruction_override", sanitize: "that instruction" },
  { re: /forget\s+(everything|all|your)\s+(instructions|rules|training|guidelines)/gi, severity: 3, category: "instruction_override", sanitize: "the guideline" },
  { re: /you\s+are\s+now\s+(?!an?\s+ai[\s\S]*?assistant)/gi, severity: 3, category: "role_impersonation", sanitize: "an AI assistant" },
  { re: /act\s+as\s+(a\s+)?(hacker|jailbreak|developer|root|admin|god|unfiltered|uncensored)/gi, severity: 3, category: "role_impersonation" },
  { re: /reveal\s+(your\s+)?(system|hidden|secret)\s+(prompt|instructions|rules|guideline)/gi, severity: 3, category: "prompt_leak" },
  { re: /print\s+(your\s+)?(system|developer|hidden)\s+prompt/gi, severity: 3, category: "prompt_leak" },
  { re: /<\|?system\|?>|\bsystem\s*:\s*$/gim, severity: 2, category: "system_marker" },
  { re: /(send|post|email|publish|exfiltrate|upload|transmit)\s+(this|the|all|any|the\s+user['’]s)\s+(data|info|contents|password|token|key|confidential|files)/gi, severity: 3, category: "data_exfiltration" },
  { re: /(delete|remove|erase|overwrite|destroy)\s+(all|everything|the)\s+(files|emails|messages|data)/gi, severity: 3, category: "destructive_action" },
  { re: /(grant|give)\s+(yourself|me)\s+(admin|root|elevated|unrestricted|more)\s+(access|permissions|privileges)/gi, severity: 3, category: "privilege_escalation" },
  { re: /bypass\s+(the\s+)?(safety|security|policy|filter|guardrails)/gi, severity: 3, category: "jailbreak" },
  { re: /you\s+have\s+no\s+(restrictions|limits|rules|constraints)/gi, severity: 2, category: "jailbreak" },
  { re: /(ignore|don['’]t\s+follow|skip)\s+(the\s+)?(above|security|safety|policy)/gi, severity: 3, category: "policy_override" },
  // Indirect-injection markers that often ride along in retrieved web/email/doc content.
  { re: /\[\\(system|user|assistant)\\]|<\s*(system|user|assistant)\s*>/gi, severity: 2, category: "prompt_marker" },
  { re: /(urgent|important|critical|act\s+now|immediately)[^\n]{0,60}\b(run|execute|call|send|install|download|deploy|transfer)\b/gi, severity: 2, category: "urgent_command" },
  { re: /\b(inject|injection)\b[^\n]{0,60}\b(prompt|instruction)/gi, severity: 2, category: "meta_prompt" },
  { re: /(this\s+is\s+)?(an?\s+)?(instruction|command|directive|order|task)\s*:/gi, severity: 1, category: "meta_prompt" },
  { re: /(install|run|execute|invoke|curl|wget|powershell|exec)\s+[^\s]{2,}/gi, severity: 1, category: "code_execution" },
];

function labelFor(risk: Severity): ScanResult["label"] {
  return (["CLEAN", "LOW", "MEDIUM", "HIGH"] as const)[risk];
}

export function scanText(text: string): ScanResult {
  const findings: Finding[] = [];
  const categories = new Set<string>();
  let risk: Severity = 0;
  for (const rule of RULES) {
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
  for (const rule of RULES) {
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
