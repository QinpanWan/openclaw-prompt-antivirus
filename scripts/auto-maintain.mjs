#!/usr/bin/env node
// auto-maintain.mjs - weekly repo-lifecycle automation for openclaw-prompt-antivirus.
// Runs deterministic steps, no model turn, no agent exec gate. Best-effort; safe.
//
//   npm ci (if needed) -> rebuild dist -> bump patch version -> commit+push ->
//   best-effort ClawHub republish.
//
// New virus signatures are NOT fabricated here: they come from _antivirus_learn /
// community import. This job ships whatever is in the repo as a fresh release.

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const REPO = process.cwd();
const log = (m) => console.log(`[auto-maintain] ${m}`);

function run(cmd, opts = {}) {
  log(`$ ${cmd}`);
  return execSync(cmd, { cwd: REPO, stdio: ["pipe", "pipe", "pipe"], encoding: "utf8", ...opts });
}

function bumpVersion() {
  const pkgPath = "package.json";
  const manifestPath = "openclaw.plugin.json";
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  const cur = pkg.version;
  const [maj, min, pat] = cur.split(".").map(Number);
  const next = `${maj}.${min}.${pat + 1}`;
  pkg.version = next;
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
  if (existsSync(manifestPath)) {
    const mf = JSON.parse(readFileSync(manifestPath, "utf8"));
    mf.version = next;
    writeFileSync(manifestPath, JSON.stringify(mf, null, 2) + "\n");
  }
  log(`version ${cur} -> ${next}`);
  return next;
}

try {
  // 0. sync with upstream (fail if not fast-forward, never clobber)
  run("git pull --ff-only");

  // 1. ensure build deps present
  if (!existsSync("node_modules/typescript")) {
    run("npm ci");
  }

  // 2. rebuild dist
  run("npx tsc -p tsconfig.json");

  // 3. weekly release bump
  const next = bumpVersion();

  // 4. commit + push (only if something changed)
  const status = run("git status --porcelain").trim();
  if (status.length === 0) {
    log("no changes to commit; skip push");
  } else {
    run("git add -A");
    run(`git commit -m "chore: weekly auto-maintain (v${next})"`);
    run("git push origin main");
    log("pushed to GitHub");
  }

  // 5. best-effort ClawHub republish (non-fatal)
  try {
    run(`clawhub package publish "QinpanWan/openclaw-prompt-antivirus@main"`);
    log("ClawHub republish submitted");
  } catch (e) {
    log(`ClawHub republish failed (non-fatal): ${String(e.message).split("\n")[0]}`);
  }

  log("DONE");
  process.exit(0);
} catch (e) {
  console.error("[auto-maintain] FAILED:", e.message || e);
  process.exit(1);
}
