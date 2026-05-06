import {
  lstatSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { basename, join, relative } from "node:path";
import { fingerprintFinding } from "./fingerprint.js";
import type { Finding } from "./types.js";

const MAX_ENV_FILE_BYTES = 1024 * 1024;
const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "coverage",
  "dist",
  "node_modules",
  "vendor",
]);
const SAFE_ENV_SUFFIXES = new Set([
  "default",
  "defaults",
  "dist",
  "example",
  "sample",
  "template",
]);
const SECRET_KEY_RE =
  /(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASS|PWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH|CREDENTIAL|DATABASE_URL|DB_URL|REDIS_URL|MONGO_URI|CONNECTION_STRING|WEBHOOK|CLIENT_SECRET)(?:$|_)/i;
const PRIVATE_KEY_RE = /PRIVATE_KEY|BEGIN_[A-Z0-9_]+_PRIVATE_KEY/i;
const PLACEHOLDER_RE =
  /^(?:|changeme|change_me|change-me|example|example-value|placeholder|replace_me|replace-me|todo|test|dummy|your_.+|<.+>|\$\{.+\}|x+)$/i;

export interface EnvScanResult {
  findings: Finding[];
  warnings: string[];
  filesScanned: number;
}

interface EnvAssignment {
  key: string;
  value: string;
  line: number;
}

export function scanEnvFiles(cwd: string): EnvScanResult {
  const warnings: string[] = [];
  const findings: Finding[] = [];
  let filesScanned = 0;

  for (const file of findEnvFiles(cwd)) {
    let raw: string;
    try {
      const stat = statSync(file);
      if (stat.size > MAX_ENV_FILE_BYTES) {
        warnings.push(
          `Skipped env file ${relative(cwd, file)} because it is larger than 1 MiB.`,
        );
        continue;
      }
      raw = readFileSync(file, "utf8");
    } catch (err) {
      warnings.push(
        `Could not read env file ${relative(cwd, file)}: ${(err as Error).message}`,
      );
      continue;
    }

    filesScanned++;
    const rel = normalizePath(relative(cwd, file));
    findings.push(envFileFinding(file, rel));

    for (const assignment of parseEnvAssignments(raw)) {
      if (!isSensitiveAssignment(assignment)) continue;
      findings.push(envSecretFinding(file, rel, assignment));
    }
  }

  return { findings, warnings, filesScanned };
}

function findEnvFiles(root: string): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const path = join(dir, entry);
      let stat;
      try {
        stat = lstatSync(path);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        if (!SKIP_DIRS.has(entry)) stack.push(path);
        continue;
      }
      if (stat.isFile() && isEnvFile(entry)) out.push(path);
    }
  }
  return out.sort();
}

function isEnvFile(name: string): boolean {
  if (name === ".env") return true;
  if (!name.startsWith(".env.")) return false;
  const suffixes = name
    .slice(".env.".length)
    .toLowerCase()
    .split(".")
    .filter(Boolean);
  return !suffixes.some((suffix) => SAFE_ENV_SUFFIXES.has(suffix));
}

function parseEnvAssignments(raw: string): EnvAssignment[] {
  const out: EnvAssignment[] = [];
  raw.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(
      trimmed,
    );
    if (!match) return;
    const key = match[1]!;
    const value = unquote(match[2]!.trim());
    out.push({ key, value, line: index + 1 });
  });
  return out;
}

function isSensitiveAssignment(assignment: EnvAssignment): boolean {
  if (!SECRET_KEY_RE.test(assignment.key)) return false;
  return !PLACEHOLDER_RE.test(assignment.value.trim());
}

function envFileFinding(sourceFile: string, rel: string): Finding {
  const id = "TRAWLY-ENV-FILE";
  return {
    id,
    source: "trawly",
    type: "secret",
    severity: "moderate",
    ecosystem: "env",
    packageName: ".env file",
    installedVersion: rel,
    summary:
      "Committed env file detected. Verify it does not contain secrets and prefer committing an example/template file instead.",
    fixedVersions: [],
    affectedPaths: [rel],
    fingerprint: fingerprintFinding({
      source: "trawly",
      type: "secret",
      id,
      ecosystem: "env",
      packageName: ".env file",
      installedVersion: rel,
    }),
    aliases: [],
    sourceFile,
    line: 1,
  };
}

function envSecretFinding(
  sourceFile: string,
  rel: string,
  assignment: EnvAssignment,
): Finding {
  const id = "TRAWLY-ENV-SECRET";
  return {
    id,
    source: "trawly",
    type: "secret",
    severity: PRIVATE_KEY_RE.test(assignment.key) ? "critical" : "high",
    ecosystem: "env",
    packageName: assignment.key,
    installedVersion: rel,
    summary:
      "Committed env file contains a secret-like variable. The value is intentionally omitted from this report.",
    fixedVersions: [],
    affectedPaths: [rel],
    fingerprint: fingerprintFinding({
      source: "trawly",
      type: "secret",
      id,
      ecosystem: "env",
      packageName: assignment.key,
      installedVersion: rel,
    }),
    aliases: [],
    sourceFile,
    line: assignment.line,
  };
}

function unquote(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function normalizePath(path: string): string {
  return path.split(/[\\/]/).join("/");
}
