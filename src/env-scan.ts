import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import type { Severity } from "./types.js";

export type EnvIssueKind =
  | "tracked-by-git"
  | "not-gitignored"
  | "would-be-published"
  | "secret-in-example"
  | "no-gitignore";

export interface EnvIssue {
  kind: EnvIssueKind;
  severity: Severity;
  file: string;
  message: string;
  detail?: string;
}

export interface EnvScanResult {
  scannedAt: string;
  cwd: string;
  envFiles: string[];
  issues: EnvIssue[];
  summary: Record<Severity, number>;
  errors: { message: string; cause?: string }[];
}

export interface EnvScanOptions {
  cwd?: string;
  /** Cap on directory recursion depth from cwd. Default 6. */
  maxDepth?: number;
  /** Override directory skip list (replaces the default). */
  skipDirs?: string[];
}

const DEFAULT_SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".nuxt",
  ".svelte-kit",
  ".turbo",
  ".cache",
  "coverage",
  "out",
  ".vercel",
  ".output",
]);

const EXAMPLE_NAME = /^\.env(\.[^.]+)*\.(example|sample|template|dist)$/i;
const EXAMPLE_SUFFIX_NAME = /(\.|^)(example|sample|template)$/i;

export async function scanEnv(
  options: EnvScanOptions = {},
): Promise<EnvScanResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const skipDirs = options.skipDirs
    ? new Set(options.skipDirs)
    : DEFAULT_SKIP_DIRS;
  const maxDepth = options.maxDepth ?? 6;

  const errors: { message: string; cause?: string }[] = [];
  const envFiles = discoverEnvFiles(cwd, skipDirs, maxDepth);

  const inGit = isGitRepo(cwd);
  const gitignorePath = join(cwd, ".gitignore");
  const hasGitignore = existsSync(gitignorePath);
  const exampleFiles = envFiles.filter(isExampleFile);
  const realEnvFiles = envFiles.filter((f) => !isExampleFile(f));

  const [trackedSet, ignoredMap, publishCheck, exampleSecrets] =
    await Promise.all([
      inGit ? gitTracked(cwd, envFiles) : Promise.resolve(new Set<string>()),
      inGit
        ? gitCheckIgnore(cwd, envFiles)
        : Promise.resolve(fallbackIgnoreMap(cwd, envFiles)),
      checkPublishExposure(cwd, realEnvFiles),
      scanExampleFilesForSecrets(cwd, exampleFiles),
    ]).catch((err) => {
      errors.push({
        message: "env scan: parallel checks failed",
        cause: (err as Error).message,
      });
      return [
        new Set<string>(),
        new Map<string, boolean>(),
        [] as PublishFinding[],
        [] as SecretFinding[],
      ] as const;
    });

  const issues: EnvIssue[] = [];

  if (envFiles.length > 0 && !hasGitignore) {
    issues.push({
      kind: "no-gitignore",
      severity: "moderate",
      file: ".gitignore",
      message: "Project has env files but no .gitignore.",
      detail:
        "Add a .gitignore that includes .env and .env.* before committing.",
    });
  }

  for (const file of realEnvFiles) {
    if (trackedSet.has(file)) {
      issues.push({
        kind: "tracked-by-git",
        severity: "critical",
        file,
        message: `${file} is tracked by git.`,
        detail:
          "This file is committed to the repo. Run `git rm --cached` and rotate any secrets that were exposed.",
      });
      continue;
    }
    const ignored = ignoredMap.get(file);
    if (hasGitignore && ignored === false) {
      issues.push({
        kind: "not-gitignored",
        severity: "high",
        file,
        message: `${file} exists but is not covered by .gitignore.`,
        detail: "Add a matching pattern (e.g. `.env*`) to .gitignore.",
      });
    }
  }

  for (const f of publishCheck) {
    issues.push({
      kind: "would-be-published",
      severity: "critical",
      file: f.file,
      message: `${f.file} would be included in the published npm tarball.`,
      detail: f.reason,
    });
  }

  for (const f of exampleSecrets) {
    issues.push({
      kind: "secret-in-example",
      severity: "high",
      file: f.file,
      message: `${f.file} appears to contain a real secret.`,
      detail: `Matched pattern: ${f.pattern} on key \`${f.key}\`. Example files should hold placeholder values only.`,
    });
  }

  issues.sort(compareIssues);

  return {
    scannedAt: new Date().toISOString(),
    cwd,
    envFiles,
    issues,
    summary: summarizeIssues(issues),
    errors,
  };
}

function compareIssues(a: EnvIssue, b: EnvIssue): number {
  const rank: Record<Severity, number> = {
    critical: 4,
    high: 3,
    moderate: 2,
    low: 1,
    unknown: 0,
  };
  const sev = rank[b.severity] - rank[a.severity];
  if (sev !== 0) return sev;
  if (a.file !== b.file) return a.file.localeCompare(b.file);
  return a.kind.localeCompare(b.kind);
}

function summarizeIssues(issues: EnvIssue[]): Record<Severity, number> {
  const out: Record<Severity, number> = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    unknown: 0,
  };
  for (const i of issues) out[i.severity]++;
  return out;
}

function discoverEnvFiles(
  cwd: string,
  skipDirs: Set<string>,
  maxDepth: number,
): string[] {
  const found: string[] = [];
  walk(cwd, cwd, 0);
  found.sort();
  return found;

  function walk(dir: string, root: string, depth: number): void {
    if (depth > maxDepth) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name) || entry.name.startsWith(".git")) continue;
        walk(join(dir, entry.name), root, depth + 1);
        continue;
      }
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      if (isEnvFilename(entry.name)) {
        found.push(toPosix(relative(root, join(dir, entry.name))));
      }
    }
  }
}

function isEnvFilename(name: string): boolean {
  if (name === ".env") return true;
  if (name.startsWith(".env.")) return true;
  return false;
}

function isExampleFile(file: string): boolean {
  const base = file.split("/").pop() ?? file;
  if (EXAMPLE_NAME.test(base)) return true;
  // Catch `.env.example` and similar where the suffix is the last segment.
  const segments = base.split(".");
  const last = segments[segments.length - 1] ?? "";
  return EXAMPLE_SUFFIX_NAME.test(last);
}

function toPosix(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

function isGitRepo(cwd: string): boolean {
  let dir = cwd;
  for (let i = 0; i < 32; i++) {
    if (existsSync(join(dir, ".git"))) return true;
    const parent = resolve(dir, "..");
    if (parent === dir) return false;
    dir = parent;
  }
  return false;
}

async function gitTracked(
  cwd: string,
  files: string[],
): Promise<Set<string>> {
  if (files.length === 0) return new Set();
  const { stdout, code } = await runGit(cwd, ["ls-files", "-z", "--", ...files]);
  if (code !== 0) return new Set();
  const tracked = stdout.split("\0").filter(Boolean).map(toPosix);
  return new Set(tracked);
}

async function gitCheckIgnore(
  cwd: string,
  files: string[],
): Promise<Map<string, boolean>> {
  const result = new Map<string, boolean>();
  if (files.length === 0) return result;
  // -z is only valid with --stdin. We pipe NUL-separated paths to a single
  // process — one spawn for any number of files.
  const stdin = `${files.join("\0")}\0`;
  const { stdout, code } = await runGit(
    cwd,
    ["check-ignore", "--no-index", "-v", "-n", "-z", "--stdin"],
    stdin,
  );
  if (code !== 0 && code !== 1) {
    // Operational failure; treat all as unknown (false).
    for (const f of files) result.set(f, false);
    return result;
  }
  // -z -v -n format: for each input path, three NUL-separated fields:
  //   <source>\0<linenum>\0<pattern>\0<pathname>\0
  // For non-matching paths: source/linenum/pattern are empty strings.
  const parts = stdout.split("\0");
  for (let i = 0; i + 3 < parts.length; i += 4) {
    const source = parts[i];
    const pathname = toPosix(parts[i + 3] ?? "");
    if (!pathname) continue;
    result.set(pathname, source !== "");
  }
  for (const f of files) {
    if (!result.has(f)) result.set(f, false);
  }
  return result;
}

function fallbackIgnoreMap(
  cwd: string,
  files: string[],
): Map<string, boolean> {
  // Not a git repo: do best-effort matching on a literal .gitignore.
  const result = new Map<string, boolean>();
  const patterns = readIgnoreFile(join(cwd, ".gitignore"));
  for (const f of files) result.set(f, matchesAny(f, patterns));
  return result;
}

function runGit(
  cwd: string,
  args: string[],
  stdin?: string,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolveP) => {
    const child = spawn("git", args, {
      cwd,
      stdio: [stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => {
      stdout += d.toString("utf8");
    });
    child.stderr?.on("data", (d) => {
      stderr += d.toString("utf8");
    });
    child.on("error", () => resolveP({ stdout, stderr, code: -1 }));
    child.on("close", (code) =>
      resolveP({ stdout, stderr, code: code ?? -1 }),
    );
    if (stdin !== undefined && child.stdin) {
      child.stdin.end(stdin);
    }
  });
}

interface PublishFinding {
  file: string;
  reason: string;
}

async function checkPublishExposure(
  cwd: string,
  envFiles: string[],
): Promise<PublishFinding[]> {
  if (envFiles.length === 0) return [];
  const pkgPath = join(cwd, "package.json");
  if (!existsSync(pkgPath)) return [];
  let pkg: { files?: unknown; private?: unknown };
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch {
    return [];
  }
  // Private packages are never published; skip the check.
  if (pkg.private === true) return [];

  const findings: PublishFinding[] = [];

  if (Array.isArray(pkg.files)) {
    const allowList = pkg.files.filter((x): x is string => typeof x === "string");
    for (const file of envFiles) {
      if (matchesAny(file, allowList)) {
        findings.push({
          file,
          reason: `package.json "files" allowlist matches this path. Remove the entry or move the file.`,
        });
      }
    }
    return findings;
  }

  // No `files` allowlist: npm uses .npmignore, falling back to .gitignore.
  const npmignorePath = join(cwd, ".npmignore");
  const ignorePath = existsSync(npmignorePath)
    ? npmignorePath
    : join(cwd, ".gitignore");
  const ignoreSource = existsSync(ignorePath)
    ? ignorePath === npmignorePath
      ? ".npmignore"
      : ".gitignore"
    : null;
  const patterns = ignoreSource ? readIgnoreFile(ignorePath) : [];

  for (const file of envFiles) {
    if (!matchesAny(file, patterns)) {
      findings.push({
        file,
        reason: ignoreSource
          ? `Not matched by any pattern in ${ignoreSource}. Add an entry like \`.env*\`.`
          : `No .npmignore or .gitignore present, so npm will include this file in the published tarball. Add an .npmignore.`,
      });
    }
  }
  return findings;
}

function readIgnoreFile(path: string): string[] {
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
  } catch {
    return [];
  }
}

/**
 * Simplified gitignore-style matcher. Supports:
 *  - exact filename / path match
 *  - leading `/` anchors to repo root
 *  - `*` wildcard within a single path segment
 *  - `**` matches any number of segments
 *  - leading `!` negation
 * Patterns without a slash match against the basename at any depth.
 */
export function matchesAny(file: string, patterns: string[]): boolean {
  let matched = false;
  for (const raw of patterns) {
    let pattern = raw;
    let negate = false;
    if (pattern.startsWith("!")) {
      negate = true;
      pattern = pattern.slice(1);
    }
    if (pattern.endsWith("/")) pattern = pattern.slice(0, -1);
    if (matchesPattern(file, pattern)) matched = !negate;
  }
  return matched;
}

function matchesPattern(file: string, pattern: string): boolean {
  if (!pattern) return false;
  const anchored = pattern.startsWith("/");
  const pat = anchored ? pattern.slice(1) : pattern;
  const hasSlash = pat.includes("/");
  const candidates = anchored
    ? [file]
    : hasSlash
      ? [file]
      : [file, file.split("/").pop() ?? file];
  const re = globToRegex(pat);
  return candidates.some((c) => re.test(c));
}

function globToRegex(pattern: string): RegExp {
  let re = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        re += ".*";
        i++;
        if (pattern[i + 1] === "/") i++;
      } else {
        re += "[^/]*";
      }
    } else if (ch === "?") {
      re += "[^/]";
    } else if (ch === ".") {
      re += "\\.";
    } else if (/[\\^$+()=!|{}[\]]/.test(ch ?? "")) {
      re += `\\${ch}`;
    } else {
      re += ch;
    }
  }
  re += "$";
  return new RegExp(re);
}

interface SecretFinding {
  file: string;
  key: string;
  pattern: string;
}

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Stripe live key", re: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Generic JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
];

const PLACEHOLDER_RE = /^(?:|x+|y+|<.*>|\{.*\}|change[-_ ]?me|todo|placeholder|your[-_ ].+|example|dummy|fake|test)$/i;

async function scanExampleFilesForSecrets(
  cwd: string,
  files: string[],
): Promise<SecretFinding[]> {
  const findings: SecretFinding[] = [];
  await Promise.all(
    files.map(async (file) => {
      let content: string;
      try {
        content = readFileSync(join(cwd, file), "utf8");
      } catch {
        return;
      }
      const lines = content.split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq <= 0) continue;
        const key = trimmed.slice(0, eq).trim();
        let value = trimmed.slice(eq + 1).trim();
        // Strip wrapping quotes and inline comment.
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          value = value.slice(1, -1);
        } else {
          const hashIdx = value.indexOf(" #");
          if (hashIdx >= 0) value = value.slice(0, hashIdx).trim();
        }
        if (!value || PLACEHOLDER_RE.test(value)) continue;
        for (const pat of SECRET_PATTERNS) {
          if (pat.re.test(value)) {
            findings.push({ file, key, pattern: pat.name });
            break;
          }
        }
      }
    }),
  );
  return findings;
}

export function envIssuesMeetThreshold(
  issues: EnvIssue[],
  threshold: Severity | "none",
): boolean {
  if (threshold === "none") return false;
  const rank: Record<Severity, number> = {
    critical: 4,
    high: 3,
    moderate: 2,
    low: 1,
    unknown: 0,
  };
  const min = rank[threshold];
  return issues.some((i) => rank[i.severity] >= min);
}

