import { existsSync, statSync } from "node:fs";
import { basename, resolve, join } from "node:path";
import { parseNpmPackageLock } from "./extractors/npm-package-lock.js";
import { parsePnpmLock } from "./extractors/pnpm-lock.js";
import { parseYarnLock } from "./extractors/yarn-lock.js";
import { queryOsv } from "./sources/osv.js";
import { SEVERITY_RANK } from "./types.js";
import type {
  Finding,
  PackageInstance,
  ScanError,
  ScanLockfileOptions,
  ScanProjectOptions,
  ScanResult,
  Severity,
} from "./types.js";

export async function scanProject(
  options: ScanProjectOptions = {},
): Promise<ScanResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const lockfilePath = options.lockfile
    ? resolve(cwd, options.lockfile)
    : detectLockfile(cwd);

  if (!lockfilePath) {
    throw new ScanInputError(
      `No supported lockfile found in ${cwd}. Pass --lockfile or run in a directory with package-lock.json, pnpm-lock.yaml, or yarn.lock.`,
    );
  }

  return scanLockfile({
    lockfilePath,
    includeDev: options.includeDev,
    prodOnly: options.prodOnly,
    fetchImpl: options.fetchImpl,
  });
}

export async function scanLockfile(
  options: ScanLockfileOptions,
): Promise<ScanResult> {
  const { lockfilePath } = options;
  if (!existsSync(lockfilePath)) {
    throw new ScanInputError(`Lockfile does not exist: ${lockfilePath}`);
  }
  const stat = statSync(lockfilePath);
  if (!stat.isFile()) {
    throw new ScanInputError(`Lockfile path is not a file: ${lockfilePath}`);
  }

  const allInstances = parseLockfile(lockfilePath);
  const instances = filterInstances(allInstances, options);
  const errors: ScanError[] = [];

  let findings: Finding[] = [];
  try {
    findings = await queryOsv(instances, { fetchImpl: options.fetchImpl });
  } catch (err) {
    errors.push({
      message: "Failed to query OSV advisory database",
      cause: (err as Error).message,
    });
  }

  findings.sort(compareFindings);

  return {
    scannedAt: new Date().toISOString(),
    packagesScanned: instances.length,
    findings,
    summary: summarize(findings),
    errors,
  };
}

export class ScanInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanInputError";
  }
}

const LOCKFILE_CANDIDATES = [
  "pnpm-lock.yaml",
  "yarn.lock",
  "package-lock.json",
  "npm-shrinkwrap.json",
] as const;

function detectLockfile(cwd: string): string | undefined {
  for (const file of LOCKFILE_CANDIDATES) {
    const candidate = join(cwd, file);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

function parseLockfile(lockfilePath: string): PackageInstance[] {
  const name = basename(lockfilePath);
  if (name === "pnpm-lock.yaml") return parsePnpmLock(lockfilePath);
  if (name === "yarn.lock") return parseYarnLock(lockfilePath);
  if (name === "package-lock.json" || name === "npm-shrinkwrap.json") {
    return parseNpmPackageLock(lockfilePath);
  }
  throw new ScanInputError(
    `Unsupported lockfile name: ${name}. Supported: package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock.`,
  );
}

function filterInstances(
  instances: PackageInstance[],
  options: { includeDev?: boolean; prodOnly?: boolean },
): PackageInstance[] {
  const includeDev = options.prodOnly ? false : options.includeDev !== false;
  if (includeDev) return instances;
  return instances.filter((p) => !p.dev);
}

export function compareFindings(a: Finding, b: Finding): number {
  const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (sev !== 0) return sev;
  if (a.packageName !== b.packageName) {
    return a.packageName.localeCompare(b.packageName);
  }
  if (a.installedVersion !== b.installedVersion) {
    return a.installedVersion.localeCompare(b.installedVersion);
  }
  return a.id.localeCompare(b.id);
}

export function summarize(findings: Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    unknown: 0,
  };
  for (const f of findings) summary[f.severity]++;
  return summary;
}

/**
 * Returns true when any finding meets or exceeds the given severity threshold.
 * "none" means never fail.
 */
export function meetsThreshold(
  findings: Finding[],
  threshold: Severity | "none",
): boolean {
  if (threshold === "none") return false;
  const min = SEVERITY_RANK[threshold];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= min);
}
