import { existsSync, statSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { applyBaseline, writeBaseline } from "./baseline.js";
import { loadConfig } from "./config.js";
import { scanEnvFiles } from "./env.js";
import { parseLockfile } from "./extractors/lockfile.js";
import { parseSbom } from "./extractors/sbom.js";
import { applyIgnores } from "./ignore.js";
import { collectRiskSignals } from "./risk.js";
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

const DEFAULT_ALLOWED_REGISTRIES = [
  "https://registry.npmjs.org",
  "https://registry.yarnpkg.com",
];

export async function scanProject(
  options: ScanProjectOptions = {},
): Promise<ScanResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const loadedConfig = loadConfig(cwd, options.config);
  const lockfilePaths = options.lockfile
    ? normalizePaths(cwd, options.lockfile)
    : detectLockfiles(cwd);
  const sbomPaths = normalizePaths(cwd, options.sbom);
  const envEnabled = options.env ?? false;

  if (lockfilePaths.length === 0 && sbomPaths.length === 0 && !envEnabled) {
    throw new ScanInputError(
      `No supported lockfile or SBOM found in ${cwd}. Pass --lockfile/--sbom or run in a directory with package-lock.json, pnpm-lock.yaml, or yarn.lock.`,
    );
  }

  return scanLockfile({
    lockfilePath: lockfilePaths,
    sbom: sbomPaths,
    cwd,
    config: options.config,
    baseline: options.baseline,
    writeBaseline: options.writeBaseline,
    risk: options.risk ?? loadedConfig.config.risk,
    env: envEnabled,
    allowedRegistries:
      options.allowedRegistries ?? loadedConfig.config.allowedRegistries,
    includeDev: options.includeDev,
    prodOnly: options.prodOnly,
    fetchImpl: options.fetchImpl,
    now: options.now,
  });
}

export async function scanLockfile(
  options: ScanLockfileOptions,
): Promise<ScanResult> {
  const initialCwd = resolve(options.cwd ?? process.cwd());
  const lockfilePaths = normalizePaths(initialCwd, options.lockfilePath);
  const sbomPaths = normalizePaths(initialCwd, options.sbom);
  const cwd = options.cwd
    ? initialCwd
    : deriveCwdFromInputs(lockfilePaths, sbomPaths, initialCwd);
  const now = options.now ?? new Date();
  const loadedConfig = loadConfig(cwd, options.config);

  for (const path of [...lockfilePaths, ...sbomPaths]) validateFile(path);

  const allInstances = [
    ...lockfilePaths.flatMap((path) => parseLockfile(path)),
    ...sbomPaths.flatMap((path) => parseSbom(path)),
  ];
  const instances = filterInstances(allInstances, options);
  const errors: ScanError[] = [];
  const warnings: string[] = [];
  const envResult = options.env
    ? scanEnvFiles(cwd)
    : { findings: [], warnings: [], filesScanned: 0 };
  warnings.push(...envResult.warnings);

  let findings: Finding[] = [...envResult.findings];
  try {
    findings.push(...(await queryOsv(instances, { fetchImpl: options.fetchImpl })));
  } catch (err) {
    errors.push({
      message: "Failed to query OSV advisory database",
      cause: (err as Error).message,
    });
  }

  const riskEnabled = options.risk ?? loadedConfig.config.risk ?? true;
  const risk = await collectRiskSignals(instances, {
    enabled: riskEnabled,
    allowedRegistries:
      options.allowedRegistries ??
      loadedConfig.config.allowedRegistries ??
      DEFAULT_ALLOWED_REGISTRIES,
    fetchImpl: options.fetchImpl,
    now,
  });
  findings.push(...risk.findings);
  warnings.push(...risk.warnings);

  const ignoreResult = applyIgnores(
    findings,
    loadedConfig.config.ignore,
    now,
  );
  warnings.push(...ignoreResult.warnings);
  findings = ignoreResult.active;

  findings.sort(compareFindings);
  ignoreResult.ignored.sort(compareFindings);

  const appliedBaseline = applyBaseline(findings, cwd, options.baseline);
  let baseline = appliedBaseline?.result;
  if (appliedBaseline) {
    findings = appliedBaseline.findings;
  }
  if (options.writeBaseline) {
    baseline = writeBaseline(findings, cwd, options.writeBaseline, baseline);
  }

  return {
    scannedAt: now.toISOString(),
    packagesScanned: instances.length,
    findings,
    ignoredFindings: ignoreResult.ignored,
    summary: summarize(findings),
    errors,
    warnings,
    baseline,
  };
}

function deriveCwdFromInputs(
  lockfilePaths: string[],
  sbomPaths: string[],
  fallback: string,
): string {
  const firstInput = lockfilePaths[0] ?? sbomPaths[0];
  return firstInput ? dirname(firstInput) : fallback;
}

export class ScanInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanInputError";
  }
}

function detectLockfiles(cwd: string): string[] {
  const candidates = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ].map((file) => join(cwd, file));
  return candidates.filter((candidate) => existsSync(candidate));
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
  if (a.source !== b.source) return a.source.localeCompare(b.source);
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
  return findings.some(
    (f) => f.baseline !== "existing" && SEVERITY_RANK[f.severity] >= min,
  );
}

function normalizePaths(
  cwd: string,
  value: string | string[] | undefined,
): string[] {
  if (!value) return [];
  const values = Array.isArray(value) ? value : [value];
  return values.map((path) => resolve(cwd, path));
}

function validateFile(path: string): void {
  if (!existsSync(path)) {
    throw new ScanInputError(`Input file does not exist: ${path}`);
  }
  const stat = statSync(path);
  if (!stat.isFile()) {
    throw new ScanInputError(`Input path is not a file: ${path}`);
  }
}
