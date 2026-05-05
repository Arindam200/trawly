import { fingerprintFinding } from "./fingerprint.js";
import type { Finding, PackageInstance } from "./types.js";

const REGISTRY_URL = "https://registry.npmjs.org";
const REQUEST_TIMEOUT_MS = 15_000;
const NEW_VERSION_DAYS = 30;
const NEW_PACKAGE_DAYS = 90;

export interface RiskOptions {
  enabled: boolean;
  allowedRegistries: string[];
  fetchImpl?: typeof fetch;
  now: Date;
}

interface Packument {
  time?: Record<string, string>;
}

export interface RiskResult {
  findings: Finding[];
  warnings: string[];
}

export async function collectRiskSignals(
  packages: PackageInstance[],
  options: RiskOptions,
): Promise<RiskResult> {
  if (!options.enabled) return { findings: [], warnings: [] };

  const findings: Finding[] = [];
  const warnings: string[] = [];
  for (const pkg of packages) {
    if (pkg.hasInstallScript) findings.push(riskFinding(pkg, {
      id: "TRAWLY-INSTALL-SCRIPT",
      severity: "moderate",
      summary: `${pkg.name}@${pkg.version} declares install-time scripts or requires a build step.`,
    }));

    const registry = normalizeRegistry(pkg.registry);
    if (registry && !isAllowedRegistry(registry, options.allowedRegistries)) {
      findings.push(riskFinding(pkg, {
        id: "TRAWLY-UNEXPECTED-REGISTRY",
        severity: "moderate",
        summary: `${pkg.name}@${pkg.version} was resolved from unexpected registry ${registry}.`,
      }));
    }
  }

  const npmPackages = dedupeNpmPackages(packages);
  const fetchImpl = options.fetchImpl ?? fetch;
  await Promise.all(
    npmPackages.map(async (pkg) => {
      try {
        const packument = await fetchPackument(fetchImpl, pkg.name);
        const createdAt = parseDate(packument.time?.created);
        const versionAt = parseDate(packument.time?.[pkg.version]);
        if (createdAt && daysBetween(createdAt, options.now) < NEW_PACKAGE_DAYS) {
          findings.push(riskFinding(pkg, {
            id: "TRAWLY-NEW-PACKAGE",
            severity: "moderate",
            summary: `${pkg.name} was first published less than ${NEW_PACKAGE_DAYS} days ago.`,
          }));
        }
        if (versionAt && daysBetween(versionAt, options.now) < NEW_VERSION_DAYS) {
          findings.push(riskFinding(pkg, {
            id: "TRAWLY-NEW-VERSION",
            severity: "low",
            summary: `${pkg.name}@${pkg.version} was published less than ${NEW_VERSION_DAYS} days ago.`,
          }));
        }
      } catch (err) {
        warnings.push(
          `Could not fetch npm publish metadata for ${pkg.name}: ${(err as Error).message}`,
        );
      }
    }),
  );

  return { findings, warnings };
}

function riskFinding(
  pkg: PackageInstance,
  input: { id: string; severity: Finding["severity"]; summary: string },
): Finding {
  return {
    id: input.id,
    source: "trawly",
    type: "risk-signal",
    severity: input.severity,
    ecosystem: pkg.ecosystem,
    packageName: pkg.name,
    installedVersion: pkg.version,
    summary: input.summary,
    fixedVersions: [],
    affectedPaths: [pkg.path],
    fingerprint: fingerprintFinding({
      source: "trawly",
      type: "risk-signal",
      id: input.id,
      ecosystem: pkg.ecosystem,
      packageName: pkg.name,
      installedVersion: pkg.version,
    }),
    aliases: [],
    sourceFile: pkg.sourceFile,
    line: pkg.line,
  };
}

function dedupeNpmPackages(packages: PackageInstance[]): PackageInstance[] {
  const seen = new Set<string>();
  const out: PackageInstance[] = [];
  for (const pkg of packages) {
    if (pkg.ecosystem !== "npm") continue;
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(pkg);
  }
  return out;
}

async function fetchPackument(
  fetchImpl: typeof fetch,
  name: string,
): Promise<Packument> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetchImpl(`${REGISTRY_URL}/${encodePackageName(name)}`, {
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`registry ${res.status}: ${res.statusText}`);
    }
    return (await res.json()) as Packument;
  } finally {
    clearTimeout(timer);
  }
}

function isAllowedRegistry(registry: string, allowed: string[]): boolean {
  const normalizedAllowed = allowed.map(normalizeRegistry).filter(isString);
  return normalizedAllowed.includes(registry);
}

function normalizeRegistry(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return value.replace(/\/+$/, "");
  }
}

function encodePackageName(name: string): string {
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash !== -1) {
      return `${encodeURIComponent(name.slice(0, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
    }
  }
  return encodeURIComponent(name);
}

function parseDate(value: string | undefined): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function daysBetween(a: Date, b: Date): number {
  return (b.getTime() - a.getTime()) / 86_400_000;
}

function isString(value: string | undefined): value is string {
  return typeof value === "string";
}
