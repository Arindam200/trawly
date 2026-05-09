import { fingerprintFinding } from "./fingerprint.js";
import type { Finding, PackageInstance } from "./types.js";

const REGISTRY_URL = "https://registry.npmjs.org";
const REGISTRY_ENV = "TRAWLY_NPM_REGISTRY_URL";
const REQUEST_TIMEOUT_MS = 15_000;
const NEW_VERSION_DAYS = 30;
const NEW_PACKAGE_DAYS = 90;
const PACKUMENT_CONCURRENCY = 8;
const PACKUMENT_MAX_RETRIES = 3;
const PACKUMENT_BACKOFF_MS = 250;

export interface RiskOptions {
  enabled: boolean;
  allowedRegistries: string[];
  fetchImpl?: typeof fetch;
  now: Date;
}

interface Packument {
  time?: Record<string, string>;
  versions?: Record<string, { deprecated?: string }>;
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
    if (pkg.hasInstallScript) {
      findings.push(riskFinding(pkg, {
        id: "TRAWLY-INSTALL-SCRIPT",
        severity: "moderate",
        summary: `${pkg.name}@${pkg.version} declares install-time scripts or requires a build step.`,
      }));
    }

    const registry = normalizeRegistry(pkg.registry);
    if (registry && !isAllowedRegistry(registry, options.allowedRegistries)) {
      findings.push(riskFinding(pkg, {
        id: "TRAWLY-UNEXPECTED-REGISTRY",
        severity: "moderate",
        summary: `${pkg.name}@${pkg.version} was resolved from unexpected registry ${registry}.`,
      }));
    }
  }

  const npmPackageGroups = groupNpmPackages(packages);
  const fetchImpl = options.fetchImpl ?? fetch;
  // One packument per package name covers every installed version, so fetch
  // by name and reuse across version groups.
  const groupsByName = new Map<string, PackageInstance[][]>();
  for (const group of npmPackageGroups) {
    const name = group[0]?.name;
    if (!name) continue;
    const list = groupsByName.get(name) ?? [];
    list.push(group);
    groupsByName.set(name, list);
  }

  await mapWithConcurrency(
    [...groupsByName.entries()],
    PACKUMENT_CONCURRENCY,
    async ([name, groups]) => {
      let packument: Packument;
      try {
        packument = await fetchPackument(fetchImpl, name);
      } catch (err) {
        warnings.push(
          `Could not fetch npm publish metadata for ${name}: ${(err as Error).message}`,
        );
        return;
      }
      const createdAt = parseDate(packument.time?.created);
      const isNewPackage =
        !!createdAt && daysBetween(createdAt, options.now) < NEW_PACKAGE_DAYS;

      for (const group of groups) {
        const representative = group[0];
        if (!representative) continue;
        const versionAt = parseDate(packument.time?.[representative.version]);
        const deprecated = packument.versions?.[representative.version]?.deprecated;
        if (isNewPackage) {
          for (const pkg of group) {
            findings.push(
              riskFinding(pkg, {
                id: "TRAWLY-NEW-PACKAGE",
                severity: "moderate",
                summary: `${pkg.name} was first published less than ${NEW_PACKAGE_DAYS} days ago.`,
              }),
            );
          }
        }
        if (deprecated) {
          for (const pkg of group) {
            findings.push(
              riskFinding(pkg, {
                id: "TRAWLY-DEPRECATED-PACKAGE",
                severity: "moderate",
                summary: `${pkg.name}@${pkg.version} is deprecated: ${deprecated}`,
              }),
            );
          }
        }
        if (versionAt && daysBetween(versionAt, options.now) < NEW_VERSION_DAYS) {
          for (const pkg of group) {
            findings.push(
              riskFinding(pkg, {
                id: "TRAWLY-NEW-VERSION",
                severity: "low",
                summary: `${pkg.name}@${pkg.version} was published less than ${NEW_VERSION_DAYS} days ago.`,
              }),
            );
          }
        }
      }
    },
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

function groupNpmPackages(packages: PackageInstance[]): PackageInstance[][] {
  const groups = new Map<string, PackageInstance[]>();
  for (const pkg of packages) {
    if (pkg.ecosystem !== "npm") continue;
    const key = `${pkg.name}@${pkg.version}`;
    const group = groups.get(key) ?? [];
    group.push(pkg);
    groups.set(key, group);
  }
  return [...groups.values()];
}

async function fetchPackument(
  fetchImpl: typeof fetch,
  name: string,
): Promise<Packument> {
  const registry = (process.env[REGISTRY_ENV] ?? REGISTRY_URL).replace(/\/+$/, "");
  const url = `${registry}/${encodePackageName(name)}`;
  let lastErr: unknown;

  for (let attempt = 0; attempt <= PACKUMENT_MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetchImpl(url, {
        signal: controller.signal,
        headers: { accept: "application/json" },
      });
      if (res.ok) return (await res.json()) as Packument;

      const err = new RegistryHttpError(
        `registry ${res.status}: ${res.statusText}`,
        res.status,
        retryAfterMs(res.headers),
      );
      if (!isRetryableRegistryError(err) || attempt === PACKUMENT_MAX_RETRIES) {
        throw err;
      }
      lastErr = err;
      await sleep(retryDelayMs(err, attempt));
    } catch (err) {
      if (err instanceof RegistryHttpError) throw err;
      lastErr = err;
      if (attempt === PACKUMENT_MAX_RETRIES) break;
      await sleep(retryDelayMs(undefined, attempt));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastErr;
}

async function mapWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (next < items.length) {
        const item = items[next++];
        if (item !== undefined) await worker(item);
      }
    },
  );
  await Promise.all(workers);
}

class RegistryHttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly retryAfterMs?: number,
  ) {
    super(message);
  }
}

function isRetryableRegistryError(err: RegistryHttpError): boolean {
  return err.status === 429 || err.status >= 500;
}

function retryDelayMs(
  err: RegistryHttpError | undefined,
  attempt: number,
): number {
  if (err?.retryAfterMs !== undefined) return err.retryAfterMs;
  const base = PACKUMENT_BACKOFF_MS * 2 ** attempt;
  return base + Math.floor(Math.random() * Math.min(base, 100));
}

function retryAfterMs(headers: Headers): number | undefined {
  const value = headers.get("retry-after");
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(value);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - Date.now());
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
