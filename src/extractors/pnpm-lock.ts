import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import yaml from "js-yaml";
import type { PackageInstance } from "../types.js";

interface PnpmDepRef {
  specifier?: string;
  version?: string;
}

type PnpmImporterDeps = Record<string, string | PnpmDepRef>;

interface PnpmImporter {
  dependencies?: PnpmImporterDeps;
  devDependencies?: PnpmImporterDeps;
  optionalDependencies?: PnpmImporterDeps;
}

interface PnpmPackageEntry {
  resolution?: { integrity?: string; tarball?: string };
  name?: string;
  version?: string;
  dev?: boolean;
  optional?: boolean;
}

interface PnpmLockfile {
  lockfileVersion?: number | string;
  importers?: Record<string, PnpmImporter>;
  packages?: Record<string, PnpmPackageEntry>;
  // v6 root-level deps when no importers section
  dependencies?: PnpmImporterDeps;
  devDependencies?: PnpmImporterDeps;
  optionalDependencies?: PnpmImporterDeps;
}

const SUPPORTED_MAJOR_VERSIONS = new Set([6, 9]);

export function parsePnpmLock(filePath: string): PackageInstance[] {
  const absolute = resolve(filePath);
  const raw = readFileSync(absolute, "utf8");
  let parsed: PnpmLockfile;
  try {
    parsed = (yaml.load(raw) ?? {}) as PnpmLockfile;
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }

  const versionRaw = parsed.lockfileVersion;
  const major = parseLockfileMajor(versionRaw);
  if (major === null || !SUPPORTED_MAJOR_VERSIONS.has(major)) {
    throw new Error(
      `Unsupported pnpm lockfileVersion ${String(versionRaw)} in ${absolute}. Supported: 6.x, 9.x.`,
    );
  }

  const packages = parsed.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error(
      `Lockfile ${absolute} has no "packages" map; cannot extract installed versions.`,
    );
  }

  const importers = parsed.importers ?? {
    ".": {
      dependencies: parsed.dependencies,
      devDependencies: parsed.devDependencies,
      optionalDependencies: parsed.optionalDependencies,
    },
  };

  const direct = collectDirectFromImporters(importers);
  const instances: PackageInstance[] = [];

  for (const [key, entry] of Object.entries(packages)) {
    const parsed = parsePnpmPackageKey(key);
    if (!parsed) continue;
    const name = entry.name ?? parsed.name;
    const version = entry.version ?? parsed.version;
    if (!name || !version) continue;

    const isDirect = direct.prod.has(name) || direct.dev.has(name) || direct.optional.has(name);
    const onlyDev = direct.dev.has(name) && !direct.prod.has(name);
    const onlyOptional =
      direct.optional.has(name) && !direct.prod.has(name) && !direct.dev.has(name);

    instances.push({
      name,
      version,
      ecosystem: "npm",
      path: key,
      direct: isDirect,
      dev: Boolean(entry.dev) || onlyDev,
      optional: Boolean(entry.optional) || onlyOptional,
      resolved: entry.resolution?.tarball,
      integrity: entry.resolution?.integrity,
    });
  }

  return instances;
}

function parseLockfileMajor(value: unknown): number | null {
  if (typeof value === "number") return Math.trunc(value);
  if (typeof value === "string") {
    const num = parseInt(value, 10);
    return Number.isNaN(num) ? null : num;
  }
  return null;
}

interface DirectSets {
  prod: Set<string>;
  dev: Set<string>;
  optional: Set<string>;
}

function collectDirectFromImporters(
  importers: Record<string, PnpmImporter>,
): DirectSets {
  const prod = new Set<string>();
  const dev = new Set<string>();
  const optional = new Set<string>();
  for (const importer of Object.values(importers)) {
    if (!importer) continue;
    addDepNames(importer.dependencies, prod);
    addDepNames(importer.devDependencies, dev);
    addDepNames(importer.optionalDependencies, optional);
  }
  return { prod, dev, optional };
}

function addDepNames(block: PnpmImporterDeps | undefined, into: Set<string>): void {
  if (!block) return;
  for (const name of Object.keys(block)) into.add(name);
}

/**
 * pnpm v9: "lodash@4.17.21", "@scope/foo@1.2.3", "vitest@2.0.0(peer)"
 * pnpm v6: "/lodash@4.17.21", "/@scope/foo@1.2.3", "/vitest@2.0.0(peer)"
 */
export function parsePnpmPackageKey(
  key: string,
): { name: string; version: string } | null {
  let working = key.startsWith("/") ? key.slice(1) : key;
  // Strip peer-deps suffix (everything from the first paren onward).
  const parenIdx = working.indexOf("(");
  if (parenIdx !== -1) working = working.slice(0, parenIdx);

  // Find the @ separating name from version. For scoped names (@scope/foo@x.y.z)
  // we must skip the leading @.
  const startSearch = working.startsWith("@") ? 1 : 0;
  const atIdx = working.indexOf("@", startSearch);
  if (atIdx <= 0) return null;
  const name = working.slice(0, atIdx);
  const version = working.slice(atIdx + 1);
  if (!name || !version) return null;
  return { name, version };
}
