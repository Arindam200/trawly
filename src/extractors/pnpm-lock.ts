import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { PackageInstance } from "../types.js";
import { readPackageJsonInfoFrom } from "./package-json.js";

interface PnpmDepRef {
  version?: string;
  specifier?: string;
}

interface PnpmPackageEntry {
  resolution?: { integrity?: string; tarball?: string };
  dev?: boolean;
  optional?: boolean;
  requiresBuild?: boolean;
}

interface PnpmLockfile {
  lockfileVersion?: string | number;
  importers?: Record<
    string,
    {
      dependencies?: Record<string, string | PnpmDepRef>;
      devDependencies?: Record<string, string | PnpmDepRef>;
      optionalDependencies?: Record<string, string | PnpmDepRef>;
    }
  >;
  packages?: Record<string, PnpmPackageEntry>;
  snapshots?: Record<string, unknown>;
}

export function parsePnpmLock(filePath: string): PackageInstance[] {
  const absolute = resolve(filePath);
  const raw = readFileSync(absolute, "utf8");
  let parsed: PnpmLockfile;
  try {
    parsed = parseYaml(raw) as PnpmLockfile;
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }

  if (!parsed.packages || typeof parsed.packages !== "object") {
    throw new Error(`Lockfile ${absolute} has no "packages" map.`);
  }

  const rootInfo = readPackageJsonInfoFrom(absolute);
  const importerDirect = collectImporterDirect(parsed);
  const directDeps =
    importerDirect.all.size > 0 ? importerDirect.all : rootInfo.allDirect;
  const devDeps =
    importerDirect.dev.size > 0 ? importerDirect.dev : rootInfo.devDependencies;
  const optionalDeps =
    importerDirect.optional.size > 0
      ? importerDirect.optional
      : rootInfo.optionalDependencies;

  const instances: PackageInstance[] = [];
  for (const [key, entry] of Object.entries(parsed.packages)) {
    const parsedKey = parsePnpmPackageKey(key);
    if (!parsedKey) continue;
    const direct = directDeps.has(parsedKey.name);
    instances.push({
      name: parsedKey.name,
      version: parsedKey.version,
      ecosystem: "npm",
      path: `packages:${key}`,
      direct,
      dev: direct ? devDeps.has(parsedKey.name) : Boolean(entry.dev),
      optional: direct
        ? optionalDeps.has(parsedKey.name)
        : Boolean(entry.optional),
      inputKind: "lockfile",
      sourceFile: absolute,
      line: lineOf(raw, key),
      manager: "pnpm",
      resolved: entry.resolution?.tarball,
      integrity: entry.resolution?.integrity,
      registry: registryFromResolved(entry.resolution?.tarball),
      hasInstallScript: Boolean(entry.requiresBuild),
    });
  }
  return instances;
}

export function parsePnpmPackageKey(
  key: string,
): { name: string; version: string } | null {
  let normalized = key.replace(/^\/+/, "");
  const peerStart = normalized.indexOf("(");
  if (peerStart !== -1) normalized = normalized.slice(0, peerStart);
  normalized = normalized.split("_")[0] ?? normalized;
  const at = normalized.lastIndexOf("@");
  if (at <= 0) return null;
  const name = normalized.slice(0, at);
  const version = normalized.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}

function collectImporterDirect(lock: PnpmLockfile): {
  all: Set<string>;
  dev: Set<string>;
  optional: Set<string>;
} {
  const all = new Set<string>();
  const dev = new Set<string>();
  const optional = new Set<string>();
  for (const importer of Object.values(lock.importers ?? {})) {
    addKeys(importer.dependencies, all);
    addKeys(importer.devDependencies, all, dev);
    addKeys(importer.optionalDependencies, all, optional);
  }
  return { all, dev, optional };
}

function addKeys(
  value: Record<string, string | PnpmDepRef> | undefined,
  all: Set<string>,
  bucket?: Set<string>,
): void {
  if (!value) return;
  for (const name of Object.keys(value)) {
    all.add(name);
    bucket?.add(name);
  }
}

function registryFromResolved(resolved: string | undefined): string | undefined {
  if (!resolved) return undefined;
  try {
    const url = new URL(resolved);
    return `${url.protocol}//${url.host}`;
  } catch {
    return undefined;
  }
}

function lineOf(raw: string, needle: string): number | undefined {
  const idx = raw.indexOf(needle);
  if (idx === -1) return undefined;
  return raw.slice(0, idx).split(/\r?\n/).length;
}
