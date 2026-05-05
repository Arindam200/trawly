import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { PackageInstance } from "../types.js";

interface NpmLockEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  hasInstallScript?: boolean;
  dev?: boolean;
  devOptional?: boolean;
  optional?: boolean;
  peer?: boolean;
  link?: boolean;
  // Present on the root ("") entry only.
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface NpmLockfile {
  name?: string;
  lockfileVersion?: number;
  packages?: Record<string, NpmLockEntry>;
}

/**
 * Parse an npm `package-lock.json` (v2 or v3) and return one
 * PackageInstance per node in the `packages` map.
 *
 * The empty-string key represents the root project and is skipped.
 */
export function parseNpmPackageLock(filePath: string): PackageInstance[] {
  const absolute = resolve(filePath);
  const raw = readFileSync(absolute, "utf8");
  let parsed: NpmLockfile;
  try {
    parsed = JSON.parse(raw) as NpmLockfile;
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }

  if (parsed.lockfileVersion !== 2 && parsed.lockfileVersion !== 3) {
    throw new Error(
      `Unsupported npm lockfileVersion ${String(
        parsed.lockfileVersion,
      )} in ${absolute}. Only v2 and v3 are supported.`,
    );
  }

  const packages = parsed.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error(
      `Lockfile ${absolute} has no "packages" map; cannot extract installed versions.`,
    );
  }

  const directDeps = collectDirectDependencyNames(packages[""] ?? {});
  const instances: PackageInstance[] = [];

  for (const [path, entry] of Object.entries(packages)) {
    if (path === "") continue;
    if (entry.link) continue; // workspace symlink, not a real install
    const name = packagePathToName(path);
    if (!name) continue;
    if (!entry.version) continue;

    instances.push({
      name,
      version: entry.version,
      ecosystem: "npm",
      path,
      direct: directDeps.has(name) && isTopLevelInstance(path),
      dev: Boolean(entry.dev || entry.devOptional),
      optional: Boolean(entry.optional || entry.devOptional),
      inputKind: "lockfile",
      sourceFile: absolute,
      line: lineOf(raw, JSON.stringify(path)),
      manager: "npm",
      resolved: entry.resolved,
      integrity: entry.integrity,
      registry: registryFromResolved(entry.resolved),
      hasInstallScript: Boolean(entry.hasInstallScript),
    });
  }

  return instances;
}

function collectDirectDependencyNames(rootEntry: NpmLockEntry): Set<string> {
  const names = new Set<string>();
  for (const key of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ] as const) {
    const block = rootEntry[key];
    if (!block) continue;
    for (const name of Object.keys(block)) names.add(name);
  }
  return names;
}

/**
 * "node_modules/foo" -> "foo"
 * "node_modules/@scope/bar" -> "@scope/bar"
 * "node_modules/foo/node_modules/bar" -> "bar"
 */
export function packagePathToName(path: string): string | null {
  const marker = "node_modules/";
  const idx = path.lastIndexOf(marker);
  if (idx === -1) return null;
  const tail = path.slice(idx + marker.length);
  if (!tail) return null;
  if (tail.startsWith("@")) {
    const firstSlash = tail.indexOf("/");
    if (firstSlash === -1) return null;
    const secondSlash = tail.indexOf("/", firstSlash + 1);
    return secondSlash === -1 ? tail : tail.slice(0, secondSlash);
  }
  const next = tail.indexOf("/");
  return next === -1 ? tail : tail.slice(0, next);
}

/** A direct-install path has exactly one `node_modules/` segment. */
function isTopLevelInstance(path: string): boolean {
  const first = path.indexOf("node_modules/");
  if (first === -1) return false;
  return path.indexOf("node_modules/", first + 1) === -1;
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
