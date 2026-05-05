import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import * as yarnClassicModule from "@yarnpkg/lockfile";
import type { PackageInstance } from "../types.js";
import { readPackageJsonInfoFrom } from "./package-json.js";

const yarnClassic = (
  "parse" in yarnClassicModule
    ? yarnClassicModule
    : (yarnClassicModule as { default: typeof yarnClassicModule }).default
) as { parse(input: string): { type: string; object: Record<string, unknown> } };

interface YarnClassicEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  optionalDependencies?: Record<string, string>;
}

interface YarnBerryEntry {
  version?: string;
  resolution?: string;
  checksum?: string;
  languageName?: string;
  linkType?: string;
}

export function parseYarnLock(filePath: string): PackageInstance[] {
  const absolute = resolve(filePath);
  const raw = readFileSync(absolute, "utf8");
  return isBerryLock(raw)
    ? parseYarnBerryLock(absolute, raw)
    : parseYarnClassicLock(absolute, raw);
}

export function parseYarnClassicLock(
  absolute: string,
  raw: string,
): PackageInstance[] {
  const parsed = yarnClassic.parse(raw);
  if (parsed.type === "conflict") {
    throw new Error(`Yarn lockfile ${absolute} contains merge conflicts.`);
  }
  const rootInfo = readPackageJsonInfoFrom(absolute);
  const instances: PackageInstance[] = [];
  for (const [descriptor, value] of Object.entries(parsed.object)) {
    if (!isRecord(value)) continue;
    const entry = value as YarnClassicEntry;
    if (!entry.version) continue;
    const name = parseYarnDescriptorName(descriptor);
    if (!name) continue;
    const direct = rootInfo.allDirect.has(name);
    instances.push({
      name,
      version: entry.version,
      ecosystem: "npm",
      path: descriptor,
      direct,
      dev: direct ? rootInfo.devDependencies.has(name) : false,
      optional: direct ? rootInfo.optionalDependencies.has(name) : false,
      inputKind: "lockfile",
      sourceFile: absolute,
      line: lineOf(raw, descriptor),
      manager: "yarn",
      resolved: entry.resolved,
      integrity: entry.integrity,
      registry: registryFromResolved(entry.resolved),
      hasInstallScript: false,
    });
  }
  return dedupeInstances(instances);
}

export function parseYarnBerryLock(
  absolute: string,
  raw: string,
): PackageInstance[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseYaml(raw) as Record<string, unknown>;
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }
  const rootInfo = readPackageJsonInfoFrom(absolute);
  const instances: PackageInstance[] = [];
  for (const [descriptor, value] of Object.entries(parsed)) {
    if (descriptor === "__metadata" || !isRecord(value)) continue;
    const entry = value as YarnBerryEntry;
    if (!entry.version) continue;
    const resolution = entry.resolution ?? descriptor;
    if (resolution.includes("@workspace:")) {
      continue;
    }
    const name =
      parseYarnDescriptorName(resolution) ?? parseYarnDescriptorName(descriptor);
    if (!name) continue;
    const direct = rootInfo.allDirect.has(name);
    instances.push({
      name,
      version: entry.version,
      ecosystem: "npm",
      path: descriptor,
      direct,
      dev: direct ? rootInfo.devDependencies.has(name) : false,
      optional: direct ? rootInfo.optionalDependencies.has(name) : false,
      inputKind: "lockfile",
      sourceFile: absolute,
      line: lineOf(raw, descriptor),
      manager: "yarn",
      integrity: entry.checksum,
      hasInstallScript: false,
    });
  }
  return dedupeInstances(instances);
}

export function parseYarnDescriptorName(descriptor: string): string | null {
  const first = descriptor.split(",")[0]?.trim().replace(/^"|"$/g, "");
  if (!first) return null;
  for (const marker of ["@npm:", "@patch:", "@workspace:", "@portal:", "@file:"]) {
    const idx = first.lastIndexOf(marker);
    if (idx > 0) return first.slice(0, idx);
  }
  if (first.startsWith("@")) {
    const slash = first.indexOf("/");
    if (slash === -1) return null;
    const at = first.indexOf("@", slash + 1);
    return at === -1 ? first : first.slice(0, at);
  }
  const at = first.indexOf("@");
  return at === -1 ? first : first.slice(0, at);
}

function isBerryLock(raw: string): boolean {
  return raw.includes("__metadata:") || raw.includes("cacheKey:");
}

function dedupeInstances(instances: PackageInstance[]): PackageInstance[] {
  const seen = new Set<string>();
  const out: PackageInstance[] = [];
  for (const instance of instances) {
    const key = `${instance.name}@${instance.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(instance);
  }
  return out;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
