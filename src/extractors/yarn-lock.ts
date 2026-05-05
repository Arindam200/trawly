import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import yaml from "js-yaml";
import type { PackageInstance } from "../types.js";

interface YarnEntry {
  specs: string[];
  fields: Record<string, string>;
}

interface BerryEntry {
  version?: string;
  resolution?: string;
  checksum?: string;
  // language and linker keys are ignored
}

/**
 * Parse a yarn lockfile (classic v1 or berry v2+) and return one
 * PackageInstance per resolved entry.
 *
 * Direct/dev flags are inferred by reading the sibling package.json,
 * since yarn lockfiles don't carry that information themselves.
 */
export function parseYarnLock(filePath: string): PackageInstance[] {
  const absolute = resolve(filePath);
  const content = readFileSync(absolute, "utf8");
  const projectDir = dirname(absolute);
  const directs = readDirectDepsFromPackageJson(projectDir);
  const isBerry = /^__metadata:/m.test(content);
  return isBerry
    ? parseBerry(absolute, content, directs)
    : parseClassic(absolute, content, directs);
}

interface DirectSets {
  prod: Set<string>;
  dev: Set<string>;
  optional: Set<string>;
  any: Set<string>;
}

function readDirectDepsFromPackageJson(projectDir: string): DirectSets {
  const result: DirectSets = {
    prod: new Set(),
    dev: new Set(),
    optional: new Set(),
    any: new Set(),
  };
  const pkgPath = join(projectDir, "package.json");
  if (!existsSync(pkgPath)) return result;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    for (const name of Object.keys(pkg.dependencies ?? {})) result.prod.add(name);
    for (const name of Object.keys(pkg.devDependencies ?? {})) result.dev.add(name);
    for (const name of Object.keys(pkg.optionalDependencies ?? {}))
      result.optional.add(name);
    for (const set of [result.prod, result.dev, result.optional]) {
      for (const n of set) result.any.add(n);
    }
    for (const name of Object.keys(pkg.peerDependencies ?? {})) result.any.add(name);
  } catch {
    // malformed package.json: leave sets empty
  }
  return result;
}

// ---------- yarn classic v1 ----------

function parseClassic(
  absolute: string,
  content: string,
  directs: DirectSets,
): PackageInstance[] {
  const entries = parseClassicEntries(content);
  const instances: PackageInstance[] = [];
  for (const entry of entries) {
    const version = entry.fields.version;
    if (!version) continue;
    const names = uniq(entry.specs.map((s) => parseYarnSpec(s).name).filter(Boolean));
    const name = names[0];
    if (!name) continue;
    const isDirect = names.some((n) => directs.any.has(n));
    const inProd = names.some((n) => directs.prod.has(n));
    const inDev = names.some((n) => directs.dev.has(n));
    const inOpt = names.some((n) => directs.optional.has(n));
    instances.push({
      name,
      version,
      ecosystem: "npm",
      path: `${name}@${version}`,
      direct: isDirect,
      dev: inDev && !inProd,
      optional: inOpt && !inProd && !inDev,
      resolved: entry.fields.resolved,
      integrity: entry.fields.integrity,
    });
  }
  void absolute;
  return instances;
}

export function parseClassicEntries(content: string): YarnEntry[] {
  const lines = content.split(/\r?\n/);
  const entries: YarnEntry[] = [];
  let current: YarnEntry | null = null;
  for (const rawLine of lines) {
    if (rawLine === "" || rawLine.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(rawLine)) {
      // Header line ending with ":"
      if (current) entries.push(current);
      const header = rawLine.replace(/:\s*$/, "");
      current = { specs: splitClassicSpecs(header), fields: {} };
      continue;
    }
    if (!current) continue;
    // Top-level field for this entry has indent of exactly 2 spaces.
    const indent = rawLine.match(/^ +/)?.[0].length ?? 0;
    if (indent !== 2) continue;
    const trimmed = rawLine.trim();
    const m =
      trimmed.match(/^([^\s"]+)\s+"((?:[^"\\]|\\.)*)"$/) ??
      trimmed.match(/^([^\s"]+)\s+(\S+)$/);
    if (m && m[1] !== undefined && m[2] !== undefined) {
      current.fields[m[1]] = m[2];
    }
  }
  if (current) entries.push(current);
  return entries;
}

function splitClassicSpecs(header: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  for (const ch of header) {
    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (ch === "," && !inQuote) {
      const spec = cur.trim();
      if (spec) out.push(spec);
      cur = "";
      continue;
    }
    cur += ch;
  }
  const last = cur.trim();
  if (last) out.push(last);
  return out;
}

// ---------- yarn berry (v2+) ----------

function parseBerry(
  absolute: string,
  content: string,
  directs: DirectSets,
): PackageInstance[] {
  let parsed: Record<string, BerryEntry | unknown>;
  try {
    parsed = (yaml.load(content) ?? {}) as Record<string, BerryEntry | unknown>;
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }
  const instances: PackageInstance[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (key === "__metadata") continue;
    if (!value || typeof value !== "object") continue;
    const entry = value as BerryEntry;
    if (!entry.version) continue;
    const specs = splitClassicSpecs(key);
    const names = uniq(specs.map((s) => parseYarnSpec(s).name).filter(Boolean));
    const name = names[0];
    if (!name) continue;
    const isDirect = names.some((n) => directs.any.has(n));
    const inProd = names.some((n) => directs.prod.has(n));
    const inDev = names.some((n) => directs.dev.has(n));
    const inOpt = names.some((n) => directs.optional.has(n));
    instances.push({
      name,
      version: entry.version,
      ecosystem: "npm",
      path: `${name}@${entry.version}`,
      direct: isDirect,
      dev: inDev && !inProd,
      optional: inOpt && !inProd && !inDev,
      resolved: entry.resolution,
      integrity: entry.checksum,
    });
  }
  return instances;
}

// ---------- shared ----------

/**
 * "lodash@^4.17.20" -> { name: "lodash", selector: "^4.17.20" }
 * "@scope/foo@^1.0.0" -> { name: "@scope/foo", selector: "^1.0.0" }
 * Berry: "lodash@npm:^4.17.20" -> { name: "lodash", selector: "^4.17.20" }
 */
export function parseYarnSpec(spec: string): { name: string; selector: string } {
  const startSearch = spec.startsWith("@") ? 1 : 0;
  const atIdx = spec.indexOf("@", startSearch);
  if (atIdx <= 0) return { name: spec, selector: "" };
  const name = spec.slice(0, atIdx);
  let selector = spec.slice(atIdx + 1);
  if (selector.startsWith("npm:")) selector = selector.slice(4);
  return { name, selector };
}

function uniq(values: string[]): string[] {
  return Array.from(new Set(values));
}
