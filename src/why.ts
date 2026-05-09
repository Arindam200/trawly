import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseLockfile } from "./extractors/lockfile.js";
import type { PackageInstance } from "./types.js";

export interface WhyOptions {
  cwd?: string;
  lockfile?: string | string[];
}

export interface WhyMatch {
  package: PackageInstance;
  chain: string[];
  note?: string;
}

export interface WhyResult {
  packageName: string;
  lockfiles: string[];
  matches: WhyMatch[];
}

export function explainWhy(
  packageName: string,
  options: WhyOptions = {},
): WhyResult {
  const cwd = resolve(options.cwd ?? process.cwd());
  const lockfiles = options.lockfile
    ? normalizePaths(cwd, options.lockfile)
    : detectLockfiles(cwd);
  const packages = lockfiles.flatMap((path) => parseLockfile(path));
  const matches = packages
    .filter((pkg) => pkg.name === packageName)
    .map((pkg) => ({
      package: pkg,
      chain: inferChain(pkg),
      note: graphNote(pkg),
    }))
    .sort((a, b) => {
      const source = (a.package.sourceFile ?? "").localeCompare(
        b.package.sourceFile ?? "",
      );
      if (source !== 0) return source;
      return a.package.path.localeCompare(b.package.path);
    });

  return { packageName, lockfiles, matches };
}

function inferChain(pkg: PackageInstance): string[] {
  if (pkg.manager === "npm") {
    const chain = packageNamesFromNodeModulesPath(pkg.path);
    if (chain.length > 0) return chain;
  }
  return [pkg.name];
}

function graphNote(pkg: PackageInstance): string | undefined {
  if (pkg.manager === "npm") return undefined;
  if (pkg.direct) return "direct dependency";
  return `${pkg.manager ?? "lockfile"} lock entry; full parent chain is not available yet`;
}

function packageNamesFromNodeModulesPath(path: string): string[] {
  const parts = path.split("/");
  const names: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] !== "node_modules") continue;
    const first = parts[i + 1];
    if (!first) continue;
    if (first.startsWith("@")) {
      const second = parts[i + 2];
      if (!second) continue;
      names.push(`${first}/${second}`);
      i += 2;
    } else {
      names.push(first);
      i += 1;
    }
  }
  return names;
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

function normalizePaths(
  cwd: string,
  value: string | string[] | undefined,
): string[] {
  if (!value) return [];
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values.map((path) => resolve(cwd, path)))];
}

