import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface PackageJsonInfo {
  dependencies: Set<string>;
  devDependencies: Set<string>;
  optionalDependencies: Set<string>;
  allDirect: Set<string>;
}

export function readPackageJsonInfoFrom(filePath: string): PackageJsonInfo {
  return readPackageJsonInfo(dirname(filePath));
}

export function readPackageJsonInfo(cwd: string): PackageJsonInfo {
  const info: PackageJsonInfo = {
    dependencies: new Set(),
    devDependencies: new Set(),
    optionalDependencies: new Set(),
    allDirect: new Set(),
  };
  const path = join(cwd, "package.json");
  if (!existsSync(path)) return info;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    collect(raw.dependencies, info.dependencies, info.allDirect);
    collect(raw.devDependencies, info.devDependencies, info.allDirect);
    collect(raw.optionalDependencies, info.optionalDependencies, info.allDirect);
    collect(raw.peerDependencies, info.dependencies, info.allDirect);
  } catch {
    return info;
  }
  return info;
}

function collect(
  value: unknown,
  target: Set<string>,
  allDirect: Set<string>,
): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return;
  for (const name of Object.keys(value)) {
    target.add(name);
    allDirect.add(name);
  }
}
