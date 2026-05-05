import { basename } from "node:path";
import type { PackageInstance } from "../types.js";
import { parseNpmPackageLock } from "./npm-package-lock.js";
import { parsePnpmLock } from "./pnpm-lock.js";
import { parseYarnLock } from "./yarn-lock.js";

export function parseLockfile(filePath: string): PackageInstance[] {
  const file = basename(filePath);
  if (file === "package-lock.json" || file === "npm-shrinkwrap.json") {
    return parseNpmPackageLock(filePath);
  }
  if (file === "pnpm-lock.yaml") return parsePnpmLock(filePath);
  if (file === "yarn.lock") return parseYarnLock(filePath);
  throw new Error(
    `Unsupported lockfile ${filePath}. Supported: package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock.`,
  );
}
