export {
  scanProject,
  scanLockfile,
  meetsThreshold,
  summarize,
  compareFindings,
  ScanInputError,
} from "./scanner.js";

export { parseNpmPackageLock } from "./extractors/npm-package-lock.js";
export { parsePnpmLock } from "./extractors/pnpm-lock.js";
export { parseYarnLock } from "./extractors/yarn-lock.js";
export { queryOsv, dedupeForQuery } from "./sources/osv.js";
export { SEVERITY_RANK } from "./types.js";
export type {
  Severity,
  Ecosystem,
  FindingType,
  PackageInstance,
  Finding,
  ScanError,
  ScanResult,
  ScanProjectOptions,
  ScanLockfileOptions,
  FailOnLevel,
} from "./types.js";
