export {
  scanProject,
  scanLockfile,
  meetsThreshold,
  summarize,
  compareFindings,
  ScanInputError,
} from "./scanner.js";

export { parseNpmPackageLock } from "./extractors/npm-package-lock.js";
export { parsePnpmLock, parsePnpmPackageKey } from "./extractors/pnpm-lock.js";
export { parseYarnLock, parseYarnDescriptorName } from "./extractors/yarn-lock.js";
export { parseLockfile } from "./extractors/lockfile.js";
export { parseSbom, parsePurlPackage } from "./extractors/sbom.js";
export { queryOsv, dedupeForQuery } from "./sources/osv.js";
export { loadConfig, ConfigError } from "./config.js";
export { SEVERITY_RANK } from "./types.js";
export type {
  Severity,
  Ecosystem,
  FindingType,
  FindingSource,
  InputKind,
  PackageInstance,
  Finding,
  ScanError,
  ScanResult,
  ScanProjectOptions,
  ScanLockfileOptions,
  IgnoreEntry,
  TrawlyConfig,
  BaselineFile,
  BaselineResult,
  FailOnLevel,
} from "./types.js";
