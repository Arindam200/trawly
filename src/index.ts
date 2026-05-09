export {
  scanProject,
  scanLockfile,
  meetsThreshold,
  summarize,
  compareFindings,
  ScanInputError,
} from "./scanner.js";

export { scanEnv, envIssuesMeetThreshold } from "./env-scan.js";
export { initProject } from "./init.js";
export { explainWhy } from "./why.js";
export { POLICY_PRESETS, resolvePolicy } from "./policy.js";
export type {
  EnvIssue,
  EnvIssueKind,
  EnvScanResult,
  EnvScanOptions,
} from "./env-scan.js";

export { parseNpmPackageLock } from "./extractors/npm-package-lock.js";
export { parsePnpmLock, parsePnpmPackageKey } from "./extractors/pnpm-lock.js";
export { parseYarnLock, parseYarnDescriptorName } from "./extractors/yarn-lock.js";
export { parseLockfile } from "./extractors/lockfile.js";
export { parseSbom, parsePurlPackage } from "./extractors/sbom.js";
export { scanEnvFiles } from "./env.js";
export { applyBaseline, writeBaseline, BaselineError } from "./baseline.js";
export type { AppliedBaseline } from "./baseline.js";
export { queryOsv, dedupeForQuery } from "./sources/osv.js";
export { loadConfig, ConfigError } from "./config.js";
export { SEVERITY_RANK } from "./types.js";
export { TRAWLY_VERSION } from "./version.js";
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
  PolicyPresetName,
} from "./types.js";
