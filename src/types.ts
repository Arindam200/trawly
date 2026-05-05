export type Severity = "critical" | "high" | "moderate" | "low" | "unknown";

export type Ecosystem = string;

export type FindingType =
  | "vulnerability"
  | "malware"
  | "risk-signal"
  | "integrity";

export type FindingSource = "osv" | "trawly";

export type InputKind = "lockfile" | "sbom" | "adhoc";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
  unknown: 0,
};

export interface PackageInstance {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** Path within the source manifest, e.g. "node_modules/foo" or an SBOM ref. */
  path: string;
  direct: boolean;
  dev: boolean;
  optional: boolean;
  inputKind?: InputKind;
  purl?: string;
  sourceFile?: string;
  line?: number;
  manager?: "npm" | "pnpm" | "yarn" | "sbom" | string;
  resolved?: string;
  integrity?: string;
  registry?: string;
  hasInstallScript?: boolean;
  publishedAt?: string;
  packagePublishedAt?: string;
}

export interface Finding {
  id: string;
  source: FindingSource;
  type: FindingType;
  severity: Severity;
  ecosystem: Ecosystem;
  packageName: string;
  installedVersion: string;
  summary: string;
  url?: string;
  fixedVersions: string[];
  affectedPaths: string[];
  fingerprint: string;
  aliases: string[];
  sourceFile?: string;
  line?: number;
  ignored?: boolean;
  baseline?: "new" | "existing";
}

export interface ScanError {
  message: string;
  cause?: string;
}

export interface ScanResult {
  scannedAt: string;
  packagesScanned: number;
  findings: Finding[];
  ignoredFindings: Finding[];
  summary: Record<Severity, number>;
  errors: ScanError[];
  warnings: string[];
  baseline?: BaselineResult;
}

export interface IgnoreEntry {
  id: string;
  package?: string;
  ecosystem?: string;
  version?: string;
  expires: string;
  reason: string;
}

export interface TrawlyConfig {
  failOn?: FailOnLevel;
  risk?: boolean;
  allowedRegistries?: string[];
  ignore: IgnoreEntry[];
}

export interface BaselineFile {
  version: 1;
  generatedAt: string;
  findings: string[];
}

export interface BaselineResult {
  path?: string;
  loaded: boolean;
  written?: string;
  total: number;
  existing: number;
  new: number;
}

export interface ScanProjectOptions {
  cwd?: string;
  lockfile?: string | string[];
  sbom?: string | string[];
  config?: string;
  baseline?: string;
  writeBaseline?: string;
  risk?: boolean;
  allowedRegistries?: string[];
  includeDev?: boolean;
  prodOnly?: boolean;
  cache?: boolean;
  fetchImpl?: typeof fetch;
  now?: Date;
}

export interface ScanLockfileOptions {
  lockfilePath: string | string[];
  sbom?: string | string[];
  cwd?: string;
  config?: string;
  baseline?: string;
  writeBaseline?: string;
  risk?: boolean;
  allowedRegistries?: string[];
  includeDev?: boolean;
  prodOnly?: boolean;
  fetchImpl?: typeof fetch;
  now?: Date;
}

export type FailOnLevel = Severity | "none";
