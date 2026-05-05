import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { mkdirSync } from "node:fs";
import type { BaselineFile, BaselineResult, Finding } from "./types.js";

export class BaselineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BaselineError";
  }
}

export function applyBaseline(
  findings: Finding[],
  cwd: string,
  baselinePath?: string,
): BaselineResult | undefined {
  if (!baselinePath) return undefined;
  const absolute = resolve(cwd, baselinePath);
  const loaded = readBaseline(absolute);
  const fingerprints = new Set(loaded.findings);
  let existing = 0;
  let fresh = 0;
  for (const finding of findings) {
    if (fingerprints.has(finding.fingerprint)) {
      finding.baseline = "existing";
      existing++;
    } else {
      finding.baseline = "new";
      fresh++;
    }
  }
  return {
    path: absolute,
    loaded: true,
    total: findings.length,
    existing,
    new: fresh,
  };
}

export function writeBaseline(
  findings: Finding[],
  cwd: string,
  baselinePath: string,
  existing?: BaselineResult,
): BaselineResult {
  const absolute = resolve(cwd, baselinePath);
  const unique = [...new Set(findings.map((f) => f.fingerprint))].sort();
  const payload: BaselineFile = {
    version: 1,
    generatedAt: new Date().toISOString(),
    findings: unique,
  };
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, `${JSON.stringify(payload, null, 2)}\n`);
  return {
    path: existing?.path,
    loaded: existing?.loaded ?? false,
    written: absolute,
    total: findings.length,
    existing: existing?.existing ?? 0,
    new: existing?.new ?? findings.length,
  };
}

function readBaseline(path: string): BaselineFile {
  if (!existsSync(path)) {
    throw new BaselineError(`Baseline file does not exist: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (err) {
    throw new BaselineError(
      `Failed to parse baseline ${path}: ${(err as Error).message}`,
    );
  }
  if (!isRecord(parsed) || parsed.version !== 1) {
    throw new BaselineError(`${path}: unsupported baseline format.`);
  }
  if (!Array.isArray(parsed.findings)) {
    throw new BaselineError(`${path}: findings must be an array.`);
  }
  const findings = parsed.findings.filter((v): v is string => typeof v === "string");
  return {
    version: 1,
    generatedAt:
      typeof parsed.generatedAt === "string" ? parsed.generatedAt : "",
    findings,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
