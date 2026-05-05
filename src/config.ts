import { existsSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { parse as parseToml } from "smol-toml";
import type { FailOnLevel, IgnoreEntry, TrawlyConfig } from "./types.js";

const CONFIG_NAME = "trawly.toml";
const FAIL_ON_VALUES = new Set<FailOnLevel>([
  "critical",
  "high",
  "moderate",
  "low",
  "none",
]);

export interface LoadedConfig {
  path?: string;
  config: TrawlyConfig;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function loadConfig(cwd: string, explicitPath?: string): LoadedConfig {
  const configPath = explicitPath
    ? resolve(cwd, explicitPath)
    : findConfig(cwd);

  if (!configPath) return { config: { ignore: [] } };
  if (!existsSync(configPath)) {
    throw new ConfigError(`Config file does not exist: ${configPath}`);
  }

  let raw: unknown;
  try {
    raw = parseToml(readFileSync(configPath, "utf8"));
  } catch (err) {
    throw new ConfigError(
      `Failed to parse ${configPath}: ${(err as Error).message}`,
    );
  }

  return { path: configPath, config: normalizeConfig(raw, configPath) };
}

function findConfig(cwd: string): string | undefined {
  const candidate = join(cwd, CONFIG_NAME);
  return existsSync(candidate) ? candidate : undefined;
}

function normalizeConfig(raw: unknown, path: string): TrawlyConfig {
  if (!isRecord(raw)) throw new ConfigError(`${path} must be a TOML table.`);

  const failOn = optionalString(raw.failOn, "failOn", path);
  if (failOn !== undefined && !FAIL_ON_VALUES.has(failOn as FailOnLevel)) {
    throw new ConfigError(
      `${path}: failOn must be one of ${[...FAIL_ON_VALUES].join(", ")}.`,
    );
  }

  const risk = optionalBoolean(raw.risk, "risk", path);
  const allowedRegistries = normalizeStringArray(
    raw.allowedRegistries,
    "allowedRegistries",
    path,
  );
  const ignore = normalizeIgnore(raw.ignore ?? raw.IgnoredVulns ?? [], path);

  return {
    failOn: failOn as FailOnLevel | undefined,
    risk,
    allowedRegistries,
    ignore,
  };
}

function normalizeIgnore(raw: unknown, path: string): IgnoreEntry[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new ConfigError(`${path}: ignore must be an array of tables.`);
  }
  return raw.map((item, idx) => {
    if (!isRecord(item)) {
      throw new ConfigError(`${path}: ignore[${idx}] must be a table.`);
    }
    const id = requiredString(item.id, `ignore[${idx}].id`, path);
    const expires = requiredDateString(
      item.expires,
      `ignore[${idx}].expires`,
      path,
    );
    const reason = requiredString(item.reason, `ignore[${idx}].reason`, path);
    return {
      id,
      expires,
      reason,
      package: optionalString(item.package, `ignore[${idx}].package`, path),
      ecosystem: optionalString(item.ecosystem, `ignore[${idx}].ecosystem`, path),
      version: optionalString(item.version, `ignore[${idx}].version`, path),
    };
  });
}

function normalizeStringArray(
  raw: unknown,
  field: string,
  path: string,
): string[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw) || raw.some((v) => typeof v !== "string")) {
    throw new ConfigError(`${path}: ${field} must be an array of strings.`);
  }
  return raw;
}

function requiredDateString(raw: unknown, field: string, path: string): string {
  const value = requiredString(raw, field, path);
  if (!isIsoDate(value)) {
    throw new ConfigError(`${path}: ${field} must be YYYY-MM-DD.`);
  }
  return value;
}

function requiredString(raw: unknown, field: string, path: string): string {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new ConfigError(`${path}: ${field} is required.`);
  }
  return raw;
}

function optionalString(
  raw: unknown,
  field: string,
  path: string,
): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") {
    throw new ConfigError(`${path}: ${field} must be a string.`);
  }
  return raw;
}

function optionalBoolean(
  raw: unknown,
  field: string,
  path: string,
): boolean | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "boolean") {
    throw new ConfigError(`${path}: ${field} must be true or false.`);
  }
  return raw;
}

function isIsoDate(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const date = new Date(`${s}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().startsWith(s);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
