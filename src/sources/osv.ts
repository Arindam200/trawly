import { fingerprintFinding, packageKey } from "../fingerprint.js";
import type { Ecosystem, Finding, PackageInstance, Severity } from "../types.js";

const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const QUERY_CHUNK_SIZE = 500;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RETRIES = 2;

interface OsvQueryBatchResponse {
  results: Array<{
    vulns?: Array<{ id: string; modified?: string }>;
    next_page_token?: string;
  }>;
}

interface OsvSeverity {
  type: string;
  score: string;
}

interface OsvAffectedRange {
  type: string;
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

interface OsvAffectedPackage {
  package?: { ecosystem?: string; name?: string; purl?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
  ecosystem_specific?: { severity?: string };
}

interface OsvVulnDetail {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  references?: Array<{ type?: string; url?: string }>;
  severity?: OsvSeverity[];
  database_specific?: { severity?: string };
  affected?: OsvAffectedPackage[];
}

export interface OsvQueryDeps {
  fetchImpl?: typeof fetch;
}

interface UniquePackage {
  name: string;
  version: string;
  ecosystem?: Ecosystem;
  purl?: string;
}

/**
 * Build the deduplicated list of unique name@version pairs to query OSV with.
 */
export function dedupeForQuery(
  packages: PackageInstance[],
): UniquePackage[] {
  const seen = new Set<string>();
  const out: UniquePackage[] = [];
  for (const pkg of packages) {
    const key = packageKey(pkg);
    if (seen.has(key)) continue;
    seen.add(key);
    if (pkg.purl) out.push({ name: pkg.name, version: pkg.version, purl: pkg.purl });
    else if (pkg.ecosystem === "npm") out.push({ name: pkg.name, version: pkg.version });
    else {
      out.push({
        name: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
      });
    }
  }
  return out;
}

/**
 * Query OSV for the given installed packages and return one Finding per
 * (advisory, affected package instance) pair.
 */
export async function queryOsv(
  packages: PackageInstance[],
  deps: OsvQueryDeps = {},
): Promise<Finding[]> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const unique = dedupeForQuery(packages);
  if (unique.length === 0) return [];

  const idsByPackage = new Map<string, Set<string>>();
  for (const chunk of chunked(unique, QUERY_CHUNK_SIZE)) {
    await queryBatchWithPagination(fetchImpl, chunk, idsByPackage);
  }

  const allIds = new Set<string>();
  for (const ids of idsByPackage.values()) {
    for (const id of ids) allIds.add(id);
  }

  const detailsById = new Map<string, OsvVulnDetail>();
  for (const id of allIds) {
    try {
      const detail = await getJson<OsvVulnDetail>(
        fetchImpl,
        `${OSV_VULN_URL}/${encodeURIComponent(id)}`,
      );
      detailsById.set(id, detail);
    } catch {
      // Skip missing/broken records; we still have the id reported below.
    }
  }

  const findings: Finding[] = [];
  for (const pkg of packages) {
    const key = packageKey(pkg);
    const ids = idsByPackage.get(key);
    if (!ids) continue;
    for (const id of ids) {
      const detail = detailsById.get(id);
      findings.push(buildFinding(pkg, id, detail));
    }
  }
  return findings;
}

async function queryBatchWithPagination(
  fetchImpl: typeof fetch,
  initial: UniquePackage[],
  idsByPackage: Map<string, Set<string>>,
): Promise<void> {
  let pending = initial;
  const pageTokens = new Map<string, string>();

  while (pending.length > 0) {
    const res = await postJson<OsvQueryBatchResponse>(
      fetchImpl,
      OSV_QUERYBATCH_URL,
      { queries: pending.map((q) => toOsvQuery(q, pageTokens.get(queryKey(q)))) },
    );

    const next: UniquePackage[] = [];
    res.results.forEach((result, i) => {
      const q = pending[i];
      if (!q) return;
      const key = queryKey(q);
      if (result.vulns && result.vulns.length > 0) {
        const ids = idsByPackage.get(key) ?? new Set<string>();
        for (const v of result.vulns) ids.add(v.id);
        idsByPackage.set(key, ids);
      }
      if (result.next_page_token) {
        pageTokens.set(key, result.next_page_token);
        next.push(q);
      } else {
        pageTokens.delete(key);
      }
    });
    pending = next;
  }
}

function toOsvQuery(
  q: UniquePackage,
  pageToken: string | undefined,
): Record<string, unknown> {
  const query = q.purl
    ? { package: { purl: q.purl } }
    : {
        package: { ecosystem: q.ecosystem ?? "npm", name: q.name },
        version: q.version,
      };
  return pageToken ? { ...query, page_token: pageToken } : query;
}

function queryKey(q: UniquePackage): string {
  return q.purl ?? `${q.ecosystem ?? "npm"}:${q.name}@${q.version}`;
}

function buildFinding(
  pkg: PackageInstance,
  id: string,
  detail: OsvVulnDetail | undefined,
): Finding {
  const severity = detail ? parseSeverity(detail) : "unknown";
  const summary = detail?.summary ?? detail?.details ?? id;
  const aliases = detail?.aliases ?? [];
  const fingerprint = fingerprintFinding({
    source: "osv",
    type: "vulnerability",
    id,
    ecosystem: pkg.ecosystem,
    packageName: pkg.name,
    installedVersion: pkg.version,
  });
  return {
    id,
    source: "osv",
    type: "vulnerability",
    severity,
    ecosystem: pkg.ecosystem,
    packageName: pkg.name,
    installedVersion: pkg.version,
    summary: truncate(summary, 240),
    url: pickAdvisoryUrl(detail) ?? `https://osv.dev/vulnerability/${id}`,
    fixedVersions: detail ? collectFixedVersions(detail, pkg.name) : [],
    affectedPaths: [pkg.path],
    fingerprint,
    aliases,
    sourceFile: pkg.sourceFile,
    line: pkg.line,
  };
}

export function parseSeverity(detail: OsvVulnDetail): Severity {
  // GHSA records expose a normalized severity in database_specific.severity.
  const dbSpecific = detail.database_specific?.severity?.toLowerCase();
  if (
    dbSpecific === "critical" ||
    dbSpecific === "high" ||
    dbSpecific === "moderate" ||
    dbSpecific === "low"
  ) {
    return dbSpecific;
  }
  if (dbSpecific === "medium") return "moderate";

  for (const aff of detail.affected ?? []) {
    const ecosystemSeverity = aff.ecosystem_specific?.severity?.toLowerCase();
    if (
      ecosystemSeverity === "critical" ||
      ecosystemSeverity === "high" ||
      ecosystemSeverity === "moderate" ||
      ecosystemSeverity === "low"
    ) {
      return ecosystemSeverity;
    }
    if (ecosystemSeverity === "medium") return "moderate";
  }

  const cvss = detail.severity?.find((s) => s.type?.startsWith("CVSS_"));
  if (cvss) {
    const score = parseCvssScore(cvss.score);
    if (score === undefined) return "unknown";
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "moderate";
    if (score > 0) return "low";
  }
  return "unknown";
}

function parseCvssScore(vector: string): number | undefined {
  const direct = Number.parseFloat(vector);
  if (!Number.isNaN(direct) && vector.trim() !== "") return direct;
  // Some entries store the full CVSS vector string; we don't compute it here.
  return undefined;
}

function pickAdvisoryUrl(detail: OsvVulnDetail | undefined): string | undefined {
  if (!detail?.references) return undefined;
  const advisory = detail.references.find((r) => r.type === "ADVISORY");
  return advisory?.url ?? detail.references[0]?.url;
}

export function collectFixedVersions(
  detail: OsvVulnDetail,
  packageName: string,
): string[] {
  const out = new Set<string>();
  for (const aff of detail.affected ?? []) {
    if (aff.package?.name && aff.package.name !== packageName) continue;
    for (const range of aff.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) out.add(event.fixed);
      }
    }
  }
  return [...out];
}

function* chunked<T>(items: T[], size: number): Generator<T[]> {
  for (let i = 0; i < items.length; i += size) {
    yield items.slice(i, i + size);
  }
}

async function postJson<T>(
  fetchImpl: typeof fetch,
  url: string,
  body: unknown,
): Promise<T> {
  return withRetry(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new HttpError(
          `OSV ${res.status}: ${res.statusText}`,
          res.status,
          retryAfterMs(res.headers),
        );
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  });
}

async function getJson<T>(fetchImpl: typeof fetch, url: string): Promise<T> {
  return withRetry(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetchImpl(url, { signal: controller.signal });
      if (!res.ok) {
        throw new HttpError(
          `OSV ${res.status}: ${res.statusText}`,
          res.status,
          retryAfterMs(res.headers),
        );
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  });
}

class HttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly retryAfterMs?: number,
  ) {
    super(message);
  }
}

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (!isRetryable(err) || attempt === MAX_RETRIES) break;
      const delay = err instanceof HttpError && err.retryAfterMs !== undefined
        ? err.retryAfterMs
        : 250 * 2 ** attempt;
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

function isRetryable(err: unknown): boolean {
  if (err instanceof HttpError) return err.status === 429 || err.status >= 500;
  // AbortError (timeout) and network errors are retryable.
  return true;
}

function retryAfterMs(headers: Headers): number | undefined {
  const value = headers.get("retry-after");
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(value);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - Date.now());
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}
