import type { Finding, IgnoreEntry } from "./types.js";

export interface IgnoreResult {
  active: Finding[];
  ignored: Finding[];
  warnings: string[];
}

export function applyIgnores(
  findings: Finding[],
  ignores: IgnoreEntry[],
  now: Date,
): IgnoreResult {
  if (ignores.length === 0) return { active: findings, ignored: [], warnings: [] };

  const warnings: string[] = [];
  const activeIgnores = ignores.filter((entry) => {
    const expires = new Date(`${entry.expires}T23:59:59.999Z`);
    if (Number.isNaN(expires.getTime()) || expires < now) {
      warnings.push(
        `Ignore for ${entry.id} expired on ${entry.expires} and was not applied.`,
      );
      return false;
    }
    return true;
  });

  const active: Finding[] = [];
  const ignored: Finding[] = [];
  for (const finding of findings) {
    const matched = activeIgnores.some((entry) => matchesIgnore(finding, entry));
    if (matched) {
      ignored.push({ ...finding, ignored: true });
    } else {
      active.push(finding);
    }
  }
  return { active, ignored, warnings };
}

function matchesIgnore(finding: Finding, entry: IgnoreEntry): boolean {
  const ids = new Set([finding.id, ...finding.aliases]);
  if (!ids.has(entry.id)) return false;
  if (entry.package && entry.package !== finding.packageName) return false;
  if (entry.ecosystem && entry.ecosystem !== finding.ecosystem) return false;
  if (entry.version && entry.version !== finding.installedVersion) return false;
  return true;
}
