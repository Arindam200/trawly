import kleur from "kleur";
import {
  type Finding,
  type ScanResult,
  type Severity,
  SEVERITY_RANK,
} from "../types.js";
import { renderBanner } from "./banner.js";

export type TableView = "grouped" | "details" | "summary";

export interface ReportTableOptions {
  /** @deprecated use `view` instead */
  details?: boolean;
  view?: TableView;
  /**
   * When true, renders a boxed `trawly` nameplate at the top in place of the
   * plain `trawly: …` header. CLI sets this only when stdout is a TTY so that
   * piped/CI output stays log-parser friendly.
   */
  brand?: boolean;
}

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => kleur.bold().red(s),
  high: (s) => kleur.red(s),
  moderate: (s) => kleur.yellow(s),
  low: (s) => kleur.cyan(s),
  unknown: (s) => kleur.gray(s),
};

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "moderate",
  "low",
  "unknown",
];

interface PackageGroup {
  packageName: string;
  installedVersion: string;
  topSeverity: Severity;
  counts: Record<Severity, number>;
  findings: Finding[];
  recommendedFix: string | null;
}

export function reportTable(
  result: ScanResult,
  options: ReportTableOptions = {},
): string {
  const view: TableView = options.view ?? (options.details ? "details" : "grouped");
  const lines: string[] = [];
  const warnings = result.warnings ?? [];
  const ignoredFindings = result.ignoredFindings ?? [];

  if (options.brand) {
    const { metricsLine, timestamp } = headerParts(result);
    lines.push(renderBanner({ metrics: metricsLine, timestamp }));
  } else {
    lines.push(kleur.bold(formatHeader(result)));
  }

  if (result.errors.length > 0) {
    for (const err of result.errors) {
      lines.push(
        kleur.red(`! ${err.message}${err.cause ? ` (${err.cause})` : ""}`),
      );
    }
  }
  if (warnings.length > 0) {
    for (const warning of warnings) {
      lines.push(kleur.yellow(`~ ${warning}`));
    }
  }
  if (ignoredFindings.length > 0) {
    lines.push(
      kleur.gray(`${ignoredFindings.length} finding(s) ignored by config.`),
    );
  }
  if (result.baseline) {
    lines.push(
      kleur.gray(
        `Baseline: ${result.baseline.new} new, ${result.baseline.existing} existing.`,
      ),
    );
  }

  if (result.findings.length === 0) {
    lines.push(kleur.green("✓ No active findings. No known advisories found."));
    lines.push(
      kleur.gray(
        "  Note: this only checks known advisories. It cannot prove a package is safe.",
      ),
    );
    return lines.join("\n");
  }

  if (view === "summary") {
    lines.push(formatSummary(result.summary));
    lines.push(reminder());
    return lines.join("\n");
  }

  lines.push("");
  lines.push(formatSummary(result.summary));
  lines.push("");

  if (view === "details") {
    lines.push(formatDetailRows(sortFindings(result.findings)));
  } else {
    const groups = groupByPackage(result.findings);
    lines.push(formatGroupedRows(groups));
    lines.push("");
    lines.push(
      kleur.gray("Run `trawly scan --details` to see individual advisories."),
    );
  }

  lines.push("");
  lines.push(reminder());
  return lines.join("\n");
}

function formatHeader(result: ScanResult): string {
  const { metricsLine, timestamp } = headerParts(result);
  return `trawly: ${metricsLine} (${timestamp})`;
}

function headerParts(result: ScanResult): {
  metricsLine: string;
  timestamp: string;
} {
  const vulnerable = new Set(
    result.findings.map((f) => `${f.packageName}@${f.installedVersion}`),
  ).size;
  const advisories = result.findings.length;
  const metricsLine = [
    `${result.packagesScanned} packages`,
    `${vulnerable} vulnerable`,
    `${advisories} ${advisories === 1 ? "advisory" : "advisories"}`,
  ].join(" · ");
  return { metricsLine, timestamp: result.scannedAt };
}

function formatSummary(summary: ScanResult["summary"]): string {
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const count = summary[sev];
    if (count === 0) continue;
    parts.push(SEVERITY_COLOR[sev](`${sev}: ${count}`));
  }
  if (parts.length === 0) return kleur.green("No findings.");
  return `Findings : ${parts.join("  ")}`;
}

function reminder(): string {
  return kleur.gray(
    "Reminder: trawly reports known advisories only. Absence of findings is not proof of safety.",
  );
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    const name = a.packageName.localeCompare(b.packageName);
    if (name !== 0) return name;
    return a.id.localeCompare(b.id);
  });
}

function groupByPackage(findings: Finding[]): PackageGroup[] {
  const map = new Map<string, PackageGroup>();
  for (const f of findings) {
    const key = `${f.packageName}@${f.installedVersion}`;
    let group = map.get(key);
    if (!group) {
      group = {
        packageName: f.packageName,
        installedVersion: f.installedVersion,
        topSeverity: f.severity,
        counts: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 },
        findings: [],
        recommendedFix: null,
      };
      map.set(key, group);
    }
    group.findings.push(f);
    group.counts[f.severity] += 1;
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[group.topSeverity]) {
      group.topSeverity = f.severity;
    }
  }

  for (const group of map.values()) {
    group.recommendedFix = pickRecommendedFix(group.findings);
  }

  return [...map.values()].sort((a, b) => {
    const sev = SEVERITY_RANK[b.topSeverity] - SEVERITY_RANK[a.topSeverity];
    if (sev !== 0) return sev;
    const totalA = a.findings.length;
    const totalB = b.findings.length;
    if (totalA !== totalB) return totalB - totalA;
    return a.packageName.localeCompare(b.packageName);
  });
}

function formatGroupedRows(groups: PackageGroup[]): string {
  const rows: string[][] = [
    ["PACKAGE", "VERSION", "SEVERITY", "FIX"],
  ];
  for (const g of groups) {
    rows.push([
      g.packageName,
      g.installedVersion,
      formatSeverityCounts(g.counts),
      g.recommendedFix ? `>=${g.recommendedFix}` : ":",
    ]);
  }
  return renderTable(rows, (rowIdx, _row, cells) => {
    if (rowIdx === 0) return kleur.bold().underline(cells.join("  "));
    return cells.join("  ");
  });
}

function formatDetailRows(findings: Finding[]): string {
  const rows: string[][] = [
    ["SEV", "PACKAGE", "VERSION", "ID", "FIXED IN", "SUMMARY"],
  ];
  for (const f of findings) {
    rows.push([
      f.severity,
      f.packageName,
      f.installedVersion,
      f.id,
      f.fixedVersions.length ? f.fixedVersions.join(", ") : ":",
      truncate(f.summary, 70),
    ]);
  }
  return renderTable(rows, (rowIdx, row, cells) => {
    if (rowIdx === 0) return kleur.bold().underline(cells.join("  "));
    const sev = row[0] as Severity;
    const colorize = SEVERITY_COLOR[sev] ?? ((s: string) => s);
    cells[0] = colorize(cells[0]!);
    return cells.join("  ");
  });
}

function formatSeverityCounts(counts: Record<Severity, number>): string {
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const n = counts[sev];
    if (n === 0) continue;
    parts.push(SEVERITY_COLOR[sev](`${n} ${sev}`));
  }
  return parts.join(", ");
}

function renderTable(
  rows: string[][],
  format: (rowIdx: number, row: string[], cells: string[]) => string,
): string {
  const widths = rows[0]!.map((_, col) =>
    Math.max(...rows.map((r) => visibleLength(r[col]!))),
  );
  return rows
    .map((row, i) => {
      const cells = row.map((cell, col) => padEndVisible(cell, widths[col]!));
      return format(i, row, cells);
    })
    .join("\n");
}

/**
 * Pick the highest semver-ish value across all fixedVersions in the group.
 * Picking the max guarantees the upgrade clears every known advisory; users
 * can drop into `--details` if they want to evaluate alternative fix lines
 * (e.g. staying on a previous major).
 */
function pickRecommendedFix(findings: Finding[]): string | null {
  const candidates: string[] = [];
  for (const f of findings) {
    for (const v of f.fixedVersions) candidates.push(v);
  }
  if (candidates.length === 0) return null;
  const unique = [...new Set(candidates)];
  unique.sort(compareSemver);
  return unique[unique.length - 1] ?? null;
}

function compareSemver(a: string, b: string): number {
  const pa = parseSemverParts(a);
  const pb = parseSemverParts(b);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return a.localeCompare(b);
}

function parseSemverParts(v: string): number[] {
  const m = v.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return [0, 0, 0];
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

// kleur wraps strings in ANSI escape codes; padEnd needs the visible width.
const ANSI_RE = /\u001B\[[0-9;]*m/g;
function visibleLength(s: string): number {
  return s.replace(ANSI_RE, "").length;
}
function padEndVisible(s: string, width: number): string {
  const pad = Math.max(0, width - visibleLength(s));
  return s + " ".repeat(pad);
}
