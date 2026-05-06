import kleur from "kleur";
import type { EnvIssue, EnvScanResult } from "../env-scan.js";
import type { Severity } from "../types.js";
import { renderBanner } from "./banner.js";

export interface ReportEnvTableOptions {
  /**
   * When true, renders a boxed `trawly` nameplate at the top in place of the
   * plain `trawly env: …` header. CLI sets this only when stdout is a TTY so
   * that piped/CI output stays log-parser friendly.
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

const KIND_LABEL: Record<EnvIssue["kind"], string> = {
  "tracked-by-git": "tracked-by-git",
  "not-gitignored": "not-gitignored",
  "would-be-published": "would-be-published",
  "secret-in-example": "secret-in-example",
  "no-gitignore": "no-gitignore",
};

export function reportEnvTable(
  result: EnvScanResult,
  options: ReportEnvTableOptions = {},
): string {
  const lines: string[] = [];

  if (options.brand) {
    const { metricsLine, timestamp } = headerParts(result);
    lines.push(renderBanner({ metrics: metricsLine, timestamp }));
  } else {
    lines.push(kleur.bold(formatHeader(result)));
  }

  for (const err of result.errors) {
    lines.push(
      kleur.red(`! ${err.message}${err.cause ? ` (${err.cause})` : ""}`),
    );
  }

  if (result.envFiles.length === 0) {
    lines.push("");
    lines.push(kleur.gray("No .env files found in project."));
    return lines.join("\n");
  }

  if (result.issues.length === 0) {
    lines.push("");
    lines.push(kleur.green("✓ No env-leak issues found."));
    lines.push(kleur.gray("  Files checked:"));
    for (const f of result.envFiles) lines.push(kleur.gray(`    ${f}`));
    return lines.join("\n");
  }

  lines.push("");
  lines.push(formatSummary(result.summary));
  lines.push("");

  lines.push(formatIssueRows(result.issues));

  lines.push("");
  lines.push(
    kleur.gray(
      "Reminder: trawly env checks ignore coverage and publish exposure. It cannot prove a secret hasn't already leaked elsewhere — rotate any value you suspect was committed.",
    ),
  );
  return lines.join("\n");
}

function formatIssueRows(issues: EnvIssue[]): string {
  const rows: string[][] = [["SEV", "KIND", "FILE", "MESSAGE", "HINT"]];
  for (const issue of issues) {
    rows.push([
      issue.severity,
      KIND_LABEL[issue.kind],
      issue.file,
      truncate(issue.message, 60),
      issue.detail ? truncate(issue.detail, 60) : ":",
    ]);
  }

  return renderTable(rows, (rowIdx, row, cells) => {
    if (rowIdx === 0) return kleur.bold().underline(cells.join("  "));
    const sev = row[0] as Severity;
    const colorize = SEVERITY_COLOR[sev] ?? ((s: string) => s);
    cells[0] = colorize(cells[0]!);
    cells[2] = kleur.cyan(cells[2]!);
    cells[1] = kleur.bold(cells[1]!);
    return cells.join("  ");
  });
}

function formatHeader(result: EnvScanResult): string {
  const { metricsLine, timestamp } = headerParts(result);
  return `trawly env: ${metricsLine} (${timestamp})`;
}

function headerParts(result: EnvScanResult): {
  metricsLine: string;
  timestamp: string;
} {
  const fileCount = result.envFiles.length;
  const issueCount = result.issues.length;
  const metricsLine = [
    `${fileCount} env file${fileCount === 1 ? "" : "s"} scanned`,
    `${issueCount} issue${issueCount === 1 ? "" : "s"}`,
  ].join(" · ");
  return { metricsLine, timestamp: result.scannedAt };
}

function formatSummary(summary: Record<Severity, number>): string {
  const parts: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const count = summary[sev];
    if (count === 0) continue;
    parts.push(SEVERITY_COLOR[sev](`${sev}: ${count}`));
  }
  if (parts.length === 0) return kleur.green("No findings.");
  return `Issues : ${parts.join("  ")}`;
}

export function reportEnvJson(result: EnvScanResult): string {
  return JSON.stringify(result, null, 2);
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
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

// kleur wraps strings in ANSI escape codes; padEnd needs the visible width.
const ANSI_RE = /\u001B\[[0-9;]*m/g;
function visibleLength(s: string): number {
  return s.replace(ANSI_RE, "").length;
}
function padEndVisible(s: string, width: number): string {
  const pad = Math.max(0, width - visibleLength(s));
  return s + " ".repeat(pad);
}
