# trawly

A dependency sanity scanner for JavaScript projects and SBOMs. Reads exact
installed versions from npm, pnpm, and Yarn lockfiles, or from SPDX/CycloneDX
Package URLs, and queries the
[OSV](https://google.github.io/osv.dev/api/) advisory database for known
vulnerabilities. It can also flag lightweight supply-chain risk signals such as
install scripts, unexpected registries, and unusually new packages.

> **Limitation:** trawly reports known advisories. It cannot prove a package is
> safe : absence of findings is not absence of risk.

## Install

```bash
npm install --save-dev trawly
# or run ad-hoc:
npx trawly scan
```

Requires Node.js >= 20.

## Quickstart

```bash
# log-only run (always exits 0) : best for interactive inspection
npx trawly inspect

# gating run : exits non-zero when findings meet --fail-on (default: high). Use this in CI.
npx trawly scan

# scan specific lockfiles or SBOMs
npx trawly scan --lockfile path/to/package-lock.json
npx trawly scan --lockfile pnpm-lock.yaml --lockfile yarn.lock
npx trawly scan --sbom bom.cdx.json --sbom bom.spdx.json

# machine-readable output
npx trawly scan --format json > trawly-report.json
npx trawly scan --format sarif --output trawly.sarif
npx trawly scan --format markdown --output trawly.md

# fail only on findings absent from a saved baseline
npx trawly scan --baseline trawly-baseline.json
npx trawly inspect --write-baseline trawly-baseline.json

# only production deps
npx trawly scan --prod

# show every advisory instead of grouping by package
npx trawly scan --details
```

## Two ways to run

trawly intentionally separates the gating and reporting concerns:

| Command          | Exit code on findings                       | When to use                                   |
| ---------------- | ------------------------------------------- | --------------------------------------------- |
| `trawly scan`    | non-zero (`--fail-on`, default `high`)      | CI, pre-commit, anywhere a build should fail  |
| `trawly inspect` | always 0 unless an operational error occurs | local exploration, dashboards, "just show me" |

Both produce identical output. Only the exit behaviour differs.

## CLI

```
trawly scan [path]      Gating run. Exits non-zero when --fail-on is met.
trawly inspect [path]   Log-only run. Always exits 0 on findings.

Common options (both commands):

  --lockfile <path>          Explicit lockfile path; may be repeated
  --sbom <path>              Explicit SPDX/CycloneDX SBOM path; may be repeated
  --format table|json|markdown|sarif
                             Output format (default: table)
  --output <path>            Write report output to a file
  --config <path>            Path to trawly.toml
  --baseline <path>          Mark existing findings and fail only on new ones
  --write-baseline <path>    Write the current active findings baseline
  --risk / --no-risk         Enable or disable risk signals
  --prod                     Skip dev dependencies
  --include-dev              Include dev dependencies (default)
  --no-cache                 Bypass any local cache
  -v, --details              Show one row per advisory instead of grouping
  -q, --summary              Print only the one-line severity summary

scan-only:
  --fail-on <level>          Severity gate
                             (critical|high|moderate|low|none, default: high)
```

### Exit codes

| Code | Meaning                                                                                       |
| ---- | --------------------------------------------------------------------------------------------- |
| 0    | `inspect`: any outcome with no operational error. `scan`: no finding at or above `--fail-on`. |
| 1    | `scan` only: at least one finding at or above `--fail-on`.                                    |
| 2    | Operational error (e.g. lockfile read failed, OSV unreachable).                               |
| 3    | Invalid CLI input.                                                                            |

## Library API

```ts
import { scanProject, scanLockfile } from "trawly";

const result = await scanProject({ cwd: process.cwd() });
for (const finding of result.findings) {
  console.log(finding.packageName, finding.severity, finding.id);
}
```

The result follows this shape:

```jsonc
{
  "scannedAt": "2026-05-03T12:34:56.000Z",
  "packagesScanned": 412,
  "findings": [
    {
      "id": "GHSA-...",
      "source": "osv",
      "type": "vulnerability",
      "severity": "high",
      "ecosystem": "npm",
      "packageName": "lodash",
      "installedVersion": "4.17.20",
      "summary": "Prototype pollution in lodash",
      "url": "https://github.com/advisories/GHSA-...",
      "fixedVersions": ["4.17.21"],
      "affectedPaths": ["node_modules/lodash"],
      "fingerprint": "sha256...",
      "aliases": ["CVE-..."],
    },
  ],
  "ignoredFindings": [],
  "summary": {
    "critical": 0,
    "high": 1,
    "moderate": 0,
    "low": 0,
    "unknown": 0,
  },
  "errors": [],
  "warnings": [],
}
```

## Config

trawly auto-discovers `trawly.toml` in the scanned project, or you can pass
`--config`.

```toml
failOn = "high"
risk = true
allowedRegistries = ["https://registry.npmjs.org", "https://registry.yarnpkg.com"]

[[ignore]]
id = "GHSA-example"
package = "lodash"
ecosystem = "npm"
expires = "2026-06-30"
reason = "Not reachable in our app"
```

Every ignore entry must include an expiry date.

## CI example (GitHub Actions)

```yaml
name: trawly
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6
      - uses: Arindam200/trawly@main
        with:
          fail-on: high
          upload-sarif: "true"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: trawly-report
          path: |
            trawly.sarif
            trawly.md
```

## Testing

```bash
npm test
npm run typecheck
npm run build

# Extra parser dialect corpus and generated invariant checks.
npm run test:corpus

# Live differential checks against npm, pnpm, Yarn classic, and Yarn Berry.
npm run test:differential

# Larger generated graphs and OSV reliability behavior.
npm run test:stress
```

The optional `trawly-reliability` workflow can run the corpus, package-manager
differential, and stress layers on demand in GitHub Actions.

## Roadmap

Implemented in this branch:

- pnpm and Yarn lockfile support
- SARIF + Markdown reporters and a GitHub Action
- Config file with ignore entries (with required expiry)
- Baseline mode (fail only on new findings)
- Risk signals: install scripts, unexpected registries, package age
- Multi-ecosystem scanning via SBOM (SPDX, CycloneDX)
