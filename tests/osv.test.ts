import { describe, expect, it } from "vitest";
import {
  collectFixedVersions,
  dedupeForQuery,
  parseSeverity,
  queryOsv,
} from "../src/sources/osv.js";
import type { PackageInstance } from "../src/types.js";

function pkg(name: string, version: string, path = `node_modules/${name}`): PackageInstance {
  return {
    name,
    version,
    ecosystem: "npm",
    path,
    direct: true,
    dev: false,
    optional: false,
  };
}

describe("dedupeForQuery", () => {
  it("dedupes by name@version while preserving order", () => {
    const out = dedupeForQuery([
      pkg("foo", "1.0.0", "node_modules/foo"),
      pkg("bar", "2.0.0", "node_modules/bar"),
      pkg("foo", "1.0.0", "node_modules/dep/node_modules/foo"),
      pkg("foo", "1.1.0", "node_modules/foo2"),
    ]);
    expect(out).toEqual([
      { name: "foo", version: "1.0.0" },
      { name: "bar", version: "2.0.0" },
      { name: "foo", version: "1.1.0" },
    ]);
  });
});

describe("parseSeverity", () => {
  it("uses database_specific.severity when available", () => {
    expect(
      parseSeverity({
        id: "x",
        database_specific: { severity: "HIGH" },
      } as Parameters<typeof parseSeverity>[0]),
    ).toBe("high");
  });

  it("normalizes 'medium' to 'moderate'", () => {
    expect(
      parseSeverity({
        id: "x",
        database_specific: { severity: "medium" },
      } as Parameters<typeof parseSeverity>[0]),
    ).toBe("moderate");
  });

  it("falls back to CVSS numeric score buckets", () => {
    expect(
      parseSeverity({
        id: "x",
        severity: [{ type: "CVSS_V3", score: "9.5" }],
      } as Parameters<typeof parseSeverity>[0]),
    ).toBe("critical");
    expect(
      parseSeverity({
        id: "x",
        severity: [{ type: "CVSS_V3", score: "7.5" }],
      } as Parameters<typeof parseSeverity>[0]),
    ).toBe("high");
    expect(
      parseSeverity({
        id: "x",
        severity: [{ type: "CVSS_V3", score: "5.0" }],
      } as Parameters<typeof parseSeverity>[0]),
    ).toBe("moderate");
    expect(
      parseSeverity({
        id: "x",
        severity: [{ type: "CVSS_V3", score: "2.0" }],
      } as Parameters<typeof parseSeverity>[0]),
    ).toBe("low");
  });

  it("returns 'unknown' when no severity data is available", () => {
    expect(
      parseSeverity({ id: "x" } as Parameters<typeof parseSeverity>[0]),
    ).toBe("unknown");
  });
});

describe("collectFixedVersions", () => {
  it("collects fixed events for the matching package", () => {
    const fixed = collectFixedVersions(
      {
        id: "GHSA-x",
        affected: [
          {
            package: { ecosystem: "npm", name: "foo" },
            ranges: [
              {
                type: "ECOSYSTEM",
                events: [{ introduced: "0" }, { fixed: "1.2.3" }],
              },
            ],
          },
          {
            package: { ecosystem: "npm", name: "bar" },
            ranges: [
              { type: "ECOSYSTEM", events: [{ fixed: "9.9.9" }] },
            ],
          },
        ],
      } as Parameters<typeof collectFixedVersions>[0],
      "foo",
    );
    expect(fixed).toEqual(["1.2.3"]);
  });
});

describe("queryOsv", () => {
  it("returns one Finding per (advisory, affected instance) pair", async () => {
    const calls: Array<{ url: string; body?: unknown }> = [];

    const fakeFetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push({ url, body: init?.body });

      if (url.endsWith("/v1/querybatch")) {
        const body = JSON.parse(String(init?.body)) as {
          queries: Array<{ package: { name: string }; version: string }>;
        };
        const results = body.queries.map((q) =>
          q.package.name === "lodash" && q.version === "4.17.20"
            ? { vulns: [{ id: "GHSA-test-1" }] }
            : {},
        );
        return new Response(JSON.stringify({ results }), { status: 200 });
      }

      if (url.includes("/v1/vulns/GHSA-test-1")) {
        return new Response(
          JSON.stringify({
            id: "GHSA-test-1",
            summary: "Prototype pollution",
            database_specific: { severity: "HIGH" },
            references: [
              { type: "ADVISORY", url: "https://example.com/advisory" },
            ],
            affected: [
              {
                package: { ecosystem: "npm", name: "lodash" },
                ranges: [
                  { type: "ECOSYSTEM", events: [{ fixed: "4.17.21" }] },
                ],
              },
            ],
          }),
          { status: 200 },
        );
      }

      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    const findings = await queryOsv(
      [
        pkg("lodash", "4.17.20", "node_modules/lodash"),
        pkg("lodash", "4.17.20", "node_modules/x/node_modules/lodash"),
        pkg("safe-buffer", "5.2.1"),
      ],
      { fetchImpl: fakeFetch },
    );

    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((f) => f.affectedPaths[0]))).toEqual(
      new Set([
        "node_modules/lodash",
        "node_modules/x/node_modules/lodash",
      ]),
    );
    for (const f of findings) {
      expect(f.id).toBe("GHSA-test-1");
      expect(f.severity).toBe("high");
      expect(f.fixedVersions).toEqual(["4.17.21"]);
      expect(f.url).toBe("https://example.com/advisory");
    }
  });

  it("queries PURLs without a top-level version and carries aliases", async () => {
    const calls: Array<{ url: string; body?: unknown }> = [];
    const purlPkg: PackageInstance = {
      name: "django",
      version: "4.2.0",
      ecosystem: "PyPI",
      path: "sbom:django",
      direct: false,
      dev: false,
      optional: false,
      purl: "pkg:pypi/django@4.2.0",
    };

    const fakeFetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push({ url, body: init?.body });
      if (url.endsWith("/v1/querybatch")) {
        return new Response(
          JSON.stringify({ results: [{ vulns: [{ id: "PYSEC-1" }] }] }),
          { status: 200 },
        );
      }
      if (url.endsWith("/v1/vulns/PYSEC-1")) {
        return new Response(
          JSON.stringify({
            id: "PYSEC-1",
            aliases: ["CVE-2026-0001"],
            summary: "Django issue",
            database_specific: { severity: "MEDIUM" },
          }),
          { status: 200 },
        );
      }
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    const findings = await queryOsv([purlPkg], { fetchImpl: fakeFetch });
    const body = JSON.parse(String(calls[0]?.body)) as {
      queries: Array<{ version?: string; package: { purl?: string } }>;
    };

    expect(body.queries[0]).toEqual({
      package: { purl: "pkg:pypi/django@4.2.0" },
    });
    expect(findings[0]).toMatchObject({
      aliases: ["CVE-2026-0001"],
      ecosystem: "PyPI",
      severity: "moderate",
    });
    expect(findings[0]?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it("follows querybatch pagination", async () => {
    let page = 0;
    const fakeFetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/v1/querybatch")) {
        page++;
        const body = JSON.parse(String(init?.body)) as {
          queries: Array<{ page_token?: string }>;
        };
        if (page === 1) {
          return new Response(
            JSON.stringify({
              results: [
                {
                  vulns: [{ id: "GHSA-page-1" }],
                  next_page_token: "next",
                },
              ],
            }),
            { status: 200 },
          );
        }
        expect(body.queries[0]?.page_token).toBe("next");
        return new Response(
          JSON.stringify({
            results: [{ vulns: [{ id: "GHSA-page-2" }] }],
          }),
          { status: 200 },
        );
      }
      const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      return new Response(JSON.stringify({ id, summary: id }), { status: 200 });
    }) as unknown as typeof fetch;

    const findings = await queryOsv([pkg("lodash", "4.17.20")], {
      fetchImpl: fakeFetch,
    });
    expect(findings.map((f) => f.id).sort()).toEqual([
      "GHSA-page-1",
      "GHSA-page-2",
    ]);
  });
});
