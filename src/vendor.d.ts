declare module "@yarnpkg/lockfile" {
  export function parse(input: string): {
    type: "success" | "merge" | "conflict";
    object: Record<string, unknown>;
  };
}

declare module "packageurl-js" {
  export class PackageURL {
    type: string;
    namespace: string | undefined;
    name: string;
    version: string | undefined;
    qualifiers: Record<string, string> | undefined;
    subpath: string | undefined;
    constructor(
      type: string,
      namespace: string | undefined | null,
      name: string,
      version?: string | undefined | null,
      qualifiers?: Record<string, string> | string | undefined | null,
      subpath?: string | undefined | null,
    );
    toString(): string;
    static fromString(purlStr: string): PackageURL;
  }
}
