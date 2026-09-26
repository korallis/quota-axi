import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { createRequire } from "node:module";
import { readBoundedFile } from "../lib/fs.js";
import { usableLiteralSecret } from "../lib/secret.js";
import { registerInputPathResolver, traceInput } from "../lib/input-trace.js";
import { classifyPiAuthEntry } from "../lib/pi-auth-store.js";
import { resolvePiAuthFilePath } from "../lib/pi-agent-dir.js";

const PI_AUTH_LIMIT_BYTES = 64 * 1024;
const OMP_DATABASE = [".omp", "agent", "agent.db"] as const;
export const OMP_OAUTH_PROVIDERS = [
  "openai-codex",
  "anthropic",
  "google-antigravity",
  "kimi-code",
  "xai-oauth",
  "devin",
] as const;
export type OmpOAuthProvider = (typeof OMP_OAUTH_PROVIDERS)[number];

registerInputPathResolver((identity) => {
  if (identity.startsWith("pi-auth:")) {
    const path = resolvePiAuthFilePath(process.env, homedir);
    return tracedStoreIdentity("pi-auth", path) === identity ? path : undefined;
  }
  if (
    identity.startsWith("omp-agent-db:") ||
    identity.startsWith("omp-agent-db-wal:")
  ) {
    const home = nonempty(process.env.HOME) ?? homedir();
    const databasePath = join(home, ...OMP_DATABASE);
    const path = identity.startsWith("omp-agent-db-wal:")
      ? `${databasePath}-wal`
      : databasePath;
    const source = identity.startsWith("omp-agent-db-wal:")
      ? "omp-agent-db-wal"
      : "omp-agent-db";
    return tracedStoreIdentity(source, path) === identity ? path : undefined;
  }
  return undefined;
});

type StoredOAuthCredential = {
  accessToken: string;
  expiresAt?: number;
  email?: string;
  accountId?: string;
  organization?: string;
  projectId?: string;
  cacheIdentity?: string;
};

export type LocalOAuthResolution =
  | { status: "available"; credential: StoredOAuthCredential }
  | {
      status: "expired";
      credential: StoredOAuthCredential;
      refreshable: boolean;
    }
  | { status: "missing" | "invalid" | "unsupported" | "error" };

export type LocalOAuthBroker = {
  resolve(): Promise<LocalOAuthResolution>;
  inspect(): Promise<{ status: LocalOAuthResolution["status"] }>;
};

type Dependencies = {
  environment: Readonly<Record<string, string | undefined>>;
  homeDirectory: () => string;
  now: () => number;
};

function dependencies(overrides: Partial<Dependencies> = {}): Dependencies {
  return {
    environment: process.env,
    homeDirectory: homedir,
    now: Date.now,
    ...overrides,
  };
}

export function createPiAnthropicCredentialBroker(
  overrides: Partial<Dependencies> = {},
): LocalOAuthBroker {
  const deps = dependencies(overrides);
  return createBroker(() => resolvePiAnthropic(deps));
}

export function createPiAntigravityCredentialBroker(
  overrides: Partial<Dependencies> = {},
): LocalOAuthBroker {
  const deps = dependencies(overrides);
  return createBroker(() => resolvePiAntigravity(deps));
}

export function createOmpOAuthCredentialBroker(
  provider: OmpOAuthProvider,
  overrides: Partial<Dependencies> = {},
): LocalOAuthBroker {
  const deps = dependencies(overrides);
  return createBroker(() => resolveOmpCredential(provider, deps));
}

function createBroker(
  resolve: () => Promise<LocalOAuthResolution>,
): LocalOAuthBroker {
  return {
    resolve,
    inspect: async () => ({ status: (await resolve()).status }),
  };
}

async function resolvePiAnthropic(
  deps: Dependencies,
): Promise<LocalOAuthResolution> {
  const path = resolvePiAuthFilePath(deps.environment, deps.homeDirectory);
  let contents: Buffer;
  try {
    contents = await readBoundedFile(
      path,
      PI_AUTH_LIMIT_BYTES,
      tracedStoreIdentity("pi-auth", path),
    );
  } catch (error) {
    return errorCode(error) === "ENOENT"
      ? { status: "missing" }
      : { status: "error" };
  }
  if (contents.byteLength > PI_AUTH_LIMIT_BYTES) return { status: "invalid" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(contents.toString("utf8")) as unknown;
  } catch {
    return { status: "invalid" };
  }
  const classified = classifyPiAuthEntry(parsed, "anthropic");
  if (classified.status !== "present") return classified;
  const { entry } = classified;
  if (entry.type !== "oauth") return { status: "unsupported" };
  const accessToken = usableLiteralSecret(entry.access);
  if (!accessToken) return { status: "invalid" };
  const expiresAt = timestampMs(entry.expires);
  if (Object.hasOwn(entry, "expires") && expiresAt === undefined) {
    return { status: "invalid" };
  }
  const accountIdentity =
    optionalString(entry.accountId) ?? optionalString(entry.email);
  const credential = {
    accessToken,
    expiresAt,
    ...(accountIdentity
      ? { cacheIdentity: `pi:anthropic:${accountIdentity}` }
      : {}),
  };
  if (expiresAt !== undefined && expiresAt <= deps.now()) {
    return {
      status: "expired",
      credential,
      refreshable: usableLiteralSecret(entry.refresh) !== undefined,
    };
  }
  return { status: "available", credential };
}

async function resolvePiAntigravity(
  deps: Dependencies,
): Promise<LocalOAuthResolution> {
  const path = resolvePiAuthFilePath(deps.environment, deps.homeDirectory);
  let contents: Buffer;
  try {
    contents = await readBoundedFile(
      path,
      PI_AUTH_LIMIT_BYTES,
      tracedStoreIdentity("pi-auth", path),
    );
  } catch (error) {
    return errorCode(error) === "ENOENT"
      ? { status: "missing" }
      : { status: "error" };
  }
  if (contents.byteLength > PI_AUTH_LIMIT_BYTES) return { status: "invalid" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents.toString("utf8")) as unknown;
  } catch {
    return { status: "invalid" };
  }
  const classified = classifyPiAuthEntry(parsed, "google-antigravity");
  if (classified.status !== "present") return classified;
  const { entry } = classified;
  if (entry.type !== "oauth") return { status: "unsupported" };
  const accessToken = usableLiteralSecret(entry.access);
  if (!accessToken) return { status: "invalid" };
  const expiresAt = timestampMs(entry.expires);
  if (Object.hasOwn(entry, "expires") && expiresAt === undefined)
    return { status: "invalid" };
  const credential: StoredOAuthCredential = {
    accessToken,
    expiresAt,
    projectId: optionalString(entry.projectId),
    email: optionalString(entry.email),
    accountId: optionalString(entry.accountId),
  };
  if (expiresAt !== undefined && expiresAt <= deps.now()) {
    return {
      status: "expired",
      credential,
      refreshable: usableLiteralSecret(entry.refresh) !== undefined,
    };
  }
  return { status: "available", credential };
}

async function resolveOmpCredential(
  provider: OmpOAuthProvider,
  deps: Dependencies,
): Promise<LocalOAuthResolution> {
  const home = nonempty(deps.environment.HOME) ?? deps.homeDirectory();
  const path = join(home, ...OMP_DATABASE);
  traceInput(path, tracedStoreIdentity("omp-agent-db", path));
  traceInput(
    `${path}-wal`,
    tracedStoreIdentity("omp-agent-db-wal", `${path}-wal`),
  );
  try {
    await stat(path);
  } catch (error) {
    return errorCode(error) === "ENOENT"
      ? { status: "missing" }
      : { status: "error" };
  }
  try {
    const DatabaseSync = loadDatabaseSync();
    const database = new DatabaseSync(path, { readOnly: true });
    try {
      database.function("usable_refresh", (value: unknown) =>
        Number(usableLiteralSecret(value) !== undefined),
      );
      const row = database
        .prepare(
          `SELECT credential_type AS credentialType,
                  json_extract(data, '$.access') AS access,
                  json_extract(data, '$.expires') AS expires,
                  json_extract(data, '$.email') AS email,
                  json_extract(data, '$.accountId') AS accountId,
                  json_extract(data, '$.orgName') AS organization,
                  json_extract(data, '$.projectId') AS projectId,
                  identity_key AS identityKey,
                  usable_refresh(json_extract(data, '$.refresh')) AS hasRefresh
             FROM auth_credentials
            WHERE provider = ?
              AND credential_type = 'oauth'
              AND disabled_cause IS NULL
            ORDER BY id DESC
            LIMIT 1`,
        )
        .get(provider);
      if (!row) return { status: "missing" };
      const accessToken = ompAccessToken(provider, row.access);
      if (!accessToken) return { status: "invalid" };
      const expiresAt = timestampMs(row.expires);
      if (
        row.expires !== null &&
        row.expires !== undefined &&
        expiresAt === undefined
      ) {
        return { status: "invalid" };
      }
      const identityKey = optionalString(row.identityKey);
      const credential: StoredOAuthCredential = {
        accessToken,
        expiresAt,
        email: optionalString(row.email),
        accountId: optionalString(row.accountId),
        organization: optionalString(row.organization),
        projectId: optionalString(row.projectId),
        ...(identityKey
          ? { cacheIdentity: `omp:${provider}:identity:${identityKey}` }
          : {}),
      };
      if (expiresAt !== undefined && expiresAt <= deps.now()) {
        return {
          status: "expired",
          credential,
          refreshable: row.hasRefresh === 1,
        };
      }
      return { status: "available", credential };
    } finally {
      database.close();
    }
  } catch (error) {
    return errorCode(error) === "ENOENT"
      ? { status: "missing" }
      : { status: "error" };
  }
}

type DatabaseSyncConstructor = new (
  path: string,
  options?: { readOnly?: boolean },
) => {
  prepare(sql: string): {
    get(...params: string[]): Record<string, unknown> | undefined;
  };
  function(name: string, callback: (value: unknown) => number): void;
  close(): void;
};

function loadDatabaseSync(): DatabaseSyncConstructor {
  const emitWarning = process.emitWarning;
  process.emitWarning = ((warning: string | Error, ...args: unknown[]) => {
    const category = typeof args[0] === "string" ? args[0] : undefined;
    if (
      category === "ExperimentalWarning" &&
      String(warning).includes("SQLite is an experimental feature")
    ) {
      return;
    }
    return Reflect.apply(emitWarning, process, [warning, ...args]);
  }) as typeof process.emitWarning;
  try {
    const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
      DatabaseSync: DatabaseSyncConstructor;
    };
    const probe = new DatabaseSync(":memory:");
    probe.close();
    return DatabaseSync;
  } finally {
    process.emitWarning = emitWarning;
  }
}

function timestampMs(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value < 1_000_000_000_000 ? value * 1000 : value;
  }
  if (typeof value === "string" && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) {
      return numeric < 1_000_000_000_000 ? numeric * 1000 : numeric;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
}
function ompAccessToken(
  provider: OmpOAuthProvider,
  value: unknown,
): string | undefined {
  if (
    provider === "devin" &&
    typeof value === "string" &&
    /^devin-session-token\$[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}$/.test(
      value,
    )
  ) {
    return value;
  }
  return usableLiteralSecret(value);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function nonempty(value: string | undefined): string | undefined {
  return value && value.length > 0 ? value : undefined;
}

function tracedStoreIdentity(source: string, path: string): string {
  return `${source}:${createHash("sha256").update(path).digest("hex")}`;
}

function errorCode(error: unknown): string | undefined {
  return error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string"
    ? error.code
    : undefined;
}
