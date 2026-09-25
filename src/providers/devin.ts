import { gunzipSync } from "node:zlib";
import { TextDecoder } from "node:util";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  deleteCachedProvider as deleteCachedProviderFromDisk,
  readCachedDevinProvider as readCachedProviderFromDisk,
} from "../cache.js";
import { providerFetch } from "../lib/http.js";
import { usableLiteralSecret } from "../lib/secret.js";
import { retryAfterToIso } from "../lib/time.js";
import type {
  AuthProviderReport,
  AuthSourceReport,
  ProviderAdapter,
  ProviderOptions,
  ProviderAuthStatus,
  ProviderQuota,
  ProviderStatus,
  QuotaWindow,
  SourceAttempt,
} from "../types.js";
import { VERSION } from "../version.js";
import { staleFromCache } from "./common.js";
import { selectCredential } from "./credential-selection.js";
import {
  clearDevinReadingContextId,
  devinCacheContextId,
  publishDevinReadingContextId,
} from "./devin-cache-context.js";
import { traceInput } from "../lib/input-trace.js";
import {
  createOmpOAuthCredentialBroker,
  type LocalOAuthBroker,
} from "./local-oauth-credential.js";

export const DEVIN_API_ORIGIN = "https://server.codeium.com";
export const DEVIN_USER_STATUS_PATH =
  "/exa.seat_management_pb.SeatManagementService/GetUserStatus";

export const DEVIN_ENV_SOURCE = "env:WINDSURF_API_KEY";
export const DEVIN_FILE_SOURCE = "file:credentials.toml";
export const OMP_DEVIN_SOURCE = "omp:devin";

/**
 * Ownership-stability order. The vendor CLI resolves `WINDSURF_API_KEY` before
 * the credentials file, so a non-blank environment value is this session's
 * identity. A blank value selects nothing and leaves the file path in place.
 */
export const DEVIN_SOURCE_ORDER = [
  DEVIN_ENV_SOURCE,
  DEVIN_FILE_SOURCE,
] as const;

export type DevinSourceName =
  | (typeof DEVIN_SOURCE_ORDER)[number]
  | typeof OMP_DEVIN_SOURCE;

const LABEL = "Devin";
const OPERATION_DEADLINE_MS = 15_000;
const OMP_DEVIN_CLI_VERSION = "3000.6.2";
const OMP_DEVIN_USAGE_METADATA = {
  ideName: "devin-cli",
  ideType: "chisel",
  ideVersion: OMP_DEVIN_CLI_VERSION,
  extensionName: "chisel",
  extensionVersion: OMP_DEVIN_CLI_VERSION,
  locale: "en",
  os:
    process.platform === "darwin"
      ? "darwin"
      : process.platform === "win32"
        ? "windows"
        : "linux",
} as const;
const RESPONSE_LIMIT_BYTES = 1_048_576;
const CREDENTIALS_LIMIT_BYTES = 65_536;
const DAY_SECONDS = 86_400;
const WEEK_SECONDS = 604_800;
const USER_AGENT = `quota-axi/${VERSION}`;
const QUOTA_BILLING = "BILLING_STRATEGY_QUOTA";
const QUOTA_FIELDS = [
  "weeklyQuotaRemainingPercent",
  "weeklyQuotaResetAtUnix",
  "dailyQuotaRemainingPercent",
  "dailyQuotaResetAtUnix",
];
const SIGN_IN_REMEDY = "devin auth login";

/**
 * Vendor session tokens embed one literal `$` separator
 * (`devin-session-token$<jwt>`). `usableLiteralSecret` rejects every `$` so a
 * shell or template reference is never executed; that rule would also refuse
 * every real Devin session. This pattern is the only `$` form accepted, and it
 * is sent verbatim rather than resolved.
 */
const DEVIN_SESSION_TOKEN =
  /^devin-session-token\$[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}$/;

const CREDENTIAL_KEYS = new Set(["windsurf_api_key", "api_server_url"]);

export type DevinResolvedCredential = {
  token: string;
  origin: string;
};

export type DevinLocalResolution =
  | { status: "resolved"; credential: DevinResolvedCredential }
  | { status: "absent" }
  | { status: "structurally_invalid"; error: string }
  | { status: "unsupported"; error: string }
  | { status: "read_error"; error: string };

export type DevinCredentialSource = {
  name: DevinSourceName;
  resolve(): DevinLocalResolution;
  inspect(): {
    status: AuthSourceReport["status"];
    error?: string;
    path?: string;
    credentialPresent?: boolean;
  };
};

export type NormalizedDevinPayload = {
  plan?: string;
  account?: ProviderQuota["account"];
  windows: QuotaWindow[];
  credits?: NonNullable<ProviderQuota["credits"]>;
  untrustedWindowIds: string[];
};

type DevinDependencies = {
  sources: readonly DevinCredentialSource[];
  ompBroker: LocalOAuthBroker;
  fetch: typeof globalThis.fetch;
  readCachedProvider: typeof readCachedProviderFromDisk;
  deleteCachedProvider: (provider: "devin") => void;
  now: () => number;
  deadlineMs: number;
};

type DevinFailureOptions = {
  status?: ProviderStatus;
  staleEligible?: boolean;
  definitiveAuth?: boolean;
  authUsable?: boolean;
  readonly authStatus?: ProviderAuthStatus;
  readonly retryAfter?: string;
};

type ResponseBodyLifetime = {
  markConsumed(): void;
  cancel(action?: () => Promise<unknown> | undefined): Promise<void>;
};

type CredentialFields = {
  windsurf_api_key?: string;
  api_server_url?: string;
};

/**
 * Accept a Devin credential only when it is a literal secret. A vendor session
 * token is allowed through the `$` exception above; every other `$` or `!`
 * form is refused locally and never sent.
 */
export function usableDevinCredential(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (DEVIN_SESSION_TOKEN.test(trimmed)) return trimmed;
  return usableLiteralSecret(trimmed);
}

export function devinCredentialsFilePath(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  options: { platform?: NodeJS.Platform; home?: string } = {},
): string | undefined {
  const platform = options.platform ?? process.platform;
  const home = options.home ?? homedir();
  const xdg = environment.XDG_DATA_HOME?.trim();
  if (xdg) return join(xdg, "devin", "credentials.toml");
  if (platform === "win32") {
    const appData = environment.APPDATA?.trim();
    return appData ? join(appData, "devin", "credentials.toml") : undefined;
  }
  return join(home, ".local", "share", "devin", "credentials.toml");
}

export function createDevinEnvSource(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): DevinCredentialSource {
  const resolve = (): DevinLocalResolution => {
    const raw = environment.WINDSURF_API_KEY;
    if (raw === undefined || raw.trim().length === 0)
      return { status: "absent" };
    return resolutionFromFields({
      windsurf_api_key: raw,
      api_server_url: blankToUndefined(environment.WINDSURF_API_SERVER_URL),
    });
  };
  return {
    name: DEVIN_ENV_SOURCE,
    resolve,
    inspect() {
      return inspectResolution(resolve(), "WINDSURF_API_KEY");
    },
  };
}

export function createDevinFileSource(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  io: {
    readFile?: (path: string) => Uint8Array;
    platform?: NodeJS.Platform;
    home?: string;
  } = {},
): DevinCredentialSource {
  const readFile =
    io.readFile ??
    ((path: string): Uint8Array => {
      traceInput(path);
      const bytes = readFileSync(path);
      return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    });
  const resolve = (): DevinLocalResolution => {
    const path = devinCredentialsFilePath(environment, io);
    if (!path) return { status: "absent" };
    let bytes: Uint8Array;
    try {
      bytes = readFile(path);
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? String((error as { code?: unknown }).code)
          : undefined;
      if (code === "ENOENT") return { status: "absent" };
      return { status: "read_error", error: "devin_credentials_unreadable" };
    }
    if (bytes.byteLength > CREDENTIALS_LIMIT_BYTES) {
      return { status: "read_error", error: "devin_credentials_unreadable" };
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return {
        status: "structurally_invalid",
        error: "devin_credentials_malformed",
      };
    }
    const fields = parseDevinCredentialsToml(text);
    if (!fields) {
      return {
        status: "structurally_invalid",
        error: "devin_credentials_malformed",
      };
    }
    if (fields.windsurf_api_key === undefined) return { status: "absent" };
    return resolutionFromFields(fields);
  };
  return {
    name: DEVIN_FILE_SOURCE,
    resolve,
    inspect() {
      const path = devinCredentialsFilePath(environment, io);
      return inspectResolution(resolve(), path);
    },
  };
}

export function createDevinAdapter(
  overrides: Partial<DevinDependencies> = {},
): ProviderAdapter {
  const dependencies: DevinDependencies = {
    sources: [createDevinEnvSource(), createDevinFileSource()],
    ompBroker: createOmpOAuthCredentialBroker("devin"),
    fetch: providerFetch,
    readCachedProvider: readCachedProviderFromDisk,
    deleteCachedProvider: () => deleteCachedProviderFromDisk("devin"),
    // Resolve Date at call time so a clock swapped in after load still applies
    now: () => Date.now(),
    deadlineMs: OPERATION_DEADLINE_MS,
    ...overrides,
  };
  let inFlight: Promise<ProviderQuota> | undefined;

  return {
    id: "devin",
    label: LABEL,
    isUncertainSkip(attempt) {
      return attempt.error === "unsupported_server";
    },
    fetchQuota(_options: ProviderOptions): Promise<ProviderQuota> {
      if (inFlight) return inFlight;
      const acquisition = acquireDevinQuota(dependencies).finally(() => {
        if (inFlight === acquisition) inFlight = undefined;
      });
      inFlight = acquisition;
      return acquisition;
    },
    async inspectAuth(_options: ProviderOptions): Promise<AuthProviderReport> {
      return inspectAuth(dependencies);
    },
  };
}

export const devinAdapter = createDevinAdapter();

async function inspectAuth(
  dependencies: DevinDependencies,
): Promise<AuthProviderReport> {
  const omp = await dependencies.ompBroker.inspect();
  return {
    provider: "devin",
    sources: [
      ...dependencies.sources.map((source) => {
        try {
          const inspection = source.inspect();
          return {
            source: source.name,
            ...(inspection.path ? { path: inspection.path } : {}),
            status: inspection.status,
            ...(inspection.error ? { error: inspection.error } : {}),
            ...(inspection.credentialPresent
              ? { credentialPresent: true as const }
              : {}),
          };
        } catch {
          return {
            source: source.name,
            status: "error" as const,
            error: "credential_resolution_failed",
          };
        }
      }),
      {
        source: OMP_DEVIN_SOURCE,
        status: omp.status === "unsupported" ? "invalid" : omp.status,
        ...(omp.status === "expired" ? { error: "credentials_expired" } : {}),
      },
    ],
  };
}

async function acquireDevinQuota(
  dependencies: DevinDependencies,
): Promise<ProviderQuota> {
  const controller = new AbortController();
  const deadline = setTimeout(
    () => controller.abort(),
    dependencies.deadlineMs,
  );
  const attempts: SourceAttempt[] = [];
  let rejectedContextId: string | undefined;
  let rejectedFailure: DevinFailure | undefined;
  clearDevinReadingContextId();

  try {
    for (const source of dependencies.sources) {
      const resolution = resolveSource(source);
      if (resolution.status === "absent") {
        attempts.push({
          source: source.name,
          status: "skipped",
          error: "devin_credential_unavailable",
        });
        continue;
      }
      if (resolution.status === "structurally_invalid") {
        attempts.push({
          source: source.name,
          status: "failed",
          error: resolution.error,
          credentialPresent: true,
        });
        // A present but unusable value is the identity the vendor would use.
        // Falling through would report a different account.
        return failureReport(
          new DevinFailure(resolution.error),
          undefined,
          attempts,
          dependencies,
        );
      }
      if (resolution.status === "read_error") {
        attempts.push({
          source: source.name,
          status: "failed",
          error: resolution.error,
        });
        return failureReport(
          new DevinFailure(resolution.error, { staleEligible: true }),
          undefined,
          attempts,
          dependencies,
        );
      }
      if (resolution.status === "unsupported") {
        attempts.push({
          source: source.name,
          status: "skipped",
          error: resolution.error,
          credentialPresent: true,
        });
        return failureReport(
          new DevinFailure(resolution.error),
          undefined,
          attempts,
          dependencies,
        );
      }

      const contextId = devinCacheContextId(
        source.name,
        resolution.credential.origin,
        resolution.credential.token,
      );
      publishDevinReadingContextId(contextId);
      let emptyReading: NormalizedDevinPayload | undefined;
      const selection = await selectCredential(
        [
          {
            source: source.name,
            localState: "valid",
            credential: resolution.credential,
          },
        ],
        async (candidate) => {
          try {
            const payload = await requestUserStatus(
              candidate.credential,
              controller.signal,
              dependencies,
            );
            const normalized = normalizeDevinPayload(
              payload,
              dependencies.now(),
            );
            if (
              normalized.windows.length === 0 &&
              normalized.credits === undefined
            ) {
              emptyReading = normalized;
              return { kind: "live_no_quota" };
            }
            return { kind: "quota", result: normalized };
          } catch (error) {
            const failure = asDevinFailure(error);
            if (failure.definitiveAuth) {
              return { kind: "rejected", error: failure.code };
            }
            return {
              kind: "transient",
              error: failure.code,
              ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
            };
          }
        },
      );

      if (selection.outcome === "quota" && selection.result) {
        attempts.push({ source: source.name, status: "success" });
        return freshReport(selection.result, attempts, dependencies);
      }
      if (selection.outcome === "live_no_quota" && emptyReading) {
        // The credential is live and this source is the session identity.
        // Handover waits for a definitive rejection, not an empty quota body.
        attempts.push({ source: source.name, status: "success" });
        return freshReport(emptyReading, attempts, dependencies);
      }
      if (selection.outcome === "transient") {
        attempts.push({
          source: source.name,
          status: "failed",
          error: selection.transientError,
        });
        return failureReport(
          failureFromTransient(selection.transientError, selection.retryAfter),
          contextId,
          attempts,
          dependencies,
        );
      }

      const error = selection.results[0]?.error ?? "provider_auth_rejected";
      attempts.push({
        source: source.name,
        status: "failed",
        error,
        credentialPresent: true,
      });
      rejectedContextId = contextId;
      rejectedFailure = new DevinFailure(error, {
        status: "auth_required",
        definitiveAuth: true,
      });
    }

    let ompResolution;
    try {
      ompResolution = await dependencies.ompBroker.resolve();
    } catch {
      ompResolution = { status: "error" as const };
    }
    if (
      ompResolution.status === "available" ||
      ompResolution.status === "expired"
    ) {
      const source = OMP_DEVIN_SOURCE;
      const credential = {
        token: ompResolution.credential.accessToken,
        origin: DEVIN_API_ORIGIN,
      };
      const contextId = devinCacheContextId(
        source,
        credential.origin,
        credential.token,
      );
      attempts.push({ source, status: "failed" });
      try {
        const payload = await requestUserStatus(
          credential,
          controller.signal,
          dependencies,
          "omp-protobuf",
        );
        const normalized = normalizeDevinPayload(payload, dependencies.now());
        attempts[attempts.length - 1] = { source, status: "success" };
        publishDevinReadingContextId(contextId);
        return freshReport(normalized, attempts, dependencies, source);
      } catch (error) {
        const failure = asDevinFailure(error);
        attempts[attempts.length - 1] = {
          source,
          status: "failed",
          error: failure.code,
          credentialPresent: true,
        };
        if (
          failure.definitiveAuth &&
          ompResolution.status === "expired" &&
          ompResolution.refreshable
        ) {
          return failureReport(
            new DevinFailure("credentials_expired", {
              status: "unavailable",
              staleEligible: true,
              authStatus: "expired_refreshable",
            }),
            contextId,
            attempts,
            dependencies,
          );
        }
        if (!failure.definitiveAuth) {
          return failureReport(failure, contextId, attempts, dependencies);
        }
        rejectedFailure = failure;
        rejectedContextId = contextId;
      }
    } else {
      attempts.push({
        source: OMP_DEVIN_SOURCE,
        status: ompResolution.status === "missing" ? "skipped" : "failed",
        error: `credentials_${ompResolution.status}`,
        ...(ompResolution.status === "missing"
          ? {}
          : { credentialPresent: true }),
      });
    }

    if (rejectedFailure) {
      return failureReport(
        rejectedFailure,
        rejectedContextId,
        attempts,
        dependencies,
      );
    }
    return failureReport(
      new DevinFailure("devin_credential_unavailable", {
        status: "auth_required",
        definitiveAuth: true,
      }),
      undefined,
      attempts,
      dependencies,
    );
  } catch (error) {
    const failure = asDevinFailure(error);
    if (attempts.length === 0) {
      attempts.push({
        source: DEVIN_ENV_SOURCE,
        status: "failed",
        error: failure.code,
      });
    }
    return failureReport(failure, undefined, attempts, dependencies);
  } finally {
    clearTimeout(deadline);
  }
}

function resolveSource(source: DevinCredentialSource): DevinLocalResolution {
  try {
    return source.resolve();
  } catch {
    return { status: "read_error", error: "credential_resolution_failed" };
  }
}

function freshReport(
  normalized: NormalizedDevinPayload,
  attempts: SourceAttempt[],
  dependencies: DevinDependencies,
  source: ProviderQuota["source"] = "api",
): ProviderQuota {
  return {
    provider: "devin",
    label: LABEL,
    source,
    ...(normalized.plan ? { plan: normalized.plan } : {}),
    ...(normalized.account ? { account: normalized.account } : {}),
    windows: normalized.windows,
    ...(normalized.credits ? { credits: normalized.credits } : {}),
    state: {
      status: "fresh",
      stale: false,
      authStatus: "usable",
      refreshedAt: new Date(dependencies.now()).toISOString(),
      ...(normalized.untrustedWindowIds.length > 0
        ? { untrustedWindowIds: normalized.untrustedWindowIds }
        : {}),
      sourcesTried: attempts.map(({ source }) => source),
    },
    attempts,
  };
}

function failureReport(
  failure: DevinFailure,
  cacheContextId: string | undefined,
  attempts: SourceAttempt[],
  dependencies: DevinDependencies,
): ProviderQuota {
  if (
    failure.definitiveAuth &&
    failure.authStatus !== "expired_refreshable" &&
    cacheContextId
  ) {
    retireMatchingCache(cacheContextId, dependencies);
  }

  if (failure.staleEligible && cacheContextId) {
    try {
      const cached = dependencies.readCachedProvider(cacheContextId);
      const stale = cached
        ? staleFromCache(
            cached,
            failure.code,
            attempts.map(({ source }) => source),
            attempts,
            dependencies.now(),
          )
        : undefined;
      if (stale) {
        return {
          ...stale,
          label: LABEL,
          state: {
            ...stale.state,
            authStatus:
              failure.authStatus ??
              (failure.authUsable ? "usable" : stale.state.authStatus),
            ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
          },
        };
      }
    } catch {
      // Cache I/O cannot replace the bounded current provider failure.
    }
  }

  return {
    provider: "devin",
    label: LABEL,
    source: "unavailable",
    windows: [],
    state: {
      status: failure.status,
      stale: false,
      error: failure.code,
      ...(failure.authStatus
        ? { authStatus: failure.authStatus }
        : failure.authUsable
          ? { authStatus: "usable" as const }
          : failure.definitiveAuth
            ? { authStatus: "unusable" as const }
            : {}),
      ...(failure.status === "auth_required"
        ? { remedyCommand: SIGN_IN_REMEDY }
        : {}),
      ...(failure.retryAfter ? { retryAfter: failure.retryAfter } : {}),
      sourcesTried: attempts.map(({ source }) => source),
    },
    attempts,
  };
}

function retireMatchingCache(
  contextId: string,
  dependencies: DevinDependencies,
): void {
  try {
    if (dependencies.readCachedProvider(contextId)) {
      dependencies.deleteCachedProvider("devin");
    }
  } catch {
    // The current auth failure is still definitive even if the cache is not writable.
  }
}

function failureFromTransient(
  error: string | undefined,
  retryAfter: string | undefined,
): DevinFailure {
  const code = error ?? "provider_unavailable";
  const httpFailure =
    code === "provider_request_rejected" ||
    code === "provider_unavailable" ||
    code === "provider_timeout" ||
    code === "provider_rate_limited";
  return new DevinFailure(code, {
    staleEligible: true,
    ...(httpFailure ? { authUsable: true } : {}),
    ...(code === "provider_rate_limited"
      ? { status: "rate_limited" as const }
      : {}),
    ...(retryAfter ? { retryAfter } : {}),
  });
}

async function requestUserStatus(
  credential: DevinResolvedCredential,
  signal: AbortSignal,
  dependencies: DevinDependencies,
  protocol: "connect-json" | "omp-protobuf" = "connect-json",
): Promise<unknown> {
  const url = new URL(DEVIN_USER_STATUS_PATH, credential.origin).href;
  const isOmp = protocol === "omp-protobuf";
  const body: string | ArrayBuffer = isOmp
    ? encodeOmpDevinRequest(credential.token)
    : JSON.stringify({
        metadata: {
          apiKey: credential.token,
          ideName: "quota-axi",
          ideVersion: VERSION,
          extensionName: "quota-axi",
          extensionVersion: VERSION,
        },
      });
  let response: Response;
  try {
    response = await waitForDeadline(
      dependencies.fetch(url, {
        method: "POST",
        headers: {
          accept: isOmp ? "*/*" : "application/json",
          "content-type": isOmp ? "application/proto" : "application/json",
          "connect-protocol-version": "1",
          ...(!isOmp ? { "user-agent": USER_AGENT } : {}),
        },
        body,
        credentials: "omit",
        redirect: "manual",
        signal,
      }),
      signal,
    );
  } catch (error) {
    if (signal.aborted || isAbortError(error)) {
      throw new DevinFailure("request_timeout", { staleEligible: true });
    }
    throw new DevinFailure(localTransportCode(error), { staleEligible: true });
  }

  const lifetime = createResponseBodyLifetime(response);
  try {
    rejectHttpFailure(response, dependencies.now());
    let bytes: Uint8Array;
    try {
      bytes = await readBoundedBody(response, signal, lifetime);
      lifetime.markConsumed();
    } catch (error) {
      if (error instanceof DevinFailure) throw error;
      if (signal.aborted || isAbortError(error)) {
        throw new DevinFailure("request_timeout", { staleEligible: true });
      }
      throw new DevinFailure("network_unavailable", { staleEligible: true });
    }

    if (isOmp) return decodeOmpDevinResponse(bytes);
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new DevinFailure("response_invalid_utf8", { staleEligible: true });
    }
    let payload: unknown;
    try {
      payload = text.length === 0 ? undefined : (JSON.parse(text) as unknown);
    } catch {
      throw new DevinFailure("malformed_json", { staleEligible: true });
    }
    return payload;
  } finally {
    void lifetime.cancel();
  }
}

type DevinProtoField = {
  number: number;
  wire: number;
  value: bigint | Uint8Array;
};

function encodeOmpDevinRequest(token: string): ArrayBuffer {
  const apiKey = token.startsWith("devin-session-token$")
    ? token
    : `devin-session-token$${token}`;
  const metadata = [
    protoStringField(1, OMP_DEVIN_USAGE_METADATA.ideName),
    protoStringField(7, OMP_DEVIN_USAGE_METADATA.ideVersion),
    protoStringField(28, OMP_DEVIN_USAGE_METADATA.ideType),
    protoStringField(12, OMP_DEVIN_USAGE_METADATA.extensionName),
    protoStringField(2, OMP_DEVIN_USAGE_METADATA.extensionVersion),
    protoStringField(3, apiKey),
    protoStringField(4, OMP_DEVIN_USAGE_METADATA.locale),
    protoStringField(5, OMP_DEVIN_USAGE_METADATA.os),
  ];
  return protoBytesField(1, joinBytes(metadata)).buffer;
}

function protoStringField(
  number: number,
  value: string,
): Uint8Array<ArrayBuffer> {
  return protoBytesField(number, new TextEncoder().encode(value));
}

function protoBytesField(
  number: number,
  value: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  return joinBytes([
    protoVarint(BigInt((number << 3) | 2)),
    protoVarint(BigInt(value.length)),
    value,
  ]);
}

function protoVarint(value: bigint): Uint8Array<ArrayBuffer> {
  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0x7fn) {
    bytes.push(Number((remaining & 0x7fn) | 0x80n));
    remaining >>= 7n;
  }
  bytes.push(Number(remaining));
  const result = new Uint8Array(bytes.length);
  result.set(bytes);
  return result;
}

function joinBytes(
  parts: readonly Uint8Array<ArrayBuffer>[],
): Uint8Array<ArrayBuffer> {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function decodeOmpDevinResponse(bytes: Uint8Array): unknown {
  try {
    return convertOmpDevinResponse(bytes);
  } catch {
    try {
      const unzipped = gunzipSync(bytes, {
        maxOutputLength: RESPONSE_LIMIT_BYTES,
      });
      const decoded = new Uint8Array(unzipped.length);
      decoded.set(unzipped);
      return convertOmpDevinResponse(decoded);
    } catch {
      throw new DevinFailure("response_invalid_protobuf", {
        staleEligible: true,
      });
    }
  }
}

function convertOmpDevinResponse(bytes: Uint8Array): unknown {
  const response = scanDevinProto(bytes);
  const userStatusBytes = protoMessage(response, 1);
  if (!userStatusBytes) {
    throw new DevinFailure("response_invalid_protobuf", {
      staleEligible: true,
    });
  }
  const userStatus = scanDevinProto(userStatusBytes);
  const planStatusBytes = protoMessage(userStatus, 13);
  const planStatus = planStatusBytes
    ? scanDevinProto(planStatusBytes)
    : undefined;
  const planInfoBytes =
    protoMessage(response, 2) ??
    (planStatus ? protoMessage(planStatus, 1) : undefined);
  const planInfo = planInfoBytes ? scanDevinProto(planInfoBytes) : undefined;
  const email = protoString(userStatus, 7);
  const accountId = protoString(userStatus, 36);
  const tier = protoInteger(userStatus, 10);
  const billingStrategy = planInfo ? protoInteger(planInfo, 35) : undefined;
  const planName = planInfo ? protoString(planInfo, 2) : undefined;
  const teamId = protoString(userStatus, 5);
  const devinInfoBytes = planInfo ? protoMessage(planInfo, 33) : undefined;
  const devinInfo = devinInfoBytes ? scanDevinProto(devinInfoBytes) : undefined;
  const organizationId =
    (devinInfo ? protoString(devinInfo, 4) : undefined) || teamId;
  const organization = devinInfo ? protoString(devinInfo, 8) : undefined;
  const mappedPlanStatus = planStatus
    ? mapOmpDevinPlanStatus(planStatus)
    : undefined;
  return {
    userStatus: {
      ...(email ? { email } : {}),
      ...(accountId ? { userId: accountId } : {}),
      ...(organizationId ? { organizationId } : {}),
      ...(organization ? { organization } : {}),
      ...(tier === undefined ? {} : { teamsTier: devinTierName(tier) }),
      ...(mappedPlanStatus ? { planStatus: mappedPlanStatus } : {}),
    },
    ...(planInfo
      ? {
          planInfo: {
            ...(planName ? { planName } : {}),
            billingStrategy: devinBillingStrategy(billingStrategy),
            hideDailyQuota: protoInteger(planInfo, 36) === 1n,
            hideWeeklyQuota: protoInteger(planInfo, 37) === 1n,
            ...protoCreditLimits(planInfo),
          },
        }
      : {}),
  };
}

function mapOmpDevinPlanStatus(
  fields: DevinProtoField[],
): Record<string, string> {
  const mapped: Record<string, string> = {};
  for (const [number, key] of [
    [14, "dailyQuotaRemainingPercent"],
    [15, "weeklyQuotaRemainingPercent"],
    [17, "dailyQuotaResetAtUnix"],
    [18, "weeklyQuotaResetAtUnix"],
    [16, "overageBalanceMicros"],
    [8, "availablePromptCredits"],
    [9, "availableFlowCredits"],
    [4, "availableFlexCredits"],
    [6, "usedPromptCredits"],
    [5, "usedFlowCredits"],
    [7, "usedFlexCredits"],
  ] as const) {
    const value = protoInteger(fields, number);
    if (value !== undefined) mapped[key] = value.toString();
  }
  const planStart = protoTimestampString(fields, 2);
  const planEnd = protoTimestampString(fields, 3);
  if (planStart) mapped.planStart = planStart;
  if (planEnd) mapped.planEnd = planEnd;
  return mapped;
}
function protoCreditLimits(fields: DevinProtoField[]): Record<string, string> {
  const limits: Record<string, string> = {};
  for (const [number, key] of [
    [12, "monthlyPromptCredits"],
    [13, "monthlyFlowCredits"],
    [14, "monthlyFlexCreditPurchaseAmount"],
  ] as const) {
    const value = protoInteger(fields, number);
    if (value !== undefined) limits[key] = value.toString();
  }
  return limits;
}

function protoTimestampString(
  fields: DevinProtoField[],
  number: number,
): string | undefined {
  const bytes = protoMessage(fields, number);
  if (!bytes) return undefined;
  const timestamp = scanDevinProto(bytes);
  const seconds = protoInteger(timestamp, 1);
  const nanos = protoInteger(timestamp, 2) ?? 0n;
  if (seconds === undefined || nanos < 0n || nanos >= 1_000_000_000n) {
    return undefined;
  }
  const milliseconds = Number(seconds) * 1000 + Number(nanos) / 1_000_000;
  if (!Number.isFinite(milliseconds)) return undefined;
  try {
    return new Date(milliseconds).toISOString();
  } catch {
    return undefined;
  }
}

function devinBillingStrategy(value: bigint | undefined): string {
  if (value === 2n) return QUOTA_BILLING;
  if (value === 1n) return "BILLING_STRATEGY_CREDITS";
  if (value === 3n) return "BILLING_STRATEGY_ACU";
  return "BILLING_STRATEGY_UNSPECIFIED";
}

function devinTierName(value: bigint): string {
  const names: Record<string, string> = {
    "1": "TEAMS",
    "2": "PRO",
    "3": "ENTERPRISE_SAAS",
    "4": "HYBRID",
    "5": "ENTERPRISE_SELF_HOSTED",
    "6": "WAITLIST_PRO",
    "7": "TEAMS_ULTIMATE",
    "8": "PRO_ULTIMATE",
    "9": "TRIAL",
    "10": "ENTERPRISE_SELF_SERVE",
    "11": "ENTERPRISE_SAAS_POOLED",
    "12": "DEVIN_ENTERPRISE",
    "14": "DEVIN_TEAMS",
    "15": "DEVIN_TEAMS_V2",
    "16": "DEVIN_PRO",
    "17": "DEVIN_MAX",
    "18": "MAX",
    "19": "DEVIN_FREE",
    "20": "DEVIN_TRIAL",
  };
  return names[value.toString()] ?? "UNSPECIFIED";
}

function scanDevinProto(bytes: Uint8Array): DevinProtoField[] {
  const fields: DevinProtoField[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const key = readDevinVarint(bytes, offset);
    offset = key.offset;
    const number = Number(key.value >> 3n);
    const wire = Number(key.value & 7n);
    if (number < 1 || number > 0x1fffffff) throw new Error("invalid field");
    if (wire === 0) {
      const value = readDevinVarint(bytes, offset);
      fields.push({ number, wire, value: value.value });
      offset = value.offset;
      continue;
    }
    if (wire === 1 || wire === 5) {
      const length = wire === 1 ? 8 : 4;
      if (offset + length > bytes.length) throw new Error("truncated field");
      fields.push({
        number,
        wire,
        value: bytes.subarray(offset, offset + length),
      });
      offset += length;
      continue;
    }
    if (wire === 2) {
      const length = readDevinVarint(bytes, offset);
      offset = length.offset;
      if (length.value > BigInt(RESPONSE_LIMIT_BYTES))
        throw new Error("field too large");
      const end = offset + Number(length.value);
      if (!Number.isSafeInteger(end) || end > bytes.length)
        throw new Error("truncated field");
      fields.push({ number, wire, value: bytes.subarray(offset, end) });
      offset = end;
      continue;
    }
    throw new Error("unsupported wire type");
  }
  return fields;
}

function readDevinVarint(
  bytes: Uint8Array,
  start: number,
): { value: bigint; offset: number } {
  let value = 0n;
  let offset = start;
  for (let index = 0; index < 10 && offset < bytes.length; index += 1) {
    const byte = bytes[offset];
    offset += 1;
    if (index === 9 && byte > 1) throw new Error("invalid varint");
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return { value, offset };
  }
  throw new Error("truncated varint");
}

function protoMessage(
  fields: DevinProtoField[],
  number: number,
): Uint8Array | undefined {
  const field = fields.find(
    (candidate) => candidate.number === number && candidate.wire === 2,
  );
  return field?.value instanceof Uint8Array ? field.value : undefined;
}

function protoString(
  fields: DevinProtoField[],
  number: number,
): string | undefined {
  const value = protoMessage(fields, number);
  return value
    ? new TextDecoder("utf-8", { fatal: true }).decode(value)
    : undefined;
}

function protoInteger(
  fields: DevinProtoField[],
  number: number,
): bigint | undefined {
  const field = fields.find(
    (candidate) => candidate.number === number && candidate.wire === 0,
  );
  return typeof field?.value === "bigint" ? field.value : undefined;
}

function rejectHttpFailure(response: Response, receivedAt: number): void {
  const status = response.status;
  if (status === 200) return;
  if (status >= 300 && status <= 399) {
    throw new DevinFailure("redirect_rejected", { staleEligible: true });
  }
  if (status === 401 || status === 403) {
    throw new DevinFailure("provider_auth_rejected", {
      status: "auth_required",
      definitiveAuth: true,
    });
  }
  if (status === 408) {
    throw new DevinFailure("provider_timeout", {
      authUsable: true,
      staleEligible: true,
    });
  }
  if (status === 429) {
    throw new DevinFailure("provider_rate_limited", {
      status: "rate_limited",
      authUsable: true,
      staleEligible: true,
      retryAfter: retryAfterToIso(
        response.headers.get("retry-after"),
        receivedAt,
      ),
    });
  }
  if (status >= 500 && status <= 599) {
    throw new DevinFailure("provider_unavailable", {
      authUsable: true,
      staleEligible: true,
    });
  }
  throw new DevinFailure("provider_request_rejected", {
    authUsable: true,
    staleEligible: true,
  });
}

/**
 * Normalize a Connect-JSON `GetUserStatus` body.
 *
 * The daily window reuses the existing `session` kind; malformed or elapsed
 * readings stay untrusted.
 * Prompt, flow, and flex credits remain separate vendor-reported buckets and
 * never become binding windows.
 */
export function normalizeDevinPayload(
  payload: unknown,
  now: number,
): NormalizedDevinPayload {
  const root = objectValue(payload);
  const userStatus = objectValue(root?.userStatus);
  if (!root || !userStatus) {
    throw new DevinFailure("schema_invalid", { staleEligible: true });
  }
  if (
    Object.hasOwn(root, "planInfo") &&
    root.planInfo !== undefined &&
    !objectValue(root.planInfo)
  ) {
    throw new DevinFailure("schema_invalid", { staleEligible: true });
  }
  const planInfo = objectValue(root.planInfo);
  if (
    planInfo &&
    Object.hasOwn(planInfo, "billingStrategy") &&
    planInfo.billingStrategy !== undefined &&
    typeof planInfo.billingStrategy !== "string"
  ) {
    throw new DevinFailure("schema_invalid", { staleEligible: true });
  }
  for (const key of ["hideDailyQuota", "hideWeeklyQuota"] as const) {
    if (
      planInfo &&
      Object.hasOwn(planInfo, key) &&
      planInfo[key] !== undefined &&
      typeof planInfo[key] !== "boolean"
    ) {
      throw new DevinFailure("schema_invalid", { staleEligible: true });
    }
  }
  const planStatus = objectValue(userStatus.planStatus);
  if (
    Object.hasOwn(userStatus, "planStatus") &&
    userStatus.planStatus !== undefined &&
    !planStatus
  ) {
    throw new DevinFailure("schema_invalid", { staleEligible: true });
  }

  const plan = nonemptyString(userStatus.teamsTier);
  const email = nonemptyString(userStatus.email);
  const accountId = nonemptyString(userStatus.userId);
  const organization = nonemptyString(userStatus.organization);
  const organizationId = nonemptyString(userStatus.organizationId);
  const account =
    email || accountId || organization || organizationId
      ? {
          ...(email ? { email } : {}),
          ...(accountId ? { accountId } : {}),
          ...(organization ? { organization } : {}),
          ...(organizationId ? { organizationId } : {}),
        }
      : undefined;
  const credits = planStatus
    ? creditsFromMicros(planStatus, planInfo, now)
    : undefined;
  const untrustedWindowIds: string[] = [];
  const windows: QuotaWindow[] = [];
  const quotaFields =
    planStatus !== undefined &&
    QUOTA_FIELDS.some((key) => Object.hasOwn(planStatus, key));
  const quotaPlan = planInfo?.billingStrategy === QUOTA_BILLING;
  const hasPositiveReset =
    planStatus !== undefined &&
    ["dailyQuotaResetAtUnix", "weeklyQuotaResetAtUnix"].some(
      (key) => (integerValue(planStatus[key]) ?? 0) > 0,
    );
  if (
    quotaFields &&
    planInfo?.billingStrategy === undefined &&
    !hasPositiveReset
  ) {
    throw new DevinFailure("schema_incomplete", { staleEligible: true });
  }

  if (planStatus) {
    const candidates = [
      {
        id: "weekly",
        label: "week",
        kind: "weekly" as const,
        duration: WEEK_SECONDS,
        percent: "weeklyQuotaRemainingPercent",
        reset: "weeklyQuotaResetAtUnix",
        hidden: planInfo?.hideWeeklyQuota === true,
      },
      {
        id: "daily",
        label: "day",
        kind: "session" as const,
        duration: DAY_SECONDS,
        percent: "dailyQuotaRemainingPercent",
        reset: "dailyQuotaResetAtUnix",
        hidden: planInfo?.hideDailyQuota === true,
      },
    ];
    let expectedCount = 0;
    for (const candidate of candidates) {
      const hasPositiveReset =
        (integerValue(planStatus[candidate.reset]) ?? 0) > 0;
      if (
        candidate.hidden ||
        (!quotaPlan && !hasPositiveReset) ||
        (!hasPositiveReset && !quotaFields)
      ) {
        continue;
      }
      if (
        candidate.id === "daily" &&
        quotaPlan &&
        planInfo?.hideDailyQuota === undefined &&
        !hasPositiveReset
      ) {
        untrustedWindowIds.push("daily");
        continue;
      }
      expectedCount += 1;
      const window = normalizeQuotaWindow(
        planStatus,
        candidate.id,
        candidate.label,
        candidate.kind,
        candidate.duration,
        candidate.percent,
        candidate.reset,
        now,
      );
      if (window) windows.push(window);
      if (window?.percentRemaining === undefined) {
        untrustedWindowIds.push(candidate.id);
      }
    }
    if (expectedCount > 0 && windows.length === 0) {
      throw new DevinFailure("schema_incomplete", { staleEligible: true });
    }
  }

  return {
    ...(plan ? { plan } : {}),
    ...(account ? { account } : {}),
    windows,
    ...(credits ? { credits } : {}),
    untrustedWindowIds,
  };
}

function normalizeQuotaWindow(
  planStatus: Record<string, unknown>,
  id: string,
  label: string,
  kind: QuotaWindow["kind"],
  windowSeconds: number,
  percentKey: string,
  resetKey: string,
  now: number,
): QuotaWindow | undefined {
  const hasPercent = Object.hasOwn(planStatus, percentKey);
  const hasReset = Object.hasOwn(planStatus, resetKey);
  if (!hasPercent && !hasReset) return undefined;

  const percent = hasPercent
    ? integerPercent(planStatus[percentKey])
    : undefined;
  const resetsAt = hasReset
    ? parseUnixSeconds(planStatus[resetKey])
    : undefined;
  // A reset the vendor says has already passed belongs to a finished cycle.
  if (resetsAt && Date.parse(resetsAt) <= now) return undefined;
  if (hasPercent && percent === undefined) {
    return windowWithoutPercent(id, label, kind, windowSeconds, resetsAt);
  }
  if (!hasPercent && !resetsAt) return undefined;
  const percentRemaining = percent ?? 0;
  const startsAt = resetsAt
    ? new Date(Date.parse(resetsAt) - windowSeconds * 1000).toISOString()
    : undefined;
  return {
    id,
    label,
    kind,
    percentRemaining,
    percentUsed: 100 - percentRemaining,
    windowSeconds,
    ...(startsAt ? { startsAt } : {}),
    ...(resetsAt ? { resetsAt } : {}),
  };
}

function windowWithoutPercent(
  id: string,
  label: string,
  kind: QuotaWindow["kind"],
  windowSeconds: number,
  resetsAt: string | undefined,
): QuotaWindow {
  const startsAt = resetsAt
    ? new Date(Date.parse(resetsAt) - windowSeconds * 1000).toISOString()
    : undefined;
  return {
    id,
    label,
    kind,
    windowSeconds,
    ...(startsAt ? { startsAt } : {}),
    ...(resetsAt ? { resetsAt } : {}),
  };
}

function creditsFromMicros(
  planStatus: Record<string, unknown>,
  planInfo: Record<string, unknown> | undefined,
  now: number,
): NormalizedDevinPayload["credits"] | undefined {
  const credits: NonNullable<NormalizedDevinPayload["credits"]> = {};
  if (Object.hasOwn(planStatus, "overageBalanceMicros")) {
    const micros = integerValue(planStatus.overageBalanceMicros);
    if (micros !== undefined && micros >= 0) {
      credits.remaining = micros / 1_000_000;
      credits.unit = "usd";
    }
  }

  const resetsAt = nonemptyString(planStatus.planEnd);
  if (!resetsAt || Date.parse(resetsAt) > now) {
    const buckets: NonNullable<
      NonNullable<NormalizedDevinPayload["credits"]>["buckets"]
    > = [];
    const startsAt = nonemptyString(planStatus.planStart);
    for (const [id, usedKey, availableKey, limitKey] of [
      [
        "prompt",
        "usedPromptCredits",
        "availablePromptCredits",
        "monthlyPromptCredits",
      ],
      ["flow", "usedFlowCredits", "availableFlowCredits", "monthlyFlowCredits"],
      [
        "flex",
        "usedFlexCredits",
        "availableFlexCredits",
        "monthlyFlexCreditPurchaseAmount",
      ],
    ] as const) {
      const usedValue = integerValue(planStatus[usedKey]);
      const availableValue = integerValue(planStatus[availableKey]);
      const limitValue = integerValue(planInfo?.[limitKey]);
      const used = Math.max(0, usedValue ?? 0);
      const available = Math.max(0, availableValue ?? 0);
      const limit =
        limitValue !== undefined && limitValue > 0 ? limitValue : undefined;
      if (used === 0 && available === 0 && limit === undefined) continue;
      buckets.push({
        id,
        used,
        available,
        unit: "credits",
        ...(limit !== undefined ? { limit } : {}),
        ...(startsAt ? { startsAt } : {}),
        ...(resetsAt ? { resetsAt } : {}),
      });
    }
    if (buckets.length > 0) credits.buckets = buckets;
  }
  return Object.keys(credits).length > 0 ? credits : undefined;
}

function resolutionFromFields(fields: CredentialFields): DevinLocalResolution {
  const token = usableDevinCredential(fields.windsurf_api_key);
  if (!token) {
    return {
      status: "structurally_invalid",
      error: "devin_credential_invalid",
    };
  }
  const origin = classifyOrigin(fields.api_server_url);
  if (origin.status === "invalid") {
    return { status: "structurally_invalid", error: "devin_server_invalid" };
  }
  if (origin.status === "unsupported") {
    return { status: "unsupported", error: "unsupported_server" };
  }
  return { status: "resolved", credential: { token, origin: origin.origin } };
}

function classifyOrigin(
  value: string | undefined,
):
  | { status: "default" | "allowed"; origin: string }
  | { status: "invalid" }
  | { status: "unsupported" } {
  if (value === undefined)
    return { status: "default", origin: DEVIN_API_ORIGIN };
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { status: "invalid" };
  }
  if (
    url.username ||
    url.password ||
    url.protocol !== "https:" ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.search ||
    url.hash ||
    (url.port !== "" && url.port !== "443") ||
    url.hostname !== "server.codeium.com"
  ) {
    return { status: "unsupported" };
  }
  return { status: "allowed", origin: DEVIN_API_ORIGIN };
}

function inspectResolution(
  resolution: DevinLocalResolution,
  path: string | undefined,
): ReturnType<DevinCredentialSource["inspect"]> {
  const located = path ? { path } : {};
  if (resolution.status === "resolved")
    return { status: "available", ...located };
  if (resolution.status === "absent") return { status: "missing", ...located };
  if (resolution.status === "unsupported") {
    return {
      status: "skipped",
      error: resolution.error,
      credentialPresent: true,
      ...located,
    };
  }
  if (resolution.status === "structurally_invalid") {
    return {
      status: "invalid",
      error: resolution.error,
      credentialPresent: true,
      ...located,
    };
  }
  return { status: "error", error: resolution.error, ...located };
}

/**
 * A deliberately narrow TOML reader for the flat credentials file. It keeps
 * only top-level `windsurf_api_key` and `api_server_url`. Other lines and
 * sections are ignored; malformed or duplicate needed values fail closed.
 */
export function parseDevinCredentialsToml(
  text: string,
): CredentialFields | undefined {
  const fields: CredentialFields = {};
  const seen = new Set<string>();
  let inSection = false;
  let index = 0;
  if (text.charCodeAt(0) === 0xfeff) index = 1;
  const source = text;

  const atEnd = (): boolean => index >= source.length;
  const skipIgnorable = (): void => {
    while (!atEnd()) {
      const char = source[index];
      if (char === " " || char === "\t" || char === "\r" || char === "\n") {
        index += 1;
      } else if (char === "#") {
        while (!atEnd() && source[index] !== "\n") index += 1;
      } else {
        return;
      }
    }
  };

  try {
    while (true) {
      skipIgnorable();
      if (atEnd()) return fields;
      const lineEnd = source.indexOf("\n", index);
      const line = source.slice(index, lineEnd < 0 ? undefined : lineEnd);
      if (line.startsWith("[")) inSection = true;
      const key = line.match(/^([A-Za-z0-9_-]+)[ \t]*=/)?.[1];
      if (inSection || !key || !CREDENTIAL_KEYS.has(key)) {
        index = lineEnd < 0 ? source.length : lineEnd + 1;
        continue;
      }
      readKey();
      skipInline();
      if (source[index] !== "=") return undefined;
      index += 1;
      skipInline();
      const value = readString();
      if (value === undefined) return undefined;
      skipInline();
      if (!atEnd() && source[index] === "#") {
        while (!atEnd() && source[index] !== "\n") index += 1;
      }
      if (!atEnd() && source[index] !== "\n" && source[index] !== "\r") {
        return undefined;
      }
      if (seen.has(key)) return undefined;
      seen.add(key);
      if (key === "windsurf_api_key") fields.windsurf_api_key = value;
      if (key === "api_server_url") fields.api_server_url = value;
    }
  } catch {
    return undefined;
  }

  function readKey(): string {
    const start = index;
    while (!atEnd() && /[A-Za-z0-9_-]/.test(source[index])) index += 1;
    if (index === start) throw new Error("key");
    return source.slice(start, index);
  }

  function skipInline(): void {
    while (!atEnd() && (source[index] === " " || source[index] === "\t")) {
      index += 1;
    }
  }

  function readString(): string | undefined {
    const quote = source[index];
    if (quote !== '"' && quote !== "'") return undefined;
    index += 1;
    if (quote === "'") {
      const start = index;
      while (!atEnd() && source[index] !== "'") index += 1;
      if (atEnd()) return undefined;
      const value = source.slice(start, index);
      index += 1;
      return value;
    }
    let value = "";
    while (!atEnd()) {
      const char = source[index];
      if (char === '"') {
        index += 1;
        return value;
      }
      if (char === "\n" || char === "\r") return undefined;
      if (char === "\\") {
        index += 1;
        const escaped = source[index];
        if (escaped === "\\") value += "\\";
        else if (escaped === '"') value += '"';
        else if (escaped === "n") value += "\n";
        else if (escaped === "t") value += "\t";
        else if (escaped === "r") value += "\r";
        else return undefined;
        index += 1;
        continue;
      }
      value += char;
      index += 1;
    }
    return undefined;
  }
}

function integerPercent(value: unknown): number | undefined {
  const number = integerValue(value);
  if (number === undefined || number < 0 || number > 100) return undefined;
  return number;
}

function integerValue(value: unknown): number | undefined {
  if (typeof value === "string" && /^-?(?:0|[1-9]\d*)$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  return undefined;
}

function parseUnixSeconds(value: unknown): string | undefined {
  const seconds = integerValue(value);
  if (seconds === undefined || seconds <= 0) return undefined;
  const ms = seconds * 1000;
  if (!Number.isFinite(ms)) return undefined;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

async function readBoundedBody(
  response: Response,
  signal: AbortSignal,
  lifetime: ResponseBodyLifetime,
): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length")?.trim();
  if (declaredLength && /^\d+$/.test(declaredLength)) {
    if (BigInt(declaredLength) > BigInt(RESPONSE_LIMIT_BYTES)) {
      throw new DevinFailure("response_too_large", { staleEligible: true });
    }
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await readBodyChunk(reader, signal, lifetime);
      if (done) break;
      length += value.length;
      if (length > RESPONSE_LIMIT_BYTES) {
        throw new DevinFailure("response_too_large", { staleEligible: true });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

async function readBodyChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
  lifetime: ResponseBodyLifetime,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  const cancelReader = () => lifetime.cancel(() => reader.cancel());
  if (signal.aborted) {
    void cancelReader();
    throw new DevinFailure("request_timeout", { staleEligible: true });
  }
  return new Promise((resolve, reject) => {
    let aborted = false;
    const abort = () => {
      aborted = true;
      void cancelReader();
      reject(new DevinFailure("request_timeout", { staleEligible: true }));
    };
    signal.addEventListener("abort", abort, { once: true });
    reader.read().then(
      (result) => {
        if (aborted) return;
        signal.removeEventListener("abort", abort);
        resolve(result);
      },
      (error: unknown) => {
        if (aborted) return;
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

function createResponseBodyLifetime(response: Response): ResponseBodyLifetime {
  let consumed = false;
  let cancellation: Promise<void> | undefined;
  return {
    markConsumed() {
      if (!cancellation) consumed = true;
    },
    cancel(action = () => response.body?.cancel()) {
      if (consumed) return Promise.resolve();
      cancellation ??= (async () => {
        try {
          await action();
        } catch {
          // Cancellation only releases the connection; the read already failed.
        }
      })();
      return cancellation;
    },
  };
}

function waitForDeadline<T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(
      new DevinFailure("request_timeout", { staleEligible: true }),
    );
  }
  return new Promise<T>((resolve, reject) => {
    const abort = () =>
      reject(new DevinFailure("request_timeout", { staleEligible: true }));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

function asDevinFailure(error: unknown): DevinFailure {
  return error instanceof DevinFailure
    ? error
    : new DevinFailure("credential_resolution_failed");
}

function localTransportCode(
  error: unknown,
): "tls_failed" | "network_unavailable" {
  const cause = objectValue(objectValue(error)?.cause);
  const code = typeof cause?.code === "string" ? cause.code : undefined;
  return code && /(?:TLS|SSL|CERT|UNABLE_TO_VERIFY)/i.test(code)
    ? "tls_failed"
    : "network_unavailable";
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function nonemptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function blankToUndefined(value: string | undefined): string | undefined {
  if (value === undefined || value.trim().length === 0) return undefined;
  return value.trim();
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

class DevinFailure extends Error {
  readonly code: string;
  readonly status: ProviderStatus;
  readonly staleEligible: boolean;
  readonly definitiveAuth: boolean;
  readonly authUsable: boolean;
  readonly authStatus?: ProviderAuthStatus;
  readonly retryAfter?: string;

  constructor(code: string, options: DevinFailureOptions = {}) {
    super(code);
    this.name = "DevinFailure";
    this.code = code;
    this.status = options.status ?? "error";
    this.staleEligible = options.staleEligible === true;
    this.definitiveAuth = options.definitiveAuth === true;
    this.authUsable = options.authUsable === true;
    this.authStatus = options.authStatus;
    this.retryAfter = options.retryAfter;
  }
}
