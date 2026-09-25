import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  currentUserProcessListArgs,
  type ExecFileTextOptions,
} from "../../src/lib/process.js";
import {
  agyOmpCredentialContextId,
  readCachedProvider,
  stampAgyOmpCredentialContextId,
  writeCachedProviders,
} from "../../src/cache.js";
import {
  AGY_NOT_RUNNING,
  fetchQuota,
  fetchQuotaWithRuntime,
  inspectAuthWithRuntime,
  normalizeAgyPrintUsage,
  normalizeAgyQuotaSummary,
  normalizeAgyUserStatus,
  portsFromLsof,
  processInfosFromPs,
  requestLoopbackJson,
  type AgyConnectionEndpoint,
  type AgyProbeRuntime,
} from "../../src/providers/agy.js";
import { withQuotaSemantics } from "../../src/interpretation.js";
import type { ProviderQuota } from "../../src/types.js";

const originalXdgCacheHome = process.env.XDG_CACHE_HOME;
const originalPath = process.env.PATH;
const originalWorkingDirectory = process.cwd();
let tempDir: string | undefined;
const servers: ReturnType<typeof createServer>[] = [];

beforeEach(() => {
  useTempCache();
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  await Promise.all(
    servers.splice(0).map((server) => {
      server.closeAllConnections();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    }),
  );
  if (originalXdgCacheHome === undefined) delete process.env.XDG_CACHE_HOME;
  else process.env.XDG_CACHE_HOME = originalXdgCacheHome;
  if (originalPath === undefined) delete process.env.PATH;
  else process.env.PATH = originalPath;
  process.chdir(originalWorkingDirectory);
  if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  tempDir = undefined;
});

describe("Antigravity quota parsing", () => {
  it("normalizes quota summary groups into session and weekly windows", () => {
    const result = normalizeAgyQuotaSummary(fixture("quota-summary.json"));

    expect(result?.windows).toMatchObject([
      {
        id: "gemini_5h",
        label: "Gemini 5-hour",
        kind: "session",
        percentUsed: 9,
        percentRemaining: 91,
        resetsAt: "2026-06-15T11:39:34.000Z",
      },
      {
        id: "gemini_weekly",
        label: "Gemini weekly",
        kind: "weekly",
        percentUsed: 18,
        percentRemaining: 82,
        resetsAt: "2026-06-19T08:45:39.000Z",
      },
      {
        id: "claude_gpt_5h",
        label: "Claude/GPT 5-hour",
        kind: "session",
        percentUsed: 27,
        percentRemaining: 73,
        resetsAt: "2026-06-15T12:52:10.000Z",
      },
      {
        id: "claude_gpt_weekly",
        label: "Claude/GPT weekly",
        kind: "weekly",
        percentUsed: 36,
        percentRemaining: 64,
        resetsAt: "2026-06-20T00:39:54.000Z",
      },
    ]);
    expect(result?.windows.every((w) => w.windowSeconds === undefined)).toBe(
      true,
    );
  });

  it("normalizes the Antigravity CLI 1.2.2 quota summary shape", () => {
    const result = normalizeAgyQuotaSummary(
      fixture("quota-summary-v1.2.2.json"),
    );

    expect(result?.windows).toMatchObject([
      { id: "gemini_5h", kind: "session", percentRemaining: 88 },
      { id: "gemini_weekly", kind: "weekly", percentRemaining: 76 },
      { id: "claude_gpt_5h", kind: "session", percentRemaining: 64 },
      { id: "claude_gpt_weekly", kind: "weekly", percentRemaining: 52 },
    ]);
  });

  it("normalizes the exact Antigravity CLI 1.2.2 print envelope", () => {
    const result = normalizeAgyPrintUsage(fixture("usage-print-v1.2.2.json"));

    expect(result?.windows).toMatchObject([
      { id: "gemini_5h", kind: "session", percentRemaining: 88 },
      { id: "gemini_weekly", kind: "weekly", percentRemaining: 76 },
      { id: "claude_gpt_5h", kind: "session", percentRemaining: 64 },
      { id: "claude_gpt_weekly", kind: "weekly", percentRemaining: 52 },
    ]);
  });

  it("normalizes oneof remaining values", () => {
    const result = normalizeAgyQuotaSummary({
      groups: [
        {
          displayName: "Gemini Models",
          buckets: [
            {
              bucketId: "gemini-weekly",
              displayName: "Weekly Limit",
              remaining: { case: "remainingFraction", value: 0.5 },
            },
          ],
        },
      ],
    });

    expect(result?.windows[0]).toMatchObject({
      id: "gemini_weekly",
      percentUsed: 50,
      percentRemaining: 50,
    });
    expect(result?.windows[0]?.windowSeconds).toBeUndefined();
  });

  it("normalizes the agy CLI /quota print envelope", () => {
    const result = normalizeAgyPrintUsage(fixture("cli-quota.json"));

    expect(result?.windows.map(({ id }) => id)).toEqual([
      "gemini_weekly",
      "claude_gpt_5h",
      "claude_gpt_weekly",
    ]);
    expect(result?.windows).toMatchObject([
      {
        id: "gemini_weekly",
        percentRemaining: 0,
      },
      {
        id: "claude_gpt_5h",
        percentRemaining: 100,
      },
      {
        id: "claude_gpt_weekly",
        percentRemaining: 90,
      },
    ]);
    expect(result?.windows.every((w) => w.windowSeconds === undefined)).toBe(
      true,
    );
  });

  it("falls back to model windows from user status payloads", () => {
    const result = normalizeAgyUserStatus(fixture("user-status.json"));

    expect(result?.plan).toBe("Google AI Pro");
    expect(result?.account?.email).toBe("person@example.invalid");
    expect(result?.windows).toMatchObject([
      {
        id: "model:model_fixture_gemini_flash",
        label: "Gemini 3.5 Flash (Medium)",
        kind: "model",
        percentRemaining: 100,
      },
      {
        id: "model:model_fixture_claude_sonnet",
        label: "Claude Sonnet Fixture",
        kind: "model",
        percentRemaining: 50,
      },
    ]);
  });

  it("parses Antigravity processes and listening ports without matching prompt text", () => {
    const processes = processInfosFromPs(`
      101 /Users/test/.local/bin/agy
      102 /Applications/Google Antigravity.app/Contents/Resources/bin/language-server --csrf_token token --extension_server_port 64123
      103 /usr/bin/node /opt/antigravity-cli/mcp-server.cjs --port 64124
      104 codex --prompt "antigravity-cli mcp-server.cjs language_server"
      105 /usr/bin/node /opt/runner.cjs --prompt "/opt/antigravity-cli/mcp-server.cjs"
      106 /usr/bin/codex --prompt "/Applications/Antigravity.app/Contents/bin/language_server --csrf_token fake"
      108 /usr/bin/node /Applications/Antigravity IDE.app/Contents/bin/language_server_macos_arm --csrf_token fake
    `);

    expect(processes).toMatchObject([
      { pid: 101, source: "agy" },
      {
        pid: 102,
        source: "app",
        csrfToken: "token",
        extensionPort: 64123,
      },
      { pid: 103, source: "agy" },
    ]);
    expect(
      portsFromLsof(`
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
agy 101 test 8u IPv4 0x1 0t0 TCP 127.0.0.1:64440 (LISTEN)
agy 101 test 9u IPv4 0x2 0t0 TCP 127.0.0.1:64441 (LISTEN)
`),
    ).toEqual([64440, 64441]);
  });

  it("recognizes the Antigravity IDE app bundle when its name contains spaces", () => {
    const processes = processInfosFromPs(`
      107 /Applications/Antigravity IDE.app/Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm --csrf_token ide-token --extension_server_port 56512
    `);

    expect(processes).toMatchObject([
      {
        pid: 107,
        source: "app",
        csrfToken: "ide-token",
        extensionPort: 56512,
      },
    ]);
  });
});

describe("Antigravity provider", () => {
  it("uses OMP Google OAuth with the verified Cloud Code quota summary endpoint", async () => {
    const fetchMock = vi.fn(
      async (input: string | URL | Request, init?: RequestInit) => {
        expect(String(input)).toBe(
          "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
        );
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("authorization")).toBe(
          "Bearer synthetic-antigravity-access",
        );
        expect(JSON.parse(String(init?.body))).toEqual({
          project: "synthetic-project",
        });
        return Response.json({
          groups: [
            {
              displayName: "Gemini",
              buckets: [
                {
                  bucketId: "gemini-5h",
                  remainingFraction: 0.73,
                  resetTime: "2026-09-25T16:35:02Z",
                },
              ],
            },
          ],
        });
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    const runtime = {
      ...runtimeWith({}),
      async resolveOmpAntigravity() {
        return {
          status: "available" as const,
          credential: {
            accessToken: "synthetic-antigravity-access",
            projectId: "synthetic-project",
          },
        };
      },
    };

    const result = await fetchQuotaWithRuntime(runtime);

    expect(result.state.status).toBe("fresh");
    expect(result.source).toBe("omp:google-antigravity");
    expect(result.windows).toMatchObject([
      { id: "gemini_5h", percentRemaining: 73, percentUsed: 27 },
    ]);
    expect(result.attempts).toContainEqual({
      source: "omp:google-antigravity",
      status: "success",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each(["quota", "rejected"] as const)(
    "probes a stored-expired OMP bearer before reporting %s",
    async (outcome) => {
      const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
        expect(new Headers(init?.headers).get("authorization")).toBe(
          "Bearer synthetic-expired-access",
        );
        return outcome === "quota"
          ? Response.json({
              groups: [
                {
                  displayName: "Gemini",
                  buckets: [{ bucketId: "gemini-5h", remainingFraction: 0.73 }],
                },
              ],
            })
          : new Response(null, { status: 401 });
      });
      vi.stubGlobal("fetch", fetchMock);
      const result = await fetchQuotaWithRuntime({
        ...runtimeWith({}),
        async resolveOmpAntigravity() {
          return {
            status: "expired" as const,
            refreshable: true,
            credential: {
              accessToken: "synthetic-expired-access",
              projectId: "synthetic-project",
            },
          };
        },
      });

      expect(fetchMock).toHaveBeenCalledTimes(outcome === "quota" ? 1 : 2);
      expect(result.state.status).toBe(
        outcome === "quota" ? "fresh" : "auth_required",
      );
      expect(result.windows).toHaveLength(outcome === "quota" ? 1 : 0);
      if (outcome === "quota")
        expect(result.source).toBe("omp:google-antigravity");
      expect(JSON.stringify(result)).not.toContain("synthetic-expired-access");
    },
  );

  it("uses model quota data only when the OMP summary has no reported buckets", async () => {
    let request = 0;
    const fetchMock = vi.fn(async () => {
      request += 1;
      return request === 1
        ? Response.json({ groups: [] })
        : Response.json({
            models: {
              "gemini-test": {
                displayName: "Gemini Test",
                quotaInfo: {
                  remainingFraction: 0.41,
                  resetTime: "2026-09-25T16:35:02Z",
                },
              },
            },
          });
    });
    vi.stubGlobal("fetch", fetchMock);
    const runtime = {
      ...runtimeWith({}),
      async resolveOmpAntigravity() {
        return {
          status: "available" as const,
          credential: {
            accessToken: "synthetic-antigravity-access",
            projectId: "synthetic-project",
          },
        };
      },
    };

    const result = await fetchQuotaWithRuntime(runtime);

    expect(result.state.status).toBe("fresh");
    expect(result.source).toBe("omp:google-antigravity");
    expect(result.windows).toMatchObject([
      { id: "model:gemini_test", kind: "model", percentRemaining: 41 },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    { stage: "summary", declared: false },
    { stage: "summary", declared: true },
    { stage: "models", declared: false },
    { stage: "models", declared: true },
  ])(
    "bounds the $stage OMP response with declared length $declared",
    async ({ stage, declared }) => {
      let reads = 0;
      let canceled = false;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) => {
          const requestedStage = String(url).endsWith(
            "retrieveUserQuotaSummary",
          )
            ? "summary"
            : "models";
          if (requestedStage !== stage)
            return Response.json(
              requestedStage === "summary" ? { groups: [] } : { models: {} },
            );
          return new Response(
            new ReadableStream({
              pull(controller) {
                reads += 1;
                controller.enqueue(new Uint8Array(256 * 1024));
              },
              cancel() {
                canceled = true;
              },
            }),
            {
              headers: declared
                ? { "content-length": String(1024 * 1024 + 1) }
                : {},
            },
          );
        }),
      );
      const result = await fetchQuotaWithRuntime({
        ...runtimeWith({}),
        async resolveOmpAntigravity() {
          return {
            status: "available" as const,
            credential: {
              accessToken: "synthetic-antigravity-access",
              projectId: "synthetic-project",
            },
          };
        },
      });
      expect(result.state.status).toBe("error");
      expect(result.windows).toEqual([]);
      expect(canceled).toBe(true);
      expect(reads).toBeLessThan(8);
    },
  );

  it.each(["summary", "models"] as const)(
    "keeps an OMP $stage body-read failure transient",
    async (stage) => {
      writeCachedProviders([cachedAgyQuota()]);
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) => {
          const requestedStage = String(url).endsWith(
            "retrieveUserQuotaSummary",
          )
            ? "summary"
            : "models";
          if (requestedStage !== stage)
            return Response.json(
              requestedStage === "summary" ? { groups: [] } : { models: {} },
            );
          return new Response(
            new ReadableStream({
              start(controller) {
                controller.error(new Error("private body failure"));
              },
            }),
          );
        }),
      );
      const result = await fetchQuotaWithRuntime({
        ...runtimeWith({}),
        async resolveOmpAntigravity() {
          return {
            status: "available" as const,
            credential: {
              accessToken: "synthetic-antigravity-access",
              projectId: "synthetic-project",
            },
          };
        },
      });
      expect(result.state).toMatchObject({
        status: "stale",
        error: "Antigravity quota response unreadable",
      });
      expect(result.windows).toHaveLength(1);
      expect(JSON.stringify(result)).not.toContain("private body failure");
    },
  );

  it.each([
    {
      httpStatus: 429,
      status: "rate_limited",
      error: "Antigravity quota endpoint rate limited",
    },
    {
      httpStatus: 503,
      status: "unavailable",
      error: "Antigravity quota endpoint returned HTTP 503",
    },
  ])(
    "preserves OMP HTTP $httpStatus for failed and stale readings",
    async ({ httpStatus, status, error }) => {
      const fetchMock = vi.fn(
        async () => new Response(null, { status: httpStatus }),
      );
      vi.stubGlobal("fetch", fetchMock);
      const runtime = {
        ...runtimeWith({}),
        async resolveOmpAntigravity() {
          return {
            status: "available" as const,
            credential: {
              accessToken: "synthetic-antigravity-access",
              projectId: "synthetic-project",
            },
          };
        },
      };
      const failed = await fetchQuotaWithRuntime(runtime);
      expect(failed.state).toMatchObject({ status, error });
      expect(failed.attempts?.at(-1)).toMatchObject({
        source: "omp:google-antigravity",
        status: "failed",
        error,
      });

      writeCachedProviders([cachedAgyQuota()]);
      const stale = await fetchQuotaWithRuntime(runtime);
      expect(stale.state).toMatchObject({ status: "stale", error });
      expect(stale.windows).toHaveLength(1);
      expect(readCachedProvider("agy")).toBeDefined();
      expect(fetchMock).toHaveBeenCalledTimes(4);
    },
  );

  it("serves stale OMP quota only for the same OAuth credential", async () => {
    const runtimeFor = (account: "A" | "B") => ({
      ...runtimeWith({}),
      async resolveOmpAntigravity() {
        return {
          status: "available" as const,
          credential: {
            accessToken: `synthetic-account-${account}-access`,
            cacheIdentity: `synthetic-account-${account}`,
            projectId: "synthetic-project",
          },
        };
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json(fixture("quota-summary.json"))),
    );
    const fresh = await fetchQuotaWithRuntime(runtimeFor("A"));
    expect(fresh).toMatchObject({
      source: "omp:google-antigravity",
      state: { status: "fresh" },
    });
    const futureReset = new Date(Date.now() + 60 * 60 * 1_000).toISOString();
    fresh.windows = fresh.windows.map((window) => ({
      ...window,
      resetsAt: futureReset,
    }));
    writeCachedProviders([fresh]);

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 503 })),
    );
    const sameAccount = await fetchQuotaWithRuntime(runtimeFor("A"));
    expect(sameAccount.state).toMatchObject({ status: "stale", stale: true });
    expect(sameAccount.windows.length).toBeGreaterThan(0);

    const otherAccount = await fetchQuotaWithRuntime(runtimeFor("B"));
    expect(otherAccount.state.status).toBe("unavailable");
    expect(otherAccount.state.stale).toBe(false);
    expect(otherAccount.windows).toEqual([]);
    expect(readCachedProvider("agy")?.source).toBe("omp:google-antigravity");
    expect(JSON.stringify([fresh, sameAccount, otherAccount])).not.toMatch(
      /synthetic-account-[AB]-access/,
    );
  });

  it.each([
    { summaryStatus: 429, modelsStatus: 401 },
    { summaryStatus: 401, modelsStatus: 503 },
    { summaryStatus: 200, modelsStatus: 403 },
  ])(
    "scopes cache retirement after OMP summary $summaryStatus and models $modelsStatus",
    async ({ summaryStatus, modelsStatus }) => {
      const fetchMock = vi.fn(
        async (url: string | URL | Request, init?: RequestInit) => {
          expect(new Headers(init?.headers).get("authorization")).toBe(
            "Bearer synthetic-antigravity-access",
          );
          return String(url).endsWith("retrieveUserQuotaSummary")
            ? summaryStatus === 200
              ? Response.json({ groups: [] })
              : new Response(null, { status: summaryStatus })
            : new Response(null, { status: modelsStatus });
        },
      );
      vi.stubGlobal("fetch", fetchMock);
      for (const source of ["cli-rpc", "omp:google-antigravity"] as const) {
        const snapshot =
          source === "omp:google-antigravity"
            ? cachedOmpAgyQuota()
            : cachedAgyQuota();
        writeCachedProviders([snapshot]);
        fetchMock.mockClear();
        const result = await fetchQuotaWithRuntime({
          ...runtimeWith({}),
          async resolveOmpAntigravity() {
            return {
              status: "available" as const,
              credential: {
                accessToken: "synthetic-antigravity-access",
                projectId: "synthetic-project",
              },
            };
          },
        });

        expect(fetchMock).toHaveBeenCalledTimes(2);
        expect(result.state).toMatchObject(
          source === "cli-rpc"
            ? { status: "stale", stale: true, error: AGY_NOT_RUNNING }
            : {
                status: "auth_required",
                error: "Antigravity sign-in required",
              },
        );
        expect(result.windows).toHaveLength(source === "cli-rpc" ? 1 : 0);
        expect(result.attempts?.at(-1)).toMatchObject({
          source: "omp:google-antigravity",
          status: "failed",
          error: "Antigravity sign-in required",
        });
        expect(readCachedProvider("agy")?.source).toBe(
          source === "cli-rpc" ? "cli-rpc" : undefined,
        );
        expect(JSON.stringify(result)).not.toContain(
          "synthetic-antigravity-access",
        );
      }
    },
  );

  it.each([
    {
      source: "cli" as const,
      options: {
        cliQuota: Object.assign(new Error("synthetic CLI timeout"), {
          code: "ETIMEDOUT",
        }),
      },
      error: "Antigravity CLI /quota timed out",
    },
    {
      source: "cli-rpc" as const,
      options: {
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, 64440),
        requestJson: async () => {
          throw new Error("ECONNRESET");
        },
      },
      error: "ECONNRESET",
    },
  ])(
    "keeps an uncertain $source cached reading despite OMP rejection",
    async ({ source, options, error }) => {
      const snapshot = cachedAgyQuota();
      snapshot.source = source;
      writeCachedProviders([snapshot]);
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: 401 })),
      );
      const result = await fetchQuotaWithRuntime({
        ...runtimeWith(options),
        async resolveOmpAntigravity() {
          return {
            status: "available" as const,
            credential: {
              accessToken: "synthetic-antigravity-access",
              projectId: "synthetic-project",
            },
          };
        },
      });

      expect(result.state).toMatchObject({ status: "stale", error });
      expect(result.source).toBe("cache");
      expect(result.windows).toHaveLength(1);
      expect(readCachedProvider("agy")?.source).toBe(source);
      expect(result.attempts?.at(-1)).toMatchObject({
        source: "omp:google-antigravity",
        error: "Antigravity sign-in required",
      });
    },
  );

  it("keeps a model rate limit over a summary server failure", async () => {
    writeCachedProviders([cachedAgyQuota()]);
    let request = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        ++request === 1
          ? new Response(null, { status: 503 })
          : new Response(null, { status: 429 }),
      ),
    );
    const result = await fetchQuotaWithRuntime({
      ...runtimeWith({}),
      async resolveOmpAntigravity() {
        return {
          status: "available" as const,
          credential: {
            accessToken: "synthetic-antigravity-access",
            projectId: "synthetic-project",
          },
        };
      },
    });
    expect(result.state).toMatchObject({
      status: "stale",
      error: "Antigravity quota endpoint rate limited",
    });
    expect(readCachedProvider("agy")).toBeDefined();
  });

  it("keeps OMP model-request transport failure stale-eligible after an empty summary", async () => {
    writeCachedProviders([cachedAgyQuota()]);
    let request = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        ++request === 1
          ? Response.json({ groups: [] })
          : new Response(null, { status: 503 }),
      ),
    );
    const result = await fetchQuotaWithRuntime({
      ...runtimeWith({}),
      async resolveOmpAntigravity() {
        return {
          status: "available" as const,
          credential: {
            accessToken: "synthetic-antigravity-access",
            projectId: "synthetic-project",
          },
        };
      },
    });
    expect(result.state).toMatchObject({
      status: "stale",
      error: "Antigravity quota endpoint returned HTTP 503",
    });
    expect(result.windows).toHaveLength(1);
  });

  it("keeps an OMP request timeout stale-eligible", async () => {
    writeCachedProviders([cachedAgyQuota()]);
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_url: unknown, init?: RequestInit) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(new Error("request aborted")),
            );
          }),
      ),
    );
    const reading = fetchQuotaWithRuntime({
      ...runtimeWith({}),
      async resolveOmpAntigravity() {
        return {
          status: "available" as const,
          credential: {
            accessToken: "synthetic-antigravity-access",
            projectId: "synthetic-project",
          },
        };
      },
    });
    await vi.advanceTimersByTimeAsync(31_000);
    const result = await reading;
    expect(result.state).toMatchObject({
      status: "stale",
      error: "Antigravity quota request timed out",
    });
    expect(result.windows).toHaveLength(1);
    expect(readCachedProvider("agy")).toBeDefined();
  });

  it("fetches quota from an already-running loopback endpoint and merges identity", async () => {
    const runtime = runtimeWith({
      ps: "123 /Users/test/.local/bin/agy\n",
      lsof: lsofFor(123, 64440),
      responses: {
        "https:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
          fixture("quota-summary.json"),
        "https:64440:/exa.language_server_pb.LanguageServerService/GetUserStatus":
          fixture("user-status.json"),
      },
    });

    const result = await fetchQuotaWithRuntime(runtime);

    expect(result.state.status).toBe("fresh");
    expect(result.source).toBe("cli-rpc");
    expect(result.plan).toBe("Google AI Pro");
    expect(result.account?.email).toBe("person@example.invalid");
    expect(result.windows.map((window) => window.id)).toEqual([
      "gemini_5h",
      "gemini_weekly",
      "claude_gpt_5h",
      "claude_gpt_weekly",
    ]);
  });

  it("probes app language-server endpoints with CSRF before quota requests", async () => {
    const calls: Array<{ endpoint: AgyConnectionEndpoint; path: string }> = [];
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Applications/Google Antigravity.app/Contents/Resources/bin/language-server --csrf_token token --extension_server_port 64123 --extension_server_csrf_token extension-token\n",
        lsof: lsofFor(123, 64440),
        responses: {
          "https:64440:/exa.language_server_pb.LanguageServerService/GetUnleashData":
            {},
          "https:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            fixture("quota-summary.json"),
        },
        onRequest(endpoint, path) {
          calls.push({ endpoint, path });
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(calls[0]?.path).toBe(
      "/exa.language_server_pb.LanguageServerService/GetUnleashData",
    );
    expect(calls[0]?.endpoint).toMatchObject({
      csrfToken: "token",
      requiresCsrfToken: true,
      requiresUnleashProbe: true,
    });
    expect(calls.every((call) => call.endpoint.port !== 64123)).toBe(true);
  });

  it("uses an extension port only when the app process owns its listener", async () => {
    const calls: AgyConnectionEndpoint[] = [];
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Applications/Google Antigravity.app/Contents/Resources/bin/language-server --csrf_token main-token --extension_server_port 64123 --extension_server_csrf_token extension-token\n",
        lsof: `${lsofFor(123, 64440)}agy 123 test 9u IPv4 0x2 0t0 TCP 127.0.0.1:64123 (LISTEN)\n`,
        requestJson: async (endpoint, path) => {
          calls.push(endpoint);
          if (
            endpoint.port === 64123 &&
            endpoint.csrfToken === "extension-token"
          ) {
            if (path.endsWith("GetUnleashData")) return {};
            if (path.endsWith("RetrieveUserQuotaSummary"))
              return fixture("quota-summary.json");
          }
          throw new Error("connect ECONNREFUSED");
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(calls).toContainEqual(
      expect.objectContaining({
        port: 64123,
        csrfToken: "extension-token",
      }),
    );
  });

  it("reports unavailable without trying HTTP when Antigravity is not running", async () => {
    const requestJson = vi.fn();
    const result = await fetchQuotaWithRuntime(
      runtimeWith({ ps: "", lsof: "", requestJson }),
    );

    expect(result.state.status).toBe("unavailable");
    expect(result.state.error).toBe("Antigravity/agy is not running");
    expect(requestJson).not.toHaveBeenCalled();
  });

  it("reports unavailable when discovered loopback endpoints are absent", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, 64440),
        requestJson: async () => {
          throw new Error("connect ECONNREFUSED 127.0.0.1:64440");
        },
      }),
    );

    expect(result.state.status).toBe("unavailable");
    expect(result.state.error).toBe("connect ECONNREFUSED 127.0.0.1:64440");
  });

  it("preserves sanitized process and port discovery failures", async () => {
    const processResult = await fetchQuotaWithRuntime(
      runtimeWith({ psError: new Error("ps failed at /Users/private") }),
    );
    const portResult = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsofError: new Error("lsof denied for private-host"),
      }),
    );

    expect(processResult.state).toMatchObject({
      status: "error",
      error: "Antigravity process discovery failed",
    });
    expect(portResult.state).toMatchObject({
      status: "error",
      error: "Antigravity port discovery failed",
    });
  });

  it("preserves sanitized discovery failures during auth inspection", async () => {
    const processResult = await inspectAuthWithRuntime(
      runtimeWith({ psError: new Error("ps failed at /Users/private") }),
    );
    const portResult = await inspectAuthWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsofError: new Error("lsof denied for private-host"),
      }),
    );

    expect(processResult.sources).toEqual([
      {
        source: "loopback",
        status: "error",
        error: "Antigravity process discovery failed",
      },
    ]);
    expect(portResult.sources).toEqual([
      {
        source: "loopback",
        status: "error",
        error: "Antigravity port discovery failed",
      },
    ]);
  });

  it("continues discovery when another verified process has listening ports", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n124 /Users/test/.local/bin/agy\n",
        lsofByPid: {
          123: new Error("permission denied"),
          124: lsofFor(124, 64441),
        },
        responses: {
          "https:64441:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            fixture("quota-summary.json"),
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
  });

  it("falls back to model quotas when quota summary has no usable buckets", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, 64440),
        responses: {
          "https:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            { response: { groups: [] } },
          "https:64440:/exa.language_server_pb.LanguageServerService/GetUserStatus":
            fixture("user-status.json"),
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(result.windows.map((window) => window.id)).toEqual([
      "model:model_fixture_gemini_flash",
      "model:model_fixture_claude_sonnet",
    ]);
  });

  it("continues past a malformed endpoint to a later valid port", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: `${lsofFor(123, 64440)}agy 123 test 9u IPv4 0x2 0t0 TCP 127.0.0.1:64441 (LISTEN)\n`,
        responses: {
          "https:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            { response: { groups: [] } },
          "https:64440:/exa.language_server_pb.LanguageServerService/GetUserStatus":
            { response: { groups: [] } },
          "https:64440:/exa.language_server_pb.LanguageServerService/GetCommandModelConfigs":
            { response: { groups: [] } },
          "https:64441:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            fixture("quota-summary.json"),
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(result.windows[0]?.id).toBe("gemini_5h");
  });

  it("bounds probing across all discovered endpoints", async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    const resultPromise = fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: `${lsofFor(123, 64440)}agy 123 test 9u IPv4 0x2 0t0 TCP 127.0.0.1:64441 (LISTEN)\n`,
        requestJson: async (endpoint, path) => {
          calls.push(`${endpoint.scheme}:${endpoint.port}:${path}`);
          return new Promise<never>(() => undefined);
        },
      }),
    );

    await vi.advanceTimersByTimeAsync(10_000);
    const result = await resultPromise;

    expect(result.state.status).toBe("unavailable");
    expect(result.state.error).toBe("Antigravity probe timed out");
    expect(calls).toHaveLength(4);
    vi.useRealTimers();
  });

  it("reports malformed loopback responses as errors", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, 64440),
        responses: {
          "https:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            { response: { groups: [] } },
          "https:64440:/exa.language_server_pb.LanguageServerService/GetUserStatus":
            { response: { groups: [] } },
          "https:64440:/exa.language_server_pb.LanguageServerService/GetCommandModelConfigs":
            { response: { groups: [] } },
          "http:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
            { response: { groups: [] } },
          "http:64440:/exa.language_server_pb.LanguageServerService/GetUserStatus":
            { response: { groups: [] } },
          "http:64440:/exa.language_server_pb.LanguageServerService/GetCommandModelConfigs":
            { response: { groups: [] } },
        },
      }),
    );

    expect(result.state.status).toBe("error");
    expect(result.state.error).toBe("Antigravity quota summary malformed");
  });

  it("uses stale cache when the live loopback source is unavailable", async () => {
    writeCachedProviders([cachedAgyQuota()]);

    const result = await fetchQuotaWithRuntime(runtimeWith({ ps: "" }));

    expect(result.state.status).toBe("stale");
    expect(result.source).toBe("cache");
    expect(result.windows[0]).toMatchObject({
      id: "gemini_5h",
      percentRemaining: 88,
    });
  });

  it.each([503, 429])(
    "keeps the cached loopback rejection over OMP HTTP %i",
    async (ompStatus) => {
      writeCachedProviders([cachedAgyQuota()]);
      const port = await startServer((response) => {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "synthetic rejection" }));
      });
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: ompStatus })),
      );

      const result = await fetchQuotaWithRuntime({
        ...runtimeWith({
          ps: "123 /Users/test/.local/bin/agy\n",
          lsof: lsofFor(123, port),
          requestJson: requestLoopbackJson,
        }),
        async resolveOmpAntigravity() {
          return {
            status: "available" as const,
            credential: {
              accessToken: "synthetic-antigravity-access",
              projectId: "synthetic-project",
            },
          };
        },
      });

      expect(result.state).toMatchObject({
        status: "auth_required",
        error: "Antigravity sign-in required",
      });
      expect(result.windows).toEqual([]);
      expect(result.attempts?.at(-1)).toMatchObject({
        source: "omp:google-antigravity",
        status: "failed",
        error:
          ompStatus === 503
            ? "Antigravity quota endpoint returned HTTP 503"
            : "Antigravity quota endpoint rate limited",
      });
      expect(readCachedProvider("agy")).toBeUndefined();
      expect(JSON.stringify(result)).not.toContain(
        "synthetic-antigravity-access",
      );
    },
  );

  it("preserves authentication failures and retires stale cache", async () => {
    writeCachedProviders([cachedAgyQuota()]);
    const port = await startServer((_response) => {
      _response.writeHead(401, { "content-type": "application/json" });
      _response.end(JSON.stringify({ error: "secret-account@example.test" }));
    });

    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, port),
        requestJson: requestLoopbackJson,
      }),
    );

    expect(result.state).toMatchObject({
      status: "auth_required",
      error: "Antigravity sign-in required",
    });
    expect(JSON.stringify(result)).not.toContain("secret-account");
    expect(readCachedProvider("agy")).toBeUndefined();
  });

  it("prefers agy CLI /quota over loopback when both are available", async () => {
    writeCachedProviders([cachedAgyQuota()]);
    const commands: Array<{
      command: string;
      args: string[];
      timeoutMs: number;
      path?: string;
    }> = [];
    let loopbackCalled = false;
    const port = await startServer((response) => {
      loopbackCalled = true;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(fixture("quota-summary-v1.2.2.json")));
    });

    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, port),
        agyPath: "/Users/test/.local/bin/agy",
        agyOutput: JSON.stringify(fixture("usage-print-v1.2.2.json")),
        requestJson: requestLoopbackJson,
        onExec(command, args, timeoutMs, options) {
          commands.push({
            command,
            args,
            timeoutMs,
            path: options?.env?.PATH,
          });
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(result.source).toBe("cli");
    expect(result.account).toBeUndefined();
    expect(result.windows.map((window) => window.id)).toEqual([
      "gemini_5h",
      "gemini_weekly",
      "claude_gpt_5h",
      "claude_gpt_weekly",
    ]);
    expect(commands.at(-1)).toMatchObject({
      command: "/Users/test/.local/bin/agy",
      args: ["-p", "/quota", "--output-format", "json"],
      timeoutMs: 15_000,
    });
    expect(
      commands.at(-1)?.path?.split(delimiter).slice(1).join(delimiter),
    ).toBe(process.env.PATH ?? "");
    expect(loopbackCalled).toBe(false);
  });

  it.skipIf(process.platform === "win32").each([
    ["xdg-open", "inherited PATH"],
    ["xdg-open", "working directory"],
    ["open", "inherited PATH"],
    ["open", "working directory"],
  ] as const)(
    "prevents a signed-out agy quota probe from invoking %s in the %s",
    async (opener, openerLocation) => {
      const bin = join(tempDir as string, "bin");
      const workingDirectory = join(tempDir as string, "working");
      const marker = join(tempDir as string, "browser-opened");
      mkdirSync(bin);
      mkdirSync(workingDirectory);
      writeFileSync(
        join(bin, "agy"),
        `#!/bin/sh
${opener} 'https://accounts.example.invalid/oauth'
exit 1
`,
      );
      const openerDirectory =
        openerLocation === "inherited PATH" ? bin : workingDirectory;
      writeFileSync(
        join(openerDirectory, opener),
        `#!/bin/sh
printf opened > '${marker}'
`,
      );
      chmodSync(join(bin, "agy"), 0o700);
      chmodSync(join(openerDirectory, opener), 0o700);
      process.env.PATH = bin;
      process.chdir(workingDirectory);

      const result = await fetchQuota({
        allowKeychainPrompt: false,
        refreshCredentials: false,
      });

      expect(result.state).toMatchObject({
        status: "error",
        error: "Antigravity CLI /quota failed",
      });
      expect(existsSync(marker)).toBe(false);
    },
  );

  it
    .skipIf(process.platform === "win32")
    .each([
      "#!/usr/bin/env node",
      "#!/usr/bin/env -S node --enable-source-maps",
      ...(existsSync("/bin/env") ? ["#!/bin/env node"] : []),
    ])(
    "runs an authenticated agy CLI with the %s shebang when PATH has no node",
    async (shebang) => {
      const bin = join(tempDir as string, "bin");
      const payload = JSON.stringify(fixture("usage-print-v1.2.2.json"));
      mkdirSync(bin);
      writeFileSync(
        join(bin, "agy"),
        `${shebang}
process.stdout.write(${JSON.stringify(payload)});
`,
      );
      chmodSync(join(bin, "agy"), 0o700);
      process.env.PATH = bin;

      const result = await fetchQuota({
        allowKeychainPrompt: false,
        refreshCredentials: false,
      });

      expect(result.state.status).toBe("fresh");
      expect(result.source).toBe("cli");
      expect(result.windows.map((window) => window.id)).toEqual([
        "gemini_5h",
        "gemini_weekly",
        "claude_gpt_5h",
        "claude_gpt_weekly",
      ]);
    },
  );

  it.skipIf(process.platform === "win32")(
    "preserves runtime lookup in an authenticated shell launcher",
    async () => {
      const bin = join(tempDir as string, "bin");
      const script = join(bin, "agy-cli.js");
      const payload = JSON.stringify(fixture("usage-print-v1.2.2.json"));
      mkdirSync(bin);
      writeFileSync(
        join(bin, "agy"),
        `#!/bin/sh
exec node "$0-cli.js" "$@"
`,
      );
      writeFileSync(
        script,
        `process.stdout.write(${JSON.stringify(payload)});
`,
      );
      chmodSync(join(bin, "agy"), 0o700);
      process.env.PATH = bin;

      const result = await fetchQuota({
        allowKeychainPrompt: false,
        refreshCredentials: false,
      });

      expect(result.state.status).toBe("fresh");
      expect(result.source).toBe("cli");
    },
  );

  it("does not serve stale quota when protected loopback and print usage fail", async () => {
    writeCachedProviders([cachedAgyQuota()]);
    const port = await startServer((response) => {
      response.writeHead(401, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          code: "unauthenticated",
          message: "missing CSRF token",
        }),
      );
    });

    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, port),
        requestJson: requestLoopbackJson,
      }),
    );

    expect(result.state).toMatchObject({
      status: "unavailable",
      error:
        "Antigravity CLI quota unavailable because its runtime CSRF token is not exposed; use Antigravity /quota",
    });
    expect(result.windows).toEqual([]);
    expect(readCachedProvider("agy")).toBeDefined();
  });

  it("sanitizes failures from agy CLI /quota", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "",
        agyPath: "/Users/test/.local/bin/agy",
        agyError: Object.assign(new Error("private-account@example.test"), {
          code: "EFAIL",
        }),
      }),
    );

    expect(result.state).toMatchObject({
      status: "error",
      error: "Antigravity CLI /quota failed",
    });
    expect(JSON.stringify(result)).not.toContain("private-account");
  });

  it("sends the CLI 1.2.2 read-only request envelope without a token", async () => {
    let receivedBody: unknown;
    let receivedCsrfToken: string | undefined;
    const port = await startServer((response, request) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        if (request.url?.endsWith("RetrieveUserQuotaSummary")) {
          receivedBody = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          receivedCsrfToken = request.headers["x-codeium-csrf-token"] as
            | string
            | undefined;
        }
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(fixture("quota-summary-v1.2.2.json")));
      });
    });

    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, port),
        requestJson: requestLoopbackJson,
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(receivedBody).toEqual({ request: {}, forceRefresh: false });
    expect(receivedCsrfToken).toBeUndefined();
  });

  it("preserves rate limits over protocol failures", async () => {
    const port = await startServer((response) => {
      response.writeHead(429, { "content-type": "application/json" });
      response.end(JSON.stringify({ message: "private diagnostic" }));
    });

    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "123 /Users/test/.local/bin/agy\n",
        lsof: lsofFor(123, port),
        requestJson: requestLoopbackJson,
      }),
    );

    expect(result.state).toMatchObject({
      status: "rate_limited",
      error: "Antigravity quota endpoint rate limited",
    });
    expect(JSON.stringify(result)).not.toContain("private diagnostic");
  });

  it("terminates trickling and oversized loopback responses", async () => {
    const tricklePort = await startServer((response) => {
      const interval = setInterval(() => response.write(" "), 5);
      response.on("close", () => clearInterval(interval));
    });
    const trickleRequest = requestLoopbackJson(
      endpointAt(tricklePort),
      "/quota",
      50,
    );

    await expect(trickleRequest).rejects.toThrow(
      "Antigravity loopback timed out",
    );

    const oversizedPort = await startServer((response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(`"${"x".repeat(1024 * 1024)}"`);
    });

    await expect(
      requestLoopbackJson(endpointAt(oversizedPort), "/quota", 1_000),
    ).rejects.toThrow("Antigravity loopback response too large");
  });

  it("does not launch agy when loopback quota succeeds", async () => {
    const commands: Array<{ command: string; args: string[] }> = [];
    const runtime = runtimeWith({
      ps: "123 /Users/test/.local/bin/agy\n",
      lsof: lsofFor(123, 64440),
      responses: {
        "https:64440:/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary":
          fixture("quota-summary.json"),
      },
      onExec(command, args) {
        commands.push({ command, args });
      },
    });

    const result = await fetchQuotaWithRuntime(runtime);

    expect(result.state.status).toBe("fresh");
    expect(commands).toEqual([
      {
        command: "ps",
        args: currentUserProcessListArgs(process.geteuid() as number),
      },
      {
        command: "lsof",
        args: ["-nP", "-a", "-p", "123", "-iTCP", "-sTCP:LISTEN"],
      },
    ]);
    expect(commands.map((call) => call.command)).not.toContain("agy");
  });

  it("reads agy CLI /quota when loopback is down", async () => {
    const commands: Array<{ command: string; args: string[] }> = [];
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "",
        cliQuota: JSON.stringify(fixture("cli-quota.json")),
        onExec(command, args) {
          commands.push({ command, args });
        },
      }),
    );

    expect(result.state.status).toBe("fresh");
    expect(result.source).toBe("cli");
    expect(result.windows.map(({ id }) => id)).toEqual([
      "gemini_weekly",
      "claude_gpt_5h",
      "claude_gpt_weekly",
    ]);
    expect(result.attempts).toEqual([{ source: "cli", status: "success" }]);
    expect(commands).toContainEqual({
      command: "agy",
      args: ["-p", "/quota", "--output-format", "json"],
    });
  });

  it("surfaces a genuine CLI failure over the skipped loopback error", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "",
        cliQuota: "not json",
      }),
    );

    expect(result.state).toMatchObject({
      status: "error",
      error: "agy /quota returned invalid JSON",
    });
    expect(result.attempts).toEqual([
      {
        source: "cli",
        status: "failed",
        error: "agy /quota returned invalid JSON",
        degraded: false,
      },
      {
        source: "loopback",
        status: "skipped",
        error: "Antigravity/agy is not running",
        degraded: false,
      },
    ]);
  });

  it("still serves stale cache when both loopback and the CLI are unavailable", async () => {
    writeCachedProviders([cachedAgyQuota()]);

    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "",
        cliQuota: Object.assign(new Error("agy missing"), { code: "ENOENT" }),
      }),
    );

    expect(result.state.status).toBe("stale");
    expect(result.source).toBe("cache");
    expect(result.windows[0]).toMatchObject({
      id: "gemini_5h",
      percentRemaining: 88,
    });
  });

  it("does not treat a missing agy CLI as remaining quota", async () => {
    const result = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "",
        cliQuota: Object.assign(new Error("agy missing"), { code: "ENOENT" }),
      }),
    );

    expect(result.state.status).toBe("unavailable");
    expect(result.state.error).toBe("Antigravity/agy is not running");
    expect(result.attempts).toEqual([
      {
        source: "cli",
        status: "skipped",
        error: "agy CLI is not installed",
        degraded: false,
      },
      {
        source: "loopback",
        status: "skipped",
        error: "Antigravity/agy is not running",
        degraded: false,
      },
    ]);
  });

  it("marks reading stale when resetsAt is in the past", async () => {
    const nowIso = "2026-09-15T12:00:00.000Z";
    const pastReset = new Date(Date.parse(nowIso) - 60_000).toISOString();
    const quotaData = fixture("cli-quota.json") as {
      command: {
        data: {
          groups: Array<{ buckets: Array<{ reset_time?: string }> }>;
        };
      };
    };
    const modified = JSON.parse(JSON.stringify(quotaData));
    modified.command.data.groups[0].buckets[0].reset_time = pastReset;

    const fetched = await fetchQuotaWithRuntime(
      runtimeWith({
        ps: "",
        cliQuota: JSON.stringify(modified),
      }),
    );
    expect(fetched.state.status).toBe("fresh");

    const result = withQuotaSemantics(fetched, nowIso);

    expect(result.state.status).toBe("stale");
    expect(result.state.stale).toBe(true);
  });
});

function runtimeWith(options: {
  agyPath?: string;
  agyOutput?: string;
  agyError?: Error;
  ps?: string;
  lsof?: string;
  psError?: Error;
  lsofError?: Error;
  lsofByPid?: Record<number, string | Error>;
  cliQuota?: string | Error;
  requestJson?: AgyProbeRuntime["requestJson"];
  responses?: Record<string, unknown>;
  onExec?: (
    command: string,
    args: string[],
    timeoutMs: number,
    options?: ExecFileTextOptions,
  ) => void;
  onRequest?: (endpoint: AgyConnectionEndpoint, path: string) => void;
}): AgyProbeRuntime {
  return {
    async findCommandPath(command) {
      if (command !== "agy") throw new Error(`unexpected command: ${command}`);
      return (
        options.agyPath ?? (options.cliQuota !== undefined ? "agy" : undefined)
      );
    },
    async execFileText(command, args, timeoutMs, execOptions) {
      options.onExec?.(command, args, timeoutMs, execOptions);
      if (command === "ps") {
        if (options.psError) throw options.psError;
        return options.ps ?? "";
      }
      if (command === "lsof") {
        if (options.lsofError) throw options.lsofError;
        const pid = Number(args[args.indexOf("-p") + 1]);
        const output = options.lsofByPid?.[pid];
        if (output instanceof Error) throw output;
        return output ?? options.lsof ?? "";
      }
      if (
        command === "agy" ||
        (options.agyPath && command === options.agyPath)
      ) {
        if (options.agyError) throw options.agyError;
        if (options.cliQuota instanceof Error) throw options.cliQuota;
        if (typeof options.cliQuota === "string") return options.cliQuota;
        return options.agyOutput ?? "";
      }
      throw new Error(`unexpected command: ${command}`);
    },
    async requestJson(
      endpoint: AgyConnectionEndpoint,
      path: string,
      timeoutMs: number,
    ) {
      options.onRequest?.(endpoint, path);
      if (options.requestJson)
        return options.requestJson(endpoint, path, timeoutMs);
      const key = `${endpoint.scheme}:${endpoint.port}:${path}`;
      if (options.responses && key in options.responses)
        return options.responses[key];
      throw new Error(`unexpected request: ${key}`);
    },
  };
}

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(join("test", "fixtures", "agy", name), "utf8"),
  ) as unknown;
}

function lsofFor(pid: number, port: number): string {
  return `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
agy ${pid} test 8u IPv4 0x1 0t0 TCP 127.0.0.1:${port} (LISTEN)
`;
}

async function startServer(
  handler: (response: ServerResponse, request: IncomingMessage) => void,
): Promise<number> {
  const server = createServer((request, response) =>
    handler(response, request),
  );
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

function endpointAt(port: number): AgyConnectionEndpoint {
  return {
    scheme: "http",
    port,
    source: "agy",
    pid: process.pid,
    requiresCsrfToken: false,
    requiresUnleashProbe: false,
  };
}

function useTempCache(): void {
  tempDir = mkdtempSync(join(tmpdir(), "quota-axi-agy-cache-"));
  process.env.XDG_CACHE_HOME = tempDir;
}

function cachedAgyQuota(): ProviderQuota {
  return {
    provider: "agy",
    label: "Antigravity",
    source: "cli-rpc",
    windows: [
      {
        id: "gemini_5h",
        label: "Gemini 5-hour",
        kind: "session",
        percentUsed: 12,
        percentRemaining: 88,
        // Still ahead, so a stale fallback may serve it.
        resetsAt: new Date(Date.now() + 60 * 60 * 1_000).toISOString(),
      },
    ],
    state: {
      status: "fresh",
      stale: false,
      refreshedAt: "2026-06-15T11:39:34.000Z",
      sourcesTried: ["loopback"],
    },
  };
}

function cachedOmpAgyQuota(): ProviderQuota {
  const snapshot = cachedAgyQuota();
  snapshot.source = "omp:google-antigravity";
  return stampAgyOmpCredentialContextId(
    snapshot,
    agyOmpCredentialContextId(
      "https://daily-cloudcode-pa.googleapis.com",
      undefined,
      "synthetic-antigravity-access",
    ),
  );
}
