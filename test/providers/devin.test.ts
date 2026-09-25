import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  readCachedDevinProvider,
  readReusableProviders,
  stampReadingInputs,
  writeCachedProviders,
} from "../../src/cache.js";
import { inputsDigest } from "../../src/lib/input-trace.js";
import type { LocalOAuthBroker } from "../../src/providers/local-oauth-credential.js";
import { withQuotaSemantics } from "../../src/interpretation.js";
import { renderQuotaToon } from "../../src/render.js";
import { devinCacheContextId } from "../../src/providers/devin-cache-context.js";
import {
  createDevinAdapter,
  createDevinEnvSource,
  createDevinFileSource,
  DEVIN_API_ORIGIN,
  DEVIN_ENV_SOURCE,
  DEVIN_FILE_SOURCE,
  DEVIN_SOURCE_ORDER,
  DEVIN_USER_STATUS_PATH,
  devinCredentialsFilePath,
  normalizeDevinPayload,
  type DevinCredentialSource,
  type DevinLocalResolution,
} from "../../src/providers/devin.js";
import type { ProviderQuota } from "../../src/types.js";
import { VERSION } from "../../src/version.js";

const NOW = Date.parse("2026-09-22T12:00:00.000Z");
const OPTIONS = { allowKeychainPrompt: false, refreshCredentials: false };
const SYNTHETIC_KEY = "synthetic-devin-key-481";
const FILE_KEY = "synthetic-devin-file-key-772";
const SESSION_TOKEN =
  "devin-session-token$eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiZml4dHVyZSJ9.c2lnbmF0dXJl";

const WEEKLY = {
  id: "weekly",
  label: "week",
  kind: "weekly" as const,
  percentRemaining: 60,
  percentUsed: 40,
  windowSeconds: 604_800,
  startsAt: "2026-09-20T08:00:00.000Z",
  resetsAt: "2026-09-27T08:00:00.000Z",
};
const DAILY = {
  id: "daily",
  label: "day",
  kind: "session" as const,
  percentRemaining: 80,
  percentUsed: 20,
  windowSeconds: 86_400,
  startsAt: "2026-09-22T08:00:00.000Z",
  resetsAt: "2026-09-23T08:00:00.000Z",
};

const fixture = (name: string): unknown =>
  JSON.parse(
    readFileSync(
      join(process.cwd(), `test/fixtures/devin/${name}.json`),
      "utf8",
    ),
  ) as unknown;

const PRO = fixture("pro");
const MAX = fixture("max");
const EXHAUSTED = fixture("exhausted-weekly");
const OUT_OF_RANGE = fixture("out-of-range");
const NON_QUOTA = fixture("non-quota");
const NO_QUOTA = fixture("no-quota");

type DevinTestPayload = {
  userStatus: { planStatus: Record<string, unknown> };
  planInfo: Record<string, unknown>;
};

let tempDir: string | undefined;

afterEach(() => {
  if (tempDir) rmSync(tempDir, { recursive: true, force: true });
  tempDir = undefined;
});

describe("Devin request transport", () => {
  it("posts one Connect-JSON read to the allowlisted host and identifies as quota-axi", async () => {
    const request = sequentialFetch([jsonResponse(PRO)]);
    await testAdapter({ fetch: request }).fetchQuota(OPTIONS);

    expect(request).toHaveBeenCalledTimes(1);
    const [input, init] = request.mock.calls[0];
    const url = new URL(String(input));
    expect({
      protocol: url.protocol,
      hostname: url.hostname,
      pathname: url.pathname,
      search: url.search,
      method: init?.method,
      redirect: init?.redirect,
      credentials: init?.credentials,
    }).toEqual({
      protocol: "https:",
      hostname: "server.codeium.com",
      pathname: DEVIN_USER_STATUS_PATH,
      search: "",
      method: "POST",
      redirect: "manual",
      credentials: "omit",
    });
    const headers = new Headers(init?.headers);
    expect(headers.get("connect-protocol-version")).toBe("1");
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("authorization")).toBeNull();
    const body = JSON.parse(String(init?.body)) as {
      metadata: Record<string, string>;
    };
    expect(body.metadata).toMatchObject({
      apiKey: SYNTHETIC_KEY,
      ideName: "quota-axi",
      extensionName: "quota-axi",
      ideVersion: VERSION,
      extensionVersion: VERSION,
    });
    expect(body.metadata.ideVersion).toMatch(/^\d+\.\d+\.\d+/);
    expect(new URL(DEVIN_API_ORIGIN).hostname).toBe("server.codeium.com");
  });

  it.each([
    {
      form: "unprefixed",
      accessToken: SESSION_TOKEN.slice("devin-session-token$".length),
    },
    { form: "prefixed", accessToken: SESSION_TOKEN },
  ])(
    "uses OMP's Devin CLI protobuf contract ($form)",
    async ({ accessToken }) => {
      const broker: LocalOAuthBroker = {
        resolve: async () => ({
          status: "available",
          credential: {
            accessToken,
            email: "devin@example.test",
            accountId: "devin-account-fixture",
          },
        }),
      };
      const response = ompDevinResponse({
        email: "devin@example.test",
        accountId: "devin-account-fixture",
        organizationId: "devin-org-fixture",
        organization: "Example Organization",
        weeklyRemaining: 65,
        weeklyReset: Math.floor(NOW / 1000) + 3600,
        tier: 18,
        planStart: Math.floor(Date.parse("2026-09-01T00:00:00.000Z") / 1000),
        planEnd: Math.floor(Date.parse("2026-10-01T00:00:00.000Z") / 1000),
        creditBuckets: {
          prompt: { used: 30, available: 70, limit: 100 },
          flow: { used: 20, available: 180, limit: 200 },
          flex: { used: 5, available: 45, limit: 50 },
        },
      });
      const request = sequentialFetch([response]);
      const report = await testAdapter({
        sources: [createDevinEnvSource({})],
        ompBroker: broker,
        fetch: request,
      }).fetchQuota(OPTIONS);

      expect(report).toMatchObject({
        source: "omp:devin",
        state: { status: "fresh", authStatus: "usable" },
        account: {
          email: "devin@example.test",
          accountId: "devin-account-fixture",
          organization: "Example Organization",
          organizationId: "devin-org-fixture",
        },
        plan: "MAX",
        windows: [{ id: "weekly", percentRemaining: 65 }],
        credits: {
          buckets: [
            {
              id: "prompt",
              used: 30,
              available: 70,
              limit: 100,
              unit: "credits",
              startsAt: "2026-09-01T00:00:00.000Z",
              resetsAt: "2026-10-01T00:00:00.000Z",
            },
            {
              id: "flow",
              used: 20,
              available: 180,
              limit: 200,
              unit: "credits",
              startsAt: "2026-09-01T00:00:00.000Z",
              resetsAt: "2026-10-01T00:00:00.000Z",
            },
            {
              id: "flex",
              used: 5,
              available: 45,
              limit: 50,
              unit: "credits",
              startsAt: "2026-09-01T00:00:00.000Z",
              resetsAt: "2026-10-01T00:00:00.000Z",
            },
          ],
        },
        attempts: [
          {
            source: DEVIN_ENV_SOURCE,
            status: "skipped",
            error: "devin_credential_unavailable",
          },
          { source: "omp:devin", status: "success" },
        ],
      });
      expect(JSON.stringify(report)).not.toContain(SESSION_TOKEN);
      const interpreted = withQuotaSemantics(
        report,
        new Date(NOW).toISOString(),
      );
      for (const full of [false, true]) {
        const toon = renderQuotaToon(
          {
            schemaVersion: 6,
            generatedAt: new Date(NOW).toISOString(),
            providers: [interpreted],
          },
          "quota-axi",
          full,
        );
        for (const [id, used, available, limit] of [
          ["prompt", 30, 70, 100],
          ["flow", 20, 180, 200],
          ["flex", 5, 45, 50],
        ] as const) {
          expect(toon).toContain(
            `devin,"credits:${id}",credit_bucket,"used ${used} credits · available ${available} credits · limit ${limit} credits · starts 2026-09-01T00:00:00.000Z · resets 2026-10-01T00:00:00.000Z",none`,
          );
        }
      }

      const [input, init] = request.mock.calls[0];
      expect(new URL(String(input)).href).toBe(
        `https://server.codeium.com${DEVIN_USER_STATUS_PATH}`,
      );
      const headers = new Headers(init?.headers);
      expect(headers.get("content-type")).toBe("application/proto");
      expect(headers.get("accept")).toBe("*/*");
      expect(headers.get("connect-protocol-version")).toBe("1");
      const requestFields = readTestProto(
        new Uint8Array(init?.body as ArrayBuffer),
      );
      const metadataFields = readTestProto(testProtoBytes(requestFields, 1)!);
      expect({
        ideName: testProtoString(metadataFields, 1),
        ideVersion: testProtoString(metadataFields, 7),
        ideType: testProtoString(metadataFields, 28),
        extensionName: testProtoString(metadataFields, 12),
        extensionVersion: testProtoString(metadataFields, 2),
        apiKey: testProtoString(metadataFields, 3),
        locale: testProtoString(metadataFields, 4),
        os: testProtoString(metadataFields, 5),
        userJwt: testProtoString(metadataFields, 21) ?? "",
      }).toEqual({
        ideName: "devin-cli",
        ideVersion: "3000.6.2",
        ideType: "chisel",
        extensionName: "chisel",
        extensionVersion: "3000.6.2",
        apiKey: SESSION_TOKEN,
        locale: "en",
        os: process.platform === "win32" ? "windows" : process.platform,
        userJwt: "",
      });
    },
  );

  it.each([NOW - 3600_000, NOW])(
    "omits OMP buckets when planEnd %i has elapsed but keeps the current weekly quota",
    async (planEnd) => {
      const response = ompDevinResponse({
        email: "devin@example.test",
        accountId: "devin-account-fixture",
        organizationId: "devin-org-fixture",
        organization: "Example Organization",
        weeklyRemaining: 65,
        weeklyReset: Math.floor(NOW / 1000) + 3600,
        tier: 18,
        planStart: Math.floor(Date.parse("2026-09-01T00:00:00.000Z") / 1000),
        planEnd: Math.floor(planEnd / 1000),
        creditBuckets: {
          prompt: { used: 30, available: 70, limit: 100 },
          flow: { used: 20, available: 180, limit: 200 },
          flex: { used: 5, available: 45, limit: 50 },
        },
      });
      const report = await testAdapter({
        sources: [createDevinEnvSource({})],
        ompBroker: {
          resolve: async () => ({
            status: "available",
            credential: { accessToken: SESSION_TOKEN },
          }),
        },
        fetch: sequentialFetch([response]),
      }).fetchQuota(OPTIONS);
      expect(report).toMatchObject({
        source: "omp:devin",
        state: { status: "fresh", authStatus: "usable" },
        windows: [{ id: "weekly", percentRemaining: 65 }],
      });
      expect(report.credits?.buckets).toBeUndefined();
      expect(
        withQuotaSemantics(report, new Date(NOW).toISOString()).quotaSemantics
          ?.effectiveAvailability[0]?.effectivePercentRemaining,
      ).toBe(65);
    },
  );

  it("does not infer exhausted daily or weekly quota from OMP prompt credits alone", async () => {
    const planStatus = joinProto([testProtoInt(6, 7), testProtoInt(8, 14)]);
    const response = new Response(
      joinProto([
        testProtoMessage(1, joinProto([testProtoMessage(13, planStatus)])),
        testProtoMessage(
          2,
          joinProto([testProtoInt(12, 21), testProtoInt(35, 2)]),
        ),
      ]).buffer,
      { status: 200, headers: { "content-type": "application/proto" } },
    );
    const report = await testAdapter({
      sources: [createDevinEnvSource({})],
      ompBroker: {
        resolve: async () => ({
          status: "available",
          credential: { accessToken: SESSION_TOKEN },
        }),
      },
      fetch: sequentialFetch([response]),
    }).fetchQuota(OPTIONS);

    expect(report.source).toBe("omp:devin");
    expect(report.state).toMatchObject({
      status: "fresh",
      authStatus: "usable",
    });
    expect(report.windows).toEqual([]);
    expect(report.credits?.buckets).toEqual([
      { id: "prompt", used: 7, available: 14, limit: 21, unit: "credits" },
    ]);
    const interpreted = withQuotaSemantics(report, new Date(NOW).toISOString());
    expect(interpreted.quotaSemantics?.effectiveAvailability).toEqual([]);
  });

  it.each([false, true])(
    "reports OMP credit counts without planInfo only while the plan is current (expired: %s)",
    async (expired) => {
      const planEnd = NOW + (expired ? -3600_000 : 3600_000);
      const planStatus = joinProto([
        testProtoInt(6, 7),
        testProtoInt(8, 14),
        testProtoInt(5, 5),
        testProtoInt(9, 9),
        testProtoInt(7, 3),
        testProtoInt(4, 4),
        testProtoTimestamp(3, Math.floor(planEnd / 1000)),
      ]);
      const response = new Response(
        joinProto([
          testProtoMessage(1, joinProto([testProtoMessage(13, planStatus)])),
        ]).buffer,
        { status: 200, headers: { "content-type": "application/proto" } },
      );
      const report = await testAdapter({
        sources: [createDevinEnvSource({})],
        ompBroker: {
          resolve: async () => ({
            status: "available",
            credential: { accessToken: SESSION_TOKEN },
          }),
        },
        fetch: sequentialFetch([response]),
      }).fetchQuota(OPTIONS);
      expect(report.source).toBe("omp:devin");
      expect(report.state).toMatchObject({
        status: "fresh",
        authStatus: "usable",
      });
      expect(report.windows).toEqual([]);
      expect(report.credits?.buckets).toEqual(
        expired
          ? undefined
          : [
              {
                id: "prompt",
                used: 7,
                available: 14,
                unit: "credits",
                resetsAt: new Date(planEnd).toISOString(),
              },
              {
                id: "flow",
                used: 5,
                available: 9,
                unit: "credits",
                resetsAt: new Date(planEnd).toISOString(),
              },
              {
                id: "flex",
                used: 3,
                available: 4,
                unit: "credits",
                resetsAt: new Date(planEnd).toISOString(),
              },
            ],
      );
      expect(
        withQuotaSemantics(report, new Date(NOW).toISOString()).quotaSemantics
          ?.effectiveAvailability,
      ).toEqual([]);
    },
  );

  it.each([
    { id: "weekly", resetField: 18 },
    { id: "daily", resetField: 17 },
  ] as const)(
    "defaults only the $id window to proto3 zero when its reset is present",
    async ({ id, resetField }) => {
      const planStatus = joinProto([
        testProtoInt(resetField, Math.floor(NOW / 1000) + 3600),
      ]);
      const response = new Response(
        joinProto([
          testProtoMessage(1, joinProto([testProtoMessage(13, planStatus)])),
          testProtoMessage(2, joinProto([testProtoInt(35, 2)])),
        ]).buffer,
        { status: 200, headers: { "content-type": "application/proto" } },
      );
      const report = await testAdapter({
        sources: [createDevinEnvSource({})],
        ompBroker: {
          resolve: async () => ({
            status: "available",
            credential: { accessToken: SESSION_TOKEN },
          }),
        },
        fetch: sequentialFetch([response]),
      }).fetchQuota(OPTIONS);
      expect(report.source).toBe("omp:devin");
      expect(report.windows).toEqual([
        expect.objectContaining({ id, percentRemaining: 0 }),
      ]);
    },
  );

  it("declares env before the credentials file", () => {
    expect([...DEVIN_SOURCE_ORDER]).toEqual([
      DEVIN_ENV_SOURCE,
      DEVIN_FILE_SOURCE,
    ]);
  });
});

describe("Devin credential matrix", () => {
  it("primary healthy: reports included daily and weekly quota", async () => {
    const report = await testAdapter({
      fetch: sequentialFetch([jsonResponse(PRO)]),
    }).fetchQuota(OPTIONS);
    const interpreted = withQuotaSemantics(report, new Date(NOW).toISOString());

    expect(report.state).toMatchObject({
      status: "fresh",
      authStatus: "usable",
    });
    expect(report.plan).toBe("pro");
    expect(report.account).toEqual({
      email: "person@example.invalid",
      accountId: "fixture-user",
    });
    expect(report.windows).toEqual([WEEKLY, DAILY]);
    expect(report.credits).toEqual({ remaining: 2.5, unit: "usd" });
    expect(JSON.stringify(report)).not.toContain("availablePromptCredits");
    expect(JSON.stringify(report)).not.toContain("fixture-team");
    expect(report.attempts).toEqual([
      { source: DEVIN_ENV_SOURCE, status: "success" },
    ]);
    expect(interpreted.quotaSemantics).toMatchObject({
      status: "known",
      effectiveAvailability: [
        {
          scope: "included_quota",
          status: "known",
          effectivePercentRemaining: 60,
          boundedBy: ["weekly", "daily"],
        },
      ],
    });
  });

  it("reports native credit counts without planInfo or a quota percentage", async () => {
    const report = await testAdapter({
      fetch: sequentialFetch([
        jsonResponse({
          userStatus: {
            planStatus: {
              usedPromptCredits: 7,
              availablePromptCredits: 14,
              usedFlowCredits: 5,
              availableFlowCredits: 9,
              usedFlexCredits: 3,
              availableFlexCredits: 4,
            },
          },
        }),
      ]),
    }).fetchQuota(OPTIONS);
    expect(report.state).toMatchObject({
      status: "fresh",
      authStatus: "usable",
    });
    expect(report.windows).toEqual([]);
    expect(report.credits?.buckets).toEqual([
      { id: "prompt", used: 7, available: 14, unit: "credits" },
      { id: "flow", used: 5, available: 9, unit: "credits" },
      { id: "flex", used: 3, available: 4, unit: "credits" },
    ]);
    expect(
      withQuotaSemantics(report, new Date(NOW).toISOString()).quotaSemantics
        ?.effectiveAvailability,
    ).toEqual([]);
  });

  it("requires vendor counts for each credit bucket independently of monthly caps", () => {
    const normalized = normalizeDevinPayload(
      {
        userStatus: {
          planStatus: {
            usedFlowCredits: -2,
            availableFlowCredits: 9,
            usedFlexCredits: 0,
            availableFlexCredits: 0,
          },
        },
        planInfo: {
          monthlyPromptCredits: 100,
          monthlyFlowCredits: 200,
          monthlyFlexCreditPurchaseAmount: 50,
        },
      },
      NOW,
    );
    expect(normalized.windows).toEqual([]);
    expect(normalized.credits?.buckets).toEqual([
      { id: "flex", used: 0, available: 0, limit: 50, unit: "credits" },
    ]);
    expect(
      normalizeDevinPayload(
        {
          userStatus: {
            planStatus: {
              usedPromptCredits: "invalid",
              availablePromptCredits: 4,
            },
          },
          planInfo: { monthlyPromptCredits: 100 },
        },
        NOW,
      ).credits,
    ).toBeUndefined();
  });

  it("omits expired native credit buckets without altering quota windows or overage balance", () => {
    const payload = structuredClone(PRO) as DevinTestPayload;
    Object.assign(payload.userStatus.planStatus, {
      planEnd: new Date(NOW - 1000).toISOString(),
      usedPromptCredits: 30,
      availablePromptCredits: 70,
      usedFlowCredits: 20,
      availableFlowCredits: 180,
      usedFlexCredits: 5,
      availableFlexCredits: 45,
    });
    Object.assign(payload.planInfo, {
      monthlyPromptCredits: 100,
      monthlyFlowCredits: 200,
      monthlyFlexCreditPurchaseAmount: 50,
    });
    const normalized = normalizeDevinPayload(payload, NOW);
    expect(normalized.windows).toEqual([WEEKLY, DAILY]);
    expect(normalized.credits).toEqual({ remaining: 2.5, unit: "usd" });
  });

  it("reuses the session kind for the daily window", () => {
    const normalized = normalizeDevinPayload(PRO, NOW);
    expect(
      normalized.windows.find((window) => window.id === "daily")?.kind,
    ).toBe("session");
  });

  it("omits the daily window when the vendor hides it", () => {
    const normalized = normalizeDevinPayload(MAX, NOW);
    expect(normalized.windows.map((window) => window.id)).toEqual(["weekly"]);
    expect(normalized.windows[0]).toMatchObject({
      percentRemaining: 40,
      percentUsed: 60,
    });
    expect(normalized.credits).toEqual({ remaining: 0, unit: "usd" });
    const interpreted = withQuotaSemantics(
      {
        provider: "devin",
        windows: normalized.windows,
        state: { status: "fresh", stale: false },
      },
      new Date(NOW).toISOString(),
    );
    expect(interpreted.quotaSemantics?.effectiveAvailability[0]).toMatchObject({
      scope: "included_quota",
      status: "known",
      effectivePercentRemaining: 40,
      boundedBy: ["weekly"],
    });
  });

  it("treats a missing percent with a present reset as proto3 zero", () => {
    const normalized = normalizeDevinPayload(EXHAUSTED, NOW);
    expect(normalized.windows).toEqual([
      { ...WEEKLY, percentRemaining: 0, percentUsed: 100 },
      { ...DAILY, percentRemaining: 25, percentUsed: 75 },
    ]);
    const interpreted = withQuotaSemantics(
      {
        provider: "devin",
        windows: normalized.windows,
        state: { status: "fresh", stale: false },
      },
      new Date(NOW).toISOString(),
    );
    expect(
      interpreted.quotaSemantics?.effectiveAvailability[0]
        ?.effectivePercentRemaining,
    ).toBe(0);
  });

  it("names a missing daily cap as untrusted instead of letting weekly alone bind", () => {
    const payload = structuredClone(PRO) as {
      userStatus: { planStatus: Record<string, unknown> };
    };
    delete payload.userStatus.planStatus.dailyQuotaRemainingPercent;
    delete payload.userStatus.planStatus.dailyQuotaResetAtUnix;
    const normalized = normalizeDevinPayload(payload, NOW);
    expect(normalized.windows.map((w) => w.id)).toEqual(["weekly"]);
    expect(normalized.untrustedWindowIds).toEqual(["daily"]);
    expect(interpretNormalized(normalized).quotaSemantics).toMatchObject({
      status: "partial",
      unresolvedWindowIds: ["daily"],
    });
    expect(
      interpretNormalized(normalized).quotaSemantics?.effectiveAvailability[0]
        ?.effectivePercentRemaining,
    ).toBeUndefined();
  });

  it("names a daily cap from a finished cycle as untrusted", () => {
    const payload = structuredClone(PRO) as {
      userStatus: { planStatus: Record<string, unknown> };
    };
    payload.userStatus.planStatus.dailyQuotaResetAtUnix = String(
      Date.parse("2026-09-22T08:00:00.000Z") / 1000,
    );
    const normalized = normalizeDevinPayload(payload, NOW);
    expect(normalized.windows.map((w) => w.id)).toEqual(["weekly"]);
    expect(normalized.untrustedWindowIds).toEqual(["daily"]);
    expect(interpretNormalized(normalized).quotaSemantics?.status).toBe(
      "partial",
    );
  });

  it("names a missing weekly cap as untrusted even when daily is readable", () => {
    const payload = structuredClone(PRO) as {
      userStatus: { planStatus: Record<string, unknown> };
    };
    delete payload.userStatus.planStatus.weeklyQuotaRemainingPercent;
    delete payload.userStatus.planStatus.weeklyQuotaResetAtUnix;
    const normalized = normalizeDevinPayload(payload, NOW);
    expect(normalized.windows.map((w) => w.id)).toEqual(["daily"]);
    expect(normalized.untrustedWindowIds).toEqual(["weekly"]);
    expect(interpretNormalized(normalized).quotaSemantics).toMatchObject({
      status: "partial",
      unresolvedWindowIds: ["weekly"],
    });
  });

  it("includes a daily quota when reset data is present", () => {
    const payload = structuredClone(MAX) as {
      planInfo: Record<string, unknown>;
    };
    delete payload.planInfo.hideDailyQuota;
    const normalized = normalizeDevinPayload(payload, NOW);
    expect(normalized.windows.map((window) => window.id)).toEqual([
      "weekly",
      "daily",
    ]);
    expect(normalized.untrustedWindowIds).toEqual([]);
    expect(
      interpretNormalized(normalized).quotaSemantics?.effectiveAvailability[0]
        ?.effectivePercentRemaining,
    ).toBe(10);
  });

  it("rejects a hideDailyQuota that is not a boolean", () => {
    const payload = structuredClone(MAX) as {
      planInfo: Record<string, unknown>;
    };
    payload.planInfo.hideDailyQuota = "true";
    expect(() => normalizeDevinPayload(payload, NOW)).toThrow("schema_invalid");
  });

  it("omits a hidden weekly window without omitting daily", () => {
    const payload = structuredClone(PRO) as {
      planInfo: Record<string, unknown>;
    };
    payload.planInfo.hideWeeklyQuota = true;
    const normalized = normalizeDevinPayload(payload, NOW);
    expect(normalized.windows.map((window) => window.id)).toEqual(["daily"]);
  });

  it("names an out-of-range percent as untrusted and keeps semantics partial", () => {
    const normalized = normalizeDevinPayload(OUT_OF_RANGE, NOW);
    expect(normalized.untrustedWindowIds).toEqual(["weekly"]);
    expect(
      normalized.windows.find((w) => w.id === "weekly")?.percentRemaining,
    ).toBeUndefined();
    const interpreted = withQuotaSemantics(
      {
        provider: "devin",
        windows: normalized.windows,
        state: {
          status: "fresh",
          stale: false,
          untrustedWindowIds: normalized.untrustedWindowIds,
        },
      },
      new Date(NOW).toISOString(),
    );
    expect(interpreted.quotaSemantics).toMatchObject({
      status: "partial",
      unresolvedWindowIds: ["weekly"],
    });
    expect(
      interpreted.quotaSemantics?.effectiveAvailability[0]
        ?.effectivePercentRemaining,
    ).toBeUndefined();
  });

  it("includes quota windows with reset data on a non-quota billing strategy", () => {
    const normalized = normalizeDevinPayload(NON_QUOTA, NOW);
    expect(normalized.windows.map((window) => window.id)).toEqual([
      "weekly",
      "daily",
    ]);
    expect(normalized.credits).toEqual({ remaining: 5, unit: "usd" });
    expect(JSON.stringify(normalized)).not.toContain("acuConsumed");
    expect(JSON.stringify(normalized)).not.toContain("acuLimit");
  });

  it.each([
    [
      "quota fields without reset evidence or billing strategy",
      (payload: DevinTestPayload) => {
        delete payload.planInfo.billingStrategy;
        delete payload.userStatus.planStatus.dailyQuotaResetAtUnix;
        delete payload.userStatus.planStatus.weeklyQuotaResetAtUnix;
      },
    ],
    [
      "every expected cap from a finished cycle",
      (payload: DevinTestPayload) => {
        const elapsed = String(Date.parse("2026-09-22T08:00:00.000Z") / 1000);
        payload.userStatus.planStatus.dailyQuotaResetAtUnix = elapsed;
        payload.userStatus.planStatus.weeklyQuotaResetAtUnix = elapsed;
      },
    ],
  ])("preserves the cache on %s", async (_label, mutate) => {
    const deleted: string[] = [];
    const contextId = devinCacheContextId(
      DEVIN_ENV_SOURCE,
      DEVIN_API_ORIGIN,
      SYNTHETIC_KEY,
    );
    const payload = structuredClone(PRO) as DevinTestPayload;
    mutate(payload);
    const report = await testAdapter({
      fetch: sequentialFetch([jsonResponse(payload)]),
      retireCachedContext: (id) => deleted.push(id),
      readCachedProvider: (id) =>
        id === contextId ? cachedQuota() : undefined,
    }).fetchQuota(OPTIONS);

    expect(deleted).toEqual([]);
    expect(report.state).toMatchObject({
      status: "stale",
      error: "schema_incomplete",
    });
    expect(report.windows[0]?.percentRemaining).toBe(90);
  });

  it("reports an authenticated body with no quota fields as fresh and empty", async () => {
    const report = await testAdapter({
      fetch: sequentialFetch([jsonResponse(NO_QUOTA)]),
    }).fetchQuota(OPTIONS);
    expect(report.state).toMatchObject({
      status: "fresh",
      authStatus: "usable",
    });
    expect(report.windows).toEqual([]);
    expect(report.credits).toBeUndefined();
  });

  it("does not skip a readable token unprobed, and hands a rejected env token to the file", async () => {
    const request = sequentialFetch([
      new Response(null, { status: 401 }),
      jsonResponse(PRO),
    ]);
    const report = await testAdapter({
      fetch: request,
      sources: [
        createDevinEnvSource({ WINDSURF_API_KEY: SYNTHETIC_KEY }),
        fileSource({
          status: "resolved",
          credential: { token: FILE_KEY, origin: DEVIN_API_ORIGIN },
        }),
      ],
    }).fetchQuota(OPTIONS);

    expect(request).toHaveBeenCalledTimes(2);
    expect(apiKey(request.mock.calls[0][1])).toBe(SYNTHETIC_KEY);
    expect(apiKey(request.mock.calls[1][1])).toBe(FILE_KEY);
    expect(report.state.status).toBe("fresh");
    expect(report.attempts).toEqual([
      {
        source: DEVIN_ENV_SOURCE,
        status: "failed",
        error: "provider_auth_rejected",
        credentialPresent: true,
      },
      { source: DEVIN_FILE_SOURCE, status: "success" },
    ]);
    const interpreted = withQuotaSemantics(report, new Date(NOW).toISOString());
    expect(interpreted.state.degradedSources).toEqual([
      { source: DEVIN_ENV_SOURCE, error: "provider_auth_rejected" },
    ]);
  });

  it("never sends a structurally invalid env value, and does not fall through to the file", async () => {
    const request = vi.fn();
    const report = await testAdapter({
      fetch: request as unknown as typeof fetch,
      sources: [
        createDevinEnvSource({ WINDSURF_API_KEY: "$WINDSURF_API_KEY" }),
        fileSource({
          status: "resolved",
          credential: { token: FILE_KEY, origin: DEVIN_API_ORIGIN },
        }),
      ],
    }).fetchQuota(OPTIONS);

    expect(request).not.toHaveBeenCalled();
    expect(report.state).toMatchObject({
      status: "error",
      error: "devin_credential_invalid",
    });
    expect(report.state.authStatus).toBeUndefined();
    expect(report.state.remedyCommand).toBeUndefined();
    expect(report.attempts).toEqual([
      {
        source: DEVIN_ENV_SOURCE,
        status: "failed",
        error: "devin_credential_invalid",
        credentialPresent: true,
      },
    ]);
  });

  it("treats a blank env value as absent and reads the file", async () => {
    const request = sequentialFetch([jsonResponse(MAX)]);
    const report = await testAdapter({
      fetch: request,
      sources: [
        createDevinEnvSource({ WINDSURF_API_KEY: "   " }),
        fileSource({
          status: "resolved",
          credential: { token: FILE_KEY, origin: DEVIN_API_ORIGIN },
        }),
      ],
    }).fetchQuota(OPTIONS);

    expect(apiKey(request.mock.calls[0][1])).toBe(FILE_KEY);
    expect(report.attempts[0]).toEqual({
      source: DEVIN_ENV_SOURCE,
      status: "skipped",
      error: "devin_credential_unavailable",
    });
    expect(report.attempts[0].credentialPresent).toBeUndefined();
    expect(report.windows.map((window) => window.id)).toEqual(["weekly"]);
  });

  it("absent sources make no request and carry no credentialPresent marker", async () => {
    const request = vi.fn();
    const report = await testAdapter({
      fetch: request as unknown as typeof fetch,
      sources: [createDevinEnvSource({}), fileSource({ status: "absent" })],
    }).fetchQuota(OPTIONS);

    expect(request).not.toHaveBeenCalled();
    expect(report.state).toMatchObject({
      status: "auth_required",
      error: "devin_credential_unavailable",
    });
    expect(report.state.remedyCommand).toBeUndefined();
    for (const attempt of report.attempts ?? []) {
      expect(attempt.status).toBe("skipped");
      expect(attempt.credentialPresent).toBeUndefined();
    }
  });

  it.each([false, true])(
    "does not offer native login for OMP rejection after native rejection: %s",
    async (nativeRejected) => {
      const request = sequentialFetch(
        nativeRejected
          ? [
              new Response(null, { status: 401 }),
              new Response(null, { status: 401 }),
            ]
          : [new Response(null, { status: 401 })],
      );
      const report = await testAdapter({
        sources: [
          createDevinEnvSource(
            nativeRejected ? { WINDSURF_API_KEY: SYNTHETIC_KEY } : {},
          ),
        ],
        ompBroker: {
          resolve: async () => ({
            status: "available",
            credential: { accessToken: SESSION_TOKEN },
          }),
        },
        fetch: request,
      }).fetchQuota(OPTIONS);

      expect(request).toHaveBeenCalledTimes(nativeRejected ? 2 : 1);
      expect(report.state).toMatchObject({
        status: "auth_required",
        error: "provider_auth_rejected",
        authStatus: "unusable",
      });
      expect(report.state.remedyCommand).toBeUndefined();
      expect(report.attempts?.at(-1)).toEqual({
        source: "omp:devin",
        status: "failed",
        error: "provider_auth_rejected",
        credentialPresent: true,
      });
      expect(JSON.stringify(report)).not.toContain(SESSION_TOKEN);
    },
  );

  it("retires the matching cache when every probed credential is rejected", async () => {
    const deleted: string[] = [];
    const contextId = devinCacheContextId(
      DEVIN_ENV_SOURCE,
      DEVIN_API_ORIGIN,
      SYNTHETIC_KEY,
    );
    const report = await testAdapter({
      fetch: sequentialFetch([new Response(null, { status: 401 })]),
      retireCachedContext: (id) => deleted.push(id),
      readCachedProvider: (id) =>
        id === contextId ? cachedQuota() : undefined,
    }).fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "auth_required",
      error: "provider_auth_rejected",
      authStatus: "unusable",
      remedyCommand: "devin auth login",
    });
    expect(deleted).toEqual([contextId]);
  });

  it.each(["transient", "expired_refreshable"] as const)(
    "retires rejected native quota before OMP $failure can return",
    async (failure) => {
      tempDir = mkdtempSync(join(tmpdir(), "quota-axi-devin-cache-"));
      const originalCacheHome = process.env.XDG_CACHE_HOME;
      process.env.XDG_CACHE_HOME = tempDir;
      try {
        const contextId = devinCacheContextId(
          DEVIN_ENV_SOURCE,
          DEVIN_API_ORIGIN,
          SYNTHETIC_KEY,
        );
        const initial = await testAdapter({
          fetch: sequentialFetch([jsonResponse(PRO)]),
        }).fetchQuota(OPTIONS);
        stampReadingInputs(initial, { paths: [], digest: inputsDigest([]) });
        writeCachedProviders([initial], new Date(NOW).toISOString());
        expect(readCachedDevinProvider(contextId)?.windows).toHaveLength(2);
        expect(
          readReusableProviders("devin", 120, NOW + 1000)?.[0].state.reused,
        ).toBe(true);

        let calls = 0;
        const request = vi.fn(async () => {
          calls += 1;
          if (calls === 1) return new Response(null, { status: 401 });
          expect(readCachedDevinProvider(contextId)).toBeUndefined();
          return new Response(null, {
            status: failure === "transient" ? 503 : 401,
          });
        });
        const report = await testAdapter({
          fetch: request,
          ompBroker: {
            resolve: async () =>
              failure === "transient"
                ? {
                    status: "available",
                    credential: { accessToken: SESSION_TOKEN },
                  }
                : {
                    status: "expired",
                    credential: { accessToken: SESSION_TOKEN },
                    refreshable: true,
                  },
          },
        }).fetchQuota(OPTIONS);
        expect(request).toHaveBeenCalledTimes(2);
        expect(report.state.status).toBe(
          failure === "transient" ? "error" : "unavailable",
        );
        expect(readCachedDevinProvider(contextId)).toBeUndefined();
        expect(readReusableProviders("devin", 120, NOW + 1000)).toBeUndefined();
      } finally {
        if (originalCacheHome === undefined) delete process.env.XDG_CACHE_HOME;
        else process.env.XDG_CACHE_HOME = originalCacheHome;
      }
    },
  );

  it("has no refresh delegate: refreshCredentials does not change the read", async () => {
    const adapter = testAdapter({
      fetch: sequentialFetch([jsonResponse(PRO)]),
    });
    expect(adapter.discoverAccounts).toBeUndefined();
    const refreshed = await testAdapter({
      fetch: sequentialFetch([jsonResponse(PRO)]),
    }).fetchQuota({ ...OPTIONS, refreshCredentials: true });
    const plain = await adapter.fetchQuota(OPTIONS);
    expect(refreshed.windows).toEqual(plain.windows);
    expect(refreshed.state.status).toBe("fresh");
  });

  it("stops handover on a transient failure and serves the same credential's stale windows", async () => {
    const deleted: string[] = [];
    const contextId = devinCacheContextId(
      DEVIN_ENV_SOURCE,
      DEVIN_API_ORIGIN,
      SYNTHETIC_KEY,
    );
    const request = sequentialFetch([new Response(null, { status: 503 })]);
    const report = await testAdapter({
      fetch: request,
      sources: [
        createDevinEnvSource({ WINDSURF_API_KEY: SYNTHETIC_KEY }),
        fileSource({
          status: "resolved",
          credential: { token: FILE_KEY, origin: DEVIN_API_ORIGIN },
        }),
      ],
      retireCachedContext: (id) => deleted.push(id),
      readCachedProvider: (id) =>
        id === contextId ? cachedQuota() : undefined,
    }).fetchQuota(OPTIONS);

    expect(request).toHaveBeenCalledTimes(1);
    expect(deleted).toEqual([]);
    expect(report.state.status).toBe("stale");
    expect(report.state.stale).toBe(true);
    expect(report.windows[0]?.percentRemaining).toBe(90);
    expect(report.state.sourcesTried).toEqual([DEVIN_ENV_SOURCE, "cache"]);
  });

  it("reports a 401 as a rejection without waiting on its stalled body", async () => {
    const stalled = new ReadableStream<Uint8Array>({
      pull: () => new Promise(() => {}),
    });
    const report = await testAdapter({
      fetch: sequentialFetch([new Response(stalled, { status: 401 })]),
      deadlineMs: 50,
    }).fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "auth_required",
      error: "provider_auth_rejected",
      authStatus: "unusable",
    });
  });

  it("times out a stalled body even when its cancellation never settles", async () => {
    const stalled = new ReadableStream<Uint8Array>({
      pull: () => new Promise(() => {}),
      cancel: () => new Promise(() => {}),
    });
    const report = await testAdapter({
      fetch: sequentialFetch([new Response(stalled, { status: 200 })]),
      deadlineMs: 20,
    }).fetchQuota(OPTIONS);

    expect(report.state).toMatchObject({
      status: "error",
      error: "request_timeout",
    });
  });

  it("preserves the cache on HTTP 400", async () => {
    const deleted: string[] = [];
    const contextId = devinCacheContextId(
      DEVIN_ENV_SOURCE,
      DEVIN_API_ORIGIN,
      SYNTHETIC_KEY,
    );
    const report = await testAdapter({
      fetch: sequentialFetch([new Response(null, { status: 400 })]),
      retireCachedContext: (id) => deleted.push(id),
      readCachedProvider: (id) =>
        id === contextId ? cachedQuota() : undefined,
    }).fetchQuota(OPTIONS);

    expect(deleted).toEqual([]);
    expect(report.state.status).toBe("stale");
    expect(report.state.error).toBe("provider_request_rejected");
  });

  it("does not send a token whose server is outside the allowlist", async () => {
    const request = vi.fn();
    const adapter = testAdapter({
      fetch: request as unknown as typeof fetch,
      sources: [
        createDevinEnvSource({
          WINDSURF_API_KEY: SYNTHETIC_KEY,
          WINDSURF_API_SERVER_URL: "https://enterprise.example",
        }),
        fileSource({
          status: "resolved",
          credential: { token: FILE_KEY, origin: DEVIN_API_ORIGIN },
        }),
      ],
    });
    const report = await adapter.fetchQuota(OPTIONS);

    expect(request).not.toHaveBeenCalled();
    expect(report.state.status).toBe("error");
    expect(report.state.error).toBe("unsupported_server");
    expect(report.state.authStatus).toBeUndefined();
    expect(
      adapter.isUncertainSkip?.(
        report.attempts?.[0] ?? { source: "", status: "skipped" },
      ),
    ).toBe(true);
  });

  it("sends a vendor session token that embeds $", async () => {
    const request = sequentialFetch([jsonResponse(NO_QUOTA)]);
    await testAdapter({
      fetch: request,
      sources: [createDevinEnvSource({ WINDSURF_API_KEY: SESSION_TOKEN })],
    }).fetchQuota(OPTIONS);
    expect(apiKey(request.mock.calls[0][1])).toBe(SESSION_TOKEN);
  });

  it.each([
    ["an environment reference", "$WINDSURF_API_KEY"],
    ["a command reference", "!op read op://vault/key"],
    ["a control byte", "devin-\u0007-fixture"],
  ])("never sends %s", async (_label, value) => {
    const request = vi.fn();
    const report = await testAdapter({
      fetch: request as unknown as typeof fetch,
      sources: [createDevinEnvSource({ WINDSURF_API_KEY: value })],
    }).fetchQuota(OPTIONS);
    expect(request).not.toHaveBeenCalled();
    expect(report.state.status).toBe("error");
    expect(report.state.remedyCommand).toBeUndefined();
    expect(report.attempts?.[0].credentialPresent).toBe(true);
  });
});

describe("Devin credentials file", () => {
  it("reads the XDG path and ignores every other key", async () => {
    tempDir = mkdtempSync(join(tmpdir(), "quota-axi-devin-"));
    const directory = join(tempDir, "devin");
    mkdirSync(directory);
    writeFileSync(
      join(directory, "credentials.toml"),
      [
        "# fixture",
        `windsurf_api_key = "${FILE_KEY}"`,
        'api_server_url = "https://server.codeium.com"',
        'devin_webapp_host = "app.devin.ai"',
        "dangerously_skip_plugin_authentication = false",
      ].join("\n"),
    );
    const request = sequentialFetch([jsonResponse(PRO)]);
    const report = await testAdapter({
      fetch: request,
      sources: [createDevinFileSource({ XDG_DATA_HOME: tempDir })],
    }).fetchQuota(OPTIONS);

    expect(apiKey(request.mock.calls[0][1])).toBe(FILE_KEY);
    expect(String(request.mock.calls[0][0])).toBe(
      `${DEVIN_API_ORIGIN}${DEVIN_USER_STATUS_PATH}`,
    );
    expect(report.state.status).toBe("fresh");
  });

  it.each([
    ["array", "metadata = [1, 2, 3]"],
    ["timestamp", "created_at = 2026-09-22T12:00:00Z"],
    ["float", "ratio = 0.75"],
    ["inline table", 'metadata = { version = "1.0" }'],
    ["unknown key", 'devin_webapp_host = "app.devin.ai"'],
    ["table header", "[metadata]\nwindsurf_api_key = [1, 2]"],
  ])(
    "ignores unrelated TOML %s in the credentials file",
    async (_name, metadata) => {
      tempDir = mkdtempSync(join(tmpdir(), "quota-axi-devin-"));
      mkdirSync(join(tempDir, "devin"));
      writeFileSync(
        join(tempDir, "devin", "credentials.toml"),
        `windsurf_api_key = "${FILE_KEY}"\n${metadata}\n`,
      );
      const request = sequentialFetch([jsonResponse(PRO)]);
      const source = createDevinFileSource({ XDG_DATA_HOME: tempDir });
      expect(source.inspect().status).toBe("available");
      const report = await testAdapter({
        fetch: request,
        sources: [source],
      }).fetchQuota(OPTIONS);

      expect(report.state.status).toBe("fresh");
      expect(request).toHaveBeenCalledTimes(1);
      expect(apiKey(request.mock.calls[0][1])).toBe(FILE_KEY);
    },
  );

  it.each([
    'windsurf_api_key = "valid-key"\nwindsurf_api_key = [1, 2]',
    'windsurf_api_key = "unterminated',
    `windsurf_api_key = "${FILE_KEY}"\napi_server_url = { host = 'server.codeium.com' }`,
  ])("does not send a malformed needed credential value: %s", async (line) => {
    tempDir = mkdtempSync(join(tmpdir(), "quota-axi-devin-"));
    mkdirSync(join(tempDir, "devin"));
    writeFileSync(join(tempDir, "devin", "credentials.toml"), `${line}\n`);
    const request = vi.fn();
    const report = await testAdapter({
      fetch: request as unknown as typeof fetch,
      sources: [createDevinFileSource({ XDG_DATA_HOME: tempDir })],
    }).fetchQuota(OPTIONS);

    expect(request).not.toHaveBeenCalled();
    expect(report.state.error).toBe("devin_credentials_malformed");
    expect(report.attempts?.[0].credentialPresent).toBe(true);
  });

  it("resolves XDG, the Unix default, and the Windows APPDATA path", () => {
    expect(
      devinCredentialsFilePath(
        { XDG_DATA_HOME: "/custom/data" },
        { platform: "linux", home: "/home/fixture" },
      ),
    ).toBe("/custom/data/devin/credentials.toml");
    expect(
      devinCredentialsFilePath(
        {},
        { platform: "linux", home: "/home/fixture" },
      ),
    ).toBe("/home/fixture/.local/share/devin/credentials.toml");
    expect(
      devinCredentialsFilePath(
        { APPDATA: "C:\\Users\\fixture\\AppData\\Roaming" },
        { platform: "win32", home: "C:\\Users\\fixture" },
      ),
    ).toBe(
      join("C:\\Users\\fixture\\AppData\\Roaming", "devin", "credentials.toml"),
    );
    expect(
      devinCredentialsFilePath(
        {},
        { platform: "win32", home: "C:\\Users\\fixture" },
      ),
    ).toBeUndefined();
  });
});

describe("Devin auth inspection", () => {
  it("enumerates both sources by presence and never returns the token", async () => {
    const report = await testAdapter({
      sources: [
        createDevinEnvSource({ WINDSURF_API_KEY: SYNTHETIC_KEY }),
        createDevinFileSource({ XDG_DATA_HOME: "/no/such/devin-data" }),
      ],
    }).inspectAuth(OPTIONS);

    expect(report.sources.map((source) => source.status)).toEqual([
      "available",
      "missing",
      "missing",
    ]);
    expect(JSON.stringify(report)).not.toContain(SYNTHETIC_KEY);
  });
});

function testAdapter(
  overrides: Partial<{
    fetch: typeof fetch;
    sources: readonly DevinCredentialSource[];
    ompBroker?: LocalOAuthBroker;
    readCachedProvider: (contextId: string) => ProviderQuota | undefined;
    retireCachedContext: (contextId: string) => void;
    deadlineMs: number;
  }> = {},
): ReturnType<typeof createDevinAdapter> {
  return createDevinAdapter({
    sources: overrides.sources ?? [
      createDevinEnvSource({ WINDSURF_API_KEY: SYNTHETIC_KEY }),
    ],
    ...(overrides.ompBroker ? { ompBroker: overrides.ompBroker } : {}),
    fetch:
      overrides.fetch ??
      (sequentialFetch([jsonResponse(PRO)]) as unknown as typeof fetch),
    now: () => NOW,
    ...(overrides.readCachedProvider
      ? { readCachedProvider: overrides.readCachedProvider }
      : {}),
    ...(overrides.retireCachedContext
      ? { retireCachedContext: overrides.retireCachedContext }
      : {}),
    ...(overrides.deadlineMs ? { deadlineMs: overrides.deadlineMs } : {}),
  });
}

type TestProtoField = {
  number: number;
  wire: number;
  value: number | Uint8Array;
};

function ompDevinResponse(input: {
  email: string;
  accountId: string;
  organizationId: string;
  organization: string;
  weeklyRemaining: number;
  weeklyReset: number;
  tier: number;
  planStart: number;
  planEnd: number;
  creditBuckets: Record<
    "prompt" | "flow" | "flex",
    { used: number; available: number; limit: number }
  >;
}): Response {
  const planStatus = joinProto([
    testProtoInt(15, input.weeklyRemaining),
    testProtoInt(18, input.weeklyReset),
    testProtoTimestamp(2, input.planStart),
    testProtoTimestamp(3, input.planEnd),
    testProtoInt(6, input.creditBuckets.prompt.used),
    testProtoInt(8, input.creditBuckets.prompt.available),
    testProtoInt(5, input.creditBuckets.flow.used),
    testProtoInt(9, input.creditBuckets.flow.available),
    testProtoInt(7, input.creditBuckets.flex.used),
    testProtoInt(4, input.creditBuckets.flex.available),
  ]);
  const devinInfo = joinProto([
    testProtoStringField(4, input.organizationId),
    testProtoStringField(8, input.organization),
  ]);
  const userStatus = joinProto([
    testProtoStringField(5, input.organizationId),
    testProtoStringField(7, input.email),
    testProtoInt(10, input.tier),
    testProtoMessage(13, planStatus),
    testProtoStringField(36, input.accountId),
  ]);
  const planInfo = joinProto([
    testProtoStringField(2, "Max"),
    testProtoInt(12, input.creditBuckets.prompt.limit),
    testProtoInt(13, input.creditBuckets.flow.limit),
    testProtoInt(14, input.creditBuckets.flex.limit),
    testProtoMessage(33, devinInfo),
    testProtoInt(35, 2),
    testProtoInt(36, 1),
  ]);
  return new Response(
    joinProto([testProtoMessage(1, userStatus), testProtoMessage(2, planInfo)])
      .buffer,
    { status: 200, headers: { "content-type": "application/proto" } },
  );
}
function testProtoTimestamp(
  number: number,
  seconds: number,
): Uint8Array<ArrayBuffer> {
  return testProtoMessage(
    number,
    joinProto([testProtoInt(1, seconds), testProtoInt(2, 0)]),
  );
}

function testProtoStringField(
  number: number,
  value: string,
): Uint8Array<ArrayBuffer> {
  return testProtoMessage(number, new TextEncoder().encode(value));
}

function testProtoMessage(
  number: number,
  value: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  return joinProto([
    testProtoVarint((number << 3) | 2),
    testProtoVarint(value.length),
    value,
  ]);
}

function testProtoInt(number: number, value: number): Uint8Array<ArrayBuffer> {
  return joinProto([testProtoVarint(number << 3), testProtoVarint(value)]);
}

function testProtoVarint(value: number): Uint8Array<ArrayBuffer> {
  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0x7f) {
    bytes.push((remaining & 0x7f) | 0x80);
    remaining >>>= 7;
  }
  bytes.push(remaining);
  const result = new Uint8Array(bytes.length);
  result.set(bytes);
  return result;
}

function joinProto(
  parts: readonly Uint8Array<ArrayBuffer>[],
): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(
    parts.reduce((total, part) => total + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function readTestProto(bytes: Uint8Array): TestProtoField[] {
  const fields: TestProtoField[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const key = readTestVarint(bytes, offset);
    offset = key.offset;
    const number = key.value >>> 3;
    const wire = key.value & 7;
    if (wire === 0) {
      const value = readTestVarint(bytes, offset);
      fields.push({ number, wire, value: value.value });
      offset = value.offset;
    } else if (wire === 2) {
      const length = readTestVarint(bytes, offset);
      offset = length.offset;
      fields.push({
        number,
        wire,
        value: bytes.subarray(offset, offset + length.value),
      });
      offset += length.value;
    } else {
      throw new Error("unsupported fixture wire type");
    }
  }
  return fields;
}

function readTestVarint(
  bytes: Uint8Array,
  start: number,
): { value: number; offset: number } {
  let value = 0;
  let offset = start;
  for (let shift = 0; shift < 35 && offset < bytes.length; shift += 7) {
    const byte = bytes[offset];
    offset += 1;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value, offset };
  }
  throw new Error("invalid fixture varint");
}

function testProtoBytes(
  fields: TestProtoField[],
  number: number,
): Uint8Array | undefined {
  const field = fields.find(
    (candidate) => candidate.number === number && candidate.wire === 2,
  );
  return field?.value instanceof Uint8Array ? field.value : undefined;
}

function testProtoString(
  fields: TestProtoField[],
  number: number,
): string | undefined {
  const bytes = testProtoBytes(fields, number);
  return bytes ? new TextDecoder().decode(bytes) : undefined;
}
function interpretNormalized(
  normalized: ReturnType<typeof normalizeDevinPayload>,
): ProviderQuota {
  return withQuotaSemantics(
    {
      provider: "devin",
      windows: normalized.windows,
      state: {
        status: "fresh",
        stale: false,
        untrustedWindowIds: normalized.untrustedWindowIds,
      },
    },
    new Date(NOW).toISOString(),
  );
}

function fileSource(resolution: DevinLocalResolution): DevinCredentialSource {
  return {
    name: DEVIN_FILE_SOURCE,
    resolve: () => resolution,
    inspect: () => ({ status: "missing" }),
  };
}

function sequentialFetch(responses: Response[]) {
  return vi.fn(async () => {
    const next = responses.shift();
    if (!next) throw new Error("unexpected Devin request");
    return next;
  });
}

function jsonResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function apiKey(init: RequestInit | undefined): string | undefined {
  return (JSON.parse(String(init?.body)) as { metadata?: { apiKey?: string } })
    .metadata?.apiKey;
}

function cachedQuota(): ProviderQuota {
  return {
    provider: "devin",
    label: "Devin",
    source: "api",
    windows: [
      {
        id: "weekly",
        label: "week",
        kind: "weekly",
        percentUsed: 10,
        percentRemaining: 90,
        windowSeconds: 604_800,
        startsAt: "2026-09-20T08:00:00.000Z",
        resetsAt: "2026-09-27T08:00:00.000Z",
      },
    ],
    state: {
      status: "fresh",
      stale: false,
      authStatus: "usable",
      refreshedAt: "2026-09-22T00:00:00.000Z",
    },
  };
}
