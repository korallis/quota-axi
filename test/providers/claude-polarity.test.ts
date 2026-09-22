import { describe, expect, it } from "vitest";
import { computeWindowPace } from "../../src/pace.js";
import { normalizeClaudeApiUsage } from "../../src/providers/claude.js";
import { parseClaudeNativeDebug } from "../../src/providers/claude-native-quota.js";

/**
 * Observed vendor payloads from the 0.1.50 polarity inversion (PR #248).
 * Live vendor polarity is established by Claude Code's first-party schema and
 * UI ("% used" / "Share of the window used, 0-100"); these tests do not open
 * Keychain or call the live usage endpoint.
 */
const READING_A = {
  generatedAt: "2026-09-22T21:26:20Z",
  payload: {
    limits: [
      {
        kind: "session",
        group: "session",
        percent: 48,
        resets_at: "2026-09-22T22:50:00Z",
      },
      {
        kind: "weekly_all",
        group: "weekly",
        percent: 2,
        resets_at: "2026-09-29T21:00:00Z",
      },
      {
        kind: "weekly_scoped",
        group: "weekly",
        percent: 0,
        resets_at: "2026-09-29T21:00:00Z",
        scope: { model: { display_name: "Fable" } },
      },
    ],
  },
};

const READING_B = {
  payload: {
    limits: [
      {
        kind: "session",
        group: "session",
        percent: 0,
        resets_at: "2026-09-23T02:20:00Z",
      },
      {
        kind: "weekly_all",
        group: "weekly",
        percent: 61,
        resets_at: "2026-09-26T09:00:00Z",
      },
      {
        kind: "weekly_scoped",
        group: "weekly",
        percent: 94,
        resets_at: "2026-09-26T09:00:00Z",
        scope: { model: { display_name: "Fable" } },
      },
    ],
  },
};

describe("Claude utilization polarity", () => {
  it("reads a weekly window 26 minutes after its reset as nearly full", () => {
    const windows = normalizeClaudeApiUsage(READING_A.payload, "max")!.windows;

    expect(windows).toMatchObject([
      { id: "five_hour", percentUsed: 48, percentRemaining: 52 },
      { id: "seven_day", percentUsed: 2, percentRemaining: 98 },
      { id: "model:fable", percentUsed: 0, percentRemaining: 100 },
    ]);

    const weeklyPace = computeWindowPace(windows[1]!, READING_A.generatedAt);
    expect(weeklyPace.burnMultiple).toBeLessThan(10);
  });

  it("publishes remaining for the second observed limits[] reading", () => {
    const windows = normalizeClaudeApiUsage(READING_B.payload, "max")!.windows;

    expect(windows).toMatchObject([
      { id: "five_hour", percentUsed: 0, percentRemaining: 100 },
      { id: "seven_day", percentUsed: 61, percentRemaining: 39 },
      { id: "model:fable", percentUsed: 94, percentRemaining: 6 },
    ]);
  });

  it("keeps OAuth utilization, limits[] percent, and native header polarity aligned", () => {
    const fromTopLevel = normalizeClaudeApiUsage({
      seven_day: { utilization: 40 },
    });
    const fromLimits = normalizeClaudeApiUsage({
      limits: [
        {
          kind: "weekly_all",
          group: "weekly",
          percent: 40,
          resets_at: "2026-09-29T21:00:00Z",
        },
      ],
    });
    const nativeNow = Date.parse("2026-09-22T21:26:20Z");
    const fromNative = parseClaudeNativeDebug(
      `[log_fixture] response start ${JSON.stringify({
        status: 200,
        headers: {
          "anthropic-ratelimit-unified-5h-utilization": "0.4",
          "anthropic-ratelimit-unified-5h-reset": String(
            nativeNow / 1000 + 3600,
          ),
          "anthropic-ratelimit-unified-7d-utilization": "0.4",
          "anthropic-ratelimit-unified-7d-reset": String(
            nativeNow / 1000 + 86400,
          ),
        },
      })}\n`,
      nativeNow,
    );

    expect(fromTopLevel?.windows).toMatchObject([
      { id: "seven_day", percentUsed: 40 },
    ]);
    expect(fromLimits?.windows).toMatchObject([
      { id: "seven_day", percentUsed: 40 },
    ]);
    expect(fromNative).toMatchObject({
      kind: "success",
      windows: expect.arrayContaining([
        expect.objectContaining({ id: "seven_day", percentUsed: 40 }),
      ]),
    });
  });
});
