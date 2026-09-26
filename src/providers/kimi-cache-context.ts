import type { ProviderQuota } from "../types.js";

/**
 * Attach the context of the credential that answered to its own reading.
 * Symbols survive the command's object copies without entering the cache or
 * rendered output. A missing identity must not inherit another run's context.
 */
const KIMI_READING_CONTEXT_ID = Symbol("kimiReadingContextId");

type KimiStampedQuota = ProviderQuota & {
  [KIMI_READING_CONTEXT_ID]?: string;
};

export function stampKimiReadingContextId(
  report: ProviderQuota,
  contextId: string | undefined,
): ProviderQuota {
  (report as KimiStampedQuota)[KIMI_READING_CONTEXT_ID] = contextId;
  return report;
}

export function kimiReadingContextId(
  report: ProviderQuota,
): string | undefined {
  return (report as KimiStampedQuota)[KIMI_READING_CONTEXT_ID];
}
