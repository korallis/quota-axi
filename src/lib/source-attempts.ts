import type { DegradedSource, ProviderQuota, SourceAttempt } from "../types.js";

/**
 * A credential source that was not genuinely absent and did not yield a reading.
 *
 * The default is derived from the attempt itself - a source that was tried and
 * errored, or one that was skipped after resolving beyond absence - so a new
 * provider inherits the correct answer without restating it. A provider whose
 * non-success attempt is not a credential problem (a live model-auth probe
 * that simply carries no quota, an identity lookup that is not a source at all)
 * sets `degraded: false` on that attempt to say so explicitly, and a provider
 * whose skipped source was itself unreadable - so presence could not be
 * established either way - sets `degraded: true`.
 */
export function isDegradedSourceAttempt(attempt: SourceAttempt): boolean {
  if (attempt.degraded !== undefined) return attempt.degraded;
  if (attempt.status === "failed") return true;
  return attempt.status === "skipped" && attempt.credentialPresent === true;
}

/**
 * The degraded sources behind a report, in the order they were consulted and
 * one entry per source, so a source retried across credentials or a delegated
 * refresh is named once rather than once per attempt.
 */
export function degradedSources(
  attempts: SourceAttempt[] | undefined,
): DegradedSource[] {
  const bySource = new Map<string, DegradedSource>();
  for (const attempt of attempts ?? []) {
    if (attempt.status === "success" || attempt.degraded === false) {
      bySource.delete(attempt.source);
      continue;
    }
    if (!isDegradedSourceAttempt(attempt)) continue;
    if (bySource.has(attempt.source)) continue;
    bySource.set(attempt.source, {
      source: attempt.source,
      ...(attempt.error ? { error: attempt.error } : {}),
    });
  }
  return [...bySource.values()];
}

/**
 * How present a provider is on this machine, as the human report groups it.
 *
 * - `live`: a fresh or stale reading, so there is something to draw.
 * - `attention`: no reading, but a source found something - a credential
 *   (expired, rejected, or waiting on a prompt), an installed tool that
 *   failed, or a request that failed - so the user has this provider and it is
 *   broken. A provider that recorded no attempts at all lands here too:
 *   absence was never shown.
 * - `absent`: every source was skipped as genuinely absent. This positive
 *   evidence is the only thing that lets a report fold a provider away.
 */
export type ProviderPresence = "live" | "attention" | "absent";

/**
 * Classify a provider reading by the evidence its own attempts carry. A source
 * named in `incidentalSources` can hold a credential without showing the user
 * has this provider (a GitHub CLI login is not Copilot access), so its
 * attempts never count as evidence either way.
 */
export function providerPresence(
  provider: Pick<ProviderQuota, "state" | "attempts">,
  incidentalSources: readonly string[] = [],
): ProviderPresence {
  if (provider.state.status === "fresh" || provider.state.status === "stale") {
    return "live";
  }
  const attempts = provider.attempts ?? [];
  if (attempts.length === 0) return "attention";
  const foundSomething = attempts.some(
    (attempt) =>
      !incidentalSources.includes(attempt.source) &&
      (attempt.status !== "skipped" ||
        attempt.credentialPresent === true ||
        attempt.degraded === true),
  );
  return foundSomething ? "attention" : "absent";
}
