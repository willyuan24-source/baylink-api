# Anonymous AI runtime aggregates

Added 2026-10-07. These counters make future operational measurement possible; no production latency percentile or real-model quality result was measured in this change.

## Storage and access

`AiRuntimeMetric` uses a deterministic string `_id` per Pacific calendar day, fixed feature, and fixed model family. Models outside the allowlist are `other`; a request with multiple observed model families is `mixed`; a request with no observed provider HTTP call is `none`. Provider calls retain their own model bucket. Dated model names collapse into their allowlisted family.

Only integer counters and fixed duration buckets persist. No question, answer, account ID, IP, URL, conversation token, provider response ID, arbitrary model label, exception text, or per-request timestamp is stored. Expiration is one timestamp per day bucket, at UTC midnight 30 calendar days after its day label (at most 30 days after an observation). Mongo TTL cleanup is asynchronous. The original `AiGovernance` quota/identity records still retain their existing three-day expiration; this change does not backfill them or extend their TTL.

The existing authenticated `GET /api/admin/ai-metrics` retains `days` and adds `runtime`. Existing admin authorization still applies. Its runtime report is fixed to the most recent 30 Pacific date labels, filters expired-window rows even before TTL cleanup, accepts no query fields, uses a bounded projection, and returns `Cache-Control: no-store`. Reads are limited to 60/minute per admin request IP in the existing short-lived process limiter. Neither a new public debug route nor new fields in public `/api/ai/usage` are introduced.

## What the observations mean

All durations are **server observed**, measured with a monotonic clock. They exclude time before the AI governance middleware (for example JSON body parsing), network delivery to the browser, and client rendering. The fixed, non-cumulative histogram bins end at 250, 500, 1000, 2000, 3000, 5000, 8000, 15000, 30000, 60000, 100000 and 180000 ms, with an overflow bin. Each observation increments exactly one bin. `null` in the report's upper-bound list denotes overflow.

| Field | Exact observation |
| --- | --- |
| `providerLatency` | A `fetchAiJson` HTTP attempt through complete JSON parsing or error/timeout/cancellation; includes all attempt outcomes. It excludes quota reservation and subsequent usage-counter writes. |
| `firstQuickCard` | First accepted SSE write of a validated site-record quick card; no sample when no card was sent. |
| `firstValidatedText` | First SSE write of already validated answer text; no sample for ordinary JSON responses or answers without text. This is **not provider first-token time**: the current deltas are emitted only after answer validation. |
| `completeResult` | JSON response preparation or complete SSE result write, retained only when the response subsequently ends successfully. It is separate from first text and request end. |
| `requestEnd` | Server response finish or premature disconnect, including rejected/error/cancelled requests. |

`requestCompleted` means the response ended with HTTP status below 400 and no explicit `ok:false`/SSE error envelope. It does **not** assert correctness, user satisfaction, complete factual coverage, or successful real-world action. `requestRejected` covers 4xx responses except cancellation status 499; `requestError` covers 5xx or an explicit SSE/application error; `requestCancelled` covers premature connection closure or status 499. `requestDegraded` is a subset of completed responses whose server payload explicitly reports `degraded:true`. It is not inferred from missing facts, short answers, progress events, or provider exceptions.

Provider counters describe the provider boundary: `providerCompleted` is parsed JSON without a reported failed/cancelled/incomplete/pending status; `providerIncomplete` includes explicit incomplete, queued and in-progress status; `providerError`, `providerTimeout` and `providerCancelled` are distinct. These are not final-answer quality grades: a failed first attempt may be recovered by a later model. Request buckets use all observed provider model families, including failed attempts. For a disconnect racing a provider response, request attribution uses the models observed at termination, while a later resolved provider attempt may still record its own outcome.

Input and output token totals include only valid reported nonnegative integer counts. Zero is a known value. Missing/invalid input and output usage increment `inputUsageMissing` and `outputUsageMissing` independently, including when a failed or cancelled attempt supplies no usage. Such calls may still be billable. These are observed token totals, not a billing ledger or cost estimate; no prices are assumed.

## Coverage and reliability

Coverage is the existing governed POST routes: guide chat, planner recommendations/web search, post assist, outing draft, image event extraction, conversation AI and post translation. Rejections inside that middleware/route are counted, including concurrency rejection. Safety replies returned before governance and failures before route entry are excluded. Provider counts instrument the common production `fetchAiJson` wrapper; direct injected test functions do not create provider observations. Cached/deterministic results can therefore have no provider call and still complete normally.

Each observation uses a Mongo atomic `$inc` on one `_id`. Concurrent first inserts retry only duplicate-key rejection; uncertain writes are never retried to avoid double counting. The observation queue is bounded to 256 writes per process. Writes are asynchronous, best effort, and cannot delay or fail the user response. Saturation drops observations; storage failure or process termination may also lose them. The admin report includes local-process `pendingWrites`, `failedWrites` and `droppedWrites` counters, reset on process restart. They are not a fleet-wide completeness guarantee. Successful writes aggregate across application instances in the shared collection. MongoDB TTL/index operation and real fleet behavior still require normal production observation after release.

No provider switch, budget setting, paid request, account permission, real email or SMS is part of this implementation. Local tests use memory models and synthetic provider responses; they verify atomic-update construction, concurrent callers, duplicate-insert recovery, failure isolation, incomplete/missing usage, cancellation, separate SSE timings, and administrator/public API boundaries. They are not a substitute for production data or a Mongo replica-set load test.

Validation on 2026-10-07: full backend suite **1303/1303 passed**, no skipped tests; `npm run check`, individual changed-module syntax checks and `git diff --check` passed; full `npm audit --json` reported **0 vulnerabilities**. Real model calls: **0**. Local ignored logs: `audit-ai-runtime-targeted.log`, `audit-ai-runtime-full.log`.
