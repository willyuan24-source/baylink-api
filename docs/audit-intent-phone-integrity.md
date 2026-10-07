# Contact access integrity and multilingual planning follow-up

Date: 2026-10-07. Baseline: production `45eb315377c393bc327021b2b9ccfae0fed4dfd9`.

## Contact requests (SEC-09)

Existing shared-number accounts remain valid. Phone verification confirms control of a number; it does not establish a unique natural person. No uniqueness constraint or destructive migration is added to `User.phoneNormalized`.

New contact requests reserve a persistent daily account quota (10) and, when a valid verified number exists, a daily quota (10) shared by every account with that number. Both `auto_send` and `manual_approve` use these limits. Unverified accounts can still request manual approval; automatic disclosure requires a usable verified number. A legacy verified `phone` value can supply the normalized US number when `phoneNormalized` is absent. A stale badge with no usable number must reverify before automatic disclosure.

`ContactAccessQuota` is a separate collection, keyed by the Pacific calendar day and a namespaced HMAC of the account/number. Each identity is reserved with a conditional atomic Mongo update against the inherently unique `_id`. Initialization tolerates a competing insert. App startup initializes the TTL index; records expire after three days. No raw phone or account ID is added to this collection. API restarts and concurrent instances share the stored limits. This is a Pacific-day limit, not a rolling 24-hour limit.

Eligibility, existing request lookup, declined cooldown and method checks precede quota reservation. Re-reading an existing active contact request does not consume another daily reservation. Account and number reservations are deliberately conservative attempts: if the later number claim or request write fails, the earlier account claim is not refunded. This may deny a later attempt early, but cannot release extra contact details. The quota does not promise per-post exactly-once behavior under simultaneous duplicate requests. The existing per-account minute limit remains in place.

If quota storage is unavailable, the route returns `503 CONTACT_QUOTA_UNAVAILABLE` before creating a request or disclosing contact details. Exhaustion returns `429 CONTACT_DAILY_LIMIT`. Missing valid verified phone returns the existing `403 VERIFIED_CONTACT_REQUIRED` contract. The phone number itself is never returned in these errors.

Boundaries: multiple genuinely different verified numbers are separate shared identities; manual approval remains an owner decision. Existing duplicate numbers are not evidence that all such accounts are fraudulent. SMS sending, ownership recovery, anti-SIM-farm controls and actual provider delivery are not changed or tested here. HMAC-derived anti-abuse counters expire by TTL and are not presented as user profile content.

## Task understanding (BRAIN-03 / REPLY-13)

Planning recognition now combines an arrangement action with an itinerary/outing object or a bounded leisure day, including simplified/traditional Chinese and English speech such as “排个顺路的走法”, “串成半天的遊程”, and “put together a half-day outing”. It does not assign exact clocks, ticket prices or locations from these phrases.

The latest explicit planning/cancellation directive wins. A pause preserves confirmed task facts, an explicit resume restores the planning goal, and “do not change the itinerary” retains the existing task. Historical or quoted planning descriptions do not become new planning instructions. Service requests and ordinary point-to-point route questions remain outside the leisure-planning path. A planning verb no longer reaches across a punctuation boundary to borrow a half-day phrase from an unrelated clause. Traditional transit words and English “total family/group budget” are handled by shared constraint extraction.

This is still bounded deterministic language understanding. The regression corpus covers positive paraphrases, negatives, past/quoted statements, corrections and signed multi-turn continuation; passing it is not proof of understanding every natural-language expression or of real-model answer quality.

## Quality evaluation (BRAIN-15)

The controlled real-provider casebook expands from 7 to 25 synthetic cases: 12 `zh-Hans`, 6 `zh-Hant`, 7 `en`. Each language adds a four-turn planning/correction/pause/resume chain, an uncertain food availability question and an explicit non-itinerary comparison. Cases retain factual human-review rubrics. Offline tests verify state assertions through signed continuation tokens and preserve the runner's exact-release check, 65-second spacing, no retry on quota, credential sanitization and mandatory manual factual review.

The dated corpus deliberately retains its `2026-10-10` expiry because some original and new cases refer to that day. Review the dates before running it later; do not merely extend expiry or treat old event answers as current. `--cases` can select a bounded subset together with its continuation ancestors. A dry run makes no network requests. No paid model evaluation was performed in this change.

No provider timing, research-depth, streaming or model-budget behavior is changed. Validated final-text SSE chunks remain post-validation delivery; this work does not claim provider token streaming or a measured latency reduction.

## Validation

Targeted contact tests exercise concurrent accounts/instances sharing a number, restart and number changes, Pacific-midnight reset, legacy normalization, duplicate insert contention, quota failure, actual local API disclosure count and manual approval. They use isolated in-memory models and never connect to production MongoDB or send SMS/email.

Targeted multilingual state and casebook tests run offline. Final local `npm test`: **1295/1295 passed**, zero failed/skipped/todo. `npm run check` plus syntax checks for the changed libraries passed. Full `npm audit --json` (including dev dependencies) reported **0 vulnerabilities**. Casebook dry run selected 25 cases and reported **0 network requests**. These checks do not replace production configuration, actual Mongo load acceptance or real-model evaluation.
