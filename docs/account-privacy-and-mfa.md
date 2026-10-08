# Account privacy and optional administrator MFA

Implementation date: October 6, 2026. This document describes source code and mock tests. It does not claim production deployment, successful real-user deletion, configured MFA keys, or actual administrator enrollment. No real email/SMS was sent and no production account was deleted during implementation.

## API and UI

Frontend: `src/features/profile/PrivacySecurity.tsx`, `ProfileView.tsx`, `ProfilePage.tsx`; sign-in challenge: `src/features/auth/MfaLoginChallenge.tsx` and `LoginModal.tsx`. New controls use explicit English and Simplified/Traditional Chinese text. The new CSS is imported through the application stylesheet, rather than through the component module, so Node UI tests can import it.

| Route | Authorization and behavior |
| --- | --- |
| `GET /api/users/me/security` | Authenticated owner; returns enabled/setup-available/recovery-count only. |
| `POST /api/users/me/privacy/export` | Authenticated owner plus fresh current password and MFA factor when enabled; downloads explicitly whitelisted owned records. |
| `DELETE /api/users/me/privacy/account` | Same proof plus a typed confirmation phrase in any site language: `注销我的账号`, `註銷我的帳號` or `DELETE MY ACCOUNT` (whitespace, letter case and the 账/帐/賬/帳, 注/註, 销/銷, 号/號 variants are ignored). Optional `locale` (`zh-Hans`, `zh-Hant`, `en`) picks the language of the refusal and failure messages. Administrator deletion is refused until safe role handover. Claims deletion only when account work is idle, then clears owned data transactionally. A failed transaction answers `500 ACCOUNT_DELETE_FAILED` (nothing changed, still signed in) or, if the account could not be reopened or the outcome is unknown (the driver reported a failure but the User row is gone), `503 ACCOUNT_DELETE_INTERRUPTED`. |
| `POST /api/users/me/security/revoke-sessions` | Fresh proof; increments session revision, revokes existing tokens and disconnects sockets. |
| `POST /api/users/me/security/totp/setup` | Administrator plus fresh password; requires a separate configured encryption key; returns pending secret and recovery codes once. Does not enable MFA. |
| `POST /api/users/me/security/totp/confirm` | Fresh password, saved-recovery acknowledgement, valid first six-digit code, unexpired pending setup and atomic proof comparison; activates and rotates session. |
| `POST /api/auth/login/totp` | Password-created, five-minute challenge; code/recovery verification completes sign-in. Challenge tokens have a distinct purpose and cannot authenticate API or sockets. |
| `POST /api/users/me/security/totp/disable` | Fresh password plus current MFA/recovery proof; atomically removes secret and rotates session. |
| `POST /api/users/me/security/totp/recovery-codes` | Same proof; replaces all old recovery hashes and invalidates old challenge revisions. |

Sensitive security responses and exports use `Cache-Control: no-store`. The privacy UI invokes `clearAccountSession` after account deletion or revoke-all, without making an additional logout request with an invalid token. Pending responses are guarded by the originating profile/session; they cannot clear a newer login after unmount.

## Data boundaries

`lib/accountPrivacy.js` exports the owner's profile, published records, authored text messages/comments, private planner records, own group participation and own booking fields. It excludes received private messages, contact cards, another person's contact snapshots and booking notes, security secrets, password hashes, reset tokens and internal moderation evidence. An export over 5,000 records in any query fails explicitly instead of silently truncating the file.

Deletion removes the account and challenges; revokes its tokens through identity deletion and revision checks; clears own messages, contact settings and all linked contact-card/snapshot copies; clears planner, event interest, blocks, translations, notification state and message-response associations; removes own references from shared records. Owned posts are made unavailable and stripped of their private/public authored payload. Hosted groups are cancelled and the departing host's entries removed while retaining other people's authored entries. Safety cases/action timestamps retain anonymized identifiers, with raw evidence and copied personal fields removed. Ordinary post deletion also clears stored contact copies, and private message reads redact cards whose source post/owner is unavailable even if a cleanup retry is pending.

Direct-message reports require both the stored conversation ID and message ID. The server verifies the reporter's participation before reading the selected message, derives the actual sender, and holds both accounts while recording evidence. Existing blocks do not prevent reporting received messages. Only the selected plain text (at most 3,000 characters) and minimal message metadata enter an administrator-only case; contact cards, attachment URLs and reply snapshots are omitted. Client-provided evidence is ignored. Erasing either the author or reporter clears the case's text, conversation reference and copied personal fields; a retained case is not a retained private conversation. Legacy repeated message IDs are resolved and deduplicated within their conversation.

Translation failures use a separate, post-owned cache record without source text or provider error details. Invalid translations retain a 24-hour cooldown; transient provider faults retain 60 seconds. The key changes with source text, translation version or public model identifier, and a successful translation always takes precedence. The application checks expiry even before Mongo's TTL cleanup; account/post cleanup by `postId` covers both success and failure records.

Post translations now carry a post identifier and use a per-post source hash. Account deletion clears the owner's traceable entries. Historical translation entries had only a content hash, so edited older sources cannot be reliably attributed from the current post; deletion also clears all such untraceable legacy derived-cache entries, which can be recomputed, while preserving other people's traceable entries and original posts. New translation requests do not reuse the legacy cache and hold the post/owner deletion gates through generation and storage, including anonymous requests. No production cache migration was run during implementation.

This operation does not destroy Cloudinary files based solely on user-submitted URLs. Historical uploads lack trusted stored ownership/public-ID metadata. Database references are removed, but external files/caches require an ownership-verified manual or later lifecycle process. Recipients' independent copies cannot be withdrawn. Hosting logs and backups have separate retention/cleanup processes; the code does not establish or promise an instant purge or universal fixed retention period. `src/components/PrivacyPolicyView.tsx` now discloses these boundaries and actual configured-service roles: Vercel, Render, MongoDB Atlas, Cloudinary, OpenAI, optional Resend/Twilio delivery, optional Google Routes, and OpenFreeMap.

## Concurrent operations and safe failure

Authenticated request work uses `User.activeAccountOperations` with atomic acquisition across API instances. The HTTP ledger tracks handler promises and response completion separately: disconnect/close cannot release a gate while an awaited write is still executing. The upload body parser participates in the same ledger and awaits its real parser callback. Target accounts are held for DM/contact operations, shared-post owner changes, report targets, group members/host and booking participants. Notification-token routes and provider worker calls also hold their affected accounts. Optional hooks await completion, including moderation-log writes.

Shared posts additionally use `activePostOperations`. Deletion checks all posts containing the departing author's posts/likes/comments/reports for active writes. This protects whole-array saves by another participant; concurrent counter writes conflict with the cleanup transaction and force a retry or a refusal. Outing and booking cleanup also advances their existing revision clocks, preventing stale container snapshots from restoring erased entries.

Deletion first atomically marks the account pending, then runs the cleanup transaction. While the pending flag is set every session and new account operation is refused, and a committed deletion removes the User row, so the claim does not rotate the session revision. Missing transaction support or a failed transaction does not produce a success response or partial committed erasure. On a handled failure the pending state is cleared (retried briefly) and the owner stays signed in with the same session; the response is a localized JSON error. Public profile endpoints omit banned/suspended/deletion-pending accounts. No automatic timeout clears gates while work may still run.

The conversation membership swap is two updates inside the transaction (`$addToSet` the placeholder, then `$pull` the account): MongoDB rejects `$pull` and `$addToSet` on the same path in one update with code 40, which made every deletion fail before October 8, 2026. The shared test mocks (`tests/support/update-conflicts.js`) now reject conflicting operator paths the same way, so this class of bug fails the suite.

### Crash recovery requires real operational checks

Pure counters deliberately fail closed after an unclean API/worker shutdown or failed release write. They have no TTL that could allow a still-running write to escape a gate. Operators must not blindly reset counters on a live deployment.

1. Stop incoming account mutations and notification delivery on **every** API/worker instance; drain or stop those processes. Confirm that no Mongo cleanup transaction or provider operation remains running.
2. Back up only the affected maintenance fields/identifiers, without copying contact values, messages or authentication secrets into logs. Inspect `activeAccountOperations`, affected `activePostOperations`, pending flag and deletion claim.
3. A fully committed deletion removes the User row. If the row still exists after all processes/transactions are drained, the deletion transaction has not committed; clear that account's pending claim and stale counters with a conditional maintenance update. Clear stale affected post counters only after all writers are drained. The claim does not revoke sessions; increment the session revision as well only if the account may be compromised.
4. Read back those fields, restart the deployment and ask the owner to retry the normal credential-confirmed flow. Retain a non-private maintenance audit record. This procedure was documented, **not executed against production users**.

## MFA configuration and recovery

Set `ACCOUNT_SECURITY_ENCRYPTION_KEY` to a canonical base64 encoding of exactly 32 cryptographically random bytes, stored as a server secret. It is separate from `JWT_SECRET`; no key is generated, installed or enabled for an administrator by this patch. Missing/invalid configuration disables new enrollment and leaves existing password-only administrators usable.

Per-user secrets use AES-256-GCM with user-specific associated data. Codes follow RFC 6238 SHA-1/30-second/six-digit defaults, with one adjacent step allowed on either side and atomic replay prevention. Pending setup expires after ten minutes; login challenges expire after five minutes with five attempts. Recovery codes have 128 bits of random entropy each, are stored as SHA-256 hashes and atomically consumed once. They remain usable if the encryption key is temporarily unavailable, allowing a password-proved administrator to disable MFA safely. Loss of both authenticator/key access and all recovery codes requires an identity-verified administrative recovery process; the API does not bypass MFA automatically.

Password reset increments `sessionRevision`; issued tokens carry the revision from the credential-proved snapshot. Login rechecks that password proof after bcrypt, security mutations compare that proof atomically, and activation/disable mint their new token from the CAS result rather than rereading a later reset revision. A password reset at any point invalidates tokens based on the older proof. Do not replace the encryption key blindly while enrolled users rely on it: first confirm recovery access and use a controlled disable/re-enrollment or separately reviewed migration.

Reference design sources: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html), [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

## Error responses and process lifecycle

- `lib/serverErrors.js`: every error reaching Express becomes a JSON body (numeric driver codes such as Mongo `40` are never passed to string methods; that TypeError used to fall through to Express's HTML 500). Every 5xx response, including routes that answer 5xx themselves, writes exactly one JSON line to stderr: `{level, event:'http_5xx', method, route (pattern, e.g. /api/users/:id), status, error (name), code, cause{name,code}, release, ms}`. Bodies, URLs, IPs, user ids and error messages are never logged.
- `lib/processLifecycle.js` (installed by `startProduction` only): an unhandled promise rejection is logged as `event:'unhandled_rejection'` and the process keeps serving. `SIGTERM`/`SIGINT` stop the notification and source-monitor workers, close Socket.IO and the HTTP server (in-flight requests get 20 s before open connections are cut), disconnect Mongo and exit 0; a hard deadline at 25 s exits 1.
- `lib/notifications.js`: an invalid `NOTIFICATION_FRONTEND_URL` no longer stops the API from booting. Links fall back to `https://www.baylink.us` and one `notification_origin_invalid` warning is logged (without the value).

## Validation boundary

Added mock-only suites:

- `tests/account-security.test.js`: reference vectors, encryption isolation, missing config, setup confirmation/expiry, role protection, replay, recovery, challenge limit/revision.
- `tests/account-privacy.test.js`: export privacy, real-schema scrubbing, snapshot/contact removal, transaction rollback without sign-out, localized confirmation phrases, the DM-thread member swap, conflicting-operator rejection in the mock, admin handover, disconnected-handler and shared-post races.
- `tests/server-errors.test.js`: real HTTP JSON 500s and one structured log line per 5xx, the two explicitly wrapped async routes, deletion end to end (200, login 401, post gone, the other member keeps the thread) and a failed deletion that keeps the session.
- `tests/process-lifecycle.test.js`: rejection logging without exit (with a real child-process control that crashes without the handler), SIGTERM draining an in-flight request, forced exit on a stuck shutdown.
- `tests/account-security-api.test.js`: real HTTP route integration with injected storage, challenge bearer rejection, public profile hiding, old contact reads after post removal, same-millisecond session revocation.
- `tests/account-report-privacy.test.js`: the actual `:reportId` review route holds reporter and target through delayed writes; deletion-first acquisition rejects the late review and cannot restore scrubbed evidence.
- `tests/direct-message-reports.test.js`: real HTTP participant authorization, server-derived evidence, blocked-thread reporting, legacy repeated IDs, administrator-only reads, deletion cleanup and both race outcomes.
- Frontend `tests/account-privacy-ui.test.tsx`: deletion confirmation, local cleanup without logout, English copy, stale session response guard, MFA staging and code-only requests.

The final local API suite for these changes passed 1125/1125, including the direct-message report, translation cooldown and actual public-service catalog regressions; syntax checks and `npm audit` passed with zero vulnerabilities. Exact-commit CI, frontend validation and deployed revisions are recorded separately in `C:/Users/willy/opus-qa/site-audit-1005/implementation`. No local test result proves a production deployment or real provider delivery.
