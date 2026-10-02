# Workflow release: persistence and deployment

This release adds private web candidates, optional outing preferences, appointment rescheduling and group time polls. The route estimate integration is optional and stays disabled without explicit configuration. No new credentials are required for the stored workflow features.

## Deployment sequence

1. Include the changed API files and the new `lib/guideWebSearch.js`, `lib/plannerWebLibrary.js` and `lib/plannerTravel.js` modules in the same backend release. Startup imports these files unconditionally, even when external search or routes are disabled.
2. Deploy and restart every API instance. Wait for the new version to finish initializing its Mongoose models and become healthy before sending new workflow writes to it. Do not keep a mixed pool of old and new API workers for these operations.
3. Publish the frontend only after all API workers support the new endpoints and request fields. Existing clients can read the new backend; new clients cannot fully negotiate old-backend support. In particular, old APIs reject new preference/cover fields and do not implement web-candidate storage, rescheduling or time polls.
4. Verify the deployed configuration independently. Local in-memory tests and schema casting checks do not prove production database connectivity, paid provider access, SMS delivery or billing configuration.

When a rollback is necessary, prefer reverting the frontend while keeping the compatible new backend. Do not revert the backend while new clients are still writing these fields. An older API can ignore a pending reschedule or fail to close a time poll when an arrangement changes. Preserve new data and stop new workflow writes before coordinating a backend rollback; do not delete fields as a rollback shortcut.

## Persistence

| Production model | Stored additions | Write protection and legacy behavior |
| --- | --- | --- |
| `PlannerAccount` | `webCandidates` as a Mixed array; `webCandidatesRevision` as a number; `admissionBudgetUsd` and `setting` inside existing Mixed `preferences` | Candidate replacement uses its own revision and authenticated account ID. Missing candidate revisions are accepted as version 0 on first write. Plan/preference writes update only their own fields, preserving the candidate library. Preference patches merge existing keys. |
| `ServiceBookingAgenda` | `reschedule`, `rescheduleOperations`, `rescheduleCount`, and notification `snapshot` inside the existing Mixed `bookings` array | A provider agenda revision guards the complete write. Accepting a proposal changes the existing booking atomically after rechecking the new slot; the original time remains reserved until success. Reschedule receipts do not consume ordinary cancellation receipts. |
| `Outing` | `cover` and `timePoll` as explicit Mixed schema fields; votes inside `timePoll` | Outing revisions guard changes; notification updates have a separate revision. Adopting a changed time advances `planVersion` and requires members to reconfirm. Public cards do not expose private poll answers. |

Existing records do not require a backfill, collection replacement or manual migration. Optional fields are absent or initialized when first used, and old records remain readable. These fields are covered by the production Mongoose schema and are written with explicit `$set` updates, so persistence does not depend on Mongoose noticing in-place Mixed-object edits. A process restart loads the revised schema; an already running older worker does not acquire it automatically.

Proposal expiration and notification recovery follow the existing read/write-driven mechanisms. This release does not add a scheduler that proactively delivers expiry messages when no one accesses a record.

## Configuration

- Web search uses the existing `OPENAI_API_KEY` and independently configured `OPENAI_WEB_SEARCH_MODEL`. Set `OPENAI_WEB_SEARCH_ENABLED=false` to disable the shared lookup. `OPENAI_WEB_SEARCH_MAX_TOOL_CALLS` is 1 or 2, default/cap 2. Each uncached lookup reserves that many units before execution from `PLANNER_WEB_SEARCH_DAILY_LIMIT` (default 100 per UTC day), without refunding failures or unused units. Cache hits share the result and spend no additional provider quota. Optional text extraction has separate model token usage.
- Routes require `PLANNER_TRAVEL_ENABLED=true`, server-only `GOOGLE_ROUTES_API_KEY`, and a positive `PLANNER_TRAVEL_DAILY_LIMIT` (default 100). Leave the flag false to retain map-link fallback with no Routes API calls. The key must never enter frontend build variables.
- Existing booking SMS settings and separate provider consent remain unchanged. Adding rescheduling does not turn SMS on, establish new consent, or validate a production messaging service.

The synthetic local QA fixture and its test accounts are not part of production deployment. Never configure production with the fixture's JWT secret, `NODE_ENV=test`, or injected in-memory models/providers.
