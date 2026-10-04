# BayBay assistant v2

The existing `/api/ai/guide-chat` endpoint accepts `assistantVersion: 2` to
use a shared research and planning workflow for public local-information tasks.
Old clients and specialized community-post, outing and school workflows retain
their existing handlers. `BAYBAY_AGENT_ENABLED=false` restores the old handler.

## What is connected

- Signed task state carries confirmed city, origin, date, party/children, budget
  scope, transport, exclusions and times beyond the four-turn text window.
  The token expires after 24 hours; it contains bounded public preferences and
  plan references, never credentials, arbitrary client facts or retrieved pages.
- Guide paragraphs and filtered event/place records enter one evidence store.
  The same model sees both these records and any successful public web lookup.
- Responses function tools can search again, read an already-discovered page,
  verify a candidate with exact quotations, request weather/routes, and calculate
  a plan before answering. Every tool result returns to the same model loop.
- Plans compute date, city, age, admission, timing and return constraints. Unknown
  amounts are not zero-cost assertions. Ordinary weekly hours do not confirm a
  particular day's opening. Stops without known travel remain a proposed order.
- Default plans stay within one city when cross-city travel has not been verified.
  Source-linked web leads require page verification before entering a day plan.
- Explicitly named published stops become an ordered selection. The departure
  venue stays separate; ambiguous names or alternatives need clarification.
  The model cannot silently add another stop to an exact requested itinerary.
- The source monitor's pending-review state is exposed to the research model.
  A fetched page is an observation, not automatic editorial approval.

## Configuration

Existing `OPENAI_API_KEY` is reused server-side. No key belongs in a `VITE_*`
variable or in a chat. The preferred `OPENAI_BAYBAY_MODEL` defaults to
`gpt-6.1-sol`; a provider rejection for that model uses
`OPENAI_BAYBAY_FALLBACK_MODEL` (default `gpt-4.1-mini`) and records the actual
returned model. A ten-minute circuit breaker avoids repeatedly trying an
unavailable preferred model. Model availability is established by real provider
calls, not by the capability endpoint.
When a preferred request times out and enough research time remains, the same
turn tries the fallback and records that timeout; this does not imply the
preferred model is unavailable on later turns.

`BAYBAY_MAX_MODEL_ROUNDS` defaults to four research/answer rounds, with at most
eight model-requested function calls per run. One additional call can recover
an unusable final response; it cannot extend tool research. Research rounds
allow 2,400 output tokens and the final preferred-model answer allows 4,000.
A valid complete JSON object is accepted even when the provider reports a
token-limit stop; truncated output is never repaired or shown as an answer.
The run has a 75-second deadline with 16 seconds reserved for final synthesis.
`BAYBAY_DAILY_RUN_LIMIT` defaults to
200 shared model runs per UTC day. This is a run limit, not a currency cap;
one run can include several model requests and separately metered web lookup.
The existing web-search cache and shared
quota remain authoritative, including model-triggered searches; no tool bypasses
that service. The service reads at most three pages and requests one weather
forecast per run. Site-only mode disables web, page, weather and route requests.

Routes require all of:

1. Google Cloud Routes API (`routes.googleapis.com`) enabled with billing.
2. `GOOGLE_ROUTES_API_KEY` set in the Render backend environment.
3. `PLANNER_TRAVEL_ENABLED=true` and positive `PLANNER_TRAVEL_DAILY_LIMIT`.

The key should be restricted to Routes API. Both route endpoints must have
verified venue coordinates. City-center coordinates are not precise start/end
points. A missing route, unknown origin or missing return leg remains explicit
in the plan. Exact public-origin plans can request up to three sequential route
legs, rebuilding the schedule after each result; onward times need a usable
previous stop end time. Identical route requests within one answer share their
result and charge. Invalid IDs, missing coordinates, quota exhaustion and a
provider failure have distinct safe diagnostic codes, never raw provider output.
The NWS weather lookup uses verified place coordinates and needs no
API key; a requested date outside the returned forecast remains unknown.

## Client contract

Send the last completed response's `assistantSessionToken`, never a cancelled
request's token. Reset/new conversation and account changes clear it. The UI does
not put the token in persistent browser storage. Client-provided `taskState` is
ignored; only the verified token and the current user request change task state.

Responses retain ordinary fields and add `taskState`, `assistantSessionToken`,
`assistantPlan`, `evidence`, `research` and `followups`. Answer citation numbers
refer to `sources` in order; `evidence` has stable IDs for the plan cards.
Source URLs come from server retrieval and are validated before links render.
`degraded` is true when only the grounded fallback could be produced.

Adding a plan remains an explicit user action. The existing plan-page handoff
accepts only actual published event/place IDs. It does not create a reservation,
buy tickets, or pretend that a web-only reference is a published catalog entry.

## Release and acceptance

Deploy the API first. Confirm `/api/health` commit and
`/api/ai/baybay-capabilities`, then test v2 requests before deploying the frontend.
The capability endpoint reports configuration, not a successfully billed Maps
request. Verify a real route after adding its key.

Acceptance cases cover combined site/web evidence, follow-up tool calls,
multi-turn state, clear/reset/account isolation, source forgery, unknown prices,
closed/full events, cross-city plans without routes, unavailable providers and
strict site-only mode. Run the original API regression suite as well.

Production checks must record actual model, tool results, cited sources, task
constraints, plan status and latency. Do not infer real-answer quality merely
from mocked-provider tests passing. Use synthetic public questions and never log
keys, auth tokens or private conversation contents in release artifacts.
