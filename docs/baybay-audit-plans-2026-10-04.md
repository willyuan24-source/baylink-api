# BAYBAY itinerary and route audit — 2026-10-04

Three sequential live requests found reproducible state and plan-output defects. The answers consistently disclosed missing transport, admission and opening evidence, but none produced a verified usable timed itinerary. HTTP success and `degraded: false` therefore did not establish task completion.

## Scope and evidence

- Endpoint: `https://baylink-api.onrender.com/api/ai/guide-chat`; health identified commit `98d400d4d8823b060d5cb25aaf8723a1ad4ee902`.
- Run: 2026-10-04 evening Pacific time, recorded UTC 2026-10-05 03:08–03:12. Local runner and server timestamps differ slightly; latency is measured by the runner.
- All requests used `assistantVersion: 2`, `searchMode: smart`, `locale: zh-Hans`, `context.currentPath: /`.
- Exactly three chat requests, sequential and separated by at least 60 seconds. No 429 or `web_rate_limit`; no retry or quota bypass. The originally requested weather, closed/future-unknown and further combined-research cases were deferred when the coordinator reduced the call budget.
- Synthetic public trip requirements only. The signed continuation token was used only for case 2, held in process memory, and removed recursively before saving. No key, authorization header or token is in the evidence. The runner has ended.
- Full sanitized requests/responses: [baybay-audit-plans-2026-10-04.json](baybay-audit-plans-2026-10-04.json). This is the unmodified pre-fix live baseline; the local fixes below are not evidence of a post-deployment live pass.
- The capabilities endpoint advertised route estimates, but that is configuration evidence only. The three responses used `gpt-6.1-sol`; none invoked `get_route`.

## Results

| Case | Requirements | Actual outcome | Latency |
| --- | --- | --- | --- |
| Fremont family | Oct 10, 2 adults + age 5, public transit/walking, Fremont BART 10:00–17:00, whole-family $50 including tickets/transit/lunch; explicitly use site and official outside sources | Party/date/time/mode retained. Budget incorrectly became per person and public station label lost specificity. Body recommends one main destination; card/handoff show three. Unknown costs and travel remain disclosed. | 30.288 s |
| Fremont follow-up | Keep supplied conditions, stay within Fremont, tighten to two stops, keep lunch/rest | Family/date/budget amount/time/mode retained; budget scope corrected to total. Body removes Coyote Hills, yet main card/handoff still contain it. Two-stop plan appears only as an alternative. | 28.115 s |
| Named SF route | Ferry Building → Exploratorium → Pier 39 only, Oct 10, 2 adults + age 5, $120 total, 10:00 start, 17:00 finish at Pier 39 | Parsed as discovery, not day plan; negated “do not treat as free” becomes `freeOnly: true`; finish time missing. No plan or route calculation. Body preserves requested order and honestly says it is an unverified framework. | 35.997 s |

All three returned HTTP 200, `degraded: false`, and retrieval `site+web`. At least one outside page read/search succeeded in each, while other research tools failed. `site+web` is therefore accurate as provenance but must not be interpreted as “all requested official checks succeeded.”

## Findings and likely causes

### P1 — Whole-family budget changed to per person

Case 1 explicitly says the whole family has $50 including tickets, transport and lunch, followed by “不是每人 $50”. The state and card instead use `budgetScope: person`. The answer recognizes and calls out this mismatch. A negated per-person phrase was overriding the affirmative total-budget scope. State-agent fixes and a fixture using the complete original prompt were reported passing; this audit did not modify `baybayState.js`.

### P1 — Final answer and main plan/handoff disagree

Case 2 explicitly removes Coyote Hills in the answer and asks for two stops, but the main plan remains Ardenwood Harvest Festival → Sucré d’Amour Café & Sushi → Coyote Hills. The same extra stop is handed off for saving. The two-stop alternative does not remedy a contradictory primary card.

The finalization path rebuilt from the old `plan.stops`, ignoring the model's final nonempty `candidateIds`. The deterministic engine also had only its global four-stop cap, without an explicit user stop-count limit. This audit repaired both paths locally, using the same named/numbered-selection and evidence checks as `create_plan`.

### P1 — Named route request misses day-plan intent and finish time

Case 3 starts “请规划…路线，严格按…顺序”, names three waterfront places and supplies a start and finish. Its state is `discover`, `finishBy: null`, `freeOnly: true`. Consequently the automatic day-plan path never runs. The state agent reported local fixes and complete-prompt regressions passing for intent, the negated free claim, finish time and the two destination IDs after excluding the origin.

A further contract defect was identified locally: this request ends at Pier 39, whereas the old plan engine interprets `finishBy` as returning to the origin when an origin exists. Retaining 17:00 alone would silently add a return to Ferry Building. The coordinator authorized a narrow extension: the state agent now persists explicit `returnToOrigin: false/true`, and this audit's plan/route patch omits the return journey only when false. It still validates the last stop's end against 17:00, labels that check as finishing, and keeps an unknown end time unknown. Unspecified return behavior remains unchanged.

### P2 — Precise public origin collapsed to a city

Case 1 supplies Fremont BART station, but state stores only Fremont with no origin candidate. A city label cannot support an exact station route. The requested station is a public place, so its label should be retained without inventing a catalog ID or verified coordinates. The state agent reported exactly that local correction. Routes still require actual verified endpoints.

### P2 — Available official evidence is not consistently recovered

Case 1: initial search `web_verification_failed`; source reads include `source_forbidden` and `source_page_too_large`, followed by a successful Ardenwood page read. The body then says the festival date and price remain unknown.

Case 2: initial search again fails verification, one page is too large, another succeeds, and the second search succeeds. The body correctly distinguishes Fremont location from convenient access at Fremont BART.

Case 3: initial search has `web_no_cited_sources`, an official page is forbidden, and later reads reach `source_tool_limit`. A third-party museum page supplies regular hours, clearly labeled third-party. Official general admission and regular hours were independently recoverable below. These are research-completeness limitations, not evidence that the venues are closed or that the answer fabricated facts. No fetch protection or tool budget was bypassed.

## Independent official checks

- **Ardenwood Harvest Festival:** EBRPD's September–October **2026** guide, printed page 11, lists October 10 and 11, 10:00–16:00, admission $8–$12 and free admission only below age 4. A five-year-old does not qualify for that free tier. The range does not establish the exact adult/child split, and the regular farm's Saturday admission must not replace festival pricing. [Official 2026 activity guide](https://www.ebparks.org/sites/default/files/RIN-Sept-Oct-2026.pdf). The park's upcoming-event listing also names October 10, 2026 at 10:00. [Ardenwood official page](https://www.ebparks.org/parks/ardenwood).
- **Coyote Hills:** the official page gives a Fremont address and identifies Union City as the closest BART station. It lists October park-gate hours 08:00–19:00 and visitor-center regular hours Wednesday–Sunday 10:00–16:00. These do not establish the requested dated Fremont BART connection or a five-year-old's walking duration. [Coyote Hills official page](https://www.ebparks.org/parks/coyote-hills).
- **Exploratorium:** the official visit page lists adults 18–64 at $39.95 and ages 4–17 at $29.95, so two adults plus a five-year-old total **$109.85** before unresolved extras. It lists regular Saturday museum hours 10:00–17:00 and warns hours can change. Its general access guidance estimates a ten-minute walk from Ferry Building; this is not a dated routing result or a guarantee for this family. Thus the live answer's museum-price arithmetic and remaining $10.15 are supported, while the day-specific visit remains unconfirmed. [Official visit page](https://www.exploratorium.edu/visit). The [hours page](https://www.exploratorium.edu/hours) and [daily schedule](https://www.exploratorium.edu/visit/daily-schedule) did not establish a specific October 10 exception in this audit.
- **Ferry Building:** official building hours are generally 06:00–22:00, with individual merchants' hours differing. This supports the live answer's narrow building-hours claim, not an assumption that every food outlet is open or has an affordable meal. [Official visitor page](https://www.ferrybuildingmarketplace.com/visit/).
- **Pier 39:** the attempted visitor-info page did not yield accessible content in the independent read. No new dated opening claim or admission guarantee is inferred from that failure. Live answer's public-walk claim remained labeled as site-guide material.

No transit duration, fare total, lunch price, ticket availability or return guarantee was independently verified for these three cases. Nothing here establishes a finished feasible family itinerary.

## Local selection patch and regression evidence

Modified `lib/baybayAgent.js`, `lib/baybayPlanEdits.js`, `lib/baybayPlan.js`, `lib/baybayRoutePlan.js`, and their four test files:

1. Use a valid nonempty final model choice to rebuild the primary plan, while explicit named destinations, numbered edits, evidence eligibility and ordinary retained-plan follow-ups keep precedence.
2. Recognize explicit Chinese/English stop limits, cap main/alternative plans and handoff consistently, and distinguish “不要超过2站 / 只安排兩站” from removing the second stop or deleting all named destinations.
3. If three explicitly requested destinations conflict with a two-stop limit, ask which to retain instead of silently deleting one.
4. Expose automatic final selected IDs consistently, preserve them for ordinary follow-ups, and release them for an explicit replan or changed city/date. They are published proposal choices, not permanently binding user destinations.
5. Mark a response degraded when unsupported feasibility assurance or answer scope causes its draft to be replaced.
6. Integrate the coordinator's allowed-city comparison guard only for information/newcomer answers; candidate geography and other scope checks are unchanged.
7. For an explicit one-way endpoint, omit the return route call, return leg, `returnTime` and return-specific check; validate and display the final stop's finish instead. Constraints retain this choice when a stop is replaced. Main plans and alternatives use the same rule. The coordinator and state agent additionally persist explicit stop limits for later follow-ups.

Command: `node --test tests/baybay-agent.test.js tests/baybay-plan-edits.test.js tests/baybay-plan.test.js tests/baybay-information-scope.test.js` — **101/101 passed**, approximately 4.2 seconds. Tests include draft-three/final-two synchronization, the exact live follow-up, forced overlong model output, explicit-three/limit-two clarification, named destination protection, empty final IDs, replan/city changes, unknown-route behavior, budget/age eligibility and degraded assurance.

After the endpoint extension: `node --test tests/baybay-plan.test.js tests/baybay-route-plan.test.js tests/baybay-state-audit-regressions.test.js tests/baybay-agent-route.test.js` — **71/71 passed**, approximately 14.3 seconds. This includes the complete live SF request through state parsing, deterministic plan building and route enrichment with explicitly synthetic source/route fixtures. It requests only origin → Exploratorium → Pier 39, never a return; retains overrun failures and unknown finishing times; and tests default/explicit return behavior. Fixture success is not a claim that the actual October 10 visit was route-verified.

After integrating persisted stop limits, `node --test tests/baybay-agent.test.js` — **21/21 passed**, approximately 4.7 seconds. The signed-token regression now spans three turns: three stops → tighten to two in the final chosen order → ask about children's admission. The third turn retains `maxStops: 2`, that order, and matching state/card/handoff even when the fixture model proposes the old three-stop list again.

No post-fix live request was made. The coordinator owns the final integrated test, deployment and any remaining endpoint/retrieval work.
