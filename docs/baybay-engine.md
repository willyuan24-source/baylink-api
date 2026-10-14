# BayBay engine modules

`POST /api/ai/guide-chat` answers through `createBayBayAssistant()` in `lib/baybayAgent.js`. Until API-BB-4A (H40, audit 10-13) one 870-line `run()` there carried both engines. It is now a short sequence of stages in `lib/baybayEngine/`; the behaviour is unchanged (byte-identical dry-run eval and capture, see the API-BB-4A PR).

## One turn, in order

| Step | Where | What it does |
|---|---|---|
| 1 | `baybayAgent.js` `run()` | Emergency card (no retrieval, quota or model), possible-emergency topic, professional guard, $ caps and pause state, guest scope. Builds the `turn` object. |
| 2 | `router.js` `resolveTurn()` | Task state from the signed token or the history, plan edit, clarifications (booking, nearby, invalid edit, stop limit), `researchDeadline`. |
| 3 | `baybayAgent.js` | Run-share and site-wide capacity claims start beside retrieval (H03). |
| 4 | `evidence.js` `gatherEvidence()` | Site retrieval (v2 `buildFastEvidence`, v1 `buildSiteEvidence`), evidence store, page record and v2 refs (`e1…`, `r1…`, `page`), preview cards to `onQuickCard`, plan scope from the previous turn. |
| 5 | `v1.js` `v1Instructions()` | v1 only: its SYSTEM text patched for this turn. |
| 6 | `baybayAgent.js` | Source-monitor review flags; `research.js` `createResearch()` builds the tool executor and `makePlan()`. |
| 7 | `answer.js` `finish()` | Early answers: clarification, unconfirmed food type. |
| 8 | `router.js` `routeTurn()` | `timely`, `liveCheck`; v2 path (`fast` or `agent`, budget fast-only). `prompt.js` `v2Rules()` then collects the turn's v2 rules. |
| 9 | `baybayAgent.js` | Waits for the capacity claim; none → `finish(turn, null)` with the daily notice. |
| 10 | `stream.js` `fastAnswer()` | v2 fast path: one call (frozen system blocks, v2 user turn, rules), lead/points drafts, one retry on Sonnet low. |
| 10' | `research.js` `research()` | Agent path (v1, and v2 plans, edits and live checks): web pre-search, tool rounds, final round, recovery. |
| 11 | `answer.js` `finish()` | Floors and guards, citations, final cards, v2 `lead`/`points`, signed task token, response envelope. |

## Modules

| Module | Holds | Typical change |
|---|---|---|
| `router.js` | `resolveTurn`, `routeTurn`, `LIVE_CHECK` | What a turn asks for, which path answers it |
| `evidence.js` | `gatherEvidence`, page records (`currentPageFor`), the model's view of evidence (`modelSources`, `newEvidence`, `compactCandidates`, `webSeen`, `v2UserContent`), ref resolution (`refSource`, `citeRefs`, `entityOf`, `candidateOf`, `refRegions`), `sourceContextText` | Ranking, regions, what the model sees |
| `stream.js` | `fastAnswer`, `streamDrafts`, draft rules (`DRAFT_MIN_RECORDS`, `premiseMismatch`) | First-sentence speed, drafts |
| `research.js` | `createResearch` (tools, budgets, `makePlan`), `research` (agent loop) | Tools, plans, agent rounds |
| `answer.js` | `finish`, `resolveDraft`, `renderCitations`, `stripLoginPitch` | Guards and the response |
| `fallback.js` | Answers without a model: `fallbackAnswer`, `professionalFloor`, `unavailableHelp`, `healthWorry` | Paused / unavailable answers |
| `prompt.js` | Tool schemas (`TOOLS`), v2 agent rules, `v2Rules`, `responseDiagnostic`, `cacheUsage` | Rules sent after the user turn (system block 1 stays cached) |
| `v1.js` | v1 `SYSTEM`, `FINAL_FORMAT`, `v1Instructions`, `parseDraft`, `contextInput`, `withPageAlias` | Nothing: v1 is the rollback (`BAYBAY_ENGINE=v1`) |
| `util.js` | `str`, `obj`, `arr`, `positive`, `copy`, `localeIndex` | |

## The `turn` object

`run()` creates one plain object per question: the assistant's shared dependencies (config, catalogs, providers, clock, quota `claim`, `capabilities`, `providerState`), the request (message, history, locale, search mode, page context, callbacks, signal) and the per-turn bookkeeping (`steps`, `warnings`, `modelResponses`, `rules`, …). Each stage adds its results to it (`resolveTurn` → `state`, `resolved`, `edit`…; `gatherEvidence` → `site`, `store`, refs and cards; `routeTurn` → `routing`).

Fields that change during the turn are read from the object every time, never destructured: `plan`, `model`, `webStatus`, `webCheckedAt`, `cached`, `notice`, `routing`, `draftWriter`, `instructions`. Everything else is set once and may be destructured at the top of a stage.

## Rules for changes

- `tests/baybay-engine-modules.test.js` keeps the module graph acyclic and keeps `v1.js` out of every module except `research.js` and `baybayAgent.js`, so v1 can be removed by deleting `v1.js` and the `v2 ? … : …` branches of `research.js` (a later lane, at least two weeks after the new key is stable).
- A refactor proves "no behaviour change" with the dry-run eval (`node scripts/baybay-eval-local.mjs --set engine --concurrency 1`, $0) compared row by row against the base commit, wall-clock fields aside.
