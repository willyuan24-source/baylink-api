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

Fields that change during the turn are read from the object every time, never destructured: `plan`, `model`, `webStatus`, `webCheckedAt`, `cached`, `notice`, `routing`, `draftWriter`, `instructions`.

The arrays (`rules`, `steps`, `warnings`, `travelEstimates`, `webResearch`, `modelResponses`) are created by `run()` and only ever filled in place (`rules` gets the `v2Rules()` output at step 8 and the agent rules in `research()`), so any stage may destructure them.

Every other field is set once, by one step. A stage may destructure it only when that step has already run; read too early it is `undefined`, with no error:

| Set by | Fields |
|---|---|
| Step 1, `run()` | Shared dependencies, the request, `v2`, `guard`, `floorTopic`, `professional`, `checklist`, `paused`, `deadline`, `today`, `timing`, `stage` |
| Step 2, `resolveTurn()` | `normalized`, `previous`, `resolved`, `state`, `edit`, `explicitCandidateIds`, `booking`, `nearbyAsk`, `maxStops`, `researchDeadline`, … |
| Step 4, `gatherEvidence()` | `site`, `store`, `contextReferences`, `localMatches`, `entityCards`, `itemRefs`, `pageSourceId`, `scopeGuides`, `samePlanScope`, … |
| Step 6, `createResearch()` | `execute`, `makePlan`, `availableTools`, `offeredTools`, `attempts`, `exhausted` |
| Step 8, `routeTurn()` | `timely`, `liveCheck` |
| After step 8, `run()` | `nowClock`, `refRegion` |

## Rules for changes

- `tests/baybay-engine-modules.test.js` keeps the module graph acyclic and keeps `v1.js` out of every module except `research.js` and `baybayAgent.js`. That bounds where v1's own code lives, not where the engines still branch. Removing v1 (a later lane, at least two weeks after the new key is stable) touches all of these:
  - `v1.js`: delete it.
  - `baybayAgent.js`: the `v1Instructions` call, the engine choice (`baybayEngine(config) === 'v2'`, `turn.v2`), and the public `parseDraft` export, which comes from `v1.js` and is imported by `tests/anthropic-baybay`, `anthropic-route-controls`, `baybay-agent`, `baybay-agent-recovery`, `redos` and `baybay-engine-modules`.
  - `research.js`: the `v2 ? … : …` branches (v1 input, tool list, `parseDraft`/`withPageAlias`), including the v1 `search_site` result built from `modelSources`.
  - `evidence.js`: the retrieval choice (`buildSiteEvidence` or `buildFastEvidence`), the v1 card list (`localMatches` without `entityCards`), and `modelSources()`, which only v1 uses.
  - `answer.js`: every `v2` condition in `finish()`, including the v1 "not on the site" pattern and its template, the v2-only budget notice, cards and `lead`/`points`, and the `v2 ?` envelope fields.
  - `router.js`: the follow-up `carry` flag, and the `v2 &&` booking, nearby and routing conditions.
  - `prompt.js`: the `v2 &&` conditions in `v2Rules()`.
  - The OpenAI Responses path, which only runs v1. Whether it goes too is the owner's call, because it is also the rollback in `docs/claude-baybay-rollout.md`.

  `grep -n '\bv2\b' lib/baybayAgent.js lib/baybayEngine/*.js` lists every remaining branch point (about 60 lines of code at API-BB-4A, plus comments).
- A refactor proves "no behaviour change" in two ways, both $0 and offline:
  - The dry-run eval (`node scripts/baybay-eval-local.mjs --set engine --concurrency 1`) compared row by row against the base commit, ignoring wall-clock fields.
  - The stricter byte-level capture, `scripts/baybay-capture.js`. It runs every casebook turn under 8 engine/access arms with scripted providers and records the SHA-256 of every provider request body, the full payload, and every progress, quick-card and draft event. Run it on the base (extracted with `git archive`) and on the branch, then `cmp` the two files. A v1-removal lane compares only the v2 arms (`--only`).

## Speed before the model call (API-BB-4B)

Everything before the provider request is synchronous CPU work (steps 1–9), so on a small hosted
instance it decides how soon the first sentence can start. Keep it small:

- Retrieval and task state may cache only pure functions of catalog text (token indexes, the guide
  term index in `scoreCorpusSubset`, normalised headings, `validDate`, known city spellings). Never
  cache a question, a filter result or an answer. A record searched with more than one text keeps
  one token index per text (`documentEntry`), so earlier questions never change later scores.
- The boot warm-up (`warmUp()` in `baybayAgent.js`, fixed questions in `WARM_QUESTIONS`) runs steps
  2–9 once after boot and again after `BAYBAY_WARM_INTERVAL_MS` (default 15 min) without a real
  question; `BAYBAY_WARM=off` turns it off. It makes no model, quota or network call. If a change
  to the `turn` object breaks it, `tests/baybay-latency-4b.test.js` fails (`failed` must stay 0).
- Measure with `node scripts/baybay-latency-bench.js --settle 3000` (stateMs and siteMs are the CPU
  part; preModelMs adds the bench's fixed Mongo and monitor delays), before and after.
