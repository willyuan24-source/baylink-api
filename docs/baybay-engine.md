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
  2–9 on 11 fixed questions, one stage per event-loop turn. It is opt-in: only `startWarmUp()`
  schedules it, and only `startProduction()` in `server.js` calls that (`armBayBayWarmUp()`, after
  `listen`, on the first `/api/health` answer or 30 s later). Tests, `baybay-eval-local.mjs` and
  `baybay-capture.js` never warm, so their timings and other tests' timings are not skewed. It runs
  again after `BAYBAY_WARM_INTERVAL_MS` (default 15 min, at least 60 s, 0 = never) without a real
  question; `BAYBAY_WARM=off` turns it off. It makes no model, quota or network call. If a warm-up
  question fails, the process logs one warning with the count (no question text);
  `tests/baybay-latency-4b.test.js` fails too (`failed` must stay 0).
- Boot cost: on a fresh instance the first warm-up pays the cold cost of each kind of question
  (live 10-13: about 1–2 s per kind on Render, a few hundred ms locally) in slices of one stage,
  during roughly the first 10–20 s after the first health check. A request in that window waits
  for at most one stage; without the warm-up the first reader of each kind paid the whole cost.
- API-BB-5 (live check 10-15: lead p50 2.07 s, p90 5.66 s): what still waited before the model call.
  - The run-share claims (`claim()` in `baybayAgent.js`): a row this process has not claimed yet costs one
    `findOneAndUpdate` upsert, not an upsert and a claim; a row at its limit meets the unique `id` (E11000)
    and the plain claim decides. Test doubles (`tests/support/memory-models.js`, the eval and capture quota
    stubs) follow MongoDB for both.
  - The spend level (`readBudget`): today's last known level answers after 120 ms while the 30 s cached read
    finishes; the model call still waits for the fresh level in `reserveAiCall`.
  - The database keep-alive: while idle, one indexed read of today's quota row every 25 s
    (`BAYBAY_DB_KEEPALIVE_MS`, at least 5 s; `BAYBAY_DB_KEEPALIVE=off` or `0` turns it off), started with the
    warm-up, so production only. It never writes; `warmStatus().keepAlive` counts runs and failures.
  - A new site day plan is one streamed call: the plan engine builds the plan from the site's candidates and
    the final round writes the answer (`day_plan_single_call`). Edits, plan follow-ups, member web research
    and `BAYBAY_DAY_PLAN_FAST=off` keep the agent rounds. A failed single call gets one recovery call.
  - A provider call on a pooled connection the far end had closed fails with "fetch failed" and no HTTP
    status; `failureReason` calls it `connection` (with the socket code from a fixed set) and the adapter
    sends it once more when no response or text arrived and 4 s remain (`transport.connectionRetries`).
    The retry re-sends the POST to `/v1/messages`: if the socket closed after Anthropic had already accepted
    the request, that turn is billed twice. This is rare, and `aiRequest` reserves each attempt separately, so
    the governance count stays conservative.
- Measure with `node scripts/baybay-latency-bench.js --settle 3000` (with `--settle` the bench starts
  the warm-up as the server does; stateMs and siteMs are the CPU part; preModelMs adds the bench's
  fixed Mongo and monitor delays), before and after.

## What a question means (API-BB-5)

- **Date spans** (`askedDateRange` in `lib/entityAliases.js`, engine v2 only through `carry`): 11月21日、22日 /
  11月21日到22日 / November 21-22 / 11/21-22, the weekend of December 5 / 12月5日那个周末, 12月第一个周末 /
  first weekend of December, and a month (12月, 12月初, in December, 下个月) become `state.dateRange`. A month
  bounds an outing ask or an ask about events, never "我1月要回国". A day plan still asks which day of a two-day
  span. A bare 周末 in an outing ask is the coming weekend (not 周末一般 / usually / every weekend), and a
  weekday follow-up inside a carried span ("那周日呢" after 12月第一个周末, "What about Saturday?" after the
  first weekend of December; every English spelling) is that span's weekday.
  Review round 1: a holiday's own weekend (感恩节周末, Thanksgiving / long weekend) sets no date, as before
  API-BB-5, and its own words find its events; the weekend before or after a holiday (圣诞节前那个周末, the
  weekend after Thanksgiving) is that weekend. A month that dates something else in the ask is no span: a
  move, a birth, a trip or a start (我们3月搬来湾区, 宝宝3月出生, 我1月要回国, 我12月去日本), 12月前, 五月天,
  12月天气. A child's age beside a date ("12/5 and 8 year old", "Dec 6 and 7-year-old") is not a span's end.
  `dateRangeFor` is unchanged, so v1 and the planner read dates as before.
  Review rounds 2-4: the connective forms of a holiday's weekend (感恩节那个周末 / 这个周末 / 放假的周末) set no date
  either; 长 is a long weekend only directly before 周末 (学长这个周末 is this weekend). An English month in a move,
  birth or trip-away clause, or a past arrival or start ("We arrived in March"), is no span; a coming one ("We
  arrive in December", "Winter break starts in December") is. After a span is narrowed to one day after this
  week, a bare weekday is that day of its Monday-to-Sunday week (12/05 → "What about Sunday?" is 12/06, 12/07 →
  周日呢 is 12/13); "this Sunday" is still this week's. Review round 5: a weekend asked in the message that does not
  hold the carried day replaces it (12月5号 → 这周末呢 / "What about this weekend?" is 10/17-18).
- **Day words are not subjects**: when catalog candidates are scored, 周末 / 周六 / today / 两个 are dropped
  from the question's terms (the date is a constraint in `candidateFits`), so a far-dated row titled
  感恩节周末 no longer leads a weekend ask.
- **English asks**: a candidate is matched against its English aliases with plurals, on the question's subject
  words: "there / any", a month, a day number, the asked city's own words and region words (south, east, bay,
  near) never count. An outing ask takes every fitting row; an information ask needs the usual floor (so "my
  child has a fever at night in San Jose" does not bring the night market); a dated ask needs one subject word
  in the row's English name ("Cantonese film screenings … on November 14"). An English reader's model sees
  events, places and plan stops under their English names.
- **Area and rail fit**: the four San Francisco museum names in the museums alias group name those museums
  only when the ask names San Francisco or no city. `lib/baybayTransit.js` holds the cities BART and Caltrain
  serve, from the operators' station lists (read 2026-10-15); "坐 BART 去" keeps `rail:bart` in the task state
  and, with no destination city, places the system reaches rank first. It is a city table only: it never
  states a station, a walk or a travel time.
- **The lead never states a count** of 2-6 options: `leadConsistency` strips it from the result and the draft
  writer shows the same text while the lead streams (`leadDraftText`), so the reader never sees the lead change.
  A count is a number word (English) or a numeral with a measure word (zh) before an option noun (活动, 地方,
  events, places …); never a date ("December 5"), an age range ("aged 3 to 5"), a stop (第 2 站), people
  (两个孩子, 一家三口), a duration (two hours, 两个半小时) or a period (两个周末). 这两个地方 reads 这些地方 and
  去两个地方 reads 去这些地方. While the lead streams, a count whose reading the next characters could still
  change ("周六带两个…") is held back, never stripped and then restored, so the draft is always a prefix.
  The 二-六 of 周六 / 星期六 / 礼拜六 / 初二 and of 十二 are a day or a larger number, never a count; 两 / 兩 always can be
  one ("这周两场" / "這週兩場" is held and stripped while streaming, as in the result). An approximate count
  (两三个, 两到三个, 两、三个, 2-3个, 三五个) is left whole, as English "two or three" is.
- **Indoor and plans (review round 1, v2)**: 有没有室内的 / 有沒有室內的 asks for indoor (the planner read 没有 as a
  negation); (有没有)不是室内的 / 非室内的 asks for outdoor, but the question 是不是室内的 and 除非室内 stay indoor. "Plan a Saturday for us", "Can you plan our Sunday?", "half-day plan" and, after an outing turn,
  "plan it" ask for a day plan; "back by 3" / "done by 4" / "back by 3:30" without am/pm is the afternoon, like
  3 点前; "what can kids do", "kids activities" and "anything free for kids" are outing asks.
- **Offers keep to the asked days**: a dated offer outside the span, one held only on another weekday
  (仅周三, "Wednesdays:"), one whose title or date label lists or ranges other weekdays (周二、周三 / 周一、三、五 /
  周二至周日 / Fridays and Saturdays / Thursday–Monday) and one closed on every asked day (周二、周三闭馆, Closed
  Mondays) is not an option for that ask (`offerOnAskedDays` in `lib/baybayEvidence.js`).
