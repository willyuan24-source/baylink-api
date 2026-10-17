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
  hold the carried day replaces it (12月5号 → 这周末呢 / "What about this weekend?" is 10/17-18). Review round 6: in
  English a weekday (Monday-Friday) is the first one on or after the carried day (Dec 5 → "What about Monday?" is
  12/07; Chinese 周一呢 keeps the Monday-to-Sunday week, 11/30), and days the user lists ("12月5、6号两天都行", "Dec
  5 or 6 both work") become the span even when they hold the carried day.
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
- **A lead's count of the options goes only when it differs from the points, and only a plain one** (captain
  decision 10-15; the rule of api main 74f5b50, narrowed). Five review rounds of "the lead never states a count"
  (every count of 2-6 options removed, matching or not) each found zh phrasings it damaged, and the table in
  `tests/baybay-lead-counts.test.js` still failed 11 of its first 117 leads on 3fe0801, 10 of them damaged
  (有两场或更多 → 有或更多, 活动有两场 → 活动有, 兩個鐘, 坐两站 BART, a Saturday and a Sunday count, "There is one
  free event" → "There is free event"). `leadConsistency` now removes a count only when it differs from the
  number of options listed (points with cards, else all points) and only when it is plain: '<2-6><measure word>'
  (zh) or two-six (English) right before an option noun (活动, 地方, 去处, 选择, 博物馆, 讲座, 推荐 …; events,
  options, places, ideas …), with at most two short modifiers between (免费, 亲子, 适合孩子的, 好; free, family,
  South Bay …), the lead's only count, never beside "the rest" / "each" / 其余 / 各 / 每, and never when other
  words refer back to it (both, either, neither, another, the third, the other, 二选一, 二者 / 两者, 任选, 第三场,
  另一场). 这两个地方 reads 这些地方, 去两个地方 reads 去这些地方, 下面两个活动 reads 下面的活动, and a sentence that
  opens with a quote keeps its capital. The count is read on the lead without its `[[ref]]` / `[n]` markers (as
  the streamed lead shows it) and removed from the lead itself; a marker inside the count stays. Ranges and
  approximations (两三个, 这周两三场, 两到三个, 两个到三个, 2-3个, 3、4个, 两个以上, 两个及以上, 两场或更多, 三个左右),
  qualified counts (其中两个, 前两个, 大约三场, 一共有两场, 每周两场; "only two", "about three", "the first two"),
  counts without an option noun (两场都免费, 活动有两场), "one" / 一, English digits ("2 free events"), numbers
  that are not counts (dates, times, ages, prices, lines, people, durations, 坐两站, 兩個鐘) and a lead with two
  counts are never touched. The 一-六 of 周六 / 星期六 / 礼拜六 is a day, so 周六两场 is a count; 两 / 兩 always
  starts a range (这周两三场). Known limits: a count with more than two modifiers or one not on the list
  (有两场在库比蒂诺的免费活动) and an English digit count are never repaired; a count of a subset with its own
  verb ("Two events need tickets", 两场活动需要提前预约) is generalized when the points differ.
- **The streamed lead still ends as the result** (live L04): the draft writer holds the lead from a plain count,
  and from a count whose reading the next characters could still change ("周六带两个…", "There are two…"),
  until it is settled; a plain count is settled only when the provider call ends and `end({ complete, points })`
  brings the answer's points (`lib/baybayEngine/stream.js`, `research.js`), so a removed count is never shown
  and a kept one appears with the rest of the lead. Without the points the held text is not sent (the result
  carries it). The whole rest of the lead is held, not only its sentence. The prompt forbids counts, yet 2 of the
  21 distinct leads in the two live checks (both L04) stated one; in L04 the hold would have shown "No full free
  museum day falls on Oct 17-18, but" for 2.2-2.5 s (API-BB-4B: first text 2.9 s, done 5.2 s; API-FIX5: 4.7 s and
  7.2 s). A draft field
  keeps at most 8,000 raw characters (twice the 4,000-character draft budget): a held lead sends almost nothing,
  so without the cap every flush re-read the model's whole lead; a capped field shows its streamed prefix only.
- **Indoor and plans (review round 1, v2)**: 有没有室内的 / 有沒有室內的 asks for indoor (the planner read 没有 as a
  negation); (有没有)不是室内的 / 非室内的 asks for outdoor, but the question 是不是室内的 and 除非室内 stay indoor. "Plan a Saturday for us", "Can you plan our Sunday?", "half-day plan" and, after an outing turn,
  "plan it" ask for a day plan; "back by 3" / "done by 4" / "back by 3:30" without am/pm is the afternoon, like
  3 点前; "what can kids do", "kids activities" and "anything free for kids" are outing asks. "What is fun / free
  for kids" is one too, but not about one venue or fare ("at the Oakland Zoo", "on Muni" stay information); a
  kind of place ("at the beach", "at parks", "at museums") is still an outing.
- **Offers keep to the asked days**: a dated offer outside the span, one held only on another weekday
  (仅周三, "Wednesdays:"), one whose title or date label lists or ranges other weekdays (周二、周三 / 周一、三、五 /
  周二至周日 / Fridays and Saturdays / Thursday–Monday) and one closed on every asked day (周二、周三闭馆, Closed
  Mondays) is not an option for that ask (`offerOnAskedDays` in `lib/baybayEvidence.js`).

## API-BB-6: the one-call day plan, listed dates, rainy days and block N

Live check after API-BB-5 (10-15) and the 40 unseen questions of eval block N. Tests: `tests/baybay-6.test.js`.

- **One-call site day plan, fast-path request shape** (live L07: 20,028 input tokens, all written to the prompt
  cache; first text 5.6 s, done 9.4 s). `research.js` `singleCall` (a new site day plan, not a plan edit or
  follow-up, `BAYBAY_DAY_PLAN_FAST` not `off`) runs the plan engine first, then sends one call: the frozen system
  block with its own breakpoint (the prefix every fast-path answer shares, so a cache read when the fast path is
  warm), **no tools**, **no top-level cache breakpoint** (no later call of the run would read the rest), one user
  turn with the evidence and `planView()` (`evidence.js`), and the plan-call rules (`V2_PLAN_CALL_RULES`,
  `prompt.js`) in place of the agent's research rules and final-round instruction. `planView()` sends each stop once
  with the refs to cite, its admission facts without source plumbing and its unconfirmed checks by code (`open`
  keeps only what no stop carries); a stop's record goes in full less the lines that repeat its own when and cost,
  and at most 8 other items (a guide's second section is not one) as a 120-character excerpt (`planItems`).
  Estimated input for seven day-plan asks on the final tip: 6.1k–7.8k tokens (base 15.3k–21.9k; the Oakland family
  ask is the largest at 7,766, so ≤ 8,000 holds on the estimate with about 3 % margin); the estimator,
  1.449 × CJK characters + 0.3596 × other characters of the request body, is fitted to the 11 live calls of 10-15
  (−5 % … +8 %; the eval harness's dry-run characters/3 reads the L07 call as 13.7k). A citation retry resends the
  turn with the first answer and a reminder that names `currentPlan.stops[].refs` (about 300 tokens more, so a
  retried plan costs about twice the stated $/ask); a 429/529/connection recovery resends the same turn. Plan edits, follow-ups on a plan and
  `BAYBAY_DAY_PLAN_FAST=off` keep the agent rounds, the site tools and the top-level cache.
- **One card per plan stop**: a plan answer's cards are its stops in visiting order (an event's page, a place's
  BAYLINK guide; a place without a guide page has no card), then the other cited cards, at most six
  (`planStopCards`, `answer.js`).
- **Listed dates are not a season** (live L06, L08). A weekly farmers market, or a record whose own text says it
  runs all year, is listed for a window of dates (Grand Lake 10/17–12/12) that is BAYLINK's calendar, not its season.
  `weeklyListing()` / `weeklySchedule()` (`lib/baybayEvidence.js`) give the model its weekly schedule from the
  sessions ("每周六 9:00–14:00", "Every Saturday 9:00–14:00"), 全年 / year-round only when its own text says so,
  and the next listed date from the asked day, never the window, with a note; its date line in the text is
  replaced the same way; a record whose sessions have different hours shows none. As a net,
  `listingWindowRepair()` (`lib/baybayQuality.js`, in `resolveDraft`) removes a "starting …", "from … through …",
  "…起", "从…开始" or "… 至 …" phrase with a weekly record's first or next listed date (or a range from it to the
  last) only in a point that cites the record (or, citing nothing, names it) and in a lead or gap sentence that
  does; another record's own dates stay, and a range inside the asked dates (the asked weekend) stays (warning
  `answer_listing_window_repaired`). In a segment that cites nothing, the phrase must also belong to the market:
  the nearest subject before it (with none before, the first after it) is the market's name or the market noun,
  not another subject (an evidence record that is not a weekly market, named by a title word; an exhibit /
  festival / show noun; another Latin name in Chinese prose that is not a city, weekday, month or market), so
  "先逛农夫市集，再去 OMCA 看10月17日起开放的新展" keeps the exhibit's date. A sentence that calls the dates the
  listed dates (列出的日期, "listed dates") stays; "Oct." / "Sat." does not end a lead sentence. A dated ask outside
  the listing window (the Grand Lake market in January) still drops the weekly record in retrieval: open for a
  later lane.
- **The asked day's own session first** (live X1): on a dated ask a multi-date event's view starts with its
  occurrence on the asked day and that session's hours, then the dates it is listed for ("12月5日（周六）
  10:30–11:00（列出的日期：…）").
- **Rainy-day / indoor family asks** (live L09). A mixed record (part indoor, part outdoor: The Tech and Japantown,
  the Egyptian Museum and its garden) fits an indoor or an outdoor ask, in retrieval and in the plan engine. A
  family ask's recall takes family events (free ones on a free-only ask) and never adults-only records (仅限成人 /
  adults only, or an adult audience with no children's or family audience beside it: the Xiangqi invitational's
  成人 + 亲子家庭 is a family event); with a
  city, family events and attractions rank before other events. An indoor family ask in a city with fewer than
  three indoor family records adds the same region's nearest indoor attractions and family events, each with a
  note naming its city (`nearbyFamilyRecords`). An offer whose sessions vary by store reaches the model as one to
  check and book, never a sure session.
- **Block N dev findings**: sudden vision loss with stumbling, staggering or lost balance (走路摇晃, 踉跄, 站不住)
  is the BE-FAST stroke pair (911 template); a landlord who changes the locks, locks a tenant out or cuts the
  utilities is a legal question (业主 / owner / property manager changing locks only in a tenant's message: a
  homeowner changing their own locks is not; 出租, 租车 and "help me out" are not a tenant's message, and re-keying
  between tenants is not a lockout unless the message has a dispute such as 不交房租, "won't pay" or evict);
  帮我排行程 / 排个一天的行程 is a day plan.

## API-BB-7: live-check follow-ups (family signal, storytimes, part of the day, plan stops, English times) and block O

Follow-ups of the API-BB-6 live check (10-16, api `a976e0c`). Tests: `tests/baybay-7.test.js`.

- **Family signal in task state** (live L09). `state.family` (optional, like `community`): 亲子 / 親子 / 带娃 / 孩子 /
  小朋友 / with kids / family, or any child age, sets it; a follow-up (那周日呢) keeps it; no kids / adults only clears it;
  "family doctor" and the like do not set it. Every family branch in `lib/baybayEvidence.js` (`buildSiteEvidence`,
  `audienceRecall`, the indoor widening) reads it besides the child ages and the ask's own words.
- **No evening records for grown-ups on a family ask**: an event whose audience is stated and names no children,
  families, all ages or the general public, and that is a dinner, bar or 21+ record or starts at 18:00 or later
  (`adultEvening`, beside `adultOnly`), is not a candidate (San Jose's murder-mystery dinner theatre for 朋友 / 戏剧爱好者).
- **Indoor family asks lead with fully indoor options**: an indoor family ask in a city puts that city's fully indoor
  family places (library, museum) first in the audience list; a part-indoor record (`planning.setting: mixed`) carries a
  note: never lead with it on an indoor or rainy-day ask, list it after the fully indoor options and say which part is
  outdoors. The thin-city widening (API-BB-6) is unchanged.
- **Children's programmes on a dated family ask** (live X1). `audienceRecall` lets children's programmes (an audience
  that names children: storytime, family time, LEGO club, not only 全家 / 各年龄) take turns with the day's one-off family
  events (one-off programmes first, then storytimes; the list whose head ranked first starts), with six slots on a
  dated family ask (four before). "12月5日东湾有什么适合孩子的活动": the Oakland Main storytime is item 3 (was 9 of 10;
  payload evidence 3 of 40, was 11), and the parade and book sale stay.
- **The asked part of the day** (live L06). With 下午 / 晚上 / afternoon / evening (window starts 13:00 / 18:00; 中午 11:30)
  or a start time, an event whose session that day ends within an hour of the window's start is left out of the model's
  items, or, when the ask names it (one of the ask's own subject words in its title, not a synonym), kept with a
  "closes at" note. A morning ask is not narrowed.
- **Day plan** (live L07, `lib/baybayPlan.js`). An event with no `planning.schedule` uses its own sessions
  (`recordSchedule`; a session of 3 h or more is an opening window: the science festival's 11:00–16:00, which the plan
  called missing hours). An event stop links to `/events/<id>`; a stop whose link is another site's page is
  `external: true` (the planner hand-off still keeps catalog places; only web discoveries leave it). After the first
  stop, a stop within 3 km of one already chosen comes before one with no location or farther (`routeStops`). A stop
  that closes by 15:00 goes first and stops under 0.5 km apart stay together (`closingOrder`): L07 is now Ferry Plaza
  market → Ferry Building → Chinatown (was Chinatown → the Mission Bay festival → Ferry Building). Transit lines per leg
  are not added: no catalog or guide field holds a leg's line (see PR, open item).
- **English times** (live L08). English when-lines use 12-hour times as the cards do ("Every Saturday 9am–2pm",
  "Sat, Dec 5 10:30–11am"), and `englishClockRepair()` (`lib/baybayQuality.js`, in `resolveDraft`) rewrites 24-hour
  times left in an English lead, point or gap (warning `answer_english_clock_repaired`); Chinese answers keep 24-hour
  times.
- **Block O dev findings** (`lib/baybayState.js`, `lib/safetyRouting.js`): the child's age now ("two, almost three" is 2,
  快四岁了 is 3, beside 三岁多 the "almost" adds nothing; "my son is two"); beside a full date a weekday word inside an
  event's own name ("Family Saturday", "Super Sunday") is not a second date; a neighbourhood names its city (Mission
  District, Richmond District, Inner / Outer Sunset, Sunset 图书馆, Noe Valley, Rockridge, Willow Glen, ...; "Richmond"
  alone stays the East Bay city), and a nearby ask from home (我住 X，附近…) is about the home city; an admission budget
  changed to zero (预算改成0, "budget is now zero", "no money for tickets") is budget 0 and free-only; Social Security
  credits and retirement are the SSA guard with SSA's credits page and the retirement guide; more withheld-deposit
  phrasings are legal; a follow-up that does not repeat its topic noun keeps the previous user turn's professional guard
  (`professionalFollowup`), one about an outing or a museum does not.
- **Review round 1 (10-16)**. English times written with dotted a.m. / p.m. ("9:00 a.m.–2:00 p.m.") are left as
  written. A professional follow-up needs a professional cue (还有什么办法 / 怎么办 / 找谁 / what now / can he wait…), never
  a bare pronoun, "can we" or a leading 那, and an outing word (动物园 / zoo / 画画课 / 早茶 / dim sum…) ends the carry. The
  plan engine reorders only stops it chose itself (each stop's latest start: a fixed session's start, or an hour before a
  close at or before 15:00; a 12:00 session no longer jumps ahead of a museum open from the start); a user's or a model's
  selected order is kept and the opening-window check flags a late stop. `routeStops` anchors on the first located stop
  and skips a `venue-*` record that mirrors a chosen place (Lake Merritt and venue-omca). `adultEvening` reads title,
  category and audience, not the summary, and its evening rule needs an adult-reading audience (成人 / 18岁以上 / adults).
  A neighbourhood names its city only when no city is named; "Lake Berryessa" and "tenderloin steak" are not districts;
  "no money for parking" and "预算0-50美元" are not a zero budget; English "almost N" is an age only beside a child word
  or before "years old". A place shows its recorded hours (`planning.schedule`) for the asked day or weekend (SJMA:
  周六 11:00–18:00 / Saturday 11am–6pm), and on an evening ask a place that closes within an hour of the window is
  closed for it like an event. The plan's stop `path`, `external`, `openingWindows` and `handoff` are payload fields:
  the web plan card does not read them yet (web follow-up).
- **Review round 2 (10-17)**. A cue alone no longer carries the guard: an ask that names a day, a date or a part of the
  day (周六 / 明天 / 这周末 / on Saturday / this morning) or an outing place (图书馆 / 故事会 / 市集 / 爬山 / 带她去 /
  library / storytime / farmers market / go to) is an outing unless it also names a professional action (申请 / 办 / 续 /
  预约 / office / apply / renew / appointment / appeal), and the cues are narrow (还能怎么办 / 还能找谁 / 还能申请, not a
  bare 还能; "can she still apply / qualify / keep / wait", not a bare "still"; 还有什么地方 only before 申请 / 办; "what
  else" only as the whole question). After a Medi-Cal turn, "What else can she do on Saturday in San Jose?",
  她周六还能去图书馆吗？ and "Instead, can we go to the library on Sunday?" are site answers again. When a message names a
  city, the city parse reads it without its neighbourhood, so "Richmond District" / "Outer Richmond" beside 旧金山 /
  San Francisco / SF is San Francisco and not also the East Bay city of Richmond. "9:00 a.m" (no final dot) stays as
  written, and "she" / "he" count as a child word for "almost N" only as "she is" / "he turns" / "she's".
- **Review round 3 (10-17)**. The round 2 carry was still a list of cue words: 17 of 28 new leisure follow-ups after a
  Medi-Cal, SSA or deposit turn kept the guard (那她想学英文，找谁？ / 她喜欢唱歌，还有什么选择？ / "Instead, anything nice
  for her to see around Santa Clara?"), and 17 of 23 professional ones lost it (那她要带什么证件？ / 要多久才批下来？ / "What
  if she gets denied?" / "How do I get it back?"). `professionalFollowup()` now carries on signals. A follow-up keeps the
  turn before's topic only when (a) it names that topic's domain: documents, approval, a denial, the office (also after
  去哪), an appointment, an application, eligibility, a deadline, a letter, the phone or online channel, help in Chinese
  or the wait for every topic (`FOLLOWUP_ANY`); a premium, coverage, a doctor, income or a house for Medi-Cal, Medicare
  and medical; a benefit amount (领多少 / 少多少 / how much), credits or the claiming age for SSA; a deposit, getting it
  back (要回来 / get it back), the landlord, the lease, a list of charges or small claims court for legal; a visa, an
  interview or a passport for immigration; a refund, filing or a deduction for tax (`FOLLOWUP_DOMAIN`); or (b) it is a
  bare cue with only a pronoun and filler around it (怎么办？/ 然后呢？/ 还有什么办法？/ 他还能怎么办？/ What now? /
  What else can I do? / Then what?). It never carries when it names a subject or activity that is not professional
  (`FOLLOWUP_LEISURE`: learning English, mahjong, singing, gardening, friends, hanging out, sights, food, the weekend, an
  outing with the kids, places to go, indoors / outdoors, the weather, boredom / 闷 / 无聊), even beside 找谁 / 还有什么选择
  / instead / other ways or a professional word (押金的事先放一放，那附近有什么好吃的？). A shared signal does not carry
  either when the follow-up names another topic family's subject instead (`FOLLOWUP_SUBJECT`: 房东… after a Medi-Cal
  turn); a follow-up that names two topics' domains keeps only the ones it names. A message with no professional user
  turn before it is unchanged. A chain of follow-ups (documents, then approval time) keeps the topic of the professional
  turn it started from, up to three user turns back, while every turn in it carries. Social Security credits said as
  points are SSA: 社安工作点数 / 社會安全工作點數 / 社安点数 / 工作点数 / "Social Security 退休金够不够点数" ("Social Security
  退休金怎么申请", with no credits word, stays a site answer as the G12 regression requires).

## API-BB-8: sources kept, honest counts, family hours, guide card type, evidence fit, plan lead order

Fixes from the API-BB-7 live check (10-17, api `bc0ee27`) and its independent read, then from the lane's two-lens
review (the repairs must never turn a correct answer into a wrong one). Tests: `tests/baybay-8.test.js` (the live L08
and L07 answers replayed as the model wrote them; "API-BB-8 review" blocks); `tests/redos.test.js` (API-BB-8 block).

- **A point keeps its source** (live L08: 0 sources; L07: the market point had no [n]). The cause was not a repair
  step: the model's L08 output (698 characters) is its draft without a single `[[ref]]`; both points named their market
  only in `cardIds`. In L07 the market stop's only ref was a store id (`s-…`), as the market is not an evidence item.
  `pointRepairs()` (`lib/baybayQuality.js`), the last of `resolveDraft`'s repairs, gives a point that cites nothing the
  refs it lists in `cardIds` (refs that resolve to a source), or the first ref of the plan stop it is about
  (`pointStops`, below); appended at the point's end and spaced as the answer's own markers (en always; zh when a point
  of the answer writes " [[ref]]"), so the streamed point stays a prefix of the result. Warning
  `answer_point_citation_restored`. The count, listing-window, 12-hour-clock and area repairs keep a point's markers
  (tested end to end).
- **A catalog count names its scope** (live L08 "Yes, two East Bay farmers markets run on Saturday mornings" read as
  every market). In `countRepaired` (`leadConsistency` and the streamed lead's `leadDraftText`), a plain count that
  matches the listed options and says that many exist (zh after 有, en as the subject, after "Yes," / "There are" /
  "has") says they are BAYLINK's: zh "有 BAYLINK 收录的两个农夫市集" (zh-Hant 收錄; inserted where the count starts), en "two
  East Bay farmers markets listed on BAYLINK run …" (after the option noun). Both points are at or after where the
  streamed lead is held, so the streamed lead stays a prefix. A lead that already names its scope (BAYLINK, 收录, listed,
  站内) and a count that refers back (这两个 / 两场…都 / Here are three) are unchanged; a count that differs from the points
  still loses its number. markets, museums, libraries, parks, venues, storytimes, programmes, classes, shows, fairs and
  parades (en) and 农夫市集 / 图书馆 / 美术馆 (zh) count as option nouns. Repair `lead_scope`. Review: only when the options
  are BAYLINK's: `siteListed(turn, points)` (`lib/baybayEngine/evidence.js`) is false when a point cites a web search
  result or names a web candidate (a signed-in research turn), and then the count stays as written, in the result and
  in the streamed lead (`draftWriter.end({ siteListed })`). A search result stays the web after `read_source` makes it
  `page-read` (the turn's `webResearch` keeps its id), and so does a link found on such a page (`discoveredFrom`); a
  guide's own reference link, read or not, is BAYLINK's (second review). A count of what one record contains ("The festival has two
  shows": storytimes, programmes, classes, workshops, shows, concerts, exhibits, parades after has / includes / features
  / offers / hosts / with) is no count of the options. A digit after the inserted words is spaced ("收录的 5 个").
- **Hours that matter** (`lib/baybayEvidence.js`). On a family ask a place's recorded hours lead with the children's
  area when its hours note gives that area's opening times (`childAreaOpens`, King Library: "周六 儿童区 10:00 起（全馆
  8:00–18:00）", en "Saturday children's area from 10am (building 8am–6pm)"); only the opening time is recorded, so no
  closing time is made up, and a day the area opens with the building is unchanged. A place or opening without recorded
  hours whose Chinese record says when it usually opens on an asked day gives that as its `when` (`usualDayHours`,
  Sucré: "记录：周日通常中午开门", "On record: Sunday, usually opens at noon"); a range ("周二至周日 16:00–22:00") is not
  read as one time, and events are left alone (their sessions are their hours). Review: nor a range or a negation in
  words (no 至 / 到 / 不 / 未 / 前 / 后 between the time and the verb: "周五 · 12:00 至打烊", "中午不开门"; no 至 / 到 between
  the day and the time: "周日中午到晚上营业"; no dash in either gap), and not on a date the same sentence names ("10/11
  的庆典开始时间与通常周日中午开门不同": no usual time for 10/11).
- **Guide card type**. A place shown as its BAYLINK guide (`quickRef`) is a leisure guide in the web's guide category
  `city` (all 29 place guides are): the card carries `guideType: 'leisure'`, `guideCategory: 'city'` and `typeLabel`
  (城市指南 / City guide), in the preview cards and the final cards. A guide card from the page context carries none.
  The web currently labels every guide card 办事指南 (`src/features/baybay/BayBayCards.tsx`): reading these fields (or
  the web's own `guide.category`) is a web follow-up.
- **Evidence fit**. A one-venue offer whose record names no city or region but gives a street address (Randall
  Museum, the Cable Car Museum, Happy Hollow, Poppy & Claro) is left out of a city or area ask after scoring, unless the
  ask names its venue in Latin letters; on a family ask that is not about the evening, an event whose stated audience
  names no children, families, all ages or public and whose every session starts at 18:00 or later (Rush's concerts) is
  not a candidate; with a child of 12 or older in the ask, an evening event for teens or students (青少年 / 学生 / teens /
  students / youth) is a family option. Review: a paragraph of a guide with no one city that gives a street address but
  names no city (the October freebies guide's Presidio Field Station, "603 Mason Street"; 6 paragraphs in the catalog)
  is left out of a city or area ask unless the ask names the venue, so neither it nor its official link reaches a San
  Jose ask. All of these run after scoring, so the other records keep their scores: over the 244 first turns of blocks
  A–O only those records (and King Library's hours) changed. SF asks lose the two SF offers (Randall Museum, the Cable
  Car Museum) until their records get a region (data follow-up; the PR lists which SF asks get what instead).
- **Plan lead and points** (live L07). On the one-call new day plan a lead that lists the stops out of visiting order
  lists them in order (`leadStopOrder`: each stop's one mention moves into the slots the mentions take, "逛渡轮大厦、农夫
  市集" → "逛农夫市集、渡轮大厦"; an English mention takes its "the"; warning `answer_lead_order_repaired`); a lead that
  compares or swaps stops, names a stop twice or names fewer than two is unchanged. Review: only a plain list moves.
  Between two mentions there may be only list connectors (、，, 和 与 與 及 跟, then optionally 然后 / 接着 / 最后 / 再 + 去 / 到 /
  逛; en ", " / "and" / "then"), nothing locative or possessive before the first (的 从 到 离; from, to, at, in, near, 's …)
  and only punctuation after the last. Second review: and the sentence's words before the first mention are only day or
  part-of-day words, 先 / 可以 / 可 and a generic visit verb (逛 / 去 / 游 / 走走 / 看看 / 参观; en visit, see, explore, tour,
  start with, stop by): "午饭去唐人街，再去渡轮大厦", "早茶：…", "先吃…", "Dim sum: Chinatown, then …" are kept, as moving the
  names would give lunch to the other stop. Any other out-of-order lead ("先逛渡轮大厦的农夫市集", "从渡轮大厦出发", "Chinatown for
  dim sum, then … the Ferry Building") is kept, because moving only the names would move what it says about each stop;
  warning `answer_lead_order_mismatch`. A point about a stop (`pointStops`: it names that one stop; a point that names two
  or more is about stop i only in a point-per-stop answer, as point i, naming stop i, when no one-stop point is about
  stop i, so "逛完农夫市集后，走进渡轮大厦大厅休息" is about the Ferry Building and an overview of every stop is about none) gets
  the stop's card in `cardIds` and, when it gives no clock time, the stop's time (a timed session, else the record's
  opening window that day: "记录的开放时段 8:00–14:00" / "Recorded hours: 8am–2pm", joined with "，" when the point has no end
  mark yet; warning `answer_plan_point_time_added`). `planView` gives an untimed stop its `hours`, and the plan-call rules ask for
  the stop order in the lead and each stop's time or hours in its point. Stop names: the title's and aliases' parts,
  their Latin names, a few Chinese names of Latin venues (Ferry Building / 渡轮大厦, Chinatown / 唐人街 / 华埠); a name two
  stops share names neither.
