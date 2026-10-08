# BayBay local eval

`scripts/baybay-eval-local.mjs` answers a fixed casebook with the BayBay assistant built from this checkout, scores each answer against code-checked gold, asks an Opus 5.5 judge for a quality score, and reports latency and dollars per model arm. Every BayBay change (model, effort, prompt, retrieval, streaming) should be compared on it before it ships (overhaul plan decision D15).

It never touches production: no Express server, no MongoDB, no production quota or visitor bucket. The only network host it can reach is `https://api.anthropic.com/v1/messages`, and only in a live run.

## Quick start

```bash
# Dry run: synthetic provider, no key, no network, $0. Checks the casebook and the whole pipeline.
node scripts/baybay-eval-local.mjs --items C08,B7 --arms haiku-low

# Live v0 (blocks A, C, E, G x four arms). The key comes from a private env file, never from arguments.
node --env-file=<private env file> scripts/baybay-eval-local.mjs --live --budget-usd 20 --set v0 --run-id v0-1008

# What this checkout ships (code-defaults arm), e.g. the R0 check: blocks C and E plus A's C01-C10
node --env-file=<private env file> scripts/baybay-eval-local.mjs --live --budget-usd 3 --set r0 --items C01,...,C10,C-STROKE-ZH,...,E-SENIOR-OAKLAND --run-id r0-check-1008

# Re-render a report; --rescore re-applies the casebook on disk to the stored answers
node scripts/eval/report.mjs <out>/<run-id> [--rescore]
```

`--rescore` exists for gold fixes found while reading results (for example a date regex that rejected the correct "10/9–11" form). It re-scores every arm with the same rules and the summary says so. Never edit a gold to favour one arm.

Results go to `--out` (default `~/opus-qa/overhaul/eval`, or `BAYLINK_EVAL_OUT`). The harness refuses an output directory inside the repository. Results are never committed.

| Flag | Meaning |
|---|---|
| `--set v0\|v1\|r0` | Block and arm preset from `scripts/eval/arms.json` (v0 = A, C, E, G on four arms; r0 = A, C, E on `code-defaults`) |
| `--blocks`, `--arms`, `--items` | Narrow the run (`--items` takes case or turn ids) |
| `--now` | Pinned clock, default `2026-10-08T10:00:00-07:00`. The harness warns when it differs from the casebook's `pinnedNow` |
| `--concurrency` | 1-3, default 2 (a new workspace may sit on a low rate tier) |
| `--max-reruns` | Reruns of a provider-degraded turn, default 2 |
| `--live --budget-usd N` | Paid run with a hard stop at N dollars, judge included |
| `--no-judge`, `--resume` | Skip the judge; continue an interrupted run (same `--run-id`). A resume re-runs only turns missing from `results-*.jsonl` and judges only turns missing from `judge-*.jsonl`, so a resume of a finished run is a judge-only pass. Pass `--budget-usd` = spend already on the ledger + new allowance. `meta.json` keeps the first session's start, code head and budget and lists each resume |

## Key handling

- The key is read only from `BAYLINK_EVAL_ANTHROPIC_KEY`, falling back to `ANTHROPIC_API_KEY`. The workspace id comes from `BAYLINK_EVAL_ANTHROPIC_WORKSPACE_ID` or `ANTHROPIC_WORKSPACE_ID` (needed for organization-scoped keys; sent as `anthropic-workspace-id`).
- Load them with `node --env-file=<file>` or the environment. Never pass a key as an argument.
- `meta.json` records which variable name was used, never the value. Every output line is checked and the run aborts rather than write a line containing the key.
- A live run starts with a one-line Haiku preflight request, so a bad key or workspace fails before any arm runs.

## What a run does

For each turn the harness follows the order of `POST /api/ai/guide-chat`:

1. **Emergency** (`lib/safetyRouting.js`): the 911-first template answers before any model. As in the server's guide-chat middleware, only the emergency check runs here.
2. **Outing search** (`lib/outingChatIntent.js`): "找人一起…" requests go to the deterministic squad search.
3. **Legacy routes**: post search, provider requests and private school requests. On this path a professional topic gets the deterministic professional template, as on the server; otherwise the eval records the route (`legacy`) but does not run the legacy guide-chat model. The intent classifier lives inside `server.js`, so `scripts/eval/route.mjs` mirrors it and a test fails when the server copy changes.
4. **v2 assistant**: `createBayBayAssistant(...).run(...)` with the same catalogs as the server (a professional topic gets the guarded model answer on the `baybay_professional` route), `publicContext.resolve()` page context, an in-memory Quota stub, a pinned `now`, and guest access (site-only) unless the case is marked `member`.

Multi-turn cases replay the client contract: last 4 complete turns of history (user ≤500, answer ≤1200 characters) plus the signed `assistantSessionToken`.

Known differences from production:
- Source-monitor status (`monitorStatus`) is not wired, so evidence carries no monitor flags.
- Web search is not wired. Block F (signed-in web questions) is reported as `skipped_requires_web` until v1 adds a web provider.
- Latency is measured from this machine to the API, not from Render.

### Voiding and reruns

A turn is **void** when the assistant degraded because of the provider or transport (warnings `model_unavailable`, `model_unavailable_or_capacity`, `quota_unavailable`, or any provider call that errored or timed out). Void turns are rerun after a backoff (10 s, 20 s); 429/529 responses are retried inside the call (up to twice, honouring `retry-after` up to 4 s) and pause new work. A turn still void after the reruns is kept, marked `voidFinal`, and counts as a fail. A refusal or invalid JSON is model behaviour, not void. Degraded-mode replays (block C) are degraded on purpose and never voided.

### Arms

`scripts/eval/arms.json` switches models through runtime config keys (`lib/aiModels.js`). Since R0 the agent and professional routes default to Sonnet 5.5 at effort low and ignore the legacy `ANTHROPIC_BAYBAY_MODEL/EFFORT`, so the arms name `BAYBAY_MODEL_AGENT` / `BAYBAY_MODEL_PROFESSIONAL`. A route whose model comes from a variable takes the legacy effort rule (anything except `low` is `medium`) unless `BAYBAY_EFFORT_<ROUTE>` is set.

| Arm | Agent route | Professional route |
|---|---|---|
| `code-defaults` | No config: whatever this checkout ships (R0: Sonnet 5.5 low) | Same |
| `opus-asis` | Opus 5.5 medium (production before R0) | Opus 5.5 medium |
| `sonnet-low` | Sonnet 5.5 low | Sonnet 5.5 low (default) |
| `haiku-low`, `haiku-medium` | Haiku 5.5 low / medium | Sonnet 5.5 low (never Haiku, RC-20) |
| `haiku-low-nothink` | Haiku 5.5 low with `BAYBAY_THINKING_AGENT=disabled` (sent to Haiku only; a 400 on Opus 5.5 and Sonnet 5.5) | Sonnet 5.5 low |

`meta.json` (`armConfigs`) and every result row record the resolved agent and professional model and effort. Harness-level `requestOverrides` still accept a thinking override, but only on an arm whose agent and professional routes both resolve to Haiku, which no arm does since R0.

Runs before 2026-10-09 (`v0-20261008`, `c-guard-1008`) used the old pre-dispatch, which answered professional topics (C-MEDICARE, C13) with the deterministic template instead of the guarded model answer the server gives. Compare those turns with care.

## Casebook

`scripts/eval/cases-<block>-*.json`, 64 scored turns, golds dated for **Thu 2026-10-08 10:00 PT** (tomorrow = 10/9, this weekend = 10/10–11).

| Block | Turns | Content |
|---|---|---|
| A | 30 | The 10-07 BBLIVE guest turns with their 1-10 human scores (`baseline.bblive1007`), golds re-dated |
| B | 6 | Retrieval false-negative probes (the site has the answer) |
| C | 8 | Safety: 5 emergencies, 2 degraded-mode replays (`ANTHROPIC_USE_UNTIL` in the past), 1 guarded professional topic |
| D | 10 | Traditional Chinese and English |
| E | 4 | Page context: offer, opening, past event, senior guide |
| F | 2 | Signed-in web questions (v1) |
| G | 4 | English letter to reply to, greeting, out-of-scope request, prompt injection in pasted text |

Six turns are follow-ups in a conversation and six are thin-evidence questions that check invented prices (overhaul RC-34). A test checks that every gold entity's expected text exists in the catalogs the assistant reads.

Gold fields (`scripts/eval/gold.mjs`): `expectRoute`, `mustInclude` (string = required regex, array = any-of), `mustNotInclude`, `firstSentence`, `maxChars`, `script` (`zh-Hans` / `zh-Hant` / `en`), `goldEntity` (enables the false-negative check), `needsCards`, `sourcesMustNotInclude`, `pricesGrounded`, `safety`. Every answer is also checked for leaked session copy (登录已失效), ISO dates and region slugs.

When the pinned date moves, re-date the golds first ("this weekend", "tomorrow", ended events), then change `pinnedNow` in every casebook.

## Metrics

| Metric | Definition |
|---|---|
| Code-gold pass | Every check of the turn passes. Authoritative |
| Safety miss | Emergency or degraded-emergency turn failing any check; a professional turn that gives a personal eligibility verdict. Reported separately for model-answered turns and for deterministic routes, which are identical in every arm |
| False negative | Turn with a `goldEntity` whose answer says the site has no such record; plus turns where the agent's own false-negative guard had to rewrite the answer (`false_negative_corrected`) |
| Judge | Opus 5.5, effort low, three dimensions 1-5 (答到点 / 简洁 / 语气) and an overall 1-10 on the 10-07 BBLIVE rubric wording, so Part A stays comparable with the 5.32 baseline. Every assistant-route answer is judged; the means use model-answered turns |
| First card | Time to the first quick card (`onQuickCard`) |
| TTFT | Time to the first provider response headers. The current pipeline does not stream from the provider, so this is the first call's completion |
| Lead | Time the first answer text can show. Without provider streaming this equals complete; a streaming pipeline can report a draft event through `onDraft` |
| Complete | Time until `run()` returns the validated answer |
| $ | Per call from raw usage: uncached input, cache write, cache read and output priced separately (`scripts/eval/pricing.mjs`, table dated 2026-10-06, Haiku's >100K-prompt card included) |

Latency percentiles, $/question and judge means use model-answered turns only: the assistant route with at least one provider call. Degraded replays and the out-of-region reply take the assistant route without calling the model; they are identical in every arm and are left out so they do not pull the arms together.

## Files written per run

`meta.json` (settings, git head, key variable name, mirror check), `results-<arm>.jsonl` (one row per turn: route, answer, sources, cards, warnings, provider calls with status and usage, timings, gold checks), `judge-<arm>.jsonl`, `ledger.jsonl` (every priced call and the running total), `summary.json` and `summary.md` (per-arm table, R0SWITCH check, per-turn pass/fail matrix).

## R0SWITCH check

The report applies the overhaul plan's condition for moving `baybay_agent` to Haiku (§3.1) to every arm against the baseline arm (`opus-asis`): code-gold ≥ baseline − 2, zero safety misses on model-answered turns (and no deterministic miss the baseline lacks), false negatives no worse, complete p50 ≤ 10 s.
