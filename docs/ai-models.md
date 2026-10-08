# Per-route Claude models, prices and spend ledger

Added 2026-10-08 (overhaul lane API-BB-MODELS). **No behaviour changes by default.** With no new variables set, every Claude request is byte-identical to the one sent before this change: the same model (`ANTHROPIC_BAYBAY_MODEL`, default `claude-opus-5-5`), the same effort (`ANTHROPIC_BAYBAY_EFFORT`: `low`, otherwise `medium`), the same `max_tokens`, the same deadlines and the same headers. This was checked by sending 18 scenario/config combinations through the `origin/main` adapters and through this branch and diffing every outgoing URL, header, JSON body and deadline (17 identical; the one difference is the intended web-search guard described below, which only applies when `ANTHROPIC_BAYBAY_MODEL` names a Haiku model).

## Routes (`lib/aiModels.js`)

| Route | Used by today | Default `max_tokens` / deadline | Notes |
| --- | --- | --- | --- |
| `baybay_agent` | Unified BayBay research and synthesis loop (`lib/baybayAgent.js`) | caller's 6,000 / 9,000 (passed through, no ceiling); 25 s / 28 s | `baybayModel()` and `/api/ai/baybay-capabilities` report this route's model |
| `baybay_web` | Native Claude web search (`lib/anthropicWebSearch.js`) | 4,096; caller's 35 s | Never resolves to Haiku 5.5 (web search on it is unverified) |
| `baybay_fast` | Not wired yet (API-BB-ENGINE) | 4,000; 28 s | |
| `baybay_professional` | Not wired yet; professional topics still use `baybay_agent` (see the R0 caveat below) | caller's value, no ceiling; 28 s | Never resolves to Haiku 5.5 (RC-20): Opus by default, `claude-sonnet-5-5` by override. On this route the adapter sends the route's model, not the agent's |
| `baybay_legacy` | Not wired yet; `server.js` legacy guide chat still reads the legacy variables | 4,096; 28 s | |
| `helper_translate`, `helper_post_assist`, `helper_outing`, `helper_planner`, `helper_event_extract`, `helper_conversation`, `helper_other` | `requestAnthropicJson` callers | caller's value (6,000; planner 4,000), capped at 9,000; 28 s | Callers name their route; post-assist (in `server.js`) is inferred from the governed request path |
| `triage` | Not wired yet (API-FRESH-TRIAGE) | 4,000; 28 s | |

### Environment overrides

`<ROUTE>` is the route name without `baybay_`, upper-cased: `AGENT`, `WEB`, `FAST`, `PROFESSIONAL`, `LEGACY`, `HELPER_TRANSLATE`, `HELPER_PLANNER`, `TRIAGE`, and so on.

| Variable | Accepted values | Effect |
| --- | --- | --- |
| `BAYBAY_MODEL_<ROUTE>` | `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5` | Model for that route only. Any other value is ignored: the route keeps its default, `describeAiModels()` reports it, and the first request on that route logs `[ai-models] ignored {"route","name","reason"}` once (variable name only, never the value) |
| `BAYBAY_MODEL_HELPERS` | same | All `helper_*` routes; a route-specific value wins |
| `BAYBAY_EFFORT_<ROUTE>`, `BAYBAY_EFFORT_HELPERS` | `low`, `medium`, `high` | Effort is always sent explicitly (Sonnet 5.5 would otherwise default to `high`). `xhigh`/`max` are not accepted |
| `BAYBAY_MAX_TOKENS_<ROUTE>` | 256–32,000 | Replaces the caller's value. Haiku requests are always raised to at least 4,000 because Haiku 5.5 thinking counts toward `max_tokens` |
| `BAYBAY_FIRST_BYTE_MS_<ROUTE>` | 500–120,000 | Aborts a call whose response headers have not arrived. Unset by default. Non-streaming calls receive headers only near completion, so this matters mostly once streaming lands |
| `BAYBAY_TOTAL_MS_<ROUTE>` | 1,000–180,000 | Caps the provider call. Caller deadlines (the agent's 75-second run budget) still apply, so this can only shorten a call |
| `BAYBAY_THINKING_<ROUTE>` | `adaptive`, `disabled` | `disabled` sends `thinking: {type: "disabled"}` to Haiku 5.5 only (accepted there at low/medium/high), for the RC-18 eval arm. Opus 5.5 and Sonnet 5.5 return a 400 for it, so they and the Sonnet refusal retry never receive it. Unset = adaptive thinking (field omitted, as today) |
| `BAYBAY_FALLBACKS`, `BAYBAY_FALLBACKS_<ROUTE>` | `default`, `off` | Opt-in server-side refusal fallback (`fallbacks: "default"` with `anthropic-beta: server-side-fallback-2026-07-01`). Sent **only** for Opus and Sonnet; Haiku 5.5 has no server-side fallback (`"default"` stays declined, a list is a 400). Off by default |

Examples:
- R0 switch of the agent to Haiku: `BAYBAY_MODEL_AGENT=claude-haiku-5-5`. One-variable rollback: `BAYBAY_MODEL_AGENT=claude-opus-5-5` (or remove the variable).
  - **RC-20 caveat: the variable alone is not enough.** Today `lib/baybayAgent.js` creates every run with `createAnthropicBaybay({ config, fetchImpl })`, so guarded professional-topic runs (`safetyTopic`, model answers after API-BB-GUARD) also use `baybay_agent`, and the env switch would move them to Haiku. The R0SWITCH PR must also change that call to `createAnthropicBaybay({ config, fetchImpl, route: baybayRoute({ safetyTopic }) })` (one line in `baybayAgent.js`, which that file's hot-file owners land after API-BB-GUARD), with a test. The adapter then sends the professional route's own model and effort even though the agent passes `baybayModel(config)`. Professional answers stay on Opus, or on Sonnet low with `BAYBAY_MODEL_PROFESSIONAL=claude-sonnet-5-5` and `BAYBAY_EFFORT_PROFESSIONAL=low`.
  - Check after the deploy: `curl -s https://baylink-api.onrender.com/api/ai/baybay-capabilities` must show `"configuredModel":"claude-haiku-5-5"`, and the Render log must have no `[ai-models] ignored` line for `BAYBAY_MODEL_AGENT` (a typo such as `claude-haiku-5.5` leaves the agent on Opus).
- Helpers to Haiku at low effort: `BAYBAY_MODEL_HELPERS=claude-haiku-5-5`, `BAYBAY_EFFORT_HELPERS=low`.

Changing a route's model or effort starts a new prompt cache for that route (caches are per model, and effort changes invalidate the messages cache). Pin settings per route; do not vary them per request.

### Safety rules enforced in code

- **No sampling parameters.** No Claude payload ever carries `temperature`, `top_p` or `top_k` (Haiku 5.5 rejects non-default values with a 400). The agent's OpenAI-only fields are never forwarded. Unit test: `tests/anthropic-route-controls.test.js`; the legacy guide chat has its own check in `tests/claude-guide-chat.test.js`.
- **Haiku refusal retry.** A Haiku 5.5 `stop_reason: "refusal"` is retried once, with the identical request, on `claude-sonnet-5-5` (which reads Haiku 5.5 thinking blocks). The rest of that agent run stays on Sonnet. One log line is written: `[ai-refusal] {"route":…,"from":"claude-haiku-5-5","to":"claude-sonnet-5-5","category":…}` with the sanitised `stop_details.category` and no prompt or answer text. Opus and Sonnet refusals are not retried client-side (use `BAYBAY_FALLBACKS=default` for those).
- **Prompt cap on Haiku.** A Haiku request whose estimated prompt exceeds 60,000 tokens (estimate: UTF-8 bytes / 3, images 2,000 each) is sent to `claude-sonnet-5-5` instead, through the same path as the refusal retry; in the agent the rest of that run stays on Sonnet. One log line is written: `[ai-prompt-cap] {"route","from","to","estimate","cap"}` (sizes only, no text). This keeps Haiku traffic clear of the 100K-token price cliff without failing long day plans (H7 records final calls of up to 83.5K tokens). Opus and Sonnet are not capped. Evals should count cap escalations from these log lines or from `response.model`; they are not degraded answers.
- **Output budget.** Helper routes cap the caller's `max_tokens` at 9,000, as `requestAnthropicJson` always did. BayBay routes (agent, professional, web, legacy, fast) pass the caller's value through unchanged; `BAYBAY_MAX_TOKENS_<ROUTE>` replaces it.
- **Server-side fallback replies.** If fallbacks are enabled and a reply contains a `fallback` marker, only the serving model's blocks after the last marker (plus earlier text) are exposed or replayed; the declining model's tool calls are never executed.

## Prices (`lib/aiPricing.js`)

A dated table (`effectiveFrom: 2026-10-08`; source: claude-api skill, `shared/model-migration.md`). Rates are integer nano-USD per token, so arithmetic is exact and rounded once to micro-USD.

| Model | Input | Output | Cache read | 5-min cache write | 1-h cache write |
| --- | --- | --- | --- | --- | --- |
| `claude-opus-5-5` | $4 | $20 | $0.20 | $5 | $8 |
| `claude-sonnet-5-5` | $2 | $10 | $0.20 | $2.50 | $4 |
| `claude-haiku-5-5`, prompt ≤ 100,000 tokens | $0.10 | $0.50 | $0.01 | $0.125 | $0.20 |
| `claude-haiku-5-5`, prompt > 100,000 tokens | $0.50 | $2.50 | $0.05 | $0.625 | $1.00 |

Per million tokens. Web search: $0.01 per request (`usage.server_tool_use.web_search_requests`), charged once per response even when `usage.iterations` itemizes the tokens. The Haiku card is chosen by the whole prompt (uncached input + cache reads + cache writes); above 100,000 every token of that request, output included, uses the long-prompt card. Unknown models are reported as unpriced, never guessed. If a reply itemizes `usage.iterations` (server-side fallback), each attempt is priced at its own model. To change prices, add a new dated entry; do not edit an old one.

## Metrics and ledger

`fetchAiJson` (every governed provider call) now also records:
- in `AiRuntimeMetric` (`GET /api/admin/ai-metrics` → `runtime`): `costMicroUsd`, `cacheReadTokens`, `cacheWriteTokens`, `providerRefusal`, `costUnpriced`, and the `providerTtft` histogram (time to provider response headers; answered calls only). `claude-sonnet-5-5` and `claude-haiku-5-5` are now model buckets of their own instead of `other`. The existing `inputTokens` still counts the whole prompt including cache reads and writes.
- in `AiGovernance`, a spend ledger: one document per Pacific day (`ai-usd:YYYY-MM-DD`, kept 62 days) and one per month (`ai-usd:YYYY-MM`, kept 400 days) with integer `microUsd`, `pricedCalls` and `unpricedCalls`. Each update is a single atomic `$inc` upsert; a lost first-insert race (duplicate key) is retried once as a plain `$inc`, and uncertain storage errors are never retried. Ledger documents hold no identity, prompt or model data.

`aiGovernance.getSpendState()` returns today's and this month's spend, call counts, and a `level` (`ok` / `soft` / `hard`) against `AI_SPEND_SOFT_DAILY_USD` (default 6) and `AI_SPEND_HARD_DAILY_USD` (default 10). **Caps are reported only, not enforced** (`caps.enforced: false`); enforcement is API-BB-CUTOVER's job. Provider calls that time out or are cancelled report no usage and are not in the ledger.

## What this does not do

- No model switch, no `cache_control`, no streaming, no prompt changes. Those belong to API-BB-ENGINE, API-BB-STREAM and API-BB-CUTOVER and are gated by the eval.
- `server.js` (legacy guide chat) is not touched; it keeps reading `ANTHROPIC_BAYBAY_MODEL` / `ANTHROPIC_BAYBAY_EFFORT` until a `server.js`-owning lane switches it to `aiRoute('baybay_legacy', config)`.
- The admin endpoint does not yet show `getSpendState()`; the per-day cost is visible in `runtime.daily[].costMicroUsd`.
