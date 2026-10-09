# Per-route Claude models, prices and spend ledger

> **R0 update (2026-10-09, lane API-BB-R0).** `baybay_agent` and `baybay_professional` now default to **`claude-sonnet-5-5` at effort `low`**, and guarded professional answers run on `baybay_professional`. Every other route is unchanged. The Chinese section [R0 默认模型与回滚](#r0-默认模型与回滚) below has the rollback. The rest of this paragraph describes the API-BB-MODELS change as it shipped.

Added 2026-10-08 (overhaul lane API-BB-MODELS). **No behaviour changes by default.** With no new variables set, every Claude request is byte-identical to the one sent before this change: the same model (`ANTHROPIC_BAYBAY_MODEL`, default `claude-opus-5-5`), the same effort (`ANTHROPIC_BAYBAY_EFFORT`: `low`, otherwise `medium`), the same `max_tokens`, the same deadlines and the same headers. This was checked by sending 18 scenario/config combinations through the `origin/main` adapters and through this branch and diffing every outgoing URL, header, JSON body and deadline (17 identical; the one difference is the intended web-search guard described below, which only applies when `ANTHROPIC_BAYBAY_MODEL` names a Haiku model).

## Routes (`lib/aiModels.js`)

| Route | Used by today | Default `max_tokens` / deadline | Notes |
| --- | --- | --- | --- |
| `baybay_agent` | Unified BayBay research and synthesis loop (`lib/baybayAgent.js`) | caller's 6,000 / 9,000 (passed through, no ceiling); 25 s / 28 s | **R0 default `claude-sonnet-5-5`, effort `low`**; the legacy `ANTHROPIC_BAYBAY_MODEL/EFFORT` no longer apply. `baybayModel()` and `/api/ai/baybay-capabilities` report this route's model |
| `baybay_web` | Native Claude web search (`lib/anthropicWebSearch.js`) | 4,096; caller's 35 s | Never resolves to Haiku 5.5 (web search on it is unverified) |
| `baybay_fast` | The v2 single-call fast path (`lib/baybayFastPath.js`), only with `BAYBAY_ENGINE=v2` | 4,000; 28 s | Default `claude-sonnet-5-5`, effort `low` (the R0 default); `BAYBAY_MODEL_FAST=claude-haiku-5-5` is the cheap tier. Guarded professional topics never use this route (they use `baybay_professional`) |
| `baybay_professional` | Guarded professional-topic runs: `lib/baybayAgent.js` creates each run with `route: baybayRoute({ safetyTopic })` | caller's value, no ceiling; 28 s | **R0 default `claude-sonnet-5-5`, effort `low`**. Never resolves to Haiku 5.5 (RC-20), whatever variable names it. On this route the adapter sends the route's model, not the agent's |
| `baybay_legacy` | Not wired yet; `server.js` legacy guide chat still reads the legacy variables | 4,096; 28 s | |
| `helper_translate`, `helper_post_assist`, `helper_outing`, `helper_planner`, `helper_event_extract`, `helper_conversation`, `helper_other` | `requestAnthropicJson` callers | caller's value (6,000; planner 4,000), capped at 9,000; 28 s | Callers name their route; post-assist (in `server.js`) is inferred from the governed request path |
| `triage` | Source-change triage (`lib/sourceTriage.js`), only while `SOURCE_TRIAGE` is on | 4,000; 20 s caller deadline (route cap 28 s) | **Own default `claude-haiku-5-5`, effort `low`** (API-FRESH-TRIAGE); the legacy `ANTHROPIC_BAYBAY_MODEL/EFFORT` never move it. `BAYBAY_MODEL_TRIAGE` / `BAYBAY_EFFORT_TRIAGE` / `BAYBAY_THINKING_TRIAGE` override it. See `docs/source-monitor.md` |

### Environment overrides

`<ROUTE>` is the route name without `baybay_`, upper-cased: `AGENT`, `WEB`, `FAST`, `PROFESSIONAL`, `LEGACY`, `HELPER_TRANSLATE`, `HELPER_PLANNER`, `TRIAGE`, and so on.

| Variable | Accepted values | Effect |
| --- | --- | --- |
| `BAYBAY_MODEL_<ROUTE>` | `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5` | Model for that route only. Any other value is ignored: the route keeps its default, `describeAiModels()` reports it, and the first request on that route logs `[ai-models] ignored {"route","name","reason"}` once (variable name only, never the value) |
| `BAYBAY_MODEL_HELPERS` | same | All `helper_*` routes; a route-specific value wins |
| `BAYBAY_EFFORT_<ROUTE>`, `BAYBAY_EFFORT_HELPERS` | `low`, `medium`, `high` | Effort is always sent explicitly (Sonnet 5.5 would otherwise default to `high`). `xhigh`/`max` are not accepted. Without it, a route on its own default model (R0: agent, professional) uses its own effort (`low`), also when a variable pins that same model; a route whose model a variable changes to another model uses the legacy rule (`ANTHROPIC_BAYBAY_EFFORT`: `low`, otherwise `medium`) |
| `BAYBAY_MAX_TOKENS_<ROUTE>` | 256–32,000 | Replaces the caller's value. Haiku requests are always raised to at least 4,000 because Haiku 5.5 thinking counts toward `max_tokens` |
| `BAYBAY_FIRST_BYTE_MS_<ROUTE>` | 500–120,000 | Aborts a call whose response headers have not arrived. Unset by default. Non-streaming calls receive headers only near completion, so this matters mostly once streaming lands |
| `BAYBAY_TOTAL_MS_<ROUTE>` | 1,000–180,000 | Caps the provider call. Caller deadlines (the agent's 75-second run budget) still apply, so this can only shorten a call |
| `BAYBAY_THINKING_<ROUTE>` | `adaptive`, `disabled` | `disabled` sends `thinking: {type: "disabled"}` to Haiku 5.5 only (accepted there at low/medium/high), for the RC-18 eval arm. Opus 5.5 and Sonnet 5.5 return a 400 for it, so they and the Sonnet refusal retry never receive it. Unset = adaptive thinking (field omitted, as today) |
| `BAYBAY_FALLBACKS`, `BAYBAY_FALLBACKS_<ROUTE>` | `default`, `off` | Opt-in server-side refusal fallback (`fallbacks: "default"` with `anthropic-beta: server-side-fallback-2026-07-01`). Sent **only** for Opus and Sonnet; Haiku 5.5 has no server-side fallback (`"default"` stays declined, a list is a 400). Off by default |

Examples:
- R0 default (no variable): agent and professional answers on `claude-sonnet-5-5` at effort `low`. Rollback to the pre-R0 requests: `BAYBAY_MODEL_AGENT=claude-opus-5-5` and `BAYBAY_MODEL_PROFESSIONAL=claude-opus-5-5` (effort then follows `ANTHROPIC_BAYBAY_EFFORT` again, `medium` unless it is `low`).
- Agent to Haiku: `BAYBAY_MODEL_AGENT=claude-haiku-5-5`. Guarded professional answers stay on their own route (Sonnet low by default; never Haiku), because `lib/baybayAgent.js` runs them with `route: baybayRoute({ safetyTopic })`.
  - Check after the deploy: `curl -s https://baylink-api.onrender.com/api/ai/baybay-capabilities` must show the intended `"configuredModel"`, and the Render log must have no `[ai-models] ignored` line for `BAYBAY_MODEL_AGENT` (a typo such as `claude-haiku-5.5` is ignored and leaves the agent on its default).
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

## R0 默认模型与回滚

2026-10-09（lane API-BB-R0）起，代码默认值改为：

| 路由 | 用途 | 默认模型 | effort | max_tokens |
| --- | --- | --- | --- | --- |
| `baybay_agent` | BayBay 普通问答的检索与综合 | `claude-sonnet-5-5` | `low`（显式发送；Sonnet 5.5 不写会默认 high） | 调研 6,000 / 最终 9,000 |
| `baybay_professional` | Medicare、报税、移民等专业话题的受限回答 | `claude-sonnet-5-5` | `low` | 同上 |
| `baybay_web` 与各 helper 路由 | 联网搜索、翻译、发帖助手等 | 不变（仍读 `ANTHROPIC_BAYBAY_MODEL`，生产为 Opus） | 不变 | 不变 |

要点：
- 生产环境里已设置的 `ANTHROPIC_BAYBAY_MODEL=claude-opus-5-5`、`ANTHROPIC_BAYBAY_EFFORT` **不再影响**上面两条路由，所以部署后不用改任何变量，BayBay 问答就会用 Sonnet 5.5 low。联网搜索和 helper 仍按这两个旧变量走 Opus。
- 专业话题永远不会落到 Haiku（RC-20）。即使以后把 `BAYBAY_MODEL_AGENT` 设成 Haiku，专业话题仍走 `baybay_professional`。
- 请求格式已按 Sonnet 5.5 要求核对并有单测：不发 `thinking` 字段（自适应思考；`disabled` 会 400，只发给 Haiku）；`tool_choice` 只用 `auto`/`none`（强制工具会 400）；不发 `temperature/top_p/top_k`；`fallbacks` 仍默认关闭。

**回滚（在 Render 环境变量里设置，保存后重新部署即可，无需改代码）：**

```
BAYBAY_MODEL_AGENT=claude-opus-5-5
BAYBAY_MODEL_PROFESSIONAL=claude-opus-5-5
```

- 只设第一行：普通问答回到 Opus，专业话题仍是 Sonnet low。两行都设：完全回到 R0 之前的请求。
- 用变量把模型换成**别的模型**后，effort 回到旧规则：`ANTHROPIC_BAYBAY_EFFORT=low` 时为 low，否则为 medium（即 R0 之前的生产设置）。也可以用 `BAYBAY_EFFORT_AGENT` / `BAYBAY_EFFORT_PROFESSIONAL` 单独指定 `low`/`medium`/`high`。
- 把变量设成和默认一样的值（例如 `BAYBAY_MODEL_AGENT=claude-sonnet-5-5`）不会改变任何东西：effort 仍是 low，不受 `ANTHROPIC_BAYBAY_EFFORT` 影响。
- 只想调 effort、不换模型：例如 `BAYBAY_EFFORT_AGENT=medium`（模型仍是 Sonnet 5.5）。
- 部署后核对：`curl -s https://baylink-api.onrender.com/api/ai/baybay-capabilities` 里的 `configuredModel` 应是 `claude-sonnet-5-5`（回滚后是 `claude-opus-5-5`）；Render 日志里不应出现针对这些变量的 `[ai-models] ignored`（写错值会被忽略，路由保持默认）。
- 换模型或 effort 会让该路由的 prompt cache 重新开始，属于预期。

## BAYBAY_ENGINE=v2（API-BB-ENGINE）

`BAYBAY_ENGINE` 不设（或设为 `v1`）时，BayBay 发出的请求和以前逐字节相同。设为 `v2`（只对 Claude provider 生效）后：

| 部分 | 行为 |
| --- | --- |
| 路由（`lib/baybayRouter.js`） | 调模型前确定：行程、改行程、追问已发布的行程、点名两个以上地点、会员联网问题走原来的 agent 循环；其他（约八成以上，含专业话题）走一次调用的 fast path |
| fast path（`lib/baybayFastPath.js`） | 一次调用、无工具；`baybay_fast` 路由（专业话题用 `baybay_professional`，永不 Haiku）；`max_tokens` 4,000；结构化输出 `{lead, points[{text, cardIds}], candidateIds, followups, coverage, gap}`，服务端拼出旧的 `answer`，原有 finish() 护栏全部照用；无效输出或对当前页／点名记录说"站内没有"时，用 Sonnet 5.5 low 重试一次 |
| 检索（`buildFastEvidence`） | 别名（舰队周/蓝天使 → Fleet Week 等）、按县的城市召回（San Jose → Santa Clara 县电话）、优惠和新店（discoveries）入索引、相关性门槛；最多 10 条、每条 ≤400 字，带星期的日期，BAYLINK 页面在前 |
| 缓存 | system 第 1 块冻结（不含日期、模式、用户信息），带 `cache_control`；本轮条件规则放在用户消息后的 `role:'system'` 消息里（模型不支持时自动改成 `<system-reminder>`）；agent 循环用顶层自动缓存，第二次调用读第一次的前缀，最后一轮只发新增内容 |
| 新增返回字段 | `engine`、`route{path,reason}`、`lead`、`points`、`gap`、`pageEntity`；`answer` 照旧 |

**切换与回滚（Render 环境变量，改完重新部署）：**

```
BAYBAY_ENGINE=v2                      # 打开 v2（默认 fast path = Sonnet 5.5 low）
BAYBAY_MODEL_FAST=claude-haiku-5-5    # 可选：fast path 改用 Haiku 5.5（行程与专业话题仍是 Sonnet low）
BAYBAY_EFFORT_FAST=low                # 换模型时显式指定 effort
```

- 回滚：删掉 `BAYBAY_ENGINE`（或设为 `v1`），立即回到 v1。
- 改 `BAYBAY_MODEL_FAST`、`BAYBAY_EFFORT_FAST` 或 `ANTHROPIC_BAYBAY_EFFORT` 会让对应路由的 prompt cache 重新开始（缓存按模型与 effort 区分），属于预期。
- 部署后核对：随便问一句，响应 JSON 里 `engine` 为 `v2`、`route.path` 为 `fast`；`/api/admin/ai-metrics` 的 `cacheReadTokens` 应开始大于 0。

## What this does not do

- No streaming: that is API-BB-STREAM (the v2 schema puts `lead` first so it can be streamed). Caching and the prompt layout are v2-only (above). (The R0 model default above came later, from API-BB-R0.)
- `server.js` (legacy guide chat) is not touched; it keeps reading `ANTHROPIC_BAYBAY_MODEL` / `ANTHROPIC_BAYBAY_EFFORT` until a `server.js`-owning lane switches it to `aiRoute('baybay_legacy', config)`.
- The admin endpoint does not yet show `getSpendState()`; the per-day cost is visible in `runtime.daily[].costMicroUsd`.
