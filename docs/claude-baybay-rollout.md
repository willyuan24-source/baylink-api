# BayBay direct Claude rollout

- [2026-10-09 切换到 v2 引擎（中文）](#2026-10-09-切换到-v2-引擎api-bb-cutover)
- [2026-10-09 cut-over to the v2 engine (English)](#2026-10-09-cut-over-to-the-v2-engine-api-bb-cutover)
- [Original provider rollout (2026-10)](#original-provider-rollout)

## 2026-10-09 切换到 v2 引擎（API-BB-CUTOVER）

店主 10-09 12:10 决定按评测建议切换（`C:/Users/willy/opus-qa/overhaul/eval/engine-summary.md`：v2 + 代码默认模型 Sonnet 5.5 low）。这次改成**代码默认**，合并部署后就生效，**不需要改任何 Render 环境变量**。

### 改了什么

| 项目 | 现在 | 以前 |
| --- | --- | --- |
| BayBay 引擎 | `BAYBAY_ENGINE` 不设 = **v2**：先按规则分流，普通问答一次调用（fast path），行程和会员联网走 agent；system 第 1 块缓存 | v1（每题都走多轮工具循环） |
| 流式 | v2 下对能读草稿的页面（网站 #25 已上线，`streamVersion: 3`）默认开：第一句先出来，完整答案随后 | 同（STREAM #32），但 v2 原来没开 |
| 模型 | 不变：普通问答、行程、专业话题都是 Claude Sonnet 5.5，effort low。联网搜索仍按 `ANTHROPIC_BAYBAY_MODEL`（生产是 Opus）。翻译、发帖助手等**助手类不变**（HELPERS #33 的评测以后再决定是否换 Haiku） | 同 |
| 每日花费上限（太平洋时间按天，按站内账本估算） | **软上限 $6**：BayBay 只用站内资料快速回答，全站不联网查询。**硬上限 $10**：当天不再调用 AI——BayBay 用站内资料回答并显示"今日 AI 名额已满"，翻译、发帖助手等返回同样意思的 429；**紧急 911 卡片不受影响** | 只记录，不拦截 |
| BayBay 每日次数 `BAYBAY_DAILY_RUN_LIMIT` | 默认 1000（达到后同样显示"今日 AI 名额已满"） | 200 |
| 同时处理的 AI 请求 `AI_CONCURRENCY_LIMIT` | 默认 12 | 6 |
| 暂停模式 | `/api/ai/baybay-capabilities` 在暂停时返回 `enabled: false` 和 `pause`（三种语言的横幅文字、911/211 按钮）；每条回答带 `notice`。暂停的原因：`BAYBAY_PAUSED=true`、Claude 不可用（没有 key 或 `ANTHROPIC_USE_UNTIL` 已过）、当天到了硬上限 | 没有 |
| 提醒邮件 | 本月 Claude 花费过 $100 / $150 / $180、当天到硬上限、`ANTHROPIC_USE_UNTIL` 前 7 / 3 / 1 天，各发一次 | 没有 |
| 管理指标 | `/api/admin/ai-metrics` 新增 `spend`（今天和本月花费、上限状态） | 没有 |

读者看到的提示（不显示任何金额）：

| 情况 | 横幅（简体） |
| --- | --- |
| 当天到硬上限 / BayBay 次数用完 | 今日 AI 名额已满，以下为站内资料；明天会恢复。 |
| 暂停（BAYBAY_PAUSED、Claude 额度到期或没有 key） | AI 助手暂停，以下为站内资料。 |
| 软上限（会员原来要联网时） | 今天 AI 用量较高：先用站内资料快速回答，暂不联网查询。 |

现在的网站还只显示"本次未能形成完整答复……"那行灰字；横幅和 911 按钮由 WEB-BB-UI 接 `pause` / `notice` 字段后显示（接口说明在 `docs/ai-models.md`）。

### 部署前请确认（Render → Environment）

- 如果 Render 里已经设了 `BAYBAY_ENGINE=v2`，保留或删掉都可以，效果一样。
- 如果 Render 里设了 `BAYBAY_DAILY_RUN_LIMIT`（比如 200），它会盖过新的默认 1000。想用 1000 就删掉它。
- 想收到提醒邮件：需要 `NOTIFICATION_DELIVERY_ENABLED=true`，以及 `OWNER_DIGEST_EMAIL`（或单独的 `AI_ALERT_EMAIL`）。G5 打开通知投递之前，提醒只在 Render 日志里记一行 `[ai-alerts] due, not sent (delivery-disabled): …`。

### 回滚（Render → Environment，保存后重新部署；不用改代码）

```
BAYBAY_ENGINE=v1            # 回到切换前的 v1：请求和结果与切换前逐字节相同
BAYBAY_STREAM=off           # 只关流式草稿，保留 v2
AI_SPEND_CAPS=off           # 花费上限只记录、不拦截
BAYBAY_PAUSED=true          # 立即暂停 BayBay 的 AI：站内资料 + "AI 助手暂停"横幅，911 卡片照常
AI_SPEND_SOFT_DAILY_USD=6   # 调整软上限（美元/天）
AI_SPEND_HARD_DAILY_USD=10  # 调整硬上限（美元/天）；设 0 = 今天起所有 AI 都按"名额已满"处理
BAYBAY_DAILY_RUN_LIMIT=200  # 恢复旧的 BayBay 每日次数
AI_CONCURRENCY_LIMIT=6      # 恢复旧的并发数
AI_ALERT_MTD_USD=100,150,180  # 本月提醒档位（美元）
BAYBAY_AI_PROVIDER=openai   # 整体切回 OpenAI（先用同一套评测跑一遍）
```

### 部署后看什么（线上冒烟由队长做，约 5 题、$0.05）

1. `curl -s https://baylink-api.onrender.com/api/ai/baybay-capabilities`：`engine` 为 `v2`，`enabled` 为 `true`，`pause` 为 `null`，`configuredModel` 为 `claude-sonnet-5-5`。
2. 在网站上以访客身份问一句普通问题：先出现第一句，再出完整答案；响应 JSON 里 `engine: "v2"`、`route.path: "fast"`，没有 `notice`。
3. 会员请 BayBay 排一次行程：`route.path: "agent"`。
4. `/api/admin/ai-metrics`（管理员）：`runtime` 里 `cacheReadTokens` 开始大于 0（命中率不会是评测里的 100%，流量稀疏时 fast path 常读不到缓存）、`firstDraft` 有样本、`costMicroUsd` 在涨；`spend.level` 为 `ok`，`spend.dayUsd` 合理（评测约 $0.009/题）。
5. Render 日志：没有 `[ai-models] ignored`。出现 `[ai-alerts] due, not sent` 说明有提醒到期但投递没开。

### 什么时候该回滚

- 回答明显变差、出现大量"站内没有"或卡片对不上：`BAYBAY_ENGINE=v1`。
- 只是流式第一句和最终答案对不上（`corrected: true` 很多）：`BAYBAY_STREAM=off`。
- `spend.level` 在白天就到了 `soft`/`hard`：先看 `/api/admin/ai-metrics` 是否有异常流量；是正常流量就调高上限。

## 2026-10-09 cut-over to the v2 engine (API-BB-CUTOVER)

The owner approved the eval's recommendation on 10-09 (v2 on the code-default models, Sonnet 5.5 at effort low). The switch is a **code default**: deploying the merge turns it on; **no Render variable has to change**.

**What changed**
- `BAYBAY_ENGINE` unset now means **v2** (router, single-call fast path, agent loop only for plans and member web, cached system block 1). `BAYBAY_ENGINE=v1` (also `off` / `legacy`) is the rollback; its requests and results are byte-identical to production before the cut-over (sha256 over 8 fixed turns).
- Streaming drafts stay on under v2 for capable clients (`streamVersion >= 3`, live on the web since #25); `BAYBAY_STREAM=off` turns them off.
- Models are unchanged: fast path, agent and professional on Claude Sonnet 5.5 low; web search on `ANTHROPIC_BAYBAY_MODEL`; helpers unchanged (HELPERS #33 and its eval decide later).
- **Daily $ caps are enforced** (Pacific day, in-app ledger estimate): soft $6 → BayBay answers from site evidence on the fast path and no web search runs anywhere; hard $10 → no governed AI call until Pacific midnight: BayBay answers from site records with the "今日 AI 名额已满" notice and helpers return an honest 429. The emergency card never depends on either. `AI_SPEND_CAPS=off` makes the caps report-only.
- `BAYBAY_DAILY_RUN_LIMIT` defaults to 1000 (was 200); `AI_CONCURRENCY_LIMIT` to 12 (was 6).
- Pause mode: `GET /api/ai/baybay-capabilities` reports `enabled: false` and `pause {reason, kind, banner per locale, resumesAt?, actions 911/211}` when `BAYBAY_PAUSED=true`, when Claude is unusable (no key, `ANTHROPIC_USE_UNTIL` passed) or past the hard cap; answers carry `notice {kind, text, resumesAt?}`. Contract in `docs/ai-models.md`.
- Owner e-mails at $100 / $150 / $180 month-to-date, at the daily hard cap and 7 / 3 / 1 days before `ANTHROPIC_USE_UNTIL`, once each, through Resend only with `NOTIFICATION_DELIVERY_ENABLED=true` and `AI_ALERT_EMAIL` or `OWNER_DIGEST_EMAIL`. Never sent from tests.
- `/api/admin/ai-metrics` adds `spend`.

**Before deploying:** a Render `BAYBAY_DAILY_RUN_LIMIT` overrides the new default; an existing `BAYBAY_ENGINE=v2` is harmless.

**Rollback lines (Render → Environment, then redeploy):** `BAYBAY_ENGINE=v1` (engine), `BAYBAY_STREAM=off` (drafts), `AI_SPEND_CAPS=off` (caps report-only), `BAYBAY_PAUSED=true` (pause BayBay's AI now), `AI_SPEND_SOFT_DAILY_USD` / `AI_SPEND_HARD_DAILY_USD` (cap values), `BAYBAY_DAILY_RUN_LIMIT=200`, `AI_CONCURRENCY_LIMIT=6`, `AI_ALERT_MTD_USD` (alert thresholds), `BAYBAY_AI_PROVIDER=openai` (provider).

**What to watch after the deploy:** capabilities show `engine: "v2"`, `enabled: true`, `pause: null`; a guest question returns `engine: "v2"`, `route.path: "fast"` and streams its first sentence; a member plan returns `route.path: "agent"`; `/api/admin/ai-metrics` shows `cacheReadTokens > 0`, `firstDraft` samples, rising `costMicroUsd`, and `spend.level: "ok"`; the Render log has no `[ai-models] ignored`. The merge captain runs the post-deploy smoke (about 5 questions, $0.05).

## Original provider rollout

This optional provider supports the existing frontend contract. No frontend key or new dependency is needed. Default `BAYBAY_AI_PROVIDER=openai` preserves the installed provider until the server is configured.

## Server configuration

| Variable | Value / behavior |
| --- | --- |
| `BAYBAY_AI_PROVIDER` | `anthropic` |
| `ANTHROPIC_API_KEY` | Secret stored only in hosting environment settings |
| `ANTHROPIC_WORKSPACE_ID` | Console workspace ID; required for organization-scoped identity keys |
| `ANTHROPIC_BAYBAY_MODEL` | `claude-opus-5-5` |
| `ANTHROPIC_BAYBAY_EFFORT` | `medium` default; `low` for a deliberate latency/cost tradeoff |
| `ANTHROPIC_USE_UNTIL` | Optional ISO UTC cutoff; expired or invalid nonempty cutoff disables new Claude calls |

Promotional credits belong to the Console organization. Check the actual credit applicability and expiry in Billing; the application cannot infer remaining dollars from request quotas. For the October 2026 trial, the observed credit expiry date is October 30 UTC. The deployment uses the conservative cutoff `2026-10-30T00:00:00Z` because the UI exposes a date rather than an exact expiry time. At the cutoff, site help remains available; changing provider after the trial is a separate operator decision. No payment method, auto-reload or purchase is configured by this release.

## Protocol and cost boundaries

Direct HTTPS requests go only to `api.anthropic.com/v1/messages`, with `Authorization: Bearer`, `anthropic-version: 2023-06-01`, and the optional workspace header. Existing cancellation, concurrency and shared database quotas are used. There are no automatic cross-provider retries.

Opus 5.5 uses adaptive thinking. Returned text and tool calls are selected by block type; private thinking/signatures are retained only inside an individual tool loop and are never returned to the browser. System instructions, model and tool definitions remain stable during that loop. Tool results and current evidence append to the conversation. Synthesis sets `tool_choice: none` while retaining tool definitions. Application validators still enforce candidate IDs, citations, geography, answer length and plan constraints after schema decoding.

Request `max_tokens` includes both reasoning and visible answers. Usage accounting includes cache creation/read input and counts output (including hidden thinking) once. The existing admin metrics recognize the fixed Claude model name, without storing prompts or credentials. These request/token controls do not constitute a dollar-denominated hard cap.

Native Claude web search is bounded to at most two tool uses and 35 seconds. Agent model calls allow up to 25 seconds for research or 28 seconds for synthesis, shortened to the remaining stage deadline; the complete agent run retains its 75-second budget. The tool dispatcher requires the full search window before starting a lookup, preserving time for a final answer. Only native citations pass into the existing public-URL and source validation. Private plans/history are not sent to the web-search request. The Claude search path does not run the OpenAI extraction step.

Event screenshot extraction, private conversation assistance, post drafts/translation, the older planner ranker and outing drafts follow the same selected provider. Claude helper calls have a 28-second bound; ranking uses at most 4,000 tokens and the other helpers 6,000, including thinking. Only complete `end_turn` JSON is accepted. Screenshot images are validated PNG/JPEG/GIF/WebP data images; arbitrary remote image URLs are rejected. Private assistance still receives only the explicitly selected in-thread message and user's drafting intent, never an entire conversation. A generated draft cannot publish a post, send a message or book an outing. Existing authentication, quotas, candidate constraints and numeric/URL translation validators remain enforced. Expired Claude configuration blocks new native calls while validated cached translations remain available.

Legacy guide answers retain the 1,200-character hard limit. Language-specific shorter targets keep English prose within it; an overlong, refused or incomplete answer still falls back to site information instead of being clipped into a misleading success.

## Release and verification

1. Run `npm run check`, the complete backend test suite and dependency audit.
2. Verify the API key/workspace/model against the direct Models endpoint and one small Messages request. Keep credentials out of scripts, command arguments, logs and the repository.
3. Deploy the backend commit, configure the hosting variables, and verify `/api/health` reports that exact commit.
4. Verify `/api/ai/baybay-capabilities` reports the intended provider and model. Configuration alone does not verify access.
5. Send bounded public site-only and authenticated web questions. Inspect actual response model, complete/nondegraded output, source links and native tool usage. Confirm ordinary site browsing and default-provider regression tests still pass.
6. To roll back the provider, set `BAYBAY_AI_PROVIDER=openai` and redeploy the environment; existing OpenAI variables remain untouched. Do not ship the independent frontend design preview as part of this backend release.

## Official references

- [Opus 5.5 migration](https://platform.claude.com/docs/en/models/opus-5-5/migration-guide)
- [Authentication and workspace selection](https://platform.claude.com/docs/en/manage-claude/authentication)
- [Preserved thinking](https://platform.claude.com/docs/en/build-with-claude/preserved-thinking)
- [Structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
- [Web search](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool)
