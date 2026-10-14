# BayBay direct Claude rollout

- [2026-10 换新 Anthropic key（中文）](#2026-10-换新-anthropic-keyapi-ops-key)
- [2026-10 switching to the new Anthropic key (English)](#2026-10-switching-to-the-new-anthropic-key-api-ops-key)
- [2026-10-09 切换到 v2 引擎（中文）](#2026-10-09-切换到-v2-引擎api-bb-cutover)
- [2026-10-09 cut-over to the v2 engine (English)](#2026-10-09-cut-over-to-the-v2-engine-api-bb-cutover)
- [Original provider rollout (2026-10)](#original-provider-rollout)

## 2026-10 换新 Anthropic key（API-OPS-KEY）

旧 key 的推广额度到 2026-10-30 00:00 UTC（湾区 10/29 17:00）为止，线上的 `ANTHROPIC_USE_UNTIL` 就设在这个时间。店主已决定 10/23 起换一把新的 API key（约 $1,000，约 6 个月）。**key 只由店主在 Console 和 Render 里操作**；Claude 不看、不改 key，也不改 Render。下面按时间顺序写清每一步。

### 0. 先在 Console 核对（10/21，约 15 分钟）

如果新 key 和以前的推广额度在同一个 Console 组织里：

- **余额**：可能已经不到 $1,000。先读余额，再按第 1 步分配上限。
- **组织月度上限**：组织可能已经有一个月度上限。两个工作区的上限加起来不能超过它；不够就先调高组织上限，再设工作区上限。
- **评测工作区**：可能已经有评测工作区和评测 key。先查，没有再建。
- **工作区 ID**：记下生产工作区的 ID（Console 的工作区设置里）。只有组织级 key 才需要把它填进 Render（第 2 步）。

### 1. 在 Console 设工作区和上限

| 工作区 | 例子 | 月度上限 | 说明 |
| --- | --- | --- | --- |
| 生产 | `baylink-prod` | 约 **$175**（$1,000 ÷ 6 个月 ≈ $167，留一点余量） | 不能超过组织上限。新的生产 key 建在这个工作区里 |
| 评测 | `baylink-eval` | 总共约 **$60** | 评测 key 只放店主电脑的本地环境文件；不放进 Render，不贴进聊天、PR 或文档 |

### 2. Render → baylink-api → Environment（店主操作，一次保存）

| 变量 | 填什么 | 说明 |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | 新的生产 key | |
| `ANTHROPIC_WORKSPACE_ID` | 只有新 key 是组织级 key、Console 说需要时才填 | 普通的工作区 key 不用填 |
| `ANTHROPIC_USE_UNTIL` | 新额度到期日的**前一天**，例如额度 2027-04-20 到期就填 `2027-04-19T00:00:00Z` | 快到期时提前 7 / 3 / 1 天发提醒，到期时诚实地暂停，而不是调用失败。只有绑了卡、确定不会断，才留空。**格式见下一节** |
| `AI_SPEND_SOFT_DAILY_USD` | `4` | 代码默认 6。过了软上限：BayBay 只用站内资料快速回答，全站不联网查询 |
| `AI_SPEND_HARD_DAILY_USD` | `7` | 代码默认 10。到了硬上限：当天不再调用 AI，显示"今日 AI 名额已满"，911 卡片照常 |
| `AI_ALERT_MTD_USD` | `100,140,165` | 代码默认 `100,150,180`。本月花费过这几档各发一封提醒 |
| `AI_CREDIT_TOTAL_USD` / `AI_CREDIT_START` | 新 key 的额度（例如 `1000`）/ 新 key 开始用的那天（湾区日期，例如 `2026-10-23`） | 可选（API-OPS）。管理员 `/api/admin/ai-metrics` 的 `credit` 显示从这天起用了多少、最近 7 / 30 天每天平均多少、按这个速度哪天用完、比 `ANTHROPIC_USE_UNTIL` 早几天；预计早 14 天以上用完时发**一封**提醒。数字来自站内账本（估算），准确账单看 Console |
| `AI_GUEST_BAYBAY_DAILY_LIMIT` / `AI_USER_BAYBAY_DAILY_LIMIT` | R1 建议 `15` / `40`（店主定） | BayBay 自己的每日次数（每个访客 / 每位会员）。不设时和共用的 `AI_GUEST_DAILY_LIMIT` / `AI_USER_DAILY_LIMIT` 一样（代码默认 15 / 40） |

保存后 Render 会重新部署。

**怎么看 `credit`（API-OPS）：** 网页管理员页面还没有这个面板，直接在地址栏打开 API 网址会因为没带登录令牌得到 401。做法：电脑浏览器打开 www.baylink.us，用管理员登录（开了 `ADMIN_MFA_REQUIRED` 就用密码加 6 位代码）→ F12 → Console（控制台）→ 粘贴下面这一行回车（Chrome 第一次粘贴要先输入 `allow pasting`）。不要把 `currentUser` 里的 token 发给任何人。

```js
fetch('https://baylink-api.onrender.com/api/admin/ai-metrics',{headers:{Authorization:'Bearer '+JSON.parse(localStorage.getItem('currentUser')).token}}).then(r=>r.json()).then(d=>console.log(d.credit))
```

### `ANTHROPIC_USE_UNTIL` 的格式（一定要对）

- **只接受两种写法，不能有空格**：
  - `YYYY-MM-DD`，例如 `2027-04-19`，表示这天 00:00 UTC（湾区是前一天下午 4 点或 5 点）；
  - 带 `Z` 或时区的完整 ISO 时间，例如 `2027-04-19T00:00:00Z`、`2027-04-18T17:00:00-07:00`。秒不能省，`T` 和 `Z` 要大写。
- **其他任何值**（多一个空格、`2027-04-19 00:00`、不带时区的 `2027-04-19T00:00:00`、2 月 30 日这种不存在的日期）：API 会当作 Claude 不可用，所有用 Claude 的功能（BayBay 跑在 Claude 上时也包括它）**马上停**，而且**不会先显示**"AI 助手预计…起暂停"的横幅。
- 三道检查（API-OPS-KEY 加的）：
  1. 粘贴之前，在本机仓库里跑（不联网，和 API 用同一套判断）：`node scripts/check-ai-readiness.mjs --check-value "2027-04-19T00:00:00Z"`。`RESULT: VALID` 才能用；它还会告诉你湾区几点停、横幅从哪天开始显示。
  2. 部署后，如果值不对，Render 日志里会有**一行** `[ai-config] ANTHROPIC_USE_UNTIL is set but invalid (…)`，括号里是原因（`spaces`、`missing_zone`、`invalid_date`、`format`），不会打印值本身。
  3. 管理员 `/api/admin/ai-metrics` 新增 `useUntil`：`{ set, valid, problem, at, passed }`。
- 到期前 7 天起，每页都会显示"AI 助手预计…起暂停"；到期后 BayBay 暂停（站内资料 + 横幅，911 卡片照常），翻译、发帖助手、联网查询和来源自动分诊也停。

### 3. 什么时候换

- 新 key 能用的第一天（计划 **10/23**）**同时**换 `ANTHROPIC_API_KEY` 和 `ANTHROPIC_USE_UNTIL`。只换 key 不改日期：BayBay 仍会在 10/29 17:00 停。只改日期不换 key：旧额度用完后调用会失败。
- 现在的设置会从 **10/22 17:00**（湾区）起在每页显示"AI 助手预计 10月29日…起暂停"，换完就消失。**最晚 10/29 17:00 之前**换完。

### 4. 换完后验证（只读，免费）

在仓库里跑：

```
node scripts/check-ai-readiness.mjs --expect-until 2027-04-19T00:00:00Z
```

（`--expect-until` 填你在 Render 里填的值；可以加 `--expect-commit <commit 前 7 位>` 核对部署的版本；`--json` 输出 JSON。）它只读两个公开接口 `/api/health` 和 `/api/ai/baybay-capabilities`，不带任何登录信息，不调用 AI。期望：

- `RESULT: READY`，退出码 0（1 = 没就绪，2 = 参数错，4 = 自动重试一次后仍读不到 API，过一分钟再跑）；
- `enabled true`、`pause none`、`provider anthropic`、`aiUntil` 是新日期、`scheduled no pause banner`；
- Render 日志里没有 `[ai-config]` 这一行。

这一步只证明**配置**对了，不证明新 key 真能调用（接口里 `modelAccessVerified` 永远是 `false`）。店主同意后，再问 5 个问题冒烟（约 $0.10）：1 个周末活动、1 个华人活动、1 个办事、1 个急症说法、1 个英文问题。

### 5. 48 小时后

新 key 稳定 48 小时后，店主在 Console 吊销旧 key。在那之前出问题，可以先把 `ANTHROPIC_API_KEY` 和 `ANTHROPIC_USE_UNTIL` 一起改回旧的（旧值 `2026-10-30T00:00:00Z`），或者设 `BAYBAY_PAUSED=true` 立即暂停（911 卡片照常）。其他回滚开关见下面 2026-10-09 一节的"回滚"。

### 提醒邮件的前提

- `NOTIFICATION_DELIVERY_ENABLED=true` 会**一次打开所有通知类外发邮件**：会员通知（私信、联系请求、小队申请、评论）、登录提醒、来源分诊摘要和 AI 提醒。它需要 `RESEND_API_KEY`、`RESEND_FROM_EMAIL` 和 Resend 里已验证的域名。
- 它**同时打开通知短信**：Render 里配了 Twilio（和手机验证码是同一套 `TWILIO_PHONE_NUMBER`）时，开了短信通知、验证过手机的会员会收到短信，Twilio 按条收费。上限是 `NOTIFICATION_SMS_DAILY_LIMIT` / `NOTIFICATION_SMS_USER_DAILY_LIMIT`（默认全站每天 100 条、每人每天 5 条；设 `0` = 不发通知短信）。暂时不想发通知短信，就在同一次保存里设 `NOTIFICATION_SMS_DAILY_LIMIT=0`。
- 先按 [`docs/g5-production-checklist.md`](g5-production-checklist.md) 走一遍，再打开它，并设 `AI_ALERT_EMAIL`（或 `OWNER_DIGEST_EMAIL`）。
- 不打开：提醒只在 Render 日志里记一行 `[ai-alerts] due, not sent (delivery-disabled): …`，收不到邮件，店主每周自己看一次 Console 用量。

### 预算参考（约 $1,000，6 个月）

| 项目 | 每月 | 6 个月 |
| --- | --- | --- |
| 生产（BayBay + 行程 + 翻译 + 分诊），平均每天约 $4 | 约 $120 | 约 $720 |
| 评测（每条改动 BayBay 的 lane ≤$3，每月线上 30 题 $1–2） | 约 $10 | 约 $60 |
| 余量 | | 约 $220 |

- 每个回答约 $0.022（10-13 实测），$4/天 ≈ 180 个回答/天。
- 硬上限 $7/天时最坏一个月约 $210；本月提醒到 $165 时会发邮件；Console 生产工作区的月度上限 $175 是最后一道闸。

## 2026-10 switching to the new Anthropic key (API-OPS-KEY)

The old key's promotional credit ends at 2026-10-30 00:00 UTC (Oct 29, 5:00 PM in the Bay Area), which is what `ANTHROPIC_USE_UNTIL` is set to now. From Oct 23 the owner switches to a new API key (about $1,000 for about 6 months). **Only the owner handles the key**, in the Console and on Render; Claude never sees or changes the key or the Render settings.

**0. Check the Console first (Oct 21).** If the new key lives in the same Console organization as the promotional credit: read the balance (it may already be below $1,000) before setting the limits; check for an existing organization monthly limit (the two workspace limits together must fit under it; raise it first if needed); check for an existing eval workspace and eval key before creating one; note the production workspace id (needed on Render only for an organization-scoped key).

**1. Workspaces and limits in the Console.** Production workspace (for example `baylink-prod`) with a monthly limit of about **$175** ($1,000 ÷ 6 months ≈ $167, plus a little headroom), within the organization limit; the new production key is created there. Eval workspace (for example `baylink-eval`) with about **$60** in total; the eval key stays in the owner's local env file only, never on Render, in chat, in a PR or in a doc.

**2. Render → baylink-api → Environment (the owner, one save).**

| Variable | Value | Notes |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | the new production key | |
| `ANTHROPIC_WORKSPACE_ID` | only for an organization-scoped key, when the Console says so | not needed for a workspace key |
| `ANTHROPIC_USE_UNTIL` | the day **before** the new credit expires, e.g. `2027-04-19T00:00:00Z` for credit that expires 2027-04-20 | gives the 7/3/1-day alerts and an honest pause instead of failing calls. Leave it empty only with a card on file. Format below |
| `AI_SPEND_SOFT_DAILY_USD` | `4` | code default 6: site-only fast answers and no web search past it |
| `AI_SPEND_HARD_DAILY_USD` | `7` | code default 10: no AI call for the rest of the Pacific day, "今日 AI 名额已满", the 911 card unaffected |
| `AI_ALERT_MTD_USD` | `100,140,165` | code default `100,150,180`: one e-mail per threshold per month |
| `AI_CREDIT_TOTAL_USD` / `AI_CREDIT_START` | the new key's credit (e.g. `1000`) / the Pacific day the new key starts (e.g. `2026-10-23`) | optional (API-OPS). Admin `/api/admin/ai-metrics` `credit` shows spend since that day, the 7- and 30-day average per day, the projected run-out date and how many days before `ANTHROPIC_USE_UNTIL` that is; **one** e-mail when it is more than 14 days early. Ledger estimate; the Console is the bill |
| `AI_GUEST_BAYBAY_DAILY_LIMIT` / `AI_USER_BAYBAY_DAILY_LIMIT` | R1 suggestion `15` / `40` (the owner decides) | BayBay's own daily share per visitor / member; unset = the shared `AI_GUEST_DAILY_LIMIT` / `AI_USER_DAILY_LIMIT` (code defaults 15 / 40) |

**Reading `credit` (API-OPS).** The web admin area has no panel for it yet, and opening the API URL in the address bar sends no session token (401). On a computer, open www.baylink.us, sign in as the administrator (password + authenticator code once `ADMIN_MFA_REQUIRED` is on), DevTools (F12) → Console, and run (Chrome asks for `allow pasting` before the first paste); never share the `token` inside `currentUser`:

```js
fetch('https://baylink-api.onrender.com/api/admin/ai-metrics',{headers:{Authorization:'Bearer '+JSON.parse(localStorage.getItem('currentUser')).token}}).then(r=>r.json()).then(d=>console.log(d.credit))
```

**The `ANTHROPIC_USE_UNTIL` format.** Only `YYYY-MM-DD` (00:00 UTC that day) or a full ISO time with `Z` or an offset (`2027-04-19T00:00:00Z`, `2027-04-18T17:00:00-07:00`): seconds required, upper-case `T` and `Z`, no spaces. Any other nonempty value (a stray space, `2027-04-19 00:00`, `2027-04-19T00:00:00` without a zone, Feb 30) makes the API treat Claude as unavailable: every feature that uses Claude stops at once (BayBay too while it runs on Claude), with **no** advance banner. Three checks since API-OPS-KEY: (1) before pasting, `node scripts/check-ai-readiness.mjs --check-value "<value>"` (offline, the API's own reading; only `RESULT: VALID` is safe, and it prints the Pacific stop time and the first banner day); (2) after the deploy, an invalid value logs **one** Render line `[ai-config] ANTHROPIC_USE_UNTIL is set but invalid (<problem>: …)` with the problem (`spaces`, `missing_zone`, `invalid_date`, `format`) and never the value; (3) `/api/admin/ai-metrics` (admins) has `useUntil {set, valid, problem, at, passed}`. From 7 days before a valid cutoff every page shows "AI 助手预计…起暂停"; after it BayBay pauses (site records + banner, 911 card unaffected), and translation, post drafts, web search and source triage stop too.

**3. When.** On the first day the new key works (planned **Oct 23**), change `ANTHROPIC_API_KEY` **and** `ANTHROPIC_USE_UNTIL` together. A new key with the old date still pauses BayBay on Oct 29 at 5 PM; a new date with the old key fails once the old credit is gone. Today's value shows the scheduled-pause banner on every page from **Oct 22, 5:00 PM PT**; switching removes it. Finish **before Oct 29, 5:00 PM PT**.

**4. Verify (read-only, free).** `node scripts/check-ai-readiness.mjs --expect-until <the value set on Render>` (optional `--expect-commit <sha>`, `--json`). It reads only the public `/api/health` and `/api/ai/baybay-capabilities`, without credentials, and calls no model. Expect `RESULT: READY` and exit code 0 (1 not ready, 2 bad arguments, 4 the API could not be read even after one automatic retry: rerun in a minute), `enabled true`, `pause none`, `provider anthropic`, the new `aiUntil`, `no pause banner`, and no `[ai-config]` line in the Render log. This proves the configuration, not the key (`modelAccessVerified` is always `false`): with the owner's approval, a 5-question smoke (about $0.10: a weekend event, a Chinese-community event, a how-to, an emergency phrasing, an English question) proves the key.

**5. After 48 hours.** Once the new key has been stable for 48 hours, the owner revokes the old key in the Console. Until then, a problem can be rolled back by restoring both the old key and the old `ANTHROPIC_USE_UNTIL` (`2026-10-30T00:00:00Z`), or paused at once with `BAYBAY_PAUSED=true` (the 911 card is unaffected); other levers are in the rollback lines of the 2026-10-09 section below.

**Alert e-mail prerequisites.** `NOTIFICATION_DELIVERY_ENABLED=true` turns on **all** notification e-mail at once: member notifications (messages, contact requests, team applications, comments), sign-in alerts, the source-triage digest and the AI alerts. It needs `RESEND_API_KEY`, `RESEND_FROM_EMAIL` and a domain verified in Resend. It **also turns on notification SMS** when Twilio is configured (the same `TWILIO_PHONE_NUMBER` that sends phone verification codes): members who opted in with a verified phone get texts, which Twilio bills per message, capped by `NOTIFICATION_SMS_DAILY_LIMIT` / `NOTIFICATION_SMS_USER_DAILY_LIMIT` (defaults 100 a day site-wide and 5 per member; `0` sends no notification SMS). To keep notification SMS off for now, set `NOTIFICATION_SMS_DAILY_LIMIT=0` in the same save. Run [`docs/g5-production-checklist.md`](g5-production-checklist.md) first, then turn it on and set `AI_ALERT_EMAIL` (or `OWNER_DIGEST_EMAIL`). Without it, due alerts only log `[ai-alerts] due, not sent (delivery-disabled): …` and the owner checks Console usage weekly.

**Budget (about $1,000 over 6 months).** Production (BayBay, plans, translation, triage) about $4/day ≈ $120/month ≈ $720; evals about $10/month ≈ $60 (≤$3 per BayBay-changing lane, $1–2 for the monthly 30 live questions); about $220 of headroom. At about $0.022 per answer (measured 10-13), $4/day ≈ 180 answers/day. With the $7/day hard cap the worst month is about $210; the $165 month-to-date alert e-mails first, and the production workspace's $175 monthly limit in the Console is the last gate.

## 2026-10-09 切换到 v2 引擎（API-BB-CUTOVER）

店主 10-09 12:10 决定按评测建议切换（`C:/Users/willy/opus-qa/overhaul/eval/engine-summary.md`：v2 + 代码默认模型 Sonnet 5.5 low）。这次改成**代码默认**，合并部署后就生效，**不需要改任何 Render 环境变量**。

### 改了什么

| 项目 | 现在 | 以前 |
| --- | --- | --- |
| BayBay 引擎 | `BAYBAY_ENGINE` 不设 = **v2**：先按规则分流，普通问答一次调用（fast path），行程和会员联网走 agent；system 第 1 块缓存 | v1（每题都走多轮工具循环） |
| 流式 | v2 下对能读草稿的页面（网站 #25 已上线，`streamVersion: 3`）默认开：第一句先出来，完整答案随后 | 同（STREAM #32），但 v2 原来没开 |
| 模型 | 不变：普通问答、行程、专业话题都是 Claude Sonnet 5.5，effort low。联网搜索仍按 `ANTHROPIC_BAYBAY_MODEL`（生产是 Opus）。翻译、发帖助手等**助手类不变**（HELPERS #33 的评测以后再决定是否换 Haiku） | 同 |
| 每日花费上限（太平洋时间按天，按站内账本估算） | **软上限 $6**：BayBay 只用站内资料快速回答（改已有行程，比如"换掉第二站"，仍走 agent，但只有站内工具），全站不联网查询。**硬上限 $10**：当天不再调用 AI——BayBay 用站内资料回答并显示"今日 AI 名额已满"；发帖助手、帖子翻译、私信和活动截图 AI、约伴草稿返回同样意思的 429；联网查询返回 `web_daily_limit`（429，不提示重试）；约伴草稿和联网查询在扣自己的次数之前就拒绝；行程推荐退回规则排序。**紧急 911 卡片不受影响** | 只记录，不拦截 |
| BayBay 每日次数 `BAYBAY_DAILY_RUN_LIMIT` | 默认 1000（达到后同样显示"今日 AI 名额已满"）。其中每位会员每天最多 80 次（`BAYBAY_MEMBER_RUN_LIMIT`）、每个访客最多 30 次（`BAYBAY_VISITOR_RUN_LIMIT`），一个人用完只影响他自己 | 200（全站共用，一个访客能用光） |
| 同时处理的 AI 请求 `AI_CONCURRENCY_LIMIT` | 默认 12 | 6 |
| 暂停模式 | `/api/ai/baybay-capabilities` 在暂停时返回 `enabled: false` 和 `pause`（三种语言的横幅文字、911/211 按钮）；每条回答带 `notice`。暂停的原因：`BAYBAY_PAUSED=true`、Claude 不可用（没有 key 或 `ANTHROPIC_USE_UNTIL` 已过）、当天到了硬上限。`BAYBAY_AGENT_ENABLED=false` 不算暂停：问答走旧版路径，`enabled` 照旧是 `false`，不显示暂停横幅（只有到硬上限时显示"今日 AI 名额已满"） | 没有 |
| 提醒邮件 | 本月 Claude 花费过 $100 / $150 / $180、当天到硬上限、`ANTHROPIC_USE_UNTIL` 前 7 / 3 / 1 天，各发一次；API-OPS 起，`ANTHROPIC_USE_UNTIL` 格式不对时发一封（不写出值本身），设了 `AI_CREDIT_TOTAL_USD` / `AI_CREDIT_START` 且预计比截止早 14 天以上用完时发一封 | 没有 |
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
- 想收到提醒邮件：需要 `NOTIFICATION_DELIVERY_ENABLED=true`（它同时打开会员通知邮件和通知短信，见上面"提醒邮件的前提"），以及 `OWNER_DIGEST_EMAIL`（或单独的 `AI_ALERT_EMAIL`）。G5 打开通知投递之前，提醒只在 Render 日志里记一行 `[ai-alerts] due, not sent (delivery-disabled): …`。

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
4. `/api/admin/ai-metrics`（管理员）：`runtime` 里 `cacheReadTokens` 开始大于 0（命中率不会是评测里的 100%，流量稀疏时 fast path 常读不到缓存）、`firstDraft` 有样本、`costMicroUsd` 在涨；`spend.level` 为 `ok`，`spend.dayUsd` 合理（评测约 $0.009/题）。`ai-metrics` 没有 `engine` 字段，引擎看第 1、2 步（capabilities 和每条回答）。
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
- **Daily $ caps are enforced** (Pacific day, in-app ledger estimate): soft $6 → BayBay answers from site evidence on the fast path (an edit of the plan in scope, such as "换掉第二站", keeps the agent path with site-only tools) and no web search runs anywhere; hard $10 → no governed AI call until Pacific midnight: BayBay answers from site records with the "今日 AI 名额已满" notice; post-assist, post translation, conversation and event-screenshot AI and outing drafts return the 429 `AI_DAILY_BUDGET`; the planner web search returns `web_daily_limit` (429, not retryable); outing drafts and the web search refuse before spending their own quotas; the planner ranker falls back to its rules. The emergency card never depends on either. `AI_SPEND_CAPS=off` makes the caps report-only.
- `BAYBAY_DAILY_RUN_LIMIT` defaults to 1000 (was 200); `AI_CONCURRENCY_LIMIT` to 12 (was 6).
- Pause mode: `GET /api/ai/baybay-capabilities` reports `enabled: false` and `pause {reason, kind, banner per locale, resumesAt?, actions 911/211}` when `BAYBAY_PAUSED=true`, when Claude is unusable (no key, `ANTHROPIC_USE_UNTIL` passed) or past the hard cap; answers carry `notice {kind, text, resumesAt?}`. `BAYBAY_AGENT_ENABLED=false` is not a pause (guide-chat answers on the legacy path; `enabled` stays `false` with no pause banner except at the hard cap). Contract in `docs/ai-models.md`.
- Owner e-mails at $100 / $150 / $180 month-to-date, at the daily hard cap and 7 / 3 / 1 days before `ANTHROPIC_USE_UNTIL`, once each, through Resend only with `NOTIFICATION_DELIVERY_ENABLED=true` and `AI_ALERT_EMAIL` or `OWNER_DIGEST_EMAIL`. Never sent from tests.
- `/api/admin/ai-metrics` adds `spend`.

**Before deploying:** a Render `BAYBAY_DAILY_RUN_LIMIT` overrides the new default; an existing `BAYBAY_ENGINE=v2` is harmless.

**Rollback lines (Render → Environment, then redeploy):** `BAYBAY_ENGINE=v1` (engine), `BAYBAY_STREAM=off` (drafts), `AI_SPEND_CAPS=off` (caps report-only), `BAYBAY_PAUSED=true` (pause BayBay's AI now), `AI_SPEND_SOFT_DAILY_USD` / `AI_SPEND_HARD_DAILY_USD` (cap values), `BAYBAY_DAILY_RUN_LIMIT=200`, `AI_CONCURRENCY_LIMIT=6`, `AI_ALERT_MTD_USD` (alert thresholds), `BAYBAY_AI_PROVIDER=openai` (provider).

**What to watch after the deploy:** capabilities show `engine: "v2"`, `enabled: true`, `pause: null`; a guest question returns `engine: "v2"`, `route.path: "fast"` and streams its first sentence; a member plan returns `route.path: "agent"`; `/api/admin/ai-metrics` shows `cacheReadTokens > 0`, `firstDraft` samples, rising `costMicroUsd`, and `spend.level: "ok"` (it has no `engine` field: the engine shows in the capabilities and in each answer); the Render log has no `[ai-models] ignored`. The merge captain runs the post-deploy smoke (about 5 questions, $0.05).

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
| `ANTHROPIC_USE_UNTIL` | Optional cutoff: `YYYY-MM-DD` or a full ISO time with `Z` or an offset, no spaces. Expired or invalid nonempty values disable new Claude calls (an invalid one at once, with no advance banner; see [the new-key section](#2026-10-switching-to-the-new-anthropic-key-api-ops-key)) |

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
