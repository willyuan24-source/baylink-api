# G5 上线核对清单（店主操作）

> 适用：通知与安全改动（API-NOTIFY-SEC）合并并部署之后。预计 75 分钟，需要两个**真实的测试账号**（A、B，用你自己能收信的邮箱和手机），AI 花费 < $1。
> 所有 Render / Resend / Twilio 设置都由店主本人操作；Claude 不改 Render 环境变量、不登录生产、不向真实地址发邮件或短信。

## 0. 合并后、开投递前就已经生效的变化（无需操作）

- 忘记密码：每个账号 5 分钟内最多 1 封重设邮件，每个湾区日最多 5 封；重启/部署不会清零（记在账号记录上）。被限流时页面提示和"邮箱不存在"完全一样。
- 手机验证：同一号码每天最多 5 条验证码、每个账号每天 5 条、全站每天 `SMS_VERIFY_DAILY_LIMIT` 条（默认 100），全部持久计数；一个号码已在**另外 2 个**账号验证过时，第 3 个账号会被拒绝（409，提示联系我们）。已经存在的多账号共用号码不受影响。
- 登录：同一账号在**同一访客 IP** 15 分钟内最多 8 次；同一账号所有访客合计 15 分钟 100 次。陌生人狂试 `admin` 只会锁住他自己，不会再把你锁在外面。
- 通知队列：私信等提醒改为约 5 分钟后发、且只在仍未读时发；同一对话 30 分钟内合并成 1 封。新增评论通知（`comment`）和"一键开启全部提醒"——API 已支持，网页上的开关和按钮要等网页端（WEB-ACCOUNT）接入。投递开关不打开就**只排队、不发送**。

## 1. Render 环境变量（店主在 Render 控制台设置，"Save and deploy"）

| 变量 | 设置 | 说明 |
|---|---|---|
| `NOTIFICATION_DELIVERY_ENABLED` | `true` | 总开关。不设或不是 `true` = 一封都不发（回滚就改回去） |
| `RESEND_API_KEY` | 已有则保留 | 发件服务密钥 |
| `RESEND_FROM_EMAIL` | 例如 `BAYLINK <noreply@baylink.us>` | 必须是 Resend 已验证（SPF/DKIM 通过）的域名 |
| `NOTIFICATION_EMAIL_DEFAULTS` | **不设**（只用于紧急关闭） | H14：已验证邮箱默认开启「新的私信」「新的联系请求」邮件提醒。是否开启由**代码**决定：API-NOTIFY-2 合并时关闭；网页端新文案（WEB-COMMUNITY-2）上线后，captain 用一行 API PR 打开（见第 5 节），**店主不用在 Render 加变量**。设 `off` = 立即关闭默认开启（回滚）；设 `on` = 在代码打开前提前开启（只用于提前实测，同样要等网页文案上线） |
| `NOTIFICATION_API_URL` | **不设** | 邮件里一键退订（List-Unsubscribe）指向的 API 地址，缺省 `https://baylink-api.onrender.com`；只接受这个地址或 `https://api.baylink.us`，其它值被忽略（日志一行 `notification_origin_invalid`） |
| `NOTIFICATION_FRONTEND_URL` | **不设**，或恰好 `https://www.baylink.us` | 其它值会被忽略并回落到 www.baylink.us（日志一行 `notification_origin_invalid`），不会再让 API 起不来 |
| `FRONTEND_URL` | 不设，或 `https://www.baylink.us` | 重设密码邮件里的链接域名 |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_PHONE_NUMBER` | 已有则保留 | 验证码短信 |
| `TWILIO_MESSAGING_SERVICE_SID` | 需要预约短信时设置 | 预约（bookings）短信用 |
| `SMS_VERIFY_DAILY_LIMIT` | 可不设（默认 100） | 全站每天验证码条数上限；`0` = 暂停所有验证码短信 |
| `NOTIFICATION_EMAIL_DAILY_LIMIT` / `NOTIFICATION_EMAIL_USER_DAILY_LIMIT` | 可不设（默认 1000 / 20） | 通知邮件全站 / 每人每天上限 |
| `NOTIFICATION_SMS_DAILY_LIMIT` / `NOTIFICATION_SMS_USER_DAILY_LIMIT` | 可不设（默认 100 / 5） | 通知短信全站 / 每人每天上限；`0` = 停发 |
| `ACCOUNT_SECURITY_ENCRYPTION_KEY` | 开管理员两步验证前必须设置 | **正好 32 个随机字节的 base64**（44 个字符、以 `=` 结尾），用 `openssl rand -base64 32` 生成；其他格式会让验证器设置显示"尚未配置"。设了之后不要再改（改了已绑定的验证器会失效） |

部署完成后打开 `https://<api 域名>/api/health`，确认 200。

> 首次打开投递后：投递关闭期间也会排队，所以过去 24 小时内已排队、仍未读的提醒会在打开后的头几分钟集中发出（每 30 秒最多 10 条；已读/已处理的自动取消，超过 1 天的不会发），属正常现象，不是乱发。

## 2. 实测（两个真实账号 A、B）

1. **邮箱验证**：A 注册 → 我的 → "发送验证邮件" → 约 1 分钟内收到 → 点链接显示已验证。
2. **私信提醒（新时序）**：A 开启"邮件 · 新的私信" → B 给 A 连发 2–3 条私信，A **不要**打开对话 → 约 **5 分钟**后 A 收到 **1 封**邮件（不是 3 封）→ 链接打开 `/messages/…` → 邮件里的「关闭这类邮件」链接（打开后在确认页点确认）只关「新的私信」这一类（API-NOTIFY-2 起；之前是关整个邮件渠道），详见第 5 节。
   > **投递开关的时机**：API-NOTIFY-2 合并后、WEB-COMMUNITY-2 的退订确认页新文案上线前，**先不要打开** `NOTIFICATION_DELIVERY_ENABLED`：那段时间确认页仍写「此通知渠道已退订」，但新邮件里的链接其实只关了这一类。如果投递已经打开，就知道这句话暂时不准（只关了链接对应的那一类，其它提醒照常），等网页端改好。
3. **已读不发**：B 再发 1 条，A 在 5 分钟内在网站里打开这段对话 → 之后**不应**再收到这条的邮件。
4. **30 分钟合并**：收到第 2 步的邮件后，B 在 30 分钟内再发几条，A 不读 → 距上一封约 30 分钟时只再收到 1 封。
5. **评论提醒**（网页端加上"新的评论"开关或"开启全部提醒"按钮之后再测，之前跳过）：A 开启"新的评论" → B 在 A 的帖子下评论 → 约 5 分钟后 A 收到"新的评论"邮件，链接打开 `/posts/…`。
6. **忘记密码**：用 A 的邮箱申请重设 → 邮件到达、链接可重设。5 分钟内再申请一次**不会**再来第二封（正常现象）。
7. **手机验证**：A 先完成第 1 步的邮箱验证（投递打开后，没验证邮箱的账号会被提示"请先验证邮箱"）→ 绑定手机 → 收到验证码并验证成功。只接受美国号码（加拿大和加勒比的 +1 号码会被拒绝）。Twilio 控制台核对：A2P 10DLC 或免费号码（toll-free）认证状态、地理权限只开美国、设置花费提醒（spend alert）。
8. **图片**：iPhone Safari 发帖，带一张 > 5 MB 的 HEIC 照片 → 图片正常显示（Cloudinary）。
9. **5 个 AI 检查**（记录成功与否、耗时、返回里的 `model`）：BayBay 问一个需要上网查的问题；发帖助手普通一次 + 带"报税"一次；帖子翻译；小队草稿写"刚移民"；/plan 里"帮我挑选方案"。
10. **管理员账号**：按 `docs/account-privacy-and-mfa.md` 的"管理员账号：店主操作顺序"做——先换密码（`scripts/set-admin-password.js`），再设 `ACCOUNT_SECURITY_ENCRYPTION_KEY`、绑定验证器、设 `ADMIN_MFA_REQUIRED=true`，最后撤销所有管理员登录（`scripts/revoke-admin-sessions.js --apply`）。

## 3. 出问题怎么办

- 邮件/短信乱发或发太多：Render 把 `NOTIFICATION_DELIVERY_ENABLED` 改回空或 `false` → Save and deploy。队列保留，不会补发超过 1 天的旧任务。
- 验证码短信费用异常：设 `SMS_VERIFY_DAILY_LIMIT=0`（立即停发验证码），再查 Twilio 日志。
- 正常用户被"手机号已在其他账号验证过"挡住：说明这个号码已有 2 个已验证账号；由管理员核实后处理（目前没有后台按钮，需要告诉 Claude 开一个小任务）。
- 收不到邮件：先看 Resend 控制台的投递记录（退信、垃圾箱、域名验证），再看 Render 日志；代码里不记录邮箱地址和正文。
- 默认开启引起投诉：Render 设 `NOTIFICATION_EMAIL_DEFAULTS=off` → Save and deploy（不用等代码 PR；注意是设成 `off`，不是删掉——删掉就回到代码默认值）。之后新验证的邮箱不再默认开启；**已经开启的账号保持现状**（他们可以用邮件里的「关闭这类邮件」或「我的 › 通知」关掉）。要立刻停发所有邮件，同时把 `NOTIFICATION_DELIVERY_ENABLED` 改回空。

## 4. 核对记录（店主填写）

| 步骤 | 结果 | 时间 | 备注 |
|---|---|---|---|
| 1 环境变量 + /api/health | | | |
| 2 私信 5 分钟 1 封 | | | |
| 3 已读不发 | | | |
| 4 30 分钟合并 | | | |
| 5 评论提醒 | | | |
| 6 忘记密码 | | | |
| 7 手机验证 + Twilio 设置 | | | |
| 8 HEIC 图片 | | | |
| 9 五个 AI 检查 | | | |
| 10 管理员 TOTP | | | |
| H14-1 新账号验证后默认开启 | | | |
| H14-2 私信邮件（原因行 + 关闭这类邮件） | | | |
| H14-3 联系请求邮件 | | | |
| H14-4 关闭链接只关一类 | | | |
| H14-5 DKIM 通过 + 邮件头 + 邮箱 App 的退订按钮 | | | |
| H14-6 重新打开后照常提醒 | | | |
| H14-7 老账号：没改过的迁移、改过的不动 | | | |
| H14-8 Render 日志 `notification_defaults_*` | | | |

## 5. H14：默认邮件提醒 + 一键退订，双账号实测（API-NOTIFY-2 之后，约 40 分钟）

> 店主操作。Claude 不登录生产、不发私信、不改 Render。两个**真实**测试账号：A（收件人，用一个**从没打开过通知设置**的新账号）和 B（发信人）。

**前提（缺一不做）**

1. 网页端新文案已上线（WEB-COMMUNITY-2）：「我的 › 通知」写明"验证邮箱后，新的私信和新的联系请求默认用邮件提醒你"；验证邮件的确认页不再写"验证不会自动开启通知"；退订确认页写明关掉的是哪一类；隐私政策里"通知默认关闭"已改。**网页没改之前不要打开默认开启**，否则页面说的和实际不一致。
2. 默认开启已生效：网页上线后，captain 合并一行 API PR（`lib/notifications.js` 的 `EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT` 改为 `true`）→ `https://baylink-api.onrender.com/api/health` 的 `commit` 是那个 PR 的合并 SHA；「我的 › 通知」显示"默认开启"的说明（接口字段 `defaultsActive: true`）。**店主不需要在 Render 新增变量。**
3. Render：`NOTIFICATION_DELIVERY_ENABLED=true`、`RESEND_API_KEY`、`RESEND_FROM_EMAIL` 已设（第 1 节）；`NOTIFICATION_EMAIL_DEFAULTS` **不设**（它只用于紧急关闭）。想在 captain 的 PR 之前提前测，可以临时设 `NOTIFICATION_EMAIL_DEFAULTS=on`（同样要等第 1 条满足）。

**步骤与预期**

1. **新账号默认开启**：A 注册 → 「我的 › 通知」：邮箱未验证，开关全关，页面说明验证后会默认开启 → 点"发送验证邮件" → 约 1 分钟收到**邮件①**「验证你的 BAYLINK 邮箱」→ 点链接确认 → 回「我的 › 通知」：邮件 · 新的私信 ✓、邮件 · 新的联系请求 ✓；新的小队申请、评论 ✗；短信全部 ✗。
2. **私信邮件**：B 给 A 发 2 条私信，A 不打开 → 约 5 分钟后 A 收到 **1 封邮件②**，标题「BAYLINK 站内通知：新的私信」，正文 4 行："你在 BAYLINK 收到新的私信，请登录查看：…/messages/…"；"你收到这封邮件，是因为验证邮箱后，你的账号默认开启了「新的私信」邮件提醒。"；"关闭这类邮件：…/notifications/unsubscribe#token=…&kind=message"；"管理全部提醒：…/me?view=notifications"。邮件里**没有**私信内容和 B 的名字。
3. **联系请求邮件**：B 打开 A 的一条帖子 → 点「请求联系方式」→ 约 5 分钟后 A 收到**邮件③**「BAYLINK 站内通知：新的联系请求」，链接打开 `/messages`。
4. **关闭链接只关一类**：A 在邮件②里点「关闭这类邮件」→ 确认页点确认 → 显示已关闭 → 「我的 › 通知」：新的私信 ✗，新的联系请求仍 ✓。B 再发一条私信 → 10 分钟内 A **不应**再收到私信邮件。
5. **邮件头和邮箱 App 的退订按钮**：在 Gmail 打开邮件③ → 先点"⋮ › 显示原始邮件"：确认发件域名 `DKIM: 'PASS'`，并有 `List-Unsubscribe: <https://baylink-api.onrender.com/api/notifications/unsubscribe/one-click/…>` 和 `List-Unsubscribe-Post: List-Unsubscribe=One-Click` 两行。回到邮件，发件人旁边如有"退订 / Unsubscribe"，点它 → 「我的 › 通知」里新的联系请求变 ✗（这个按钮一点即关，不经过确认页）。Gmail 只在 DKIM 通过时、而且通常只对有一定发件量的发件人显示这个按钮：DKIM 通过但按钮不显示，记下即可，**不算故障**；DKIM 不通过，去 Resend 控制台查域名验证。只认旧标准（RFC 2369）的邮箱 App（例如部分 Outlook / Thunderbird 版本）会用浏览器打开这个地址：它跳到网站的退订确认页，点确认才关闭。Apple 邮件等其它 App 没有实测过，用到的话顺手记下它的表现。
6. **重新打开照常提醒**：A 在「我的 › 通知」把新的私信打开并保存 → B 再发私信 → A 在 **5–30 分钟**内收到邮件（同一对话 30 分钟内最多一封：距邮件②不到 30 分钟时，会等到满 30 分钟才发）。原因行这时是"你的账号开启了「新的私信」邮件提醒"（A 已经做过选择）。之后默认值**不会**再改动 A 的设置。
7. **老账号**（如果有）：以前验证过邮箱、从没改过通知设置的账号，打开「我的 › 通知」→ 新的私信、新的联系请求已开启；以前保存过设置的账号 → 保持原样。打开开关**不会补发**以前的私信提醒。
8. **日志**：Render Logs 搜 `notification_defaults_applied`（每个被默认开启的账号一行，`reason` 为 `verify` / `read` / `event`）和 `notification_defaults_kept`（做过选择、保持不变的账号；`reason` 为 `choice` 表示账号的第一个动作就是自己保存设置）。这些日志里没有账号 id 和邮箱。

**A 的邮箱里应该收到**：① 验证邮件 1 封；② 新的私信 1 封；③ 新的联系请求 1 封；第 6 步再 1 封新的私信（5–30 分钟内）。第 4 步之后、第 6 步之前**没有**私信邮件。

**怎么退订（对用户的说法）**：每封提醒最后都有「关闭这类邮件」链接，打开后点确认，只关这一类；Gmail 等支持一键退订的邮箱 App 里的「退订」按钮也只关这一类；全部设置在「我的 › 通知」。

---

## 5 (English). H14 two-account production test: default email reminders and one-click unsubscribe (after API-NOTIFY-2, about 40 minutes)

> The owner runs this. Claude does not sign in on production, send messages or change Render. Two **real** test accounts: A (recipient: a new account that has **never opened** notification settings) and B (sender).

**Before you start (all three)**

1. The new web copy is live (WEB-COMMUNITY-2): Me › Notifications says that new private messages and new contact requests are emailed by default once the email is verified; the email-verification page no longer says verification never turns reminders on; the unsubscribe confirmation names the kind it turned off; the privacy policy no longer says notifications default to off. **Do not switch the defaults on before the web copy is live.**
2. The defaults are active: after the web copy is live, the captain merges a one-line API PR (`EMAIL_DEFAULTS_ACTIVE_BY_DEFAULT` in `lib/notifications.js` becomes `true`) → `commit` at `https://baylink-api.onrender.com/api/health` is that PR's merge SHA, and Me › Notifications shows the default-on copy (API field `defaultsActive: true`). **No new Render variable is needed.**
3. Render: `NOTIFICATION_DELIVERY_ENABLED=true`, `RESEND_API_KEY` and `RESEND_FROM_EMAIL` are set (section 1); leave `NOTIFICATION_EMAIL_DEFAULTS` **unset** (it is the kill switch only). To test before the captain's PR, you can set `NOTIFICATION_EMAIL_DEFAULTS=on` temporarily (still only after item 1).

**Steps and expected results**

1. **A new account gets the defaults**: A signs up → Me › Notifications: email not verified, all switches off, the page explains the default → "Request verification email" → **email 1** "Verify your BAYLINK email" within about a minute → confirm the link → Me › Notifications: Email · New private messages on, Email · New contact requests on; team applications and comments off; all SMS off.
2. **Message email**: B sends A two messages; A does not open them → about 5 minutes later A gets **one email 2**, subject "BAYLINK 站内通知：新的私信" ("BAYLINK notification: New private messages" for an English account), four lines: "You have new private messages on BAYLINK. Sign in to view: …/messages/…" (in Chinese for a Chinese account); why it was sent (the "New private messages" email reminder was turned on by default when the email was verified); "Turn off these emails: …/notifications/unsubscribe#token=…&kind=message"; the settings link `…/me?view=notifications`. No message text and no sender name.
3. **Contact-request email**: B opens one of A's posts → "Ask for contact details" → about 5 minutes later **email 3** "BAYLINK 站内通知：新的联系请求" ("… New contact requests"), linking to `/messages`.
4. **The link turns off one kind**: A clicks "Turn off these emails" (关闭这类邮件) in email 2 → confirms on the page → Me › Notifications: new private messages off, new contact requests still on. B sends another message → A gets **no** message email within 10 minutes.
5. **Headers and the mail app's unsubscribe button**: open email 3 in Gmail → "⋮ › Show original" first: check `DKIM: 'PASS'` for the sending domain and the two headers `List-Unsubscribe: <https://baylink-api.onrender.com/api/notifications/unsubscribe/one-click/…>` and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`. Back in the email, if "Unsubscribe" shows next to the sender, click it → new contact requests turn off (this button is one click, no confirmation page). Gmail shows the button only when DKIM passes, and usually only for senders with some volume: DKIM passing without a button is noted, **not a bug**; a failing DKIM is checked in the Resend dashboard (domain verification). Mail apps that only know the older RFC 2369 (some Outlook and Thunderbird versions) open the address in a browser: it goes to the site's unsubscribe confirmation page, and nothing changes until the member confirms. Apple Mail and other apps are untested; note what they do if you use them.
6. **Turning it back on works**: A turns new private messages on and saves → B sends another message → the email arrives within **5–30 minutes** (one email per conversation per 30 minutes: less than 30 minutes after email 2 it waits until the 30 minutes are up). The reason line now says the reminder is on for the account (A has made a choice). The defaults never change A's settings again.
7. **Existing accounts** (if you have one): an account that verified its email earlier and never changed its settings now shows both defaults on; an account that saved settings before keeps them. Switching on does **not** send old reminders.
8. **Logs**: search Render Logs for `notification_defaults_applied` (one line per account that got the defaults, `reason` `verify` / `read` / `event`) and `notification_defaults_kept` (accounts that had chosen; `reason` `choice` means the account's first action was saving its own settings). These lines carry no account ids or addresses.

**Expected emails in A's inbox**: 1 verification; 1 new private messages; 1 new contact requests; 1 more new private messages in step 6 (within 5–30 minutes). No message email between steps 4 and 6.

**How to unsubscribe (what to tell members)**: every reminder ends with a "Turn off these emails" link; open it and confirm, and that kind only is turned off. The Unsubscribe button in Gmail and other mail apps that support one-click unsubscribe also turns off that kind only. Every setting is under Me › Notifications.

**Rollback**: set `NOTIFICATION_EMAIL_DEFAULTS=off` in Render → Save and deploy (no code PR needed; set it to `off`, do not delete it, since unset means the code default) → newly verified emails are no longer defaulted; accounts already defaulted keep their stored settings. To stop all email at once, also clear `NOTIFICATION_DELIVERY_ENABLED`.
