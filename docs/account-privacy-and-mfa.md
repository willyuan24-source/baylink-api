# Account privacy and optional administrator MFA

Implementation date: October 6, 2026. This document describes source code and mock tests. It does not claim production deployment, successful real-user deletion, configured MFA keys, or actual administrator enrollment. No real email/SMS was sent and no production account was deleted during implementation.

## API and UI

Frontend: `src/features/profile/PrivacySecurity.tsx`, `ProfileView.tsx`, `ProfilePage.tsx`; sign-in challenge: `src/features/auth/MfaLoginChallenge.tsx` and `LoginModal.tsx`. New controls use explicit English and Simplified/Traditional Chinese text. The new CSS is imported through the application stylesheet, rather than through the component module, so Node UI tests can import it.

| Route | Authorization and behavior |
| --- | --- |
| `GET /api/users/me/security` | Authenticated owner; returns enabled/setup-available/recovery-count only. |
| `POST /api/users/me/privacy/export` | Authenticated owner plus fresh current password and MFA factor when enabled; downloads explicitly whitelisted owned records. |
| `DELETE /api/users/me/privacy/account` | Same proof plus a typed confirmation phrase in any site language: `注销我的账号`, `註銷我的帳號` or `DELETE MY ACCOUNT` (whitespace, letter case and the 账/帐/賬/帳, 注/註, 销/銷, 号/號 variants are ignored). Optional `locale` (`zh-Hans`, `zh-Hant`, `en`) picks the language of the refusal and failure messages. Administrator deletion is refused until safe role handover. Claims deletion only when account work is idle, then clears owned data transactionally. A failed transaction answers `500 ACCOUNT_DELETE_FAILED` (nothing changed, still signed in) or, if the account could not be reopened or the outcome is unknown (the driver reported a failure but the User row is gone), `503 ACCOUNT_DELETE_INTERRUPTED`. |
| `POST /api/users/me/security/revoke-sessions` | Fresh proof; increments session revision, revokes existing tokens and disconnects sockets. |
| `POST /api/users/me/password` | Current password plus the MFA factor when enabled (same proof and rate limit); new password with the sign-up strength rule (12+ characters for an administrator account, as in `scripts/set-admin-password.js`); signs every other session out and returns this browser's new session. API-SEC. |
| `POST /api/admin/sessions/revoke` | Admin route (`requireAdmin`, so an authenticator session under `ADMIN_MFA_REQUIRED`); signs every administrator account out everywhere and returns the caller a fresh session. API-SEC. |
| `POST /api/users/me/security/totp/setup` | Administrator plus fresh password; requires a separate configured encryption key; returns pending secret and recovery codes once. Does not enable MFA. |
| `POST /api/users/me/security/totp/confirm` | Fresh password, saved-recovery acknowledgement, valid first six-digit code, unexpired pending setup and atomic proof comparison; activates and rotates session. |
| `POST /api/auth/login/totp` | Password-created, five-minute challenge; code/recovery verification completes sign-in. Challenge tokens have a distinct purpose and cannot authenticate API or sockets. |
| `POST /api/users/me/security/totp/disable` | Fresh password plus current MFA/recovery proof; atomically removes secret and rotates session. |
| `POST /api/users/me/security/totp/recovery-codes` | Same proof; replaces all old recovery hashes and invalidates old challenge revisions. |

Sensitive security responses and exports use `Cache-Control: no-store`. The privacy UI invokes `clearAccountSession` after account deletion or revoke-all, without making an additional logout request with an invalid token. Pending responses are guarded by the originating profile/session; they cannot clear a newer login after unmount.

## Data boundaries

`lib/accountPrivacy.js` exports the owner's profile, published records, authored text messages/comments, private planner records, own group participation and own booking fields. It excludes received private messages, contact cards, another person's contact snapshots and booking notes, security secrets, password hashes, reset tokens and internal moderation evidence. An export over 5,000 records in any query fails explicitly instead of silently truncating the file.

Deletion removes the account and challenges; revokes its tokens through identity deletion and revision checks; clears own messages, contact settings and all linked contact-card/snapshot copies; clears planner, event interest, blocks, translations, notification state and message-response associations; removes own references from shared records. Owned posts are made unavailable and stripped of their private/public authored payload. Hosted groups are cancelled and the departing host's entries removed while retaining other people's authored entries. Safety cases/action timestamps retain anonymized identifiers, with raw evidence and copied personal fields removed. Ordinary post deletion also clears stored contact copies, and private message reads redact cards whose source post/owner is unavailable even if a cleanup retry is pending.

Direct-message reports require both the stored conversation ID and message ID. The server verifies the reporter's participation before reading the selected message, derives the actual sender, and holds both accounts while recording evidence. Existing blocks do not prevent reporting received messages. Only the selected plain text (at most 3,000 characters) and minimal message metadata enter an administrator-only case; contact cards, attachment URLs and reply snapshots are omitted. Client-provided evidence is ignored. Erasing either the author or reporter clears the case's text, conversation reference and copied personal fields; a retained case is not a retained private conversation. Legacy repeated message IDs are resolved and deduplicated within their conversation.

Translation failures use a separate, post-owned cache record without source text or provider error details. Invalid translations retain a 24-hour cooldown; transient provider faults retain 60 seconds. The key changes with source text, translation version or public model identifier, and a successful translation always takes precedence. The application checks expiry even before Mongo's TTL cleanup; account/post cleanup by `postId` covers both success and failure records.

Post translations now carry a post identifier and use a per-post source hash. Account deletion clears the owner's traceable entries. Historical translation entries had only a content hash, so edited older sources cannot be reliably attributed from the current post; deletion also clears all such untraceable legacy derived-cache entries, which can be recomputed, while preserving other people's traceable entries and original posts. New translation requests do not reuse the legacy cache and hold the post/owner deletion gates through generation and storage, including anonymous requests. No production cache migration was run during implementation.

This operation does not destroy Cloudinary files based solely on user-submitted URLs. Historical uploads lack trusted stored ownership/public-ID metadata. Database references are removed, but external files/caches require an ownership-verified manual or later lifecycle process. Recipients' independent copies cannot be withdrawn. Hosting logs and backups have separate retention/cleanup processes; the code does not establish or promise an instant purge or universal fixed retention period. `src/components/PrivacyPolicyView.tsx` now discloses these boundaries and actual configured-service roles: Vercel, Render, MongoDB Atlas, Cloudinary, OpenAI, optional Resend/Twilio delivery, optional Google Routes, and OpenFreeMap.

## Concurrent operations and safe failure

Authenticated request work uses `User.activeAccountOperations` with atomic acquisition across API instances. The HTTP ledger tracks handler promises and response completion separately: disconnect/close cannot release a gate while an awaited write is still executing. The upload body parser participates in the same ledger and awaits its real parser callback. Target accounts are held for DM/contact operations, shared-post owner changes, report targets, group members/host and booking participants. Notification-token routes and provider worker calls also hold their affected accounts. Optional hooks await completion, including moderation-log writes.

Shared posts additionally use `activePostOperations`. Deletion checks all posts containing the departing author's posts/likes/comments/reports for active writes. This protects whole-array saves by another participant; concurrent counter writes conflict with the cleanup transaction and force a retry or a refusal. Outing and booking cleanup also advances their existing revision clocks, preventing stale container snapshots from restoring erased entries.

Deletion first atomically marks the account pending, then runs the cleanup transaction. While the pending flag is set every session and new account operation is refused, and a committed deletion removes the User row, so the claim does not rotate the session revision. Missing transaction support or a failed transaction does not produce a success response or partial committed erasure. On a handled failure the pending state is cleared (retried briefly) and the owner stays signed in with the same session; the response is a localized JSON error. Public profile endpoints omit banned/suspended/deletion-pending accounts. No automatic timeout clears gates while work may still run.

The conversation membership swap is two updates inside the transaction (`$addToSet` the placeholder, then `$pull` the account): MongoDB rejects `$pull` and `$addToSet` on the same path in one update with code 40, which made every deletion fail before October 8, 2026. The shared test mocks (`tests/support/update-conflicts.js`) now reject conflicting operator paths the same way, so this class of bug fails the suite.

### Crash recovery requires real operational checks

Pure counters deliberately fail closed after an unclean API/worker shutdown or failed release write. They have no TTL that could allow a still-running write to escape a gate. Operators must not blindly reset counters on a live deployment.

1. Stop incoming account mutations and notification delivery on **every** API/worker instance; drain or stop those processes. Confirm that no Mongo cleanup transaction or provider operation remains running.
2. Back up only the affected maintenance fields/identifiers, without copying contact values, messages or authentication secrets into logs. Inspect `activeAccountOperations`, affected `activePostOperations`, pending flag and deletion claim.
3. A fully committed deletion removes the User row. If the row still exists after all processes/transactions are drained, the deletion transaction has not committed; clear that account's pending claim and stale counters with a conditional maintenance update. Clear stale affected post counters only after all writers are drained. The claim does not revoke sessions; increment the session revision as well only if the account may be compromised.
4. Read back those fields, restart the deployment and ask the owner to retry the normal credential-confirmed flow. Retain a non-private maintenance audit record. This procedure was documented, **not executed against production users**.

## MFA configuration and recovery

**Administrator sign-in (ENGSEC-03, both opt-in, off by default so the owner is never locked out).** `ADMIN_LOGIN_ID`: a private login name for the administrator account, whose legacy login name is the public word `admin`; once set, `admin` is refused like an unknown name and the owner signs in with the private name and the same password (giving the account a real e-mail address has the same effect). `ADMIN_MFA_REQUIRED=true`: admin routes (`requireAdmin`) and the admin checks inside member routes act only for a session signed in with the authenticator (`mfaVerified`); the administrator can still sign in, use member features and set up the authenticator, so turn it on after enrolling. Since API-SEC (2026-10-12) the same session rule also decides the public post views (admin-hidden posts, report counts and contact values on `/api/posts`, `/api/posts/featured`, `/api/posts/:id`), commenting on hidden posts, editing or deleting other members' comments, reserved nicknames, the self-set official badge and the unlimited daily post count; a password-only administrator session is an ordinary member there. Only the administrator's own `limited`/`suspended` exemption and the admin badge on posts and comments (the account's identity, not a power) still read the stored role. See "Administrator account: the owner's safe order" below.

Set `ACCOUNT_SECURITY_ENCRYPTION_KEY` to a canonical base64 encoding of exactly 32 cryptographically random bytes, stored as a server secret. It is separate from `JWT_SECRET`; no key is generated, installed or enabled for an administrator by this patch. Missing/invalid configuration disables new enrollment and leaves existing password-only administrators usable.

Per-user secrets use AES-256-GCM with user-specific associated data. Codes follow RFC 6238 SHA-1/30-second/six-digit defaults, with one adjacent step allowed on either side and atomic replay prevention. Pending setup expires after ten minutes; login challenges expire after five minutes with five attempts. Recovery codes have 128 bits of random entropy each, are stored as SHA-256 hashes and atomically consumed once. They remain usable if the encryption key is temporarily unavailable, allowing a password-proved administrator to disable MFA safely. Loss of both authenticator/key access and all recovery codes requires an identity-verified administrative recovery process; the API does not bypass MFA automatically.

Password reset increments `sessionRevision`; issued tokens carry the revision from the credential-proved snapshot. Login rechecks that password proof after bcrypt, security mutations compare that proof atomically, and activation/disable mint their new token from the CAS result rather than rereading a later reset revision. A password reset at any point invalidates tokens based on the older proof. Do not replace the encryption key blindly while enrolled users rely on it: first confirm recovery access and use a controlled disable/re-enrollment or separately reviewed migration.

Reference design sources: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html), [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

## Administrator account: the owner's safe order / 管理员账号：店主操作顺序

API-SEC, 2026-10-12. Everything below is opt-in: with no env change the site behaves as before and the owner cannot be locked out.

### 中文

**先知道：** 管理员账号的登录名是公开的单词 `admin`，没有邮箱，所以"忘记密码"邮件到不了它；最早的种子密码还在公开的代码历史里。下面的顺序先换密码、再加验证器、最后把旧登录全部踢掉。每一步做完都可以停，不会把自己锁在外面。

1. **换密码（任选一种）**
   - 已登录时：`POST /api/users/me/password`，正文 `{ "password": "当前密码", "newPassword": "新密码" }`（开了验证器再加 `"totpCode"`）；管理员账号的新密码和脚本一样至少 12 位。网页上的"修改密码"表单还没做（已交给网页端）。
   - 不用登录：在自己电脑的 baylink-backend 目录运行 `node scripts/set-admin-password.js --env=<含 MONGO_URI 的 .env 路径>`（先空跑，看清是哪个账号），再加 `--apply`，按提示输入两次新密码（屏幕不显示；至少 12 位，含大写字母、小写字母和数字）。Render 的 Shell 里也能跑，那里不用 `--env`。
   - 换完以后，这个账号所有已登录的设备都会退出，用新密码重新登录。
2. **设置加密密钥** `ACCOUNT_SECURITY_ENCRYPTION_KEY`（Render → Environment）。必须是**正好 32 个随机字节的 base64**（44 个字符、以 `=` 结尾），用 `openssl rand -base64 32` 或 `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` 生成。格式不对时，验证器设置会显示"尚未配置"，不会报错，也不会锁人。设好以后不要再改。
3. **绑定验证器：** 用管理员登录 → 我的 → 隐私与安全 → 开启验证器 → 用手机验证器 App 扫码 → **把 10 个恢复码抄下来离线保存** → 输入 6 位代码确认。确认的那一刻，这个账号其他所有登录都会失效；之后登录要"密码 + 6 位代码"。
4. **打开开关** `ADMIN_MFA_REQUIRED=true`（Render）。之后只用密码登录的管理员会话不能做任何管理员操作，也看不到被隐藏的帖子和别人的联系方式。
5. **撤销所有管理员登录**（第 3 步已经踢掉这个账号的旧登录；这一步再确认一次，也覆盖其他管理员账号）：
   - 已登录（验证器会话）时：`POST /api/admin/sessions/revoke`，当前页面拿到新的登录，其他设备全部退出；
   - 或者：`node scripts/revoke-admin-sessions.js --env=<.env 路径>`（空跑显示有几个管理员账号），再加 `--apply`。
6. **（可选）** `ADMIN_LOGIN_ID=<一个不公开的长登录名>`：之后 `admin` 不能再登录，改用这个名字加原密码登录。登录限制（密码和验证器两步）都按你输入的这个名字计数，别人对 `admin` 的失败次数不会挡住你。

**登录失败提醒：** 管理员账号当天登录失败到 10 / 50 / 200 / 1000 次（`ADMIN_LOGIN_ALERT_STEPS` 可改）时给店主发一封邮件，每档每天一封；"密码对了但验证器代码错"的次数单独写出来（说明密码可能已经泄露）。管理员账号开启或停用验证器、换恢复码、改密码、撤销所有管理员登录时，也各发一封"刚刚发生了什么、如果不是你本人该怎么办"的邮件。需要 `NOTIFICATION_DELIVERY_ENABLED=true`、Resend 配好、收件人 `SECURITY_ALERT_EMAIL`（单独设它就够；没有就用 `AI_ALERT_EMAIL`，再没有就用 `OWNER_DIGEST_EMAIL`）。

**登录限制（重启不清零）：** 同一访客 15 分钟内失败 10 次、同一访客对同一账号失败 8 次、所有访客对同一账号失败 100 次后，暂停到这 15 分钟结束。计数存在 Mongo 的 `authlimits` 集合，只存加密摘要，不存 IP、邮箱或账号 id，过期自动删除。

**万一出问题：** 验证器丢了 → 用恢复码登录，再在"隐私与安全"停用后重新绑定；恢复码也丢了 → 需要核实身份后人工处理数据库（API 不会自动绕过验证器）。管理员操作被挡（`ADMIN_MFA_REQUIRED`）→ 退出后用验证器重新登录；急用时删掉 `ADMIN_MFA_REQUIRED` 就恢复旧行为。

### English

**Why:** the administrator's login name is the public word `admin`, it has no mailbox (the e-mail reset cannot reach it), and the original seed password is in the public repository history. The order below replaces the password, adds the authenticator, then signs every old session out. It is safe to stop after any step.

1. **Replace the password.** Signed in: `POST /api/users/me/password` with `{ "password", "newPassword" }` (plus `totpCode` or `recoveryCode` once the authenticator is on); an administrator account needs 12+ characters here too, as in the script; the web form is a follow-up. Not signed in: `node scripts/set-admin-password.js --env=<file with MONGO_URI>` (dry run), then `--apply`; the new password is typed twice at a hidden prompt (12-128 characters, upper- and lower-case letters and a digit) and never printed. Either way every session of the account is signed out.
2. **Set `ACCOUNT_SECURITY_ENCRYPTION_KEY`:** exactly 32 random bytes in base64 (44 characters ending in `=`), e.g. `openssl rand -base64 32`. Any other value leaves authenticator setup unavailable (not an error, no lockout). Never change it after enrolling.
3. **Enroll the authenticator** (Me → Privacy & security), save the 10 recovery codes offline, confirm with a code. Confirming signs out every other session of the account; from then on sign-in is password + code.
4. **Set `ADMIN_MFA_REQUIRED=true`.** A password-only administrator session then has no admin power anywhere: admin routes, hidden posts, contact values and report counts on public post views, comment moderation, reserved nicknames, the official badge, the unlimited post count.
5. **Revoke every administrator session:** `POST /api/admin/sessions/revoke` from the authenticator session (the caller gets a fresh session), or `node scripts/revoke-admin-sessions.js --env=<file> --apply`. Both bump `sessionRevision` and `sessionsRevokedAt` on every `role: 'admin'` account; the endpoint also disconnects their sockets and logs `admin_sessions_revoked`.
6. **Optional:** `ADMIN_LOGIN_ID=<a long private login name>`; `admin` then stops working. Both sign-in steps (password and authenticator) count failures against the name typed, so failures on the retired `admin` never hold the owner.

**Sign-in limits** (`lib/loginGuard.js`, survive restarts): failed sign-ins per 15-minute window, 10 per visitor, 8 per visitor on one account, 100 per account across visitors. HMAC-keyed TTL documents in the `authlimits` collection; no IP, login name or account id is stored. An unreadable store fails open (the in-memory limiter still applies). A wrong authenticator code after a correct password counts too.

**Owner alert:** administrator sign-in failures per Pacific day at 10 / 50 / 200 / 1000 (`ADMIN_LOGIN_ALERT_STEPS`) send one e-mail per step per day, with the authenticator-failure count and these steps, and no address or IP. A change on an administrator account (authenticator enabled or disabled, recovery codes replaced, password changed, all admin sessions revoked) sends one notice each, so a change made by someone else is noticed. Gates: `NOTIFICATION_DELIVERY_ENABLED=true`, Resend configured, an owner address (`SECURITY_ALERT_EMAIL` on its own is enough, else `AI_ALERT_EMAIL`, else `OWNER_DIGEST_EMAIL`); never under `NODE_ENV=test`.

## Phone verification SMS and reset links (API-SEC, 2026-10-12)

- **US numbers only** (`lib/usPhone.js`): Canada, the non-US Caribbean, Bermuda and non-geographic codes (toll-free, premium, 5XX personal, 456, 710) are refused with `400 PHONE_NOT_US` before any SMS budget is spent. A number that is not a valid NANP number at all (mistyped, N11 exchange, reserved X9X / 37X / 96X code) gets `400 PHONE_INVALID` ("enter a valid US number") instead. US territories (787/939, 340, 671, 670, 684) are accepted. It is a refusal list, so a new US overlay code keeps working; keep Twilio geo permissions on United States only as the provider-side backstop.
- **Verified e-mail first:** `409 EMAIL_VERIFICATION_REQUIRED` until the account's current e-mail is verified (Me → notification settings → verify e-mail). `SMS_REQUIRE_VERIFIED_EMAIL` = `true` / `false`; unset = on exactly when notification e-mail delivery is on (`NOTIFICATION_DELIVERY_ENABLED=true` with Resend), so nobody is asked for a step the site cannot complete.
- **New-account share:** accounts younger than 24 hours draw on at most `SMS_NEW_ACCOUNT_DAILY_LIMIT` (default 40% of `SMS_VERIFY_DAILY_LIMIT`) of the day's pool (`503 SMS_NEW_ACCOUNT_CAPACITY`); the rest is kept for older accounts. Accounts without a creation time count as old.
- **Claim before send (CODE-API-04):** the durable per-number, per-account, new-account and site-wide ceilings are claimed before the send branch, for every delivery path; with no delivery path the request is refused without spending budget.
- **Reset links:** `forgot-password` puts the token in the fragment (`/reset-password#token=…`) when the request carries `resetLinkStyle: "fragment"` (the page that reads `location.hash` sends it) or `PASSWORD_RESET_LINK_STYLE=fragment` is set; otherwise the `?token=` form older pages read. `reset-password` takes the token from the JSON body either way. Tokens last 30 minutes.

## Error responses and process lifecycle

- `lib/serverErrors.js`: every error reaching Express becomes a JSON body (numeric driver codes such as Mongo `40` are never passed to string methods; that TypeError used to fall through to Express's HTML 500). Every 5xx response, including routes that answer 5xx themselves, writes exactly one JSON line to stderr: `{level, event:'http_5xx', method, route (pattern, e.g. /api/users/:id), status, error (name), code, cause{name,code}, release, ms}`. Bodies, URLs, IPs, user ids and error messages are never logged.
- `lib/processLifecycle.js` (installed by `startProduction` only): an unhandled promise rejection is logged as `event:'unhandled_rejection'` and the process keeps serving. `SIGTERM`/`SIGINT` stop the notification and source-monitor workers, close Socket.IO and the HTTP server (in-flight requests get 20 s before open connections are cut), disconnect Mongo and exit 0; a hard deadline at 25 s exits 1.
- `lib/notifications.js`: an invalid `NOTIFICATION_FRONTEND_URL` no longer stops the API from booting. Links fall back to `https://www.baylink.us` and one `notification_origin_invalid` warning is logged (without the value).

## Validation boundary

Added mock-only suites:

- `tests/account-security.test.js`: reference vectors, encryption isolation, missing config, setup confirmation/expiry, role protection, replay, recovery, challenge limit/revision.
- `tests/account-privacy.test.js`: export privacy, real-schema scrubbing, snapshot/contact removal, transaction rollback without sign-out, localized confirmation phrases, the DM-thread member swap, conflicting-operator rejection in the mock, admin handover, disconnected-handler and shared-post races.
- `tests/server-errors.test.js`: real HTTP JSON 500s and one structured log line per 5xx, the two explicitly wrapped async routes, deletion end to end (200, login 401, post gone, the other member keeps the thread) and a failed deletion that keeps the session.
- `tests/process-lifecycle.test.js`: rejection logging without exit (with a real child-process control that crashes without the handler), SIGTERM draining an in-flight request, forced exit on a stuck shutdown.
- `tests/account-security-api.test.js`: real HTTP route integration with injected storage, challenge bearer rejection, public profile hiding, old contact reads after post removal, same-millisecond session revocation.
- `tests/account-report-privacy.test.js`: the actual `:reportId` review route holds reporter and target through delayed writes; deletion-first acquisition rejects the late review and cannot restore scrubbed evidence.
- `tests/direct-message-reports.test.js`: real HTTP participant authorization, server-derived evidence, blocked-thread reporting, legacy repeated IDs, administrator-only reads, deletion cleanup and both race outcomes.
- Frontend `tests/account-privacy-ui.test.tsx`: deletion confirmation, local cleanup without logout, English copy, stale session response guard, MFA staging and code-only requests.

The final local API suite for these changes passed 1125/1125, including the direct-message report, translation cooldown and actual public-service catalog regressions; syntax checks and `npm audit` passed with zero vulnerabilities. Exact-commit CI, frontend validation and deployed revisions are recorded separately in `C:/Users/willy/opus-qa/site-audit-1005/implementation`. No local test result proves a production deployment or real provider delivery.
