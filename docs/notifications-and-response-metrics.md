# COMM02 / SEC10 实施边界

本次实现仅新增未来用户主动触发的邮箱验证与通知队列，不向任何真实地址发送测试邮件或短信，不回填历史私信，不为任何既有账号自动开启通知。

## 用户合同

- `GET /api/notifications/preferences` / `PATCH /api/notifications/preferences` 需要当前有效登录。八个显式选项：email/sms × message/contact_request/outing_request/comment，默认均为 false（`comment` 为 2026-10 新增；只认识前三项的旧前端照常工作，保存时不会改动 comment）。开启 email 需验证当前邮箱；开启 sms 需当前手机号已验证。返回 preferences、emailVerified、phoneVerified、deliveryEnabled、emailDeliveryAvailable、smsDeliveryAvailable、locale，以及新增的 `topics`（全部主题）与 `allEnabled`（各渠道是否全开）；不返回地址、token 或队列。
- 一键开启：`PATCH` 体可带 `enableAll: true`（所有**当前已验证**渠道的全部主题）或 `enableAll: 'email' | 'sms'`（仅该渠道，未验证则 409 `NOTIFICATION_VERIFICATION_REQUIRED`）；没有任何已验证渠道时也是 409。只覆盖当前已有主题，以后新增主题仍需用户另行开启。可与 `preferences` 同时提交（先应用 preferences，再全开）。
- `POST /api/notifications/email/start` 只为登录账户自己的邮箱排队；60秒冷却、每用户每日5次持久限制及HTTP用户/IP限制。`POST /api/notifications/email/verify` 消费30分钟单次token，只验证邮箱，不开通知。绑定当前邮箱摘要，邮箱更改会使旧链接失效。
- `POST /api/notifications/unsubscribe` 消费单次限时token，关闭链接对应渠道的全部提醒，取消待发队列；重新主动订阅不会恢复旧任务。GET/预览链接不修改偏好。token使用URL fragment，不进入HTTP URL/Referrer/页面访问指标，确认页去掉地址栏片段。

## 持久性与隐私

- 独立 Mongo `NotificationAccount` / `NotificationToken` / `NotificationJob` / `NotificationWindow` / `NotificationBudget`。认证User不存通知令牌；token索引仅SHA-256摘要，发送所需原文用AES-256-GCM密文保存，密钥源于 `NOTIFICATION_TOKEN_KEY` 或 JWT_SECRET（切换会使旧密文失效）。密文、token永不进入用户DTO或日志。
- 时序（2026-10，N2）：一个会话/帖子（收件人×渠道×scope）的第一封提醒在首个事件后 **5 分钟**到期；到期前同一 scope 的后续事件并入这份待发提醒（`events` 计数、`lastEventAt`），不另排队。发出后，新事件建立下一份提醒，到期时间为 `max(事件时间+5分钟, 上次发送+30分钟)`；持久滚动窗口保证同一 scope 30 分钟内最多一封，被节流的任务改排到窗口重开时刻（不是"现在+30分钟"）。并发竞争偶尔产生的第二份待发提醒同样受窗口约束。
- 仍未读才发：发送前 worker 调用服务器注入的 `stillUnread`——私信=该会话里仍有对方发来、收件人未读的消息；联系请求=该帖仍有发给收件人的待处理/自动发送请求；评论=该帖仍有他人自本提醒首个事件起发表、尚未删除的评论；小队申请无已读状态，照常发送。明确返回 false 时任务记为 `cancelled`、`reason: 'read'`；检查本身失败则 5 分钟后重试，绝不因此发送或把短信标成 unknown。
- 评论提醒（`comment`）：`POST /api/posts/:id/comments` 为帖主和被回复的评论作者（不含评论者本人）排队，scope 为该帖，链接 `/posts/:id`。
- 内容仅固定提示+经白名单站点构造的 `/messages/:id`、`/messages` 联系请求收件箱、`/together?outing=:id`、`/posts/:id` 链接；不包含消息/评论正文、申请备注、联系人、电话号码或其他用户身份。
- worker原子claim；每次发送前重新检查账户可用性、待删除状态、屏蔽关系、当前邮箱/手机号绑定、验证状态、显式订阅及consentRevision。匿名验证/退订只有验证有效token后才取得目标账户的持久删除闸门，并持有至HTTP handler与响应均完成；后台worker独立取得收发双方闸门，持有到本轮数据库写入与供应商等待完成，防止删除后迟写重新建立私有资料。删号事务删除队列（含actor/recipient关联）、token、偏好与节流记录。供应商超时属于未知提交，无法保证取消实际在途请求；已经接受的邮件/SMS也无法撤回。关闭偏好阻止后续提交，不能声称撤回供应商队列。
- 验证token30分钟/退订token30天TTL；通知job最多1天（验证job30分钟）；发送窗口7天，额度摘要3天。系统拒绝恢复超过5分钟的旧事件。Mongo TTL清除异步，业务查询同时检查实际到期，避免依赖TTL时机。
- 邮件重试始终使用同一Resend幂等键与相同正文，最大5次、只在创建后23小时内恢复，覆盖官方24小时幂等窗口。短信仅明确429拒绝可重试；超时、进程失联等不确定提交标 `unknown`，不自动重发。该方案不能宣称第三方严格exactly-once；unknown需要供应商查询核对。
- 持久单文档原子每日全局+账号提交上限，缺省email1000/账号20，sms100/账号5；0停发。额度在第三方调用前预占，不因网络不明退款；重试沿用同一job已占额度。用户身份额度使用每日HMAC摘要，3天TTL。

## 运维开关

- `NOTIFICATION_DELIVERY_ENABLED=true` 才开启worker，缺省关闭。准备完成数据库索引后调用 `notifications.start()`，服务器close停止。测试模式只接受注入mock，不触发真实SDK。开关关闭时UI明确请求仅排队，不能说“已经发送”。
- 邮件需要已有 `RESEND_API_KEY` / `RESEND_FROM_EMAIL` 及供应商核准域名；短信需要已有Twilio凭证/发送号码，号码通道、注册与用户退订处理需供应商实际配置。此轮没有读取或验证真实密钥，没有发送实际邮件/SMS；不能据代码测试声称供应商配置已通过。
- 可配置 `NOTIFICATION_EMAIL_DAILY_LIMIT` / `NOTIFICATION_EMAIL_USER_DAILY_LIMIT` / `NOTIFICATION_SMS_DAILY_LIMIT` / `NOTIFICATION_SMS_USER_DAILY_LIMIT`。均非退款计费保证，而是应用提交限制。
- 供应商幂等依据：[Resend官方24小时说明](https://resend.com/changelog/idempotency-keys)；短信提交/状态依据：[Twilio官方Messages资源](https://www.twilio.com/docs/messaging/api/message-resource)。

## 真实24小时回复指标

`ConversationResponseMetric` 由开聊请求中经 `Post.authorId` 核验的postId关联真实请求者/帖主。开聊本身不计数。持久私信保存后核实其为真实首次请求才原子记录时刻；真实帖主首次答复该请求者，且0–24小时内，才原子计 `owner_reply_24h`，分母 `message_request_started`。两个事件均写首次请求的湾区日期cohort，跨午夜/月底回复不会使回复日分子超出分母。系统消息/自动联系卡不计。开聊关联前已经存在任何消息的旧会话不补算。每日ProductMetric仅day/event/locale/count，私有关联180天TTL并在删号时清除；不记录正文/IP，也不向客户端返回他人身份。

可选统计失败不影响已成功发送的私信。先标记再计聚合可在数据库不确定失败时少计，不会通过重试重复计；因此此指标用于观察真实响应趋势，不是财务精确账本。前端必须在现有帖子发起开聊调用携带真实postId，服务端核验后才建立关联。

新增隔离mock测试覆盖一次token/改邮箱/到期/持久冷却、默认off、双渠道验证、合并与滚动节流、屏蔽/删除/退订后不发、Resend稳定重试、短信unknown、额度上限、实际首次请求与24小时边界。按照根代理串行资源安排，这一提交尚未自行运行Node；由根代理统一验证。
