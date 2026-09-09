# BAYLINK 后端安全与可靠性修复

日期：2026-09-08。代码已经在本地实现，未部署、未读取真实 `.env` 值、未连接生产数据库，也未发送短信、邮件或 AI 请求。

## 已实现

- `PATCH /api/users/me` 支持 contactType/contactValue，并按微信、电话、邮箱服务端校验。注册同样校验；公开注册始终创建普通用户。手机号联系方式和短信验证手机号保持独立，修改联系信息不会自动获得手机验证徽章。
- `POST /api/auth/logout` 将当前 JWT 的 SHA-256 hash 写入 Mongo `RevokedSession`，保存其到期时间；唯一 hash 索引避免重复条目，expiresAt TTL 索引用于自动清理。不会存储明文 token。只有写入成功才回复 success；存储故障返回 503，不伪报撤销成功。
- HTTP 必选鉴权、公开接口的可选鉴权及 Socket 握手统一验证签名算法、到期时间、撤销记录、用户状态与改密时间。公开接口不会把已退出的管理员 token 当成有效管理员身份。
- 新登录使用随机 jti，相同账号同一秒的两个登录也得到不同 token。旧 JWT 仍能按既有有效期验证，不需要为这次发布立即轮换 JWT_SECRET。
- 登出立即断开当前进程中该 token 的所有 Socket。消息推送前再次检查会话；Socket 收到事件时检查，空闲连接每 15 秒检查并在 JWT 到期时断开。因此其他进程已经持有的空闲连接最多等待下一次检查，不能再依靠过期/撤销会话接收新推送。
- 已结束帖子不接受新联系方式请求（HTTP 409 / status closed），历史详情仍可读取。保留发布者生命周期确认的权限校验；前端传来的 confirmedAt/authorId 不在可写字段清单。
- 保留并验证公开帖子分类/城市/类型过滤和“我的发布”接口：公开列表排除 closed；自己的发布包含本人 closed/hidden 信息，但不含已删除或其他用户信息。
- API 加入 nosniff、DENY、严格的 JSON API CSP、no-referrer、no-store；生产 HSTS；关闭 Express 版本响应头。CORS 仅允许配置中的精确来源，HTTP 与 Socket 一致；Node/原生客户端的无 Origin 请求仍须经过通常的鉴权。
- 缺少 Twilio 时生产返回 503，不返回 devCode，不保存虚假的已发送状态。开发模拟也必须显式开启 `AUTH_DEV_RETURN_TOKENS=true`，响应明确说明未发送短信。验证码改用 crypto.randomInt；移除验证码及重设密码链接的日志输出。

## 测试隔离

`require('./server')` 只导出 `createApplication` 和 `startProduction`，不会加载 `.env`、监听端口或连接 Mongo。只有执行 `node server.js` 的入口才读取 `.env` 并启动真实服务。

`npm test` 调用实际 Express 路由和本地 Socket.IO，绑定随机 `127.0.0.1` 端口，注入合成账号/帖子和内存存储适配器。测试把 dotenv.config、mongoose.connect 替换成抛错函数，防止误走真实环境；不启动默认 server。NODE_ENV=test 下禁用外部 Cloudinary/短信/邮件/AI 调用。

覆盖：公开分类/城市/类型和分页、服务集合、恶意筛选结构、隐藏/删除详情、本人 closed 列表、生命周期权限和伪造字段、联系信息更新和注册、普通用户管理员入口拒绝、JWT 注销及跨应用实例复核、存储故障关闭权限、精确 CORS、Socket 实时推送/退出断连/撤销重连/过期 token、缺失短信配置和显式模拟开关。

这些测试验证应用层行为，不能替代真实 Mongo TTL 索引创建、Mongo 故障切换、Twilio/Resend 送达及生产代理配置验证。没有声称真实短信发送成功。

## 依赖

本次 `npm audit` 从 14 个包级告警（8 high、6 moderate）降为 0；`npm audit --omit=dev` 同样为 0。19 个隔离测试与 `npm run check` 通过，发布前仍应按锁文件重新验证。

保留 Express 4 与 Mongoose 8 主版本，锁文件升级到 Express 4.22.2、Mongoose 8.24.4、Socket.IO 4.8.3 / parser 4.2.7 / engine.io 6.6.10 / ws 8.21.3。`qs` 用 `^6.16.0` override 修复 Express/Twilio 的传递依赖固定版本；升级后已用真实 Express 请求解析跑集成测试。删除未使用的 browser-image-compression；socket.io-client 移到测试用 devDependencies。没有执行 `audit fix --force`。

## 部署时需要确认

1. 使用 Node 22 或以上（本地验证 Node 24.18），执行 `npm ci`、`npm test`、`npm run check`；生产运行 `npm start`。若生产安装省略 devDependencies，部署验证测试应在完整依赖的 CI 阶段完成。
2. 保留现有 MONGO_URI/JWT_SECRET 和供应商凭据，使用 `.env.example` 的键名补齐配置；不要把示例空值覆盖真实控制台设置。JWT_SECRET 应为高熵随机值，未来若轮换会使现有 JWT 失效。
3. 生产 `NODE_ENV=production`、FRONTEND_URL 为正式 HTTPS 域名。需要预发访问 API 时，CORS_ALLOWED_ORIGINS 列出具体 HTTPS 来源，不使用 `*` 或任意后缀匹配。不要在生产允许本地开发源；本地环境自动允许 localhost/127.0.0.1 的 5173 和 4173。
4. Mongo 用户需要创建 `revokedsessions` 集合及其唯一/TTL 索引的权限。启动会连接 Mongo 并等待该模型 init 后再开放 HTTP；检查部署启动日志与索引创建结果。TTL 清理可能延迟，但 JWT 到期与撤销校验不依赖即时删除。
5. 默认 Socket.IO 内存 adapter 的房间推送限于当前实例。若 Render 多实例运行，需要配置受支持的共享 Socket adapter/粘性会话；持久撤销记录跨实例生效，空闲连接定时复核已实现，但这次没有新增多实例消息路由基础设施。
6. 生产 Twilio 三个键需完整配置，发送号码及 STOP/HELP 行为需供应商侧验证；未配置时 UI 收到可操作的 503。邮件域验证、送达、短信合规、Mongo 备份与恢复、Render/Vercel 实际控制台设置仍需在部署环境检查。
