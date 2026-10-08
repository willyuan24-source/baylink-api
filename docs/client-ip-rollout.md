# 按真实访客计数：上线与回退手册

对应审计 REG-01、BBLIVE-01（门槛 G3）。合并本 PR 不改变生产行为：两个新环境变量都为空时，中间件直接放行，不读取也不修改请求。只有店主在 Render 设置环境变量后才生效。

## 问题

生产请求路径是“访客 → Cloudflare → Render → Express”。默认 `TRUST_PROXY_HOPS=1` 时，`req.ip` 是 X-Forwarded-For 最右一项，也就是连到 Render 的那一跳。这一跳是不断轮换的 Cloudflare 出口地址，不是访客。所以同一访客的额度会在几个桶之间跳（9/1/4），而走同一出口的陌生人又共用同一个桶。注册、登录、找回密码、guide-chat 每分钟 8 次、额度读取、网页查询和访客每日 AI 额度都以 `req.ip` 为键，因此都受影响。Mongo 里的额度存储本身没有问题，错的只是计数键。

## 新变量

| 变量 | 取值与行为 |
| --- | --- |
| `CLIENT_IP_SOURCE` | 空（默认）：保持现状。`cloudflare`：如果 Express 按 `TRUST_PROXY_HOPS` 算出的可信一跳属于 Cloudflare 公布网段，就用 `CF-Connecting-IP`（必须恰好是一个有效 IP）；该头缺失或无效时，取紧邻这一跳左侧、由 Cloudflare 追加的 XFF 条目；仍不成立时用这一跳本身。可信一跳不是 Cloudflare 地址时，一律保持现状（失败即关闭）。IPv4 原样计数，IPv6 按 /64 计数，`::ffff:` 映射地址按 IPv4 计数，Cloudflare 伪 IPv4（240.0.0.0/4）也接受。其他值会让服务启动失败。 |
| `CLOUDFLARE_IP_CIDRS` | 可选。逗号分隔的 CIDR，会整体替换内置列表（2026-10-08 取自 https://www.cloudflare.com/ips-v4 和 /ips-v6）。列表过期时只会退回现状，不会放开。无效条目会让服务启动失败。 |
| `CLIENT_IP_DIAGNOSTIC_UNTIL` | 可选。ISO UTC 结束时间，例如 `2026-10-08T18:00:00Z`。只有当它在未来、并且不晚于本次进程启动后 2 小时才生效，否则忽略，日志会写明原因。生效期间有两项诊断。①`GET /api/health` 和 `GET /api/ai/usage` 输出 `[client-ip-diag]` 日志行：带 `?probe=<8–24 位小写字母或数字>` 的请求一律记录，其他请求每 20 个抽 1 个，抽样每小时最多 60 行，总计每小时最多 600 行。②`GET /api/_diag/client-ip` 返回调用者本次请求的分类信息和计数键指纹，每个键每分钟 30 次、全站每分钟 300 次。窗口外该地址就是普通 404。 |

诊断内容只有：地址类别（loopback/private/cgnat/link-local/pseudo-ipv4/cloudflare/public/invalid）、IPv4 /24 或 IPv6 /48 前缀、XFF 长度、从右到左的各项类别、`req.ip` 取自哪一项、`cf-connecting-ip`/`true-client-ip`/`x-real-ip` 等头是否存在、`cf-connecting-ip` 是否等于 XFF[-2]、CF-Ray 机房代码，以及 cloudflare 模式下键的来源。不包含完整 IP，也不写数据库。指纹是 `HMAC(JWT_SECRET, 键)` 的前 12 位十六进制，只能用来比较“两次是不是同一个键”。

已有变量提醒：`TRUSTED_PROXY_CIDRS` 一旦非空，就会整体替代 `TRUST_PROXY_HOPS`。如果漏掉 Render 自己那一跳，所有访客会被并成一个键，导致全站 429 和额度耗尽。没有诊断结论时不要设置它。

## 每次改环境变量都要知道

- 在 Render 保存环境变量后，要选会重新部署的选项（界面一般是 “Save and deploy”）。只保存不部署，新值不会生效。部署时进程会重启，可能出现短暂中断。
- 重启会清空所有内存限速计数（登录、注册、guide-chat 每分钟、额度读取、埋点等）。Mongo 里的每日 AI 额度不受影响。
- 切换 `CLIENT_IP_SOURCE` 会改变所有访客的额度身份，当天访客额度相当于重置一次。这会顺便清掉被审计脚本污染的桶。
- `GET https://baylink-api.onrender.com/api/health` 的 `commit` 用来确认当前部署版本。
- 金丝雀运行期间不要跑审计或压测脚本（REG+4）。它们会占用共享桶和全站 BayBay 每日 200 次上限。

## 上线步骤

1. **合并并确认部署**：店主合并 PR，等 Render 部署完成，确认 `/api/health` 的 `commit` 是合并后的 SHA。此时两个新变量都为空，行为与现在完全一致。
2. **打开诊断窗口（约 1 小时）**：店主设置 `CLIENT_IP_DIAGNOSTIC_UNTIL` 为“当前 UTC 时间 + 1 小时”。例如太平洋夏令时 10:00 等于 17:00 UTC，就填 `2026-10-08T18:00:00Z`。然后保存并部署。
3. **工程师免费探测**（不消耗 AI 额度）：
   - 在 IPv4 网络运行 `node scripts/canary-ai-usage.mjs --base https://baylink-api.onrender.com/api --family 4`。
   - 在手机热点（蜂窝网络，常是 IPv6）上用 `--family 6` 再运行一次。这一步是必需的：IPv4 的结论不能代表 IPv6 和蜂窝访客。
   - 也可以直接请求 `curl -4 https://baylink-api.onrender.com/api/_diag/client-ip`，再用 `https://api.ipify.org` 对比自己的 /24。
   - 如果店主能看 Render Logs，可以按 `[client-ip-diag]` 和脚本打印的 probe 值筛选，贴约 30 行给工程师。日志里只有类别和 /24、/48 前缀。
4. **对照决策表**（见下文）决定下一步。
5. **切换**：店主设置 `CLIENT_IP_SOURCE=cloudflare`；只有决策表要求时，才同时设置 `TRUST_PROXY_HOPS=2`。保存并部署。如果切换后还想用诊断，就在同一次保存中把 `CLIENT_IP_DIAGNOSTIC_UNTIL` 改成新的“当前时间 + 1 小时”，因为窗口按每次进程启动计算。
6. **金丝雀（含 1–2 次付费提问，约 $0.23–0.46，需店主事先同意）**：运行 `node scripts/canary-ai-usage.mjs --base https://baylink-api.onrender.com/api --family 4 --consume 2 --i-approve-spend`，期望全部 PASS：
   - `diag-current-key` 只有 1 个键；
   - 读取的 remaining 不变，伪造头读取的 remaining 也不变；
   - `consume-exact-drop` 显示每次真正调用模型的提问让 remaining 恰好减 1。
   然后在第二个网络（手机热点）上做只读运行，它的 remaining 应该是自己的值，不受第一个网络的提问影响。如果全站 BayBay 上限已用完，提问到不了模型，结果会是 INCONCLUSIVE，不是 PASS。
7. **关闭诊断**：删除 `CLIENT_IP_DIAGNOSTIC_UNTIL` 并保存部署（到期后也会自动失效）。确认 `/api/_diag/client-ip` 返回 404。
8. **观察 1 小时**：网站上 BayBay 的剩余次数应该每问一次减 1，不再跳动。应用本身不统计登录、注册的 429，如果 Render 有 HTTP 请求日志，可以在那里看 429 有没有突增。只读的单次金丝雀不能证明键是对的：未用过的桶总是显示上限 15，必须用指纹或至少一次真实提问。

## 决策表

| 诊断结果 | 动作 |
| --- | --- |
| A. `reqIp` 来自 `xff[-1]`，类别 `cloudflare`；`cf-connecting-ip` 存在且类别为 public；`cloudflareKeyFrom=cf-connecting-ip`；cloudflare 指纹在多次读取和伪造头下都不变；IPv4 下 cf-connecting-ip 的 /24 等于自己的 /24 | 设置 `CLIENT_IP_SOURCE=cloudflare`，保留 `TRUST_PROXY_HOPS=1`。 |
| B. `reqIp` 类别是 private 或 cgnat（Render 内部一跳），`xffRightToLeft[1]` 类别是 cloudflare | 设置 `CLIENT_IP_SOURCE=cloudflare` 和 `TRUST_PROXY_HOPS=2`，再重复第 3 步，确认 `reqIp` 变成 `xff[-2]:cloudflare`。 |
| C. 与 A 相同，但 `cf-connecting-ip` 缺失，而 `xff[-2]` 是 public、/24 等于自己的、`cloudflareKeyFrom=xff-left-of-edge` | 可以设置 `CLIENT_IP_SOURCE=cloudflare`。注意这条路径依赖 Cloudflare 追加的 XFF；Cloudflare Worker 发起的请求能否控制这一项未经验证（见风险）。 |
| D. `reqIp` 是 public 但不是 cloudflare（Render 使用了公布列表以外的出口） | 停止，不要设置。把 /24 前缀和机房代码报给工程师。只有确认这些地址属于 Cloudflare 后，才考虑 `CLOUDFLARE_IP_CIDRS`。 |
| E. 链路混杂、IPv4 与 IPv6 结论不同，或 `diag-cloudflare-key-stable` 失败 | 停止并报告。不要设置 `TRUSTED_PROXY_CIDRS`。 |

## 回退

- 删除 `CLIENT_IP_SOURCE`（如果改过，把 `TRUST_PROXY_HOPS` 改回 1），然后保存并部署，就回到现在的行为。访客额度身份会再变一次。
- **只靠环境变量的紧急方案**（PR 来不及合并时）：`TRUST_PROXY_HOPS=2` 会让 `req.ip` 变成 XFF[-2]，也就是 Cloudflare 追加的访客地址。只有在两个条件都成立时才这样做：已经确认 XFF[-1] 是 Cloudflare 出口、XFF[-2] 等于访客自己；并且没有任何路径能不经 Cloudflare 直达 Render。否则 XFF[-2] 可以由请求方伪造，每个伪造值都是一个新额度身份。这一方案没有 Cloudflare 网段校验，也没有 IPv6 /64 合并，比 `CLIENT_IP_SOURCE=cloudflare` 弱。

## 风险与容量评估

- **Cloudflare Worker**：Cloudflare 文档（HTTP headers 参考页）说明，跨 zone 的 Worker 子请求带的 `CF-Connecting-IP` 固定为 `2a06:98c0:3600::103`。这类请求只能共用一个键，不能自选身份。XFF 条目能否被 Worker 控制未经验证，所以 `CF-Connecting-IP` 优先。
- **键含义变化**：开启后 `req.ip` 是计数键，不是原始地址，IPv6 形如 `2001:db8:abcd:12::/64`。现有代码只把它用作限速和额度键。以后需要真实地址的代码不要读 `req.ip`。
- **共享出口**：运营商 CGNAT 和共享的 IPv6 /64 仍会让几个真人共用一个键，但比现在每个 Cloudflare 出口一个桶小得多。
- **服务端调用**：分享页的 Vercel 函数从服务端调用 API（`/posts/:id`、`/users/:id/public`、`/outings/:id`），开启后按 Vercel 出口计数。`/outings/:id` 是每分钟 360 次，在 R0 规模下无影响。
- **内存限速容量**：`createRateLimiter` 满容量时拒绝新键，保留已有计数（`lib/rateLimit.js:56`），也就是失败即关闭。`authLimiter` 容量 20000，被注册、登录、找回密码、埋点、行程、网页查询等共用，其中埋点每日键 `product-metrics-day` 保留 24 小时。正常浏览时每个访客每天大约占 1 个长期键，所以约 2 万个不同访客/日 才会填满。目前流量和 R0（3–5 位测试者）远低于此，本 PR 不改容量。但开启后，攻击者用大量 IPv6 /64（一个 /48 就有 65536 个）可以在一天内填满这个限速器，让新的登录、注册键返回 429，直到计数过期。建议后续给 24 小时埋点键单独设一个限速器，或对长窗口改用更粗的 IPv6 前缀。guide-chat（10000）和各交互限速器（5000）都是 1 分钟窗口，足够。
- **已登录用户**：每日 AI 额度按账号计数，不受 IP 问题影响。但 guide-chat 每分钟 8 次、会员网页查询每天 20 次和每分钟 5 次、登录、注册仍按 IP 计数，切换前与同一出口的陌生人共享。
