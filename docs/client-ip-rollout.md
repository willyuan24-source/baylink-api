# 按真实访客计数：上线与回退手册

对应审计 REG-01、BBLIVE-01（门槛 G3）。

**现在默认开启。** 店主无法修改 Render 环境变量，所以安全的解析方式直接写成代码默认值：本 PR 合并、Render 部署完成后，限速和访客 AI 额度就按真实访客计数，不需要改任何环境变量。要关掉时把 `CLIENT_IP_SOURCE` 设为 `off`，或者 revert 本 PR（见“回退”）。

## 问题

生产请求路径是“访客 → Cloudflare → Render → Express”。默认 `TRUST_PROXY_HOPS=1` 时，`req.ip` 是 X-Forwarded-For 最右一项，也就是连到 Express 的那一跳。这一跳不是访客，而是不断轮换的代理地址。所以同一访客的额度会在几个桶之间跳（9/1/4），而走同一跳的陌生人又共用同一个桶。注册、登录、找回密码、guide-chat 每分钟 8 次、额度读取、网页查询和访客每日 AI 额度都以 `req.ip` 为键，因此都受影响。Mongo 里的额度存储本身没有问题，错的只是计数键。

### 2026-10-08 诊断结论：决策表情形 B，已在代码里处理

Render 启动后的自动诊断窗口（同一 IPv4 访客，6 次探测）显示，生产链路比原先设想的多一跳：

- X-Forwarded-For 有 3 项，从左到右是：访客（public，就是访客自己的 /24）→ Cloudflare 出口（104.22.17、104.22.18、104.23.160、172.68.174、172.69.23 这几个 /24，都在 Cloudflare 公布网段内）→ Render 内部一跳（10.27.25、10.28.103、10.30.203 这几个 /24，private，轮换）。
- 连到 Express 的 socket 是 loopback。`TRUST_PROXY_HOPS=1`，所以 `req.ip` 是 Render 内部那一跳。`cf-connecting-ip` 等于访客，也就是 XFF[-3]。
- 结果：#23 的默认解析看到可信一跳不是 Cloudflare，就退回 `edge-not-cloudflare`，以这一跳本身为键。所有访客被并进大约 3 个桶，按 Render 内部地址轮换。付费金丝雀看到的 `r15 r15 ask r14 r15 ask r14 r15` 就是这个原因。

原来的处理办法是设置 `TRUST_PROXY_HOPS=2`，但店主改不了 Render 环境变量。所以本次改成在代码里处理，**不需要再设置 `TRUST_PROXY_HOPS=2`**，也不需要改任何环境变量。做法见下面 `CLIENT_IP_SOURCE` 一行。

## 变量

| 变量 | 取值与行为 |
| --- | --- |
| `CLIENT_IP_SOURCE` | **未设置、空或 `cloudflare`（默认）**：先确定“边缘”，也就是从外面连到 Render 的那个地址。如果 Express 按 `TRUST_PROXY_HOPS` 算出的可信一跳属于 Cloudflare 公布网段，它就是边缘。如果可信一跳是内部地址（loopback、10/8、172.16/12、192.168/16、fc00::/7、CGNAT 100.64/10、链路本地 169.254/16 和 fe80::/10，`::ffff:` 映射形式也算），就从这一项往左数，跳过连续的内部地址，第一个非内部条目就是边缘（生产上是 XFF[-2]）。边缘必须属于 Cloudflare 公布网段，然后用 `CF-Connecting-IP`（必须恰好是一个有效 IP）；该头缺失或无效时，取紧邻边缘左侧、由 Cloudflare 追加的 XFF 条目；仍不成立时用边缘本身。找不到非内部条目、边缘不是 Cloudflare 地址、链路和 Express 自己的计算对不上，或者信任跳数为 0 时，都以 Express 的可信一跳本身为键，和以前完全一样（失败即关闭）。IPv4 原样计数，IPv6 按 /64 计数，`::ffff:` 映射地址按 IPv4 计数，Cloudflare 伪 IPv4（240.0.0.0/4）也接受。**`off`（或 `express`）**：关闭，`req.ip` 完全按旧方式计算，中间件不读取也不修改请求。大小写和首尾空格不影响。**其他任何值**都会让服务启动失败。 |
| `CLOUDFLARE_IP_CIDRS` | 可选。逗号分隔的 CIDR，会整体替换内置列表（2026-10-08 取自 https://www.cloudflare.com/ips-v4 和 /ips-v6）。列表过期时只会退回旧键，不会放开。无效条目会让服务启动失败。 |
| `CLIENT_IP_DIAGNOSTIC_UNTIL` | 可选，只有能改 Render 环境变量的人才用得上（见“可选：诊断窗口”）。 |

已有变量提醒：`TRUSTED_PROXY_CIDRS` 一旦非空，就会整体替代 `TRUST_PROXY_HOPS`。如果漏掉 Render 自己那一跳，所有访客会被并成一个键，导致全站 429 和额度耗尽。没有诊断结论时不要设置它。

## 部署这个 PR 时会发生什么

- Render 部署时进程重启，所有内存限速计数（登录、注册、guide-chat 每分钟、额度读取、埋点等）清零。Mongo 里的每日 AI 额度不受影响。
- 所有访客的额度身份改变一次，当天访客额度相当于重置一次。这会顺便清掉被审计脚本污染的桶。
- 如果 Render 收到的可信一跳不是 Cloudflare 地址，而且往左也找不到 Cloudflare 边缘（下文决策表的 D 情形），计数键自动退回这一跳本身，和部署前一样，只是 IPv6 按 /64、`::ffff:` 地址按 IPv4 合并。所以最坏情况是“没有改善”，不会比现在更差。B 情形（Render 内部一跳）现在由代码处理，见上文。
- 金丝雀运行期间不要跑审计或压测脚本（REG+4）。它们会占用共享桶和全站 BayBay 每日 200 次上限。

### 跳过 Render 内部一跳的改动部署后

- 和上面一样，进程重启会清零内存限速计数，Mongo 里的每日 AI 额度不受影响。
- 访客的计数键从“Render 内部地址”（大约 3 个大家共用的桶）变成访客自己，所以每个访客当天的访客额度相当于再重置一次。之前共用的 3 个桶不再被正常访客使用。
- 绕过 Cloudflare 直连 Render 的请求、以及任何对不上的链路，仍然以 Render 内部那一跳为键，和部署前完全一样。
- `CLIENT_IP_SOURCE=off` 的行为一点没变。

## 验证（部署前后）

由工程师执行，**不要和审计、截图、压测同时跑**。第 0、2、4 步只读，不花钱；第 3 步要真实提问，**需要店主事先同意花费约 $0.46**。

金丝雀的四种结果和对应动作：

| 结果（退出码） | 含义 | 动作 |
| --- | --- | --- |
| `RESULT: PASS`（0） | 真正调用模型的提问让 remaining 恰好减 1，之后普通读取和伪造请求头读取都一致 | 保持默认 |
| `RESULT: INCONCLUSIVE`（3） | 没有失败，但还没有证据（只读运行一定是这个结果；付费运行时提问没到达模型，或没有任何伪造请求头到达 API） | 只读运行：正常，进入下一步。付费运行：稍后重跑 |
| `RESULT: FAIL`（1） | 某一行 FAIL：计数键在跳，或伪造请求头换掉了计数键 | 重跑一次（同一出口有人同时提问会误报）；再 FAIL 就按“回退”处理，并把整段输出发给工程师 |
| `RESULT: ERROR`（4） | 运行没跑完：DNS、网络、超时或意外的 HTTP 状态码，只出现 `run` 这一行 ERROR | **不是回退理由**，说明不了计数键。先看 `/api/health` 是否正常，稍后重跑；重复出现就把输出发给工程师。只有 `/api/health` 本身也异常时，才是部署出了问题，按“回退”处理 |

伪造请求头每次只带一种：`x-forwarded-for`、`cf-connecting-ip`、`true-client-ip`、`x-real-ip`，以及除 `cf-connecting-ip` 以外三种合在一起的一种。Cloudflare 会自己拒绝客户端发来的 `CF-Connecting-IP`（2026-10-08 实测：`403`，正文 `error code: 1000`，没有 Render 的 `rndr-id` 响应头），这种请求根本到不了 API，也就不可能换掉计数键。脚本把它列在 `forged-edge-rejected` 这一行，结果是 INFO，不算失败。PASS 要求至少有一种伪造请求头真正到达 API 并且读数不变。

0. **部署前，免费冒烟（建议）**：合并前对生产跑一次只读：
   ```
   node scripts/canary-ai-usage.mjs --base https://baylink-api.onrender.com/api --family 4
   ```
   目的只是确认脚本能和生产正常往来：结果不能是 ERROR；`forged-edge-rejected` 只列出 `cf-connecting-ip`；`usage-forged-reads` 里其余四种都有数字（说明到达了 API）。这时生产还是旧计数键（随 Cloudflare 出口跳动），所以 `usage-*` 两行出现 FAIL（读数不一致）是旧问题本身，不是脚本问题。如果是 ERROR，先不要合并，把输出发给工程师。2026-10-08 已用单独的只读请求逐个核对过：普通请求和 `x-forwarded-for`、`true-client-ip`、`x-real-ip` 都由 Render 返回 200，只有 `cf-connecting-ip` 在 Cloudflare 被拒（1000）。
1. **确认部署**：`GET https://baylink-api.onrender.com/api/health` 返回的 `commit` 等于合并后的 SHA。
2. **部署后，免费只读（付费前的前提）**：再跑一次第 0 步的命令。期望 `RESULT: INCONCLUSIVE`（退出码 3）、没有 FAIL 行、`forged-edge-rejected` 只列出 `cf-connecting-ip`。不是这个结果就不要进行第 3 步，按上表处理。
3. **付费金丝雀（2 次提问）**：
   ```
   node scripts/canary-ai-usage.mjs --base https://baylink-api.onrender.com/api --family 4 --consume 2 --i-approve-spend
   ```
   不需要诊断窗口。期望最后一行是 `RESULT: PASS`（退出码 0），并且下面四行都是 PASS：
   - `consume-monotonic`：remaining 从不回升。
   - `consume-exact-drop`：每次真正调用模型的提问让 remaining 恰好减 1。
   - `after-ask-reads-stable`：提问后连续 N 次读取（默认 10）的 remaining 完全相同，并且低于上限。记下这个值，第 4 步要用。
   - `after-ask-forged-reads`：再带伪造请求头读 N 次，所有到达 API 的读数都和上一行相同，`cf-connecting-ip` 显示 `edge-403`。

   为什么必须提问：没用过的桶在任何键下都显示上限 15，只读结果再整齐也证明不了键是对的。所以开头的 `usage-reads-stable`、`usage-forged-reads` 显示 INCONCLUSIVE 是正常的；`diag-window` 显示 SKIP 也正常。

   如果诊断窗口开着（2026-10-09 23:00 UTC 之前，Render 每次启动后 90 分钟内会自动打开），还会多出 `diag-*` 行。跳过 Render 内部一跳的改动部署后，期望 `diag-window` 一行是 `reqIp=xff[-1]:private xffLength=3 ... cloudflareKeyFrom=cf-connecting-ip cloudflareEdgeFrom=xff[-2]`，并且 `diag-cloudflare-key-stable`、`diag-cloudflare-key-forged`、`diag-current-key` 三行都是 PASS。部署前（旧代码）同一行显示 `cloudflareKeyFrom=edge-not-cloudflare`，而且没有 `cloudflareEdgeFrom`。
4. **独立性检查（第二个网络，免费）**：用另一个网络（例如手机热点）的电脑运行第 0 步的只读命令（仍是 `--family 4`）。期望 `RESULT: INCONCLUSIVE`。要看的是 `usage-reads-stable`：所有读数相同，而且是**这个网络自己的值**（没用过就是 15），**不是**第 3 步记下的值。第 3 步只证明“同一访客读数稳定、伪造不了”，这一步才证明“不同访客不是同一个键”。如果读数正好等于第 3 步的值并且低于 15，可能所有访客被并成了一个键（全站访客共用 15 次），马上告诉工程师：工程师在店主同意下（约 $0.23）从第 3 步的网络再问 1 次，如果热点这边的读数也跟着减 1，就是共用一个键，按“回退”处理。
5. **观察 1 小时**：网站上 BayBay 的剩余次数应该每问一次减 1，不再跳动。应用本身不统计登录、注册的 429，如果 Render 有 HTTP 请求日志，可以在那里看 429 有没有突增。

关于 IPv6：截至 2026-10-08，`baylink-api.onrender.com` 只有 IPv4 地址（A 记录 216.24.57.16/.18，没有 AAAA 记录），所以 `--family 6` 只会得到 `RESULT: ERROR`（“no IPv6 (AAAA) address”）。只有 IPv6 的手机网络通过运营商的 NAT64/CLAT 以 IPv4 访问，所以第 4 步一律用 `--family 4`，也没有 IPv6 的付费证明可做。IPv6 按 /64 计数的逻辑只在测试里验证。

金丝雀脚本的其他规则：`--reads` 取 5–20（每种伪造请求头每阶段至少发一次；额度读取限速是每个键每分钟 120 次）；`--consume` 取 1–4，必须同时带 `--i-approve-spend`，否则脚本直接退出（退出码 2），不发任何请求。脚本不登录，也不发送任何凭据。

## 回退

- **能改 Render 环境变量的人**：设置 `CLIENT_IP_SOURCE=off`，选“Save and deploy”。只保存不部署，新值不会生效。访客额度身份会再变一次。如果曾经改过 `TRUST_PROXY_HOPS`，改回 1。
- **店主改不了环境变量时**：在 GitHub 上 revert 本 PR 并合并，Render 会自动部署 `main`。revert 之后，未设置的 `CLIENT_IP_SOURCE` 重新等于关闭。部署后用 `/api/health` 的 `commit` 确认。
- **只撤销“跳过 Render 内部一跳”这一改动**：在 GitHub 上 revert 那个 PR 并合并。计数键回到 Render 内部地址（大约 3 个共用桶），也就是 10/8 修复前的状态，不会更差。
- **`TRUST_PROXY_HOPS=2` 已经不需要**：Render 内部一跳现在由代码跳过，并且边缘仍要通过 Cloudflare 网段校验。不要为了这个问题改 `TRUST_PROXY_HOPS`。如果以后有人把它设成 2，生产链路下 `req.ip` 会直接是 Cloudflare 出口，结果和现在相同，但没有任何好处。

## 可选：诊断窗口

只有能改 Render 环境变量的人才用得上。金丝雀 FAIL、或者想知道生产链路具体是哪种情形时使用。

**2026-10-09 前的自动窗口（店主 10/8 同意）**：店主这周没法改 Render 环境变量，所以在 Render 上（`RENDER=true`），2026-10-09 23:00 UTC 之前每次启动都会自动打开 90 分钟窗口（不会超过这个时间点），行为与下面设置 `CLIENT_IP_DIAGNOSTIC_UNTIL` 完全相同。过了这个时间点，这段代码不再起作用。本地和测试环境没有 `RENDER=true`，不会打开。

- 设置 `CLIENT_IP_DIAGNOSTIC_UNTIL` 为 ISO UTC 结束时间，例如太平洋夏令时 10:00 等于 17:00 UTC，就填 `2026-10-08T18:00:00Z`，然后保存并部署。只有当它在未来、并且不晚于本次进程启动后 2 小时才生效，否则忽略，日志会写明原因。窗口按每次进程启动计算，每次重新部署都要重设。
- 生效期间有两项诊断。①`GET /api/health` 和 `GET /api/ai/usage` 输出 `[client-ip-diag]` 日志行：带 `?probe=<8–24 位小写字母或数字>` 的请求一律记录，其他请求每 20 个抽 1 个，抽样每小时最多 60 行，总计每小时最多 600 行。②`GET /api/_diag/client-ip` 返回调用者本次请求的分类信息和计数键指纹，每个键每分钟 30 次、全站每分钟 300 次。窗口外该地址就是普通 404。
- 诊断内容只有：地址类别（loopback/private/cgnat/link-local/pseudo-ipv4/cloudflare/public/invalid）、IPv4 /24 或 IPv6 /48 前缀、XFF 长度、从右到左的各项类别、`req.ip` 取自哪一项、`cf-connecting-ip`/`true-client-ip`/`x-real-ip` 等头是否存在、`cf-connecting-ip` 是否等于 XFF[-2]、CF-Ray 机房代码，以及 cloudflare 模式下键的来源。不包含完整 IP，也不写数据库。指纹是 `HMAC(JWT_SECRET, 键)` 的前 12 位十六进制，只能用来比较“两次是不是同一个键”。
- 窗口打开时，同一个金丝雀命令会多出 `diag-*` 行（`diag-current-key` 应为 PASS，只有 1 个键）。也可以直接请求 `curl -4 https://baylink-api.onrender.com/api/_diag/client-ip`，再用 `https://api.ipify.org` 对比自己的 /24。如果能看 Render Logs，可以按 `[client-ip-diag]` 和脚本打印的 probe 值筛选，贴约 30 行给工程师。
- 用完删除 `CLIENT_IP_DIAGNOSTIC_UNTIL` 并保存部署（到期后也会自动失效），确认 `/api/_diag/client-ip` 返回 404。

### 决策表

| 诊断结果 | 动作 |
| --- | --- |
| A. `reqIp` 来自 `xff[-1]`，类别 `cloudflare`；`cf-connecting-ip` 存在且类别为 public；`cloudflareKeyFrom=cf-connecting-ip`；cloudflare 指纹在多次读取和伪造头下都不变；IPv4 下 cf-connecting-ip 的 /24 等于自己的 /24 | 预期情形。保持默认，`TRUST_PROXY_HOPS=1` 不变。 |
| B. `reqIp` 类别是 private 或 cgnat（Render 内部一跳），`xffRightToLeft[1]` 类别是 cloudflare | **2026-10-08 生产就是这种情形，现在由代码处理**，不需要 `TRUST_PROXY_HOPS=2`。部署后诊断应显示 `cloudflareMode.keyFrom=cf-connecting-ip`、`edgeFrom=xff[-2]`（中间隔几个内部地址，就是 `xff[-3]` 等），cloudflare 指纹在多次读取和伪造头下都不变。然后跑付费金丝雀。如果 `keyFrom` 仍是 `edge-not-cloudflare`，看 `edgeFrom`：为 null 说明往左找不到非内部条目，或者链路和 Express 对不上；指向某一项说明那一项不是 Cloudflare 地址，按 D 处理。 |
| C. 与 A 相同，但 `cf-connecting-ip` 缺失，而 `xff[-2]` 是 public、/24 等于自己的、`cloudflareKeyFrom=xff-left-of-edge` | 可以保持默认。注意这条路径依赖 Cloudflare 追加的 XFF；Cloudflare Worker 发起的请求能否控制这一项未经验证（见风险）。 |
| D. `reqIp` 是 public 但不是 cloudflare（Render 使用了公布列表以外的出口）；或者 `reqIp` 是内部地址，而 `edgeFrom` 指向的那一项是 public 但不是 cloudflare | 默认已退回旧键，没有改善也没有放开。把 /24 前缀和机房代码报给工程师。只有确认这些地址属于 Cloudflare 后，才考虑 `CLOUDFLARE_IP_CIDRS`。 |
| E. 链路混杂、IPv4 与 IPv6 结论不同，或 `diag-cloudflare-key-stable` 失败 | 报告工程师。如果金丝雀同时 FAIL，按“回退”关闭。不要设置 `TRUSTED_PROXY_CIDRS`。 |

## 风险与容量评估

- **直连源站**：Cloudflare 网段校验的前提是 Render 的负载均衡只接受经由 Cloudflare 的连接。如果它也接受直连，而请求方自己的地址恰好在 Cloudflare 网段内（例如 WARP 出口），就可以自选计数键。现在默认开启，这个前提默认就要成立。最坏情况是出现很多访客身份，但仍受全站每日 1000 次 AI 请求和 BayBay 每日 200 次上限约束。
- **跳过内部地址为什么安全**：每一层代理只追加“连到自己的那个地址”。Cloudflare 追加访客，Render 负载均衡追加 Cloudflare 出口，Render 内部代理追加内部地址。所以访客右边的每一项都是 Cloudflare 或 Render 写的；请求方自己在 X-Forwarded-For 里写的东西只会出现在更左边。从互联网来的连接不可能来自内部地址，所以紧挨着 Express 那一跳的一串内部地址只能是 Render 自己网络里追加的。代码只跳过这一串，遇到第一个非内部条目就停，绝不越过它。如果请求绕过 Cloudflare 直连 Render，这个位置是请求方自己的公网地址，不在 Cloudflare 网段内，于是失败即关闭，更左边伪造的条目（包括伪造的 Cloudflare 地址和伪造的内部地址）根本读不到。剩下的前提是：没人能从 Render 内部网络、不经 Cloudflare 连到负载均衡并伪造 XFF。即使这个前提不成立，影响也只是多出一些访客身份，仍受全站每日 AI 上限约束。信任跳数设为 0 时不会往左找，因为那时 socket 对端不一定是代理。
- **Cloudflare Worker**：Cloudflare 文档（HTTP headers 参考页）说明，跨 zone 的 Worker 子请求带的 `CF-Connecting-IP` 固定为 `2a06:98c0:3600::103`。这类请求只能共用一个键，不能自选身份。XFF 条目能否被 Worker 控制未经验证，所以 `CF-Connecting-IP` 优先。
- **键含义变化**：默认开启后 `req.ip` 是计数键，不是原始地址，IPv6 形如 `2001:db8:abcd:12::/64`。现有代码只把它用作限速和额度键。以后需要真实地址的代码不要读 `req.ip`。
- **共享出口**：运营商 CGNAT 和共享的 IPv6 /64 仍会让几个真人共用一个键，但比以前每个 Cloudflare 出口一个桶小得多。同一出口有人同时提问时，金丝雀可能误报 FAIL，重跑一次即可分辨。
- **服务端调用**：分享页的 Vercel 函数从服务端调用 API（`/posts/:id`、`/users/:id/public`、`/outings/:id`），现在按 Vercel 出口计数。`/outings/:id` 是每分钟 360 次，在 R0 规模下无影响。
- **内存限速容量**：`createRateLimiter` 满容量时拒绝新键，保留已有计数（`lib/rateLimit.js:56`），也就是失败即关闭。`authLimiter` 容量 20000，被注册、登录、找回密码、埋点、行程、网页查询等共用，其中埋点每日键 `product-metrics-day` 保留 24 小时。正常浏览时每个访客每天大约占 1 个长期键，所以约 2 万个不同访客/日 才会填满。目前流量和 R0（3–5 位测试者）远低于此，本 PR 不改容量。但攻击者用大量 IPv6 /64（一个 /48 就有 65536 个）可以在一天内填满这个限速器，让新的登录、注册键返回 429，直到计数过期。建议后续给 24 小时埋点键单独设一个限速器，或对长窗口改用更粗的 IPv6 前缀。guide-chat（10000）和各交互限速器（5000）都是 1 分钟窗口，足够。
- **已登录用户**：每日 AI 额度按账号计数，不受 IP 问题影响。但 guide-chat 每分钟 8 次、会员网页查询每天 20 次和每分钟 5 次、登录、注册仍按 IP 计数；默认开启后按真实访客计数，不再与同一出口的陌生人共享。
