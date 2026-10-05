# BAYBAY 优惠问答实测与状态回归，2026-10-04

测试对象：公开 API `https://baylink-api.onrender.com/api/ai/guide-chat`，健康检查提交 `98d400d4d8823b060d5cb25aaf8723a1ad4ee902`。请求为 `assistantVersion: 2`、`searchMode: smart`、`locale: zh-Hans`。两个完整响应与第三条取消记录见同名 JSON；未保存会话 token、账号凭据或密钥。

## 实际覆盖与限制

共发送 3 条请求，观察到 2 条完整 HTTP 200 响应。第三条在请求发出后终止本地 runner，没有看到响应，不能算成功或模型失败；服务端可能独立完成。没有重试、绕过限流或额外 live 请求。最初 runner 在上级将六条计划收紧为三条前已启动，因此没有实施后续建议的每次间隔 60 秒；原始开始时间保留在 JSON。未观察到 429。

本批没有得到生日、英文、过期社媒截图或泛十月福利问题的完整 live 回答。不能把本批结论扩张为这些类别已经通过。

请求实际发送了顶层 `currentPath: '/'`。当前服务端读取 `context.currentPath`，缺省仍为根路径，因此此次路径语义相同。证据保留原始发送形式，未改写成未发送的字段。

## 两条完整响应

| 场景 | 实际模型与耗时 | 答案和证据表现 | 结论 |
| --- | --- | --- | --- |
| Target eos 是否无需购买、Sunnyvale 附近哪店、时间和年龄 | gpt-6.1-sol；48.489 秒客户端、48.310 秒服务端；3 轮 | 明确买赠、16 岁及以上、10/10 12–4pm、送完为止；列出湾区四家示例并说明不是完整名单；最低消费及赠品总量未确认。只有一个站内攻略引用。官方活动页读取 `source_manual_required`，后续搜索 `research_deadline`。答案主动披露无法实时核实官方条款。 | 答案未把买赠说成无消费领取，事实边界明确。 |
| Lowe’s 10/24 Swarms 是否免会员、湾区是否全部 10 点开始 | gpt-6.1-sol；30.913 秒客户端、30.821 秒服务端；4 轮 | 明确前 100 名 MyLowe’s Rewards 会员、两只限定 Swarms、送完为止；没有把开始时间写成已确认。只有站内零售攻略引用。两次官方读取均 `source_forbidden`，搜索 `web_no_cited_sources`；答案披露这些限制。 | 正文正确，但状态错误地写入 startTime=10:00，构成已复现缺陷。 |

Target 的 `retrieval.scope=site+web`、`webStatus=completed` 只说明至少一个 web 搜索成功；最终外部引用数为零，官方条款页并未读成功。这两个字段本身不能表示答案完成了最新官方核验。Lowe’s 返回 `scope=site`、`webStatus=unavailable`。两条 `degraded=false` 仅表示模型成功产出了答复，并不代表外网核实成功。

## 已复现状态问题与修复

Lowe’s 完整原问题：

> Lowe’s 10月24日 MrBeast 那两只 Swarms，普通人不用会员也能领吗？湾区是不是每家早上10点开始？请把确认和未确认的部分分开。

旧解析器只看到数字时钟后面的“开始”，便把咨询写入 `startTime`。该值进入签名任务状态，会影响后续路线。`lib/baybayState.js` 现在按时钟所在分句区分个人出发要求、活动时间询问及来源转述；中文、英文和显式时间标签共用这个判断。保留“10点出发”“10点开始安排”“start at 10 am”等真实约束。

协同路线审计提供的两个完整问题也进入本地回归：

1. Fremont 家庭行程包含“全家总预算 $50……不是每人 $50”和“从 Fremont BART 站出发”。旧结果为 person 和 Fremont。现在否定的预算金额/范围不进入预算推断，保留 total；公共站名按用户拼写保存。目录没有匹配的 Fremont BART 坐标记录，因此 `originCandidateId` 仍为空，没有生成坐标或伪造路径证据。原有计划层仍应把缺少已验证起点/路线当作未确认。
2. 严格按 Ferry Building → Exploratorium → Pier 39 的路线包含“17:00 在 Pier 39 结束”“不要当作免费或已确认”。现在保留 day-plan、指定地点顺序、finishBy=17:00，并且不误设 freeOnly。明确在终点结束记录为 `returnToOrigin: false`；明确返回起点/同一站为 true，无明确表达时保持原默认。Plan/RoutePlan 如何使用此字段由协同代理另外修改。

同时把明确的两站限制保存为可选 `maxStops`（整数 1–6），签名状态可持续到后续询价。显式修改/清除生效；切换到非行程的新话题清除计划专属限制；完整重置仍由原会话重置流程移除旧状态。普通换日期/城市不擅自丢弃用户的站数上限。

最后对协同界面审计的完整图书馆资格问题做了窄范围修复：`venueCityContext` 会把已发表的 SFPL 简称映射为 San Francisco，而另两套 County Library 体系没有保留城市词，最终误成单一目的地。现在仅在 information 问答、明确比较/区分、多套图书馆体系、资格条件主题且没有肯定出行/参观指令时，清除 city/region、保留 Fremont 居住地。实际去旧金山办卡、单馆地址查询、真实备选目的地仍走原校验。没有放宽外国地点或行程目的地守卫。

## 独立官方事实对照

以下事实由本项目同日官方资料核验支撑，用来检查答案；不等于本次 BAYBAY live 调用读取成功。

- [Target eos 活动页](https://www.target.com/c/eos-fall-scents-demo-event/-/N-s0gmo)：10/10 12–4pm，16 岁及以上，赠品为购买 eos 后获得的 sherpa zipper pouch，送完为止。[官方参与门店 PDF](https://target.scene7.com/is/content/Target/GUEST_a3b29b09-6440-4ed2-ac4c-db8ae55a80e1) 支持回答中所列 Sunnyvale、Cupertino、San Jose Coleman、San Francisco Geary 店。未据此推断任意购买金额或逐店库存。
- [Lowe’s MrBeast 官方页](https://www.lowes.com/l/creator/mrbeast) 的[活动图片](https://mobileimages.lowes.com/marketingimages/f7219630-3ad9-4d90-85e8-14230ec50cbd/mrbeast-hero-dp18-1276909.png) 支持 10/24、首 100 名会员、两只限定 Swarms。未载统一开始时间，不能从社媒图片套用 10am，也不能保证每家湾区门店库存。
- [Starbucks Rewards 官方条款](https://www.starbucks.com/terms/rewards/)（生效日 2026-03-10）可用于后续生日测试：至少提前七天加入、账户有生日、过去一年有合格赚星交易；生日兑换期按 Green、Gold、Reserve 等级区分。**本批没有执行 Starbucks live 问答，不宣称通过。**

## 本地验证

`node --test tests/baybay-state-audit-regressions.test.js tests/baybay-state.test.js tests/baybay-information-scope.test.js`：70/70 通过，包括 11 项新增回归、55 项原有状态测试、4 项协同信息范围测试。首次加入针对原行为的六组测试时 5 组失败，证实回归确实能抓住时间污染、预算否定与站名丢失，而不是只重复新实现。

回归包含三个完整真实问题、签名状态后续、中文/英文个人时间正例、活动时刻反例、正常预算修改、门票价格咨询、免费限制正反例、已核实地点 ID 保留、未知公共站无 ID、站数上限和返回方式验证。原有四处 BART 站断言同步由城市名称更新为完整站名，继续检查无虚构 ID。

代码尚未由此代理提交或部署，也没有追加 live 验证。本地通过不能替代发布后的最终现场检查。
