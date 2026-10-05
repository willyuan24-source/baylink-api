const { fallbackExcerpt } = require('./baybayExcerpt');

const MAX_ITEMS = 8;
const string = (value, max = 600) => typeof value === 'string' ? value.trim().slice(0, max) : '';
const localized = (locale, en, zh, hant = zh) => locale === 'en' ? en : locale === 'zh-Hant' ? hant : zh;
// These patterns identify requested subjects, never supply an answer or infer
// eligibility. Conclusions must still come from this request's evidence.
const SUBJECTS = [
  ['printing', /打印|列印|\bprint(?:ing|ers?)?\b/i, ['Printing', '打印服务', '列印服務']],
  ['kanopy', /\bkanopy\b/i, ['Kanopy access', 'Kanopy 使用资格', 'Kanopy 使用資格']],
  ['museum_passes', /(?:借|图书馆|圖書館|library).{0,20}(?:馆票|館票|门票|門票|pass)|博物馆门票|博物館門票|discover\s*(?:&|and)\s*go|museum passes/i, ['Museum passes', '图书馆博物馆票', '圖書館博物館票']],
  ['card_eligibility', /(?:图书|圖書|library|ecard|SFPL|Kanopy).*(?:居住|年龄|年齡|eCard|卡种|卡種|residen|age|card type)|(?:居住|年龄|年齡|ecard).*(?:限制|资格|資格|eligib|restrict)/i, ['Residence, age and card eligibility', '居住地、年龄与卡种限制', '居住地、年齡與卡種限制']],
  ['joining', /(?:注册|註冊|加入|入会|入會|join|sign.?up|enroll).*(?:生日|birthday|奖励|獎勵|rewards)|(?:生日|birthday).*(?:注册|註冊|加入|join|sign.?up|enroll)/i, ['Joining requirements', '注册与加入条件', '註冊與加入條件']],
  ['purchase_history', /消费记录|消費紀錄|消费历史|消費歷史|购买记录|購買紀錄|purchase history|(?:earned?|earning|prior).{0,12}stars|star.earning transaction/i, ['Purchase history', '消费与积分记录', '消費與積分紀錄']],
  ['redemption', /领取时间|領取時間|兑换|兌換|有效期|redemption|redeem|rewards? tier|same window/i, ['Redemption window and tiers', '领取时段与会员等级', '領取時段與會員等級']],
  ['driving_license', /驾照|駕照|driver.?s? licen[sc]e/i, ['Driver license', '驾照办理', '駕照辦理']],
  ['vehicle_registration', /车辆登记|車輛登記|车辆注册|車輛註冊|vehicle registration/i, ['Vehicle registration', '车辆登记', '車輛登記']],
  ['address_change', /地址变更|地址變更|更新地址|更改地址|change.{0,12}address|address change/i, ['Address change', '地址更新', '地址更新']],
  ['hours', /营业|營業|开馆|開館|开放时间|開放時間|\b(?:opening|business) hours\b|open on/i, ['Opening arrangements', '开放与营业安排', '開放與營業安排']],
  ['admission', /票价|票價|儿童门票|兒童門票|\b(?:ticket prices?|admission|child tickets?)\b/i, ['Admission and child pricing', '门票与儿童票价', '門票與兒童票價']],
  ['transport', /路线时长|路線時長|交通时间|交通時間|公交票价|公交票價|交通费用|交通費用|route duration|travel time|transit fares?/i, ['Routes, time and fares', '路线、时长与交通费用', '路線、時長與交通費用']],
  ['budget', /预算|預算|\bbudget\b/i, ['Total budget', '费用与预算', '費用與預算']],
  ['documents', /材料清单|材料清單|所需材料|证明文件|證明文件|required documents|document checklist/i, ['Required documents', '所需材料', '所需材料']],
  ['deadlines', /办理期限|辦理期限|截止|期限|\bdeadlines?\b/i, ['Deadlines', '办理期限', '辦理期限']],
  ['official_entries', /官方入口|官方链接|官方連結|official (?:links?|entr|sources?)/i, ['Official service links', '官方办理与服务入口', '官方辦理與服務入口']],
];

function requestChecklist(message, locale = 'zh-Hans') {
  const input = string(message, 6000);
  const matched = SUBJECTS.filter(([, pattern]) => pattern.test(input));
  const items = matched.slice(0, MAX_ITEMS).map(([id, , labels]) => ({ id, label: localized(locale, ...labels) }));
  return { items, complex: items.length >= 4 || items.length >= 2 && /区分|區分|分别|分別|比较|比較|对比|對比|distinguish|compare|separately/i.test(input),
    // Item coverage is not a claim that arbitrary unrecognized questions were
    // exhaustively understood. The model must still answer the original turn.
    assessmentScope: items.length ? 'detected-request-items' : 'unassessed' };
}

function finalAnswerInstructions(checklist, locale) {
  const format = 'Return coverage as one item per supplied requestChecklist ID: {id,status,summary,sourceIds}; use [] when no checklist exists. status is answered, unknown, or needs_user_input. Each summary must give the actual item conclusion or precise gap in the requested language; cite only current evidence IDs. An answered item requires evidence. Do not merely say the topic was checked. Preserve known conclusions even when another institution or sub-question remains unresolved. Answer every explicit user request, including ones not detected by the checklist. A disclosed gap is better than an omitted question.';
  return checklist.complex
    ? `${format} This is a multi-part request. In answer give a short overall conclusion and any important requested facts not represented in the checklist. Put one substantive paragraph per requested subject in coverage.summary, preserving each applicable institution, person, date, eligibility and exception. The server will display these summaries as labeled paragraphs below answer. Do not apply a sentence-count limit; use up to 3600 characters across the response when needed. Do not replace available facts with generic guide excerpts or mark every subject unknown merely because current official verification is incomplete. Clearly identify site snapshots as snapshots.`
    : `${format} Keep the answer concise; use enough sentences to cover the supplied items. When the current site evidence already answers a simple eligibility question, answer it directly without redundant research.`;
}

function coverageFor({ checklist, draft, sources, locale, fallback = false }) {
  if (!checklist.items.length) return { status: 'unassessed', items: [] };
  const rows = Array.isArray(draft?.coverage) ? draft.coverage : [];
  const items = checklist.items.map(item => {
    const row = rows.find(value => value && value.id === item.id);
    const sourceIds = [...new Set((Array.isArray(row?.sourceIds) ? row.sourceIds : []).filter(id => typeof id === 'string' && sources.has(id)))].slice(0, 4);
    const summary = fallbackExcerpt(string(row?.summary, 5000), 520);
    const valid = ['answered', 'unknown', 'needs_user_input'].includes(row?.status) && !!summary;
    const unresolved = /尚未|仍未|未(?:能)?(?:确认|確認|核实|核實|查明)|待(?:确认|確認|核实|核實|查证|查證)|无法(?:确认|確認|判断|判斷)|無法(?:確認|判斷)|不(?:能|足以)(?:确认|確認|判断|判斷)|\b(?:unknown|unconfirmed|unresolved|not (?:yet )?(?:confirmed|verified|established)|still (?:needs?|requires?) (?:checking|confirmation|verification)|needs? (?:current |official )?(?:confirmation|verification)|cannot (?:confirm|establish|determine))\b/i.test(summary);
    const status = !fallback && valid && (row.status !== 'answered' || sourceIds.length && !unresolved) ? row.status : 'unknown';
    return { ...item, status, summary: !fallback && valid && (row.status !== 'answered' || sourceIds.length) ? summary : localized(locale,
      'This part has not been resolved from the available evidence.', '现有资料尚未完成这一项的核实与判断。', '現有資料尚未完成這一項的核實與判斷。'), sourceIds: fallback ? [] : sourceIds };
  });
  return { status: items.every(item => item.status === 'answered') ? 'complete' : 'partial', items };
}

// Only explicit party/venue admission totals are compared. A free stop, child
// tier, per-person price, hypothetical discount or a negated $0 is not a claim
// that the whole party's recorded admission is zero.
function admissionConflict(answer, plan) {
  if (!plan?.stops?.length || !(plan.budget?.knownTotalUsd > 0)) return null;
  const normalized = value => String(value || '').normalize('NFKD').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
  const aliases = stop => [...new Set([stop.title, String(stop.title).split(/\s*·\s*/)[0], ...(String(stop.title).match(/[A-Za-z][A-Za-z0-9 '.&-]{3,}/g) || [])].map(normalized).filter(value => value.length >= 5))];
  const sentences = String(answer || '').split(/[。！？；;\n]|[.!?](?=\s|$)/);
  for (const sentence of sentences) {
    if (/如果|假设|假設|倘若|若能|若有|可能|\b(?:if|could|might|would|hypothetically)\b/i.test(sentence)) continue;
    for (const clause of sentence.split(/[，,]/)) {
      if (/不是|并非|並非|不应|不應|不能当作|不能當作|不等于|不等於|\b(?:not|isn['’]t|incorrect|rather than)\b/i.test(clause)) continue;
      const total = /(?:门票|門票|入场|入場|全家|全组|全組|所有人|admission|tickets?|family|group).{0,45}(?:合计|合計|共计|共計|总计|總計|小计|小計|总价|總價|total|subtotal|combined)|(?:门票|門票)(?:总额|總額)|(?:全程|entire trip|whole trip|all[- ]in).{0,30}(?:费用|費用|总|總|cost|total)/i.test(clause);
      const allFree = /(?:全部|全家|全程|所有人).{0,20}(?:免费|免費)|\b(?:everyone|whole family|entire group|all admission)\b.{0,20}\bfree\b/i.test(clause);
      if (!total && !allFree) continue;
      if (/每(?:位|个|個|名|人)|人均|\b(?:per person|per adult|per child|each (?:adult|child|person))\b/i.test(clause)) continue;
      const adults = /成人|大人|\badults?\b/i.test(clause), children = /儿童|兒童|孩子|小孩|\b(?:children|child|kids?)\b/i.test(clause);
      if (adults !== children && !/全家|所有人|全程|\b(?:family|party|group|everyone)\b/i.test(clause)) continue;
      const prices = [...clause.matchAll(/(?:\$|USD\s*)\s*(\d+(?:\.\d{1,2})?)/gi)].map(match => Number(match[1]));
      if (prices.length > 1) continue; // ambiguous arithmetic belongs in the card
      const claimed = prices[0] ?? (allFree ? 0 : null);
      if (claimed === null) continue;
      let mentioned = plan.stops.filter(stop => aliases(stop).some(alias => normalized(clause).includes(alias)));
      if (!mentioned.length && allFree) {
        const sentencePlaces = plan.stops.filter(stop => aliases(stop).some(alias => normalized(sentence).includes(alias)));
        if (sentencePlaces.length === 1) mentioned = sentencePlaces;
      }
      const known = mentioned.length ? mentioned.reduce((sum, stop) => sum + (stop.admissionFacts?.knownTotalUsd || 0), 0) : plan.budget.knownTotalUsd;
      if (claimed + 0.009 < known) return { claimedUsd: claimed, recordedMinimumUsd: known, scope: mentioned.length ? 'named-stops' : 'party' };
    }
  }
  return null;
}

function admissionCorrection(plan, locale) {
  const money = value => `$${Number(value).toFixed(2)}`;
  const rows = plan.stops.filter(stop => Number.isFinite(stop.admissionFacts?.knownTotalUsd)).map(stop => {
    const facts = stop.admissionFacts;
    const basis = facts.basis === 'page-read' ? localized(locale, 'read-page record', '已读官方资料记录', '已讀官方資料記錄') : localized(locale, 'site snapshot', '站内快照', '站內快照');
    return `${stop.title}：${money(facts.knownTotalUsd)} (${basis}${facts.checkedAt ? ` · ${facts.checkedAt.slice(0, 10)}` : ''})${(facts.sourceIds || stop.sourceIds || []).slice(0, 2).map(id => ` [[${id}]]`).join('')}`;
  });
  return [localized(locale,
    'The drafted admission total conflicted with the plan’s price records, so use the following recorded calculation.',
    '原答复的门票合计与行程费用记录不一致，以下改用行程的已知费用计算。',
    '原答覆的門票合計與行程費用記錄不一致，以下改用行程的已知費用計算。'),
  localized(locale, `Recorded party admission subtotal: ${money(plan.budget.knownTotalUsd)}.`, `全家已知门票小计：${money(plan.budget.knownTotalUsd)}。`, `全家已知門票小計：${money(plan.budget.knownTotalUsd)}。`), ...rows,
  localized(locale, 'This is not a confirmed checkout or all-in trip total. Date eligibility, mandatory extras, transport and meals still need confirmation where the plan marks them unknown.', '这不是已确认的结账价或全程总价。具体日期的适用价格、票务附加费、交通和餐饮，仍需按行程卡的待确认项核实。', '這不是已確認的結帳價或全程總價。具體日期的適用價格、票務附加費、交通和餐飲，仍需按行程卡的待確認項核實。')].join('\n\n');
}

function checklistAnswer(answer, coverage, checklist) {
  if (!checklist.complex) return answer;
  const sections = coverage.items.map(item => `${item.label}：${item.summary}${item.sourceIds.map(id => ` [[${id}]]`).join('')}`);
  return [fallbackExcerpt(answer, 1000), ...sections].filter(Boolean).join('\n\n');
}

function checklistFallback({ checklist, sources, locale }) {
  if (!checklist.complex || !checklist.items.length) return null;
  const sourceRows = [...sources.values()].filter(source => source.text && (source.kind === 'guide' || source.verification === 'page-read'));
  const sections = checklist.items.map(item => {
    const pattern = SUBJECTS.find(([id]) => id === item.id)?.[1];
    const ranked = sourceRows.map(source => ({ source, score: Number(pattern?.test(`${source.title || ''} ${source.text}`)) * 5 + Number(source.verification === 'page-read') }))
      .filter(row => row.score >= 5).sort((a, b) => b.score - a.score);
    const source = ranked[0]?.source;
    // Show whole source sentences with their provenance, not a fabricated
    // personal eligibility conclusion. All fallback coverage remains partial.
    const relevant = source?.text.split(/\n\s*\n|\n(?=[^\n])/).find(part => pattern?.test(part) && part.length <= 800);
    const excerpt = fallbackExcerpt(relevant || source?.text || '', 340);
    return `${item.label}：${localized(locale, 'A complete conclusion is not available yet.', '尚未形成完整结论。', '尚未形成完整結論。')}${source && excerpt ? `\n${localized(locale, source.verification === 'page-read' ? 'Read-page excerpt' : 'Site snapshot excerpt', source.verification === 'page-read' ? '已读网页摘录' : '站内资料摘录', source.verification === 'page-read' ? '已讀網頁摘錄' : '站內資料摘錄')}：${excerpt} [[${source.id}]]` : ''}`;
  });
  return `${localized(locale, 'I could not finish the full synthesis. Here is each requested part and any retrieved source excerpt; excerpts do not establish your personal eligibility.', '本次未能完成完整综合答复。以下逐项保留你的问题与已取得的资料摘录；摘录本身不代表已确认你的个人资格。', '本次未能完成完整綜合答覆。以下逐項保留你的問題與已取得的資料摘錄；摘錄本身不代表已確認你的個人資格。')}\n\n${sections.join('\n\n')}`;
}

function directSiteAnswer({ message, checklist, state, site }) {
  return state.goal !== 'day-plan' && !checklist.complex && checklist.items.length > 0 && checklist.items.length <= 3
    && /能否|能不能|可不可以|是否|可以.{0,20}吗|可以.{0,20}嗎|\b(?:can i|can we|am i eligible|do i qualify|would i qualify)\b/i.test(message)
    && (site.guides || []).some(guide => typeof guide.text === 'string' && guide.text.length >= 80);
}

module.exports = { requestChecklist, finalAnswerInstructions, coverageFor, checklistAnswer, checklistFallback, directSiteAnswer, admissionConflict, admissionCorrection, MAX_ITEMS };
