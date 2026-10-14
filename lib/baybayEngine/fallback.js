// BayBay engine: answers without a model answer (H40 split of lib/baybayAgent.js). When the
// model is paused, over its share, unavailable or unusable, the reader still gets an honest
// floor: 911/211 first for a health worry, a professional topic's curated template with its
// official contacts and pillar guide, or matching site records and guide excerpts.
const { queryOverlap } = require('../baybayEvidence');
const { strokeSignMentioned } = require('../safetyRouting');
const { fallbackExcerpt } = require('../baybayExcerpt');
const { cardInLocale } = require('../baybayQuality');
const { str, copy, localeIndex } = require('./util');

// Without a model, a guide excerpt is shown only when it shares real terms with
// the question (or is the page being viewed). An unrelated excerpt, such as a
// roommate guide for a stroke description, is worse than an honest "cannot
// answer now" that keeps 911 and 211 in reach.
const FALLBACK_MIN_MATCHES = 2, FALLBACK_MIN_RATIO = 0.2;
// A worry about someone's body or how they feel shares incidental words
// ("serious", "today", 一起) with posting or city guides. Without a model, only
// a health guide (or the page being viewed) may be excerpted for it.
// FAST stroke signs are health worries too. strokeSignMentioned() is the emergency
// lexicon itself, strong and weak signs without the onset rule, so a phrase that
// does not route to the 911 card (我爸话都说不清了, "my mom has arm weakness",
// 我奶奶今天讲话有点含糊) still gets 911/211 here instead of an unrelated excerpt.
const HEALTH_WORRY = /流血|[在一]直?出血|出血不止|起疹|疹子|嗓子[发發]?[紧緊]|喉[咙嚨][发發]?[紧緊]|胸[闷悶]|一[动動]不[动動]|\b(?:bleeding|rash|hives|not moving|chest (?:tightness|pressure))\b|不舒服|[难難]受|[头頭][晕暈]|[发發][烧燒]|[呕嘔]吐|[没沒]力[气氣]|[无無]力|麻木|手脚|手腳|[说說]话有点怪|說話有點怪|要[紧緊][吗嗎]|[严嚴]重[吗嗎]|症状|症狀|(?<!很|真|太|挺|好|最|更|让人|讓人|令人|比较|比較)(?:[头頭]|胸|胸口|肚子|肚|胃|腿|背|腰|牙|肩|膝盖|膝蓋|[关關]节|[关關]節|喉[咙嚨]|嗓子)(?:很|好|有点|有點|非常)?(?:疼|痛)|[疼痛]得|\b(?:feels?|feeling)\s+(?:\w+\s+){0,2}(?:strange|weak|sick|unwell|dizzy|faint|off|numb)\b|\b(?:dizzy|dizziness|nause\w*|vomit\w*|fever|symptoms?|numb(?:ness)?)\b|\bin (?:\w+\s+){0,3}pain\b|\b(?:chest|stomach|back|head|tooth|leg|knee|joint|neck)\s?(?:pain|ache)s?\b|\bis (?:that|it|this) serious\b/i;
const healthWorry = message => HEALTH_WORRY.test(message) || strokeSignMentioned(message);
const HEALTH_SOURCE = /医疗|醫療|医生|醫生|[诊診]所|急[诊診]|医院|醫院|看病|健康|\b(?:health|clinic|doctors?|medical|hospital|urgent care)\b/i;
function relevantFallbackSource(source, message, pageSourceId) {
  if (source.id === pageSourceId) return true;
  if (healthWorry(message) && !HEALTH_SOURCE.test(source.title || '')) return false;
  const overlap = queryOverlap(message, `${source.title || ''}\n${source.text || ''}`);
  return overlap.matched >= FALLBACK_MIN_MATCHES && overlap.ratio >= FALLBACK_MIN_RATIO;
}
// The 911 sentence comes first (SAFETY-2), before saying that BayBay cannot answer.
function unavailableHelp(locale) {
  return locale === 'en'
    ? 'If someone is in danger or suddenly unwell, call 911 now. BayBay cannot answer this right now; for food, housing or other local services, call 211. You can also try again later, or add a city, a date or what you want to do.'
    : locale === 'zh-Hant'
      ? '如果有人正處於危險或突然身體不適，請立即撥打 911。BayBay 暫時無法回答這個問題；需要食物、住房等本地服務轉介，可撥打 211。也可以稍後再問，或補充城市、日期或想做的事。'
      : '如果有人正处于危险或突然身体不适，请立即拨打 911。BayBay 暂时无法回答这个问题；需要食物、住房等本地服务转介，可拨打 211。也可以稍后再问，或补充城市、日期或想做的事。';
}
const UNAVAILABLE_HELP = { actions: [{ id: 'call-911', label: '911', href: 'tel:911' }, { id: 'call-211', label: '211', href: 'tel:211' }] };

// H72 (audit 10-13, BB-1013-06): an English floor is English only. The English search
// catalog joins each guide's English and Chinese text, so its excerpts and titles are cut
// to their English lines (an English reader got a 301-word dump with 21 Chinese runs).
const CJK = /[㐀-鿿豈-﫿]/;
const englishLines = text => String(text || '').split('\n').filter(line => !CJK.test(line)).join('\n').trim();
const englishTitle = title => String(title || '').replace(/[　-〿㐀-鿿豈-﫿＀-￯]+[^A-Za-z]*/g, ' ').replace(/\s+/g, ' ').trim();
function guideExcerpt(guide, locale) {
  const title = locale === 'en' ? englishTitle(guide.title) || guide.title : guide.title;
  const excerpt = fallbackExcerpt(locale === 'en' ? englishLines(guide.text) : guide.text, locale === 'en' ? 360 : 450);
  return `${title}\n${excerpt || copy(locale, '请打开原文查看完整条件。', 'Open the source for its complete conditions.')} [[${guide.id}]]`;
}
function fallbackAnswer({ locale, state, store, plan, webStatus, message = '', pageSourceId }) {
  // H11/H72 (audit 10-13): a health worry without a model answer never gets an event listing
  // ("My daughter fell off the balcony", once past the card, got three event cards): 911 and
  // 211 first, then a health guide only when one really matches.
  if (!plan && healthWorry(message)) {
    const health = [...store.sources.values()].filter(s => s.kind === 'guide' && relevantFallbackSource(s, message, pageSourceId)).slice(0, 1);
    return [unavailableHelp(locale), ...health.map(guide => guideExcerpt(guide, locale))].join('\n\n');
  }
  const candidates = (plan ? plan.stops.map(s => store.candidates.get(s.id) || store.candidates.get(s.entityId)) : ['discover', 'shopping'].includes(state.goal) ? [...store.candidates.values()] : []).filter(Boolean).filter(c => !c.isOrigin && (c.origin !== 'web' || c.verification === 'page-verified')).slice(0, 3);
  // CODE-API-05: this list is shown only when no model answer exists (provider down, capacity,
  // quota, unusable output). Say so first, so it never reads as a checked recommendation.
  const intro = copy(locale, `这次没能生成 AI 回答。下面是站内收录的${state.city || '湾区'}${state.date ? ` · ${state.date}` : ''}相关资料，没有逐条核对你的全部条件，出发前请看官方页面。`, `An AI answer could not be generated this time. Below are site records for ${state.city || 'the Bay Area'}${state.date ? ` on ${state.date}` : ''}; they were not checked against all your requirements, so check the official pages before you go.`);
  // English rows use the record's English title and summary (cardInLocale), never the Chinese catalog text.
  const shown = c => locale === 'en' ? cardInLocale({ kind: c.kind, id: c.id, title: c.title, summary: c.summary }, { locale, row: c, kind: c.kind }) : c;
  const rows = candidates.map((c, i) => { const row = shown(c); const summary = locale === 'en' && CJK.test(row.summary || '') ? '' : str(row.summary, 200);
    return `${i + 1}. ${locale === 'en' && CJK.test(row.title) ? englishTitle(row.title) || row.title : row.title}${c.city ? ` · ${c.city}` : ''}${summary ? `\n${summary}` : ''}${c.sourceIds?.[0] ? ` [[${c.sourceIds[0]}]]` : ''}`; });
  if (!rows.length) {
    if (plan) return copy(locale, '目前取得的地点还不能组成符合你条件的行程，行程卡列出了需要核实或调整的原因。已排除的活动不会再作为推荐；可以调整一个条件，或继续核实新的地点。', 'The retrieved places do not yet form a plan that meets your requirements. The plan card explains what needs checking or changing. Excluded activities are not recommendations; adjust a requirement or verify another place.');
    const guides = [...store.sources.values()].filter(s => s.kind === 'guide' && relevantFallbackSource(s, message, pageSourceId) && (locale !== 'en' || englishLines(s.text))).slice(0, 2);
    if (guides.length) return `${copy(locale, '先从以下站内资料开始；当前无法完成个性化综合分析。以下是资料摘录，不是对全部问题的完整答复。', 'Start with these site references; personalized synthesis is unavailable right now. These excerpts are not a complete answer to every part of your question.')}\n\n${guides.map(guide => guideExcerpt(guide, locale)).join('\n\n')}`;
    // "Cannot answer, call 911/211" is only for a worry about someone's body or
    // how they feel. An ordinary question without a match keeps the plain copy.
    if (healthWorry(message)) return unavailableHelp(locale);
    return copy(locale, '目前没有取得符合条件且足够可靠的资料。可以补充一个城市、具体日期或想做的事；没有匹配记录不代表当地没有活动。', 'I have not obtained reliable matches for these requirements. Add a city, a date, or an activity preference; a missing match does not mean no events exist.');
  }
  return `${intro}\n\n${rows.join('\n\n')}\n\n${copy(locale, '行程卡会标出尚未核实的交通、开放时间和费用。', 'The plan card identifies any unverified travel, opening hours and costs.')}${webStatus === 'unavailable' ? copy(locale, '本次联网未完成，以上是站内收录资料。', 'Web lookup did not complete; these are editorial site records.') : ''}`;
}

/** A professional topic without a model answer: its curated template, the cited official
 * contacts and the pillar guide (the guard's floor). */
function professionalFloor(turn) {
  const { guard, resourceSourceIds, store, professional, locale } = turn;
  const label = (zh, hant, en) => [zh, hant, en][localeIndex(locale)];
  const contacts = guard.resources.map((row, index) => resourceSourceIds[index] && `${row.title}${row.phone ? ` ${row.phone}` : ''} [[${resourceSourceIds[index]}]]`).filter(Boolean);
  const guide = guard.guides.map(row => ({ row, source: [...store.sources.values()].find(source => source.kind === 'guide' && source.url === row.url) })).find(item => item.source);
  return [professional.answer, contacts.length && `${label('官方入口：', '官方入口：', 'Official contacts: ')}${contacts.join(label('；', '；', '; '))}`,
    guide && `${label('站内指南：', '站內指南：', 'BAYLINK guide: ')}${guide.row.title} [[${guide.source.id}]]`].filter(Boolean).join('\n\n');
}

module.exports = { healthWorry, unavailableHelp, UNAVAILABLE_HELP, fallbackAnswer, professionalFloor };
