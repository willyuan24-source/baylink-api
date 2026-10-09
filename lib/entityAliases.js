const indexes = new WeakMap();
const normalize = text => String(text || '').normalize('NFKC').toLowerCase().replace(/[“”"'‘’]/g, '').replace(/\s+/g, ' ').trim();
function aliasesFor(row) {
  const title = String(row.title || row.name || '');
  return [...new Set([title, title.split(/\s*[：:·（(]\s*/)[0], ...(Array.isArray(row.aliases) ? row.aliases : [])].map(normalize).filter(alias => alias.length >= 3 && alias.length <= 180))];
}
function namedEntities(query, catalog) {
  if (!catalog || typeof catalog !== 'object') return [];
  let index = indexes.get(catalog);
  if (!index) { index = [...(catalog.events || []).map(row => ({ kind: 'event', row })), ...(catalog.places || []).map(row => ({ kind: 'place', row }))].map(value => ({ ...value, aliases: aliasesFor(value.row) })); indexes.set(catalog, index); }
  const text = normalize(query);
  return index.filter(item => item.aliases.some(alias => text.includes(alias))).slice(0, 8);
}
function dateRangeFor(message, today) {
  const text = String(message || '');
  const explicit = /(20\d{2}-\d{2}-\d{2})\s*(?:到|至|through|to|[~–])\s*(20\d{2}-\d{2}-\d{2})/i.exec(text);
  if (explicit && explicit[1] <= explicit[2] && [explicit[1], explicit[2]].every(value => Number.isFinite(Date.parse(value)) && new Date(value).toISOString().startsWith(value))) return { start: explicit[1], end: explicit[2] };
  if (!/这(?:个)?周末|這(?:個)?週末|本周末|本週末|下(?:个)?周末|下(?:個)?週末|\b(?:this|next) weekend\b/i.test(text)) return null;
  const day = new Date(`${today}T12:00:00Z`), weekday = day.getUTCDay();
  let delta = weekday === 0 ? -1 : (6 - weekday + 7) % 7;
  if (/下(?:个)?周末|下(?:個)?週末|\bnext weekend\b/i.test(text)) delta += 7;
  const start = new Date(day.getTime() + delta * 86400000).toISOString().slice(0, 10);
  return { start, end: new Date(Date.parse(`${start}T12:00:00Z`) + 86400000).toISOString().slice(0, 10) };
}
// ---- BAYBAY_ENGINE=v2 retrieval aliases (API-BB-ENGINE) --------------------
// Colloquial names readers type for things the site already covers. A match
// adds the canonical terms to the retrieval query; it never states a fact.
// Keep entries to names with a real record or guide on the site.
// `subject` marks a how-to topic: an evidence item must then name the topic
// (its subject pattern) to be used, so a shared word such as 预约 or 中文 never
// pads a DMV answer with a yoga class (buildFastEvidence).
const ALIAS_GROUPS = Object.freeze([
  { id: 'fleet-week', match: /fleet\s*week|舰队周|艦隊[週周]|海[军軍](?:周|週|节|節)|[蓝藍]天使|blue\s*angels/i, terms: ['Fleet Week', '舰队周', '蓝天使', 'Blue Angels'] },
  { id: 'glass-pumpkin', match: /玻璃南瓜|glass\s*pumpkins?/i, terms: ['Glass Pumpkin', '玻璃南瓜'] },
  { id: 'social-security', match: /[养養]老金|退休金|社安(?:金|局|卡)?|社[会會]安全(?:局|金)?|social\s*security|\bssa\b/i, terms: ['Social Security', 'my Social Security', '社安', '退休福利'], subject: /[养養]老金|退休|社安|社[会會]安全|social\s*security|\bssa\b|\bssi\b/i },
  { id: 'medi-cal', match: /白卡|medi-?cal|加州[医醫][疗療]补助|加州醫療補助/i, terms: ['Medi-Cal', '白卡'], subject: /白卡|medi-?cal|[医醫][疗療]补助|醫療補助/i },
  { id: 'medicare', match: /[红紅][蓝藍]卡|medicare|[联聯]邦[医醫][疗療]保[险險]/i, terms: ['Medicare'], subject: /medicare|hicap|[红紅][蓝藍]卡|[联聯]邦[医醫][疗療]保[险險]/i },
  { id: 'chinese-doctor', match: /(?:中文|[华華]人|[会會]?[说說]中文的?|[讲講]中文的?|国语|國語|普通[话話]|粤语|粵語)\s*(?:的)?\s*[医醫]生|chinese[- ]speaking\s+doctors?/i, terms: ['医生', '保险网络', '医生名录', 'Provider Directory', '语言'], subject: /[医醫]生|doctor|provider|[诊診]所|clinic|保[险險]网络|保險網絡/i },
  { id: 'library-card', match: /[图圖][书書][馆館]卡|借[书書][证證]|[图圖][书書][证證]|library\s*card|\becard\b/i, terms: ['图书馆卡', 'library card', 'eCard'], subject: /[图圖][书書][馆館]|librar(?:y|ies)|借[书書][证證]|[办辦]卡|ecard|[实實][体體]卡|cards?-by-mail|\b(?:sfpl|sjpl|sccld?|aclibrary|smcl)\b/i },
  { id: 'dmv', match: /[驾駕](?:照|[驶駛][执執]照)|[笔筆][试試]|路考|知[识識]考[试試]|\bdmv\b|driver['’]?s?\s+licen[cs]e|\b(?:knowledge|written|driving|drive|road)\s+test\b|behind[- ]the[- ]wheel/i, terms: ['DMV', '驾照', '知识考试', '路考', 'knowledge test', 'drive test'], subject: /[驾駕]照|\bdmv\b|路考|[笔筆][试試]|driver['’]?s?\s+licen[cs]e|\b(?:knowledge|drive|driving)\s+test\b|\breal\s*id\b/i },
  { id: 'seniors', match: /[长長]者|老人|[长長][辈輩]|老年人|\bseniors?\b|\belderly\b/i, terms: ['长者', '老人', 'senior'] },
  { id: 'museums', match: /museums?|博物[馆館]|美[术術][馆館]|[艺藝][术術][馆館]/i, terms: ['museum', 'art', '艺术', '博物馆', 'SFMOMA', 'Asian Art Museum', 'de Young', 'Exploratorium'] },
  { id: 'pumpkin-patch', match: /南瓜(?:园|園|田|地|农场|農場)|摘南瓜|pumpkin\s*patch(?:es)?/i, terms: ['pumpkin patch', '南瓜田', '南瓜季', '农场', 'Farm'] },
  { id: 'newcomer', match: /新移民|刚到[湾灣]区|剛到[灣湾]區|刚搬[来到]|剛搬[來到]|新来[湾灣]区|新來[灣湾]區|\bnew(?:ly)? (?:arrived|immigrants?|to the bay area)\b|\bjust (?:moved|arrived)\b/i, terms: ['刚搬来湾区', '前 7 天', '第一周', 'SSN', '社安卡', '银行', '驾照', 'newcomer'] },
  { id: 'scam', match: /[诈詐][骗騙]|防[骗騙]|[骗騙]局|\bscams?\b|\bfraud\b/i, terms: ['诈骗', '防骗', 'scam'], subject: /[诈詐][骗騙]|[骗騙]|冒充|假冒|scam|fraud|phishing/i },
]);

/** The alias groups a question names (ids) and the canonical terms to add to its retrieval query. */
function queryAliases(query) {
  const text = String(query || '').slice(0, 4000);
  const groups = ALIAS_GROUPS.filter(group => group.match.test(text));
  const subjects = groups.filter(group => group.subject);
  return { ids: groups.map(group => group.id), terms: [...new Set(groups.flatMap(group => group.terms))],
    // A how-to question: does this evidence text name (one of) its topic(s)?
    onSubject: subjects.length ? value => subjects.some(group => group.subject.test(value)) : null };
}

const GENERIC_SUFFIX = /(?:\s*20\d{2})?\s*(?:艺术节|藝術節|音乐节|音樂節|文化节|文化節|美食节|美食節|嘉年华|嘉年華|节|節|活动|活動|展览|展覽|展|市集|集市|夜市|大会|大會|\bfestival\b|\bfair\b|\bmarket\b|\bevents?\b|\bexhibition\b|\bshow\b)\s*$/i;
const GENERIC_TOKENS = new Set(['the', 'and', 'of', 'at', 'in', 'on', 'for', 'a', 'an', 'to', 'day', 'one', 'free', 'night', 'family', '活动', '活動', '免费', '免費', '周末', '週末', '周日', '週日', '周六', '週六', '一日', '亲子', '親子', '社区', '社區', '公园', '公園']);
const latinWords = text => text.match(/[a-z0-9][a-z0-9'’&-]*/g) || [];
const cjkBigrams = text => (text.match(/[㐀-鿿]+/g) || []).flatMap(run => run.length === 1 ? [] : Array.from({ length: run.length - 1 }, (_, index) => run.slice(index, index + 2)));
const coreOf = alias => { let core = alias; for (let i = 0; i < 2; i++) core = core.replace(GENERIC_SUFFIX, '').trim(); return core; };
/** Token signature of an alias: every Latin word and CJK bigram of its core
 * name. Usable only with at least two tokens and one distinctive token, so a
 * bare city name or "free family day" never names an entity. */
function signature(alias, cityTokens) {
  const core = coreOf(alias);
  const tokens = [...new Set([...latinWords(core), ...cjkBigrams(core)])];
  const distinctive = tokens.filter(token => !GENERIC_TOKENS.has(token) && !cityTokens.has(token));
  return tokens.length >= 2 && distinctive.length >= 1 && core.replace(/\s/g, '').length >= 4 ? tokens : null;
}

const v2Indexes = new WeakMap();
const NO_DISCOVERIES = Object.freeze({ items: [] });
function v2Index(catalog, discoveries, cityTokens) {
  const catalogKey = catalog && typeof catalog === 'object' ? catalog : NO_DISCOVERIES;
  let byDiscovery = v2Indexes.get(catalogKey);
  if (!byDiscovery) { byDiscovery = new WeakMap(); v2Indexes.set(catalogKey, byDiscovery); }
  const discoveryKey = discoveries && typeof discoveries === 'object' ? discoveries : NO_DISCOVERIES;
  let index = byDiscovery.get(discoveryKey);
  if (!index) {
    const rows = [...(catalog?.events || []).map(row => ({ kind: 'event', row })), ...(catalog?.places || []).map(row => ({ kind: 'place', row })),
      ...(Array.isArray(discoveryKey.items) ? discoveryKey.items : []).filter(row => ['offer', 'opening'].includes(row?.kind)).map(row => ({ kind: row.kind, row }))];
    index = rows.map(value => {
      const aliases = aliasesFor(value.row);
      return { ...value, aliases, signatures: aliases.map(alias => signature(alias, cityTokens)).filter(Boolean) };
    });
    byDiscovery.set(discoveryKey, index);
  }
  return index;
}

/** v2 named-entity matcher (events, places, offers and openings): an exact
 * alias as in v1, or every token of an alias's core name ("santana row 玻璃南瓜"
 * for "Santana Row 玻璃南瓜艺术节") appears in the question once colloquial
 * alias groups are added (舰队周 -> Fleet Week). `cityTokens` are words that
 * never make a name distinctive on their own. */
function namedEntitiesV2(query, catalog, { discoveries, cityTokens = new Set() } = {}) {
  const text = normalize([query, ...queryAliases(query).terms].join(' '));
  const words = new Set(latinWords(text)), bigrams = new Set(cjkBigrams(text));
  const has = token => /[㐀-鿿]/.test(token) ? bigrams.has(token) : words.has(token);
  return v2Index(catalog, discoveries, cityTokens).filter(item => item.aliases.some(alias => text.includes(alias)) || item.signatures.some(tokens => tokens.every(has))).slice(0, 8);
}

module.exports = { namedEntities, dateRangeFor, aliasesFor, namedEntitiesV2, queryAliases, ALIAS_GROUPS };
