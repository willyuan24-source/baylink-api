const { validDate } = require('./planner');
const catalogAdmissions = require('../data/admission-facts.json');
const arr = value => Array.isArray(value) ? value : [];
const amount = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100000 ? value : null;
const safeUrl = value => { try { const u = new URL(value); return u.protocol === 'https:' && !u.username && !u.password ? u.href : null; } catch { return null; } };
const sourceDate = value => typeof value === 'string' && validDate(value.slice(0, 10)) ? value.slice(0, 10) : null;
const round = value => Math.round((value + Number.EPSILON) * 100) / 100;
const words = locale => { const say = (en, hans, hant = hans) => locale === 'en' ? en : locale === 'zh-Hant' ? hant : hans; return { say, party: say('Confirm the party size and child ages before calculating the full admission total.', '完整门票合计还需要人数及儿童年龄。', '完整門票合計還需要人數及兒童年齡。') }; };

const restrictedPrice = row => {
  const label = `${row.costLabel || ''} ${row.planning.admissionNote || ''}`;
  const restricted = /(?:免费|免費|\bfree\b)[^。.;；]{0,55}(?:会员|會員|居民|学生|學生|儿童|兒童|[岁歲]|\b(?:for|to|with)\s+(?:all\s+)?(?:members?|residents?|students?|children|kids?|under\s+\d|a purchase)|\b(?:members?|residents?) only\b)|(?:会员|會員|居民|学生|學生|儿童|兒童|[岁歲]|\b(?:members?|residents?|students?|children|kids?|under\s+\d)\b)[^。.;；]{0,40}(?:免费|免費|\bfree\b)|\bfree\b[^.;。；]{0,80}\b(?:with|after|on|for)\b[^.;。；]{0,35}\b(?:purchase|purchases|spending|spend)\b|\b(?:buy one|get one|bogo)\b|买一送一|買一送一|(?:须|須|需先|需要)(?:购买|購買|消费|消費)/i.test(label);
  const extraOnly = /\bfree (?:parking|gift|book|drink|food|shipping)\b|免费(?:停车|礼物|书籍|饮料)|免費(?:停車|禮物|書籍|飲料)/i.test(label)
    && !/\bfree (?:general )?(?:admission|entry)\b|\b(?:admission|entry) (?:is )?free\b|(?:入场|入場|门票|門票|基础入场|基礎入場)(?:及停车|及停車)?免费|免费入场|免費入場|入場免費/i.test(label);
  return restricted || extraOnly;
};

// Numeric catalog admission is a price for an applicable ticket, not proof that
// every child, resident, member or party qualifies for that ticket. Tier pricing
// is used only when supplied as structured, sourced data by retrieval tools.
function legacyAdmissionFor(row, state, w) {
  const p = row.planning, rule = p.admission && typeof p.admission === 'object' ? p.admission : {};
  const result = { knownTotal: 0, knownPerPerson: 0, unknowns: [], complete: false, breakdown: [] };
  const line = (category, quantity, unitUsd, extra = {}) => { if (quantity > 0) result.breakdown.push({ category, quantity, unitUsd, subtotalUsd: round(quantity * unitUsd), ...extra }); };
  const unknown = text => result.unknowns.push(`${row.title}: ${text}`);
  const unconfirmed = w.say('Admission/eligibility is unconfirmed; do not count it as free.', '入场费用或适用资格未确认，不能当作免费。', '入場費用或適用資格未確認，不能當作免費。');
  const hasSourcedRule = safeUrl(rule.sourceUrl) && sourceDate(rule.verifiedAt) && !rule.eligibility;
  const raw = amount(p.admissionUsd);
  const basic = raw !== null ? raw : row.cost === 'free' ? 0 : null;
  const restricted = restrictedPrice(row) || !!rule.eligibility || p.admissionEligibility;
  let all = hasSourcedRule ? amount(rule.allAgesUsd) : null;
  if (all === null && !hasSourcedRule && basic !== null && !restricted && (basic === 0 || p.admissionAppliesTo === 'all')) all = basic;
  const group = hasSourcedRule && rule.scope === 'group' ? amount(rule.groupUsd) : p.admissionScope === 'group' && !restricted ? basic : null;
  const adult = hasSourcedRule ? amount(rule.adultUsd) : restricted ? null : basic;
  if (group !== null) {
    const groupLimit = rule.maxPartySize ?? p.maxPartySize;
    if (!state.partySize || (Number.isInteger(groupLimit) && state.partySize > groupLimit)) unknown(unconfirmed);
    else { result.knownTotal = group; result.knownPerPerson = group / state.partySize; result.complete = true; line('group', 1, group); }
  } else if (all !== null) {
    result.knownPerPerson = all;
    if (all === 0) { result.complete = true; if (state.partySize) line('all-ages', state.partySize, 0); }
    else if (!state.partySize) unknown(w.party);
    else { result.knownTotal = all * state.partySize; result.complete = true; line('all-ages', state.partySize, all); }
  } else if (adult !== null && !(adult === 0 && restricted)) {
    result.knownPerPerson = adult;
    if (!state.partySize || state.partySize < state.childAges.length) unknown(w.party);
    else {
      result.knownTotal = adult * (state.partySize - state.childAges.length);
      line('adult', state.partySize - state.childAges.length, adult, rule.adultMinAge !== undefined ? { minAge: rule.adultMinAge, maxAge: rule.adultMaxAge } : {});
      result.complete = true;
      for (const age of state.childAges) {
        const applicable = hasSourcedRule ? arr(rule.children).filter(t => Number.isInteger(t.minAge) && Number.isInteger(t.maxAge) && age >= t.minAge && age <= t.maxAge && amount(t.usd) !== null && !t.eligibility) : [];
        const child = applicable.length === 1 ? applicable[0] : null;
        if (!child) { result.complete = false; unknown(w.say(`Admission for age ${age} is unconfirmed.`, `${age} 岁儿童的适用票价未确认。`, `${age} 歲兒童的適用票價未確認。`)); }
        else { result.knownTotal += child.usd; result.knownPerPerson = Math.max(result.knownPerPerson, child.usd); line('child', 1, child.usd, { age, minAge: child.minAge, maxAge: child.maxAge }); }
      }
    }
  } else unknown(unconfirmed);
  if (restricted && !hasSourcedRule) { result.complete = false; unknown(w.say('A conditional discount is listed; full-party eligibility is unconfirmed.', '记录含附条件优惠，尚未核实全体人员是否适用。', '記錄含附條件優惠，尚未核實全體人員是否適用。')); }
  if (result.knownPerPerson > 0 || result.knownTotal > 0) {
    if (hasSourcedRule && rule.feesIncluded === true) { /* Sourced all-in price. */ }
    else if (p.feesIncluded !== true) { result.complete = false; unknown(w.say('Mandatory ticket fees/taxes are unconfirmed.', '必要票务附加费及税费未确认。', '必要票務附加費及稅費未確認。')); }
  }
  result.knownTotal = round(result.knownTotal);
  result.knownPerPerson = round(result.knownPerPerson);
  if (hasSourcedRule && all !== null) result.admissionUsd = all;
  else if (basic !== null && (!restricted || (hasSourcedRule && amount(rule.adultUsd) !== null))) result.admissionUsd = basic;
  if (hasSourcedRule) result.sourceUrl = safeUrl(rule.sourceUrl);
  return result;
}

/** Audited editorial prices are reusable snapshots, never live verification.
 * A short editorial freshness window does not assert an official expiry date. */
function catalogAdmissionRuleFor(row, date) {
  if (row.planning?.admission || row.verifiedFacts?.admission || row.origin === 'web' || row.external || row.sourceKind === 'web') return null;
  const record = catalogAdmissions.find(item => item.candidateId === row.id && safeUrl(item.officialUrl) === safeUrl(row.officialUrl));
  if (!record || !validDate(date)) return null;
  const ageDays = (Date.parse(`${date}T12:00:00Z`) - Date.parse(`${record.verifiedAt}T12:00:00Z`)) / 86400000;
  return ageDays >= 0 && ageDays <= record.snapshotMaxAgeDays ? { ...record, children: record.children.map(tier => ({ ...tier })) } : null;
}

function admissionFactsFor(input, inputState = {}, { locale = 'zh-Hans', today } = {}) {
  const state = { ...inputState, childAges: arr(inputState.childAges), partySize: Number.isInteger(inputState.partySize) && inputState.partySize > 0 ? inputState.partySize : null };
  const date = validDate(state.date) ? state.date : validDate(today) ? today : null;
  const catalogRule = catalogAdmissionRuleFor(input, date);
  let row = { ...input, planning: { ...(input.planning || {}), ...(catalogRule ? { admission: catalogRule } : {}) } };
  const rule = row.planning.admission || {}, w = words(locale);
  const sourced = !!(safeUrl(rule.sourceUrl) && sourceDate(rule.verifiedAt));
  const snapshotAge = date && sourced ? (Date.parse(`${date}T12:00:00Z`) - Date.parse(`${sourceDate(rule.verifiedAt)}T12:00:00Z`)) / 86400000 : null;
  const outOfRange = sourced && (rule.validFrom && !validDate(rule.validFrom) || rule.validThrough && !validDate(rule.validThrough)
    || date && (rule.validFrom && date < rule.validFrom || rule.validThrough && date > rule.validThrough || Array.isArray(rule.dates) && !rule.dates.includes(date))
    || rule.verification === 'catalog-snapshot' && (!Number.isFinite(snapshotAge) || snapshotAge < 0 || snapshotAge > rule.snapshotMaxAgeDays));
  // A dated rule outside its range invalidates its accompanying basic price as
  // well; neither can silently fall back to a catalog "free" flag.
  if (outOfRange) row = { ...row, cost: 'unknown', planning: { ...row.planning, admission: null, admissionUsd: null, admissionEligibility: 'date-unconfirmed' } };
  const result = legacyAdmissionFor(row, state, w);
  const basis = sourced && rule.verification === 'page-read' ? 'page-read' : sourced && rule.verification === 'catalog-snapshot' ? 'catalog-snapshot' : 'catalog';
  const regularUnconfirmed = sourced && rule.regularAdmission === true && !(rule.dates?.includes(date) || rule.validFrom && rule.validThrough && date >= rule.validFrom && date <= rule.validThrough);
  if (outOfRange) result.unknowns.push(`${row.title}: ${w.say('The admission rule does not apply to the selected date.', '这条票价规则不适用于所选日期。', '這條票價規則不適用於所選日期。')}`);
  if (regularUnconfirmed) {
    result.complete = false;
    result.unknowns.push(`${row.title}: ${w.say('Regular admission price recorded; the selected date and checkout total still need confirmation.', '这是普通票价记录；所选日期的适用价格与结账总额仍待确认。', '這是普通票價記錄；所選日期的適用價格與結帳總額仍待確認。')}`);
  }
  result.facts = {
    status: result.complete ? 'complete' : result.breakdown.length || result.knownPerPerson > 0 ? 'partial' : 'unknown', basis,
    knownTotalUsd: result.breakdown.length || result.complete ? result.knownTotal : null,
    knownPerPersonUsd: result.breakdown.length || result.knownPerPerson > 0 || result.complete ? result.knownPerPerson : null,
    partySize: state.partySize, childAges: [...state.childAges], breakdown: result.breakdown,
    ...(sourced ? { sourceUrl: safeUrl(rule.sourceUrl), checkedAt: rule.verifiedAt, ...(rule.guideUrl ? { guideUrl: rule.guideUrl } : {}) } : safeUrl(row.officialUrl) ? { sourceUrl: safeUrl(row.officialUrl), ...(row.recordedAt ? { checkedAt: row.recordedAt } : {}) } : {}),
    sourceIds: [...new Set([...arr(rule.sourceIds), ...(arr(row.sourceIds).length ? row.sourceIds : row.evidenceId ? [row.evidenceId] : [])])],
    applicability: { date, dateStatus: outOfRange ? 'out-of-range' : regularUnconfirmed ? 'regular-unconfirmed' : sourced && (rule.dates?.includes(date) || rule.validFrom && rule.validThrough) ? 'date-specific' : 'unconfirmed', feesIncluded: rule.feesIncluded === true || row.planning.feesIncluded === true ? true : null },
    unknowns: [...result.unknowns], ...(rule.note ? { note: rule.note } : {}),
  };
  return result;
}

function withAdmissionFacts(candidate, state, options) {
  const rule = catalogAdmissionRuleFor(candidate, state?.date || options?.today);
  const row = rule ? { ...candidate, planning: { ...(candidate.planning || {}), admission: rule } } : candidate;
  return { ...row, admissionFacts: admissionFactsFor(row, state, options).facts };
}

/** Only parse literal, uncomplicated general-admission labels from an already
 * read exact quotation. Model-provided numbers/eligibility fields are ignored. */
function admissionRuleFromQuote({ quote, source, candidate, unqualifiedFree = false }) {
  const flat = value => String(value || '').replace(/\s+/g, ' ').trim();
  const text = flat(source?.text), exact = flat(quote), index = text.indexOf(exact);
  if (source?.verification !== 'page-read' || !safeUrl(source.url) || !sourceDate(source.checkedAt) || exact.length < 3 || index < 0) return null;
  const before = text.slice(Math.max(0, index - 160), index).split(/[!?;。；]|\.(?=\s|$)/).pop();
  const after = text.slice(index + exact.length, index + exact.length + 200).split(/[!?;。；]|\.(?=\s|$)/)[0];
  const context = `${before} ${exact} ${/[.!?;。；]$/.test(exact) ? '' : after}`;
  // Cropping an offer's heading or qualifier cannot manufacture a general price.
  const restricted = /\b(?:members?|membership|residents?|students?|seniors?|military|veterans?|EBT|SNAP|discount|coupon|promotion|starting at|from\s*\$|after dark|first friday|with purchase|plus|additional|add-on|dome|only|every|except|weekends?|weekdays?|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b|会员|會員|居民|学生|學生|老人|优惠|優惠|起价|起價|加购|加購|仅限|僅限/i;
  if (!unqualifiedFree && restricted.test(context)) return null;
  const following = text.slice(index + exact.length, index + exact.length + 250).replace(/^[.!?;。；]\s*/, '').split(/[!?;。；]|\.(?=\s|$)/)[0].trim();
  if (!unqualifiedFree && /^(?:(?:this|the)\s+)?(?:offer|admission|tickets?|price|rate|valid|available|requires?|only)\b/i.test(following) && restricted.test(following)) return null;
  if (!/\b(?:admission|entry|tickets?|pass)\b|门票|門票|入场|入場/i.test(context)) return null;
  const base = { sourceUrl: safeUrl(source.url), verifiedAt: source.checkedAt, verification: 'page-read', sourceIds: source.id ? [source.id] : [],
    sourceQuote: exact, feesIncluded: /\b(?:includes? (?:all )?(?:taxes? and fees|fees and taxes)|(?:all )?(?:taxes? and fees|fees and taxes) included)\b|含全部税费|含全部稅費/i.test(exact), regularAdmission: true };
  // A verified event date can anchor that event's own admission quotation.
  if (candidate?.kind === 'event' && candidate.verifiedFacts?.date && validDate(candidate.startDate) && candidate.startDate === candidate.endDate) {
    base.dates = [candidate.startDate]; base.regularAdmission = false;
  }
  if (unqualifiedFree) return { ...base, allAgesUsd: 0, feesIncluded: true };
  const currency = '(?:\\$|USD\\s*)\\s*(\\d{1,4}(?:\\.\\d{1,2})?)(?!\\d|\\.\\d)';
  const group = exact.match(new RegExp('(?:group|family)\\s+(?:admission|ticket|pass)\\s*[:\\-]?\\s*' + currency + '\\s+(?:for|covers?)\\s+(?:up to\\s+)?(\\d{1,2})\\s+(?:people|persons|guests)', 'i'));
  if (group && Number(group[2]) >= 1 && Number(group[2]) <= 30) return { ...base, scope: 'group', groupUsd: Number(group[1]), maxPartySize: Number(group[2]) };
  const adults = [...exact.matchAll(new RegExp('\\badults?\\s*(?:\\(?\\s*(?:ages?\\s*)?(\\d{1,2})\\s*[–—-]\\s*(\\d{1,2})\\s*\\)?)?\\s*[:\\-]?\\s*' + currency, 'gi'))];
  if (adults.length !== 1) return null;
  const adult = adults[0], rule = { ...base, adultUsd: Number(adult[3]), children: [] };
  if (adult[1]) { if (Number(adult[1]) < 16 || Number(adult[2]) < Number(adult[1])) return null; rule.adultMinAge = Number(adult[1]); rule.adultMaxAge = Number(adult[2]); }
  const range = new RegExp('(?:\\b(?:children|child|youth|kids?)\\s*(?:aged?\\s*|ages?\\s*)?|\\bages?\\s*)(?:\\(\\s*)?(\\d{1,2})\\s*[–—-]\\s*(\\d{1,2})\\s*\\)?\\s*[:\\-]?\\s*(?:' + currency + '|(free))', 'gi');
  for (const match of exact.matchAll(range)) {
    if (match.index >= adult.index && match.index < adult.index + adult[0].length) continue;
    const minAge = Number(match[1]), maxAge = Number(match[2]);
    if (minAge > maxAge || maxAge > 17) return null;
    rule.children.push({ minAge, maxAge, usd: match[4] ? 0 : Number(match[3]) });
  }
  for (const match of exact.matchAll(/\b(?:children|kids?|ages?)\s+(?:ages?\s+)?(?:(under)\s+(\d{1,2})|(\d{1,2})\s+and\s+under)\s*[:\-]?\s*(free)/gi)) {
    const maxAge = match[1] ? Number(match[2]) - 1 : Number(match[3]);
    if (maxAge < 0 || maxAge > 17) return null;
    rule.children.push({ minAge: 0, maxAge, usd: 0 });
  }
  return rule;
}

module.exports = { admissionFactsFor, withAdmissionFacts, catalogAdmissionRuleFor, admissionRuleFromQuote };

