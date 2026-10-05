const { buildItinerary } = require('./baybayPlan');

const array = value => Array.isArray(value) ? value : [];
const rawId = value => typeof value === 'string' ? value.replace(/^(?:event|place):/, '') : null;
const ids = values => [...new Set(array(values).map(rawId).filter(id => id && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}$/.test(id)))].slice(0, 6);
const normalized = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();
const cloneState = state => ({ ...state, selectedCandidateIds: [...array(state?.selectedCandidateIds)], excludedCandidateIds: [...array(state?.excludedCandidateIds)] });
const venueName = value => normalized(value).replace(/\s+/g, ' ');
const escapePattern = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// A count is a limit only when the user asks for one. Party size, ordinal
// edits and a question about travel between two stops are not stop limits.
const stopLimitPattern = /(?:最多|至多|不超过|不超過|不要超过|不要超過|收紧成|收緊成|缩减(?:到|成|为)|縮減(?:到|成|為)|减少到|減少到|控制在|只(?:安排|保留|留|要))\s*([1-9]|[一二两兩三四五六七八九])\s*站|([1-9]|[一二两兩三四五六七八九])\s*站以内|\b(?:at most|no more than|only|(?:limit|reduce|trim|tighten)(?:\s+(?:it|the (?:plan|trip|itinerary)))?\s+to)\s+(one|two|three|four|five|six|seven|eight|nine|[1-9])\s+stops?\b/gi;
function requestedStopLimit(message) {
  const values = [...String(message || '').matchAll(stopLimitPattern)].map(match => {
    const value = (match[1] || match[2] || match[3]).toLowerCase();
    if (/^[1-9]$/.test(value)) return Number(value);
    if (value === '两' || value === '兩') return 2;
    return value.length === 1 ? '一二三四五六七八九'.indexOf(value) + 1 : ['one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'].indexOf(value) + 1;
  });
  return values.length ? Math.min(...values) : null;
}

// Signed refs establish an old stop's identity only. They never restore its
// opening hours, admission or verification into the current candidate store.
function namesOf(row) {
  return [...new Set([row?.title, row?.name, ...array(row?.aliases), String(row?.title || '').split(/\s*[·|｜]\s*/)[0]]
    .map(venueName).filter(name => name.length >= 3 && name.length <= 160))];
}

function namedMatches(text, rows) {
  const message = venueName(text), found = [];
  for (const row of rows) for (const name of namesOf(row)) {
    const pattern = new RegExp(`${/^[a-z0-9]/.test(name) ? '(?<![a-z0-9])' : ''}${escapePattern(name)}${/[a-z0-9]$/.test(name) ? '(?![a-z0-9])' : ''}`, 'gu');
    for (const match of message.matchAll(pattern)) found.push({ id: rawId(row.id), name, start: match.index, end: match.index + match[0].length });
  }
  return found.filter(item => item.id && !found.some(other => other.start <= item.start && other.end >= item.end && other.end - other.start > item.end - item.start));
}

function requestedNamedEdit(message, previousIds, catalog, lastPlan) {
  const rows = [...array(catalog?.events), ...array(catalog?.places), ...array(lastPlan?.selectedRefs).filter(ref => previousIds.includes(rawId(ref.id)))];
  const removeIds = new Set(), keepNames = [], matchedKeepIds = new Set();
  let only = false;
  for (const rawClause of String(message || '').replace(stopLimitPattern, '').split(/[，,。.!！？?；;\n]/)) {
    const clause = rawClause.trim();
    const keep = clause.match(/^(?:那(?:就)?|现在|現在|这次|這次|请|請|就|我們|我们|我|改成|改为|改為|改成了|\s)*(?:只保留|仅保留|僅保留|只去|仅去|僅去|只安排)\s*(.+)$|^\s*(?:(?:please|now|then|we will|we want to)\s+)*(?:only\s+(?:keep|visit|include|go to)|keep only|visit only|go only to)\s+(.+)$/i);
    if (keep) {
      const target = (keep[1] || keep[2]).trim();
      // Retaining a condition is not a command to delete all destinations.
      if (/^(?:孩子|儿童|兒童|年龄|年齡|人数|人數|预算|預算|条件|條件|时间|時間|日期|交通|出发|出發|返程|原(?:来|來)?(?:的)?(?:安排|计划|計劃)|\d|the (?:budget|time|date|conditions)|(?:budget|time|date|conditions|children|kids))/.test(target)) continue;
      only = true;
      const parts = rows.some(row => namesOf(row).includes(venueName(target))) ? [target] : target.split(/\s+(?:and|&)\s+|[、和与與及]/i);
      for (const part of parts) {
        const matches = namedMatches(part, rows);
        if (matches.length) { for (const match of matches) { matchedKeepIds.add(match.id); keepNames.push(match.name); } continue; }
        // A newly requested web venue can be admitted later only by matching
        // this exact user name AND passing the normal engine verification.
        const name = venueName(part.replace(/(?:就好|即可|就行|吧|了|不要补.*|不要補.*)$/u, '').replace(/[。.!?]+$/, ''));
        if (name.length >= 3 && name.length <= 160) keepNames.push(name);
      }
    }
    const cancel = clause.match(/^(?:那(?:就)?|现在|現在|这次|這次|请|請|就|我們|我们|我|\s)*(?:取消|去掉|删掉|刪掉|删除|刪除|移除|不要(?!(?:取消|删掉|刪掉|删除|刪除|移除|去掉))(?:再?去)?|不去|别去|別去)\s*(.+)$|^\s*(?:(?:please|now|then)\s+)*(?:cancel|remove|delete|drop|skip|do not visit|don't visit)\s+(.+)$/i);
    const suffix = !cancel && clause.match(/^(.+?)(?:就)?(?:取消|去掉|删掉|刪掉|删除|刪除|移除|不要了)\s*$/);
    if (cancel || suffix) for (const match of namedMatches(cancel ? cancel[1] || cancel[2] : suffix[1], rows)) removeIds.add(match.id);
  }
  if (!only && !removeIds.size) return null;
  // Only signed previous IDs can be removed from the old plan.
  const targetIds = previousIds.filter(id => removeIds.has(id) || only && !matchedKeepIds.has(id)
    && !namesOf(rows.find(row => rawId(row.id) === id)).some(name => keepNames.includes(name)));
  const retainedIds = previousIds.filter(id => !targetIds.includes(id));
  return { kind: 'remove', named: true, only, targetIds, retainedIds, keepNames: [...new Set(keepNames)].slice(0, 6), requestedIds: [...matchedKeepIds].slice(0, 6) };
}

function requestedEdit(message) {
  // "不要超过 2 站" must not become "remove the second stop".
  const text = String(message || '').replace(stopLimitPattern, '');
  const replace = /换掉|換掉|替换|替換|换一|換一|换个|換個|換成|换成|\b(?:replace|swap|change)\b/i.test(text);
  const remove = /取消|去掉|删掉|刪掉|删除|刪除|移除|不要|\b(?:cancel|remove|delete|drop|skip)\b/i.test(text);
  if (!replace && !remove) return null;
  const positions = [];
  const chinese = /(?:第\s*([一二三四五六1-6])(?:\s*(?:站|个|個|项|項))?|([1-6])\s*(?:站|个|個|项|項))/g;
  const english = /\b(first|second|third|fourth|fifth|sixth|[1-6](?:st|nd|rd|th))(?:\s+(?:stop|place|option))?\b|\b(?:stop|place|option)\s*([1-6])\b/gi;
  for (const match of text.matchAll(chinese)) {
    const value = match[1] || match[2]; positions.push(/\d/.test(value) ? Number(value) - 1 : '一二三四五六'.indexOf(value));
  }
  for (const match of text.matchAll(english)) {
    const value = (match[1] || match[2]).toLowerCase(); positions.push(/\d/.test(value) ? Number(value[0]) - 1 : ['first', 'second', 'third', 'fourth', 'fifth', 'sixth'].indexOf(value));
  }
  const unique = [...new Set(positions)];
  return unique.length === 1 ? { kind: replace ? 'replace' : 'remove', index: unique[0] } : unique.length > 1 ? { kind: 'ambiguous' } : null;
}

/** Run before site retrieval. Only signed prior IDs establish the old order;
 * after a clarification, signed requested IDs can exist without a built plan.
 * catalog rows, never identity hints in a token, re-establish candidate facts.
 * resolvePlanSelection then merges against this turn's actual evidence store. */
function preparePlanEdit({ message, previousState = {}, state = {}, lastPlan, catalog } = {}) {
  const next = cloneState(state), publishedIds = ids(lastPlan?.selectedIds);
  const requestedIds = ids(previousState.selectedCandidateIds);
  const previousIds = publishedIds.length ? publishedIds : requestedIds;
  const operation = requestedEdit(message);
  // A requested stop rejected by the first plan still has a signed identity
  // that can be explicitly cancelled. Numbered edits keep the displayed order.
  const named = requestedNamedEdit(message, [...new Set([...previousIds, ...requestedIds])], catalog, lastPlan);
  if (named) named.retainedIds = named.retainedIds.filter(id => previousIds.includes(id));
  // A fresh explicit "only this venue" is also a selection constraint, even
  // before a prior plan exists. Never take prior IDs from this turn's state.
  if (!previousIds.length && !named?.only) return { state: next, edit: null };
  const changed = ['date', 'city', 'goal'].filter(field => {
    const before = field === 'date' ? previousState.date ?? lastPlan?.date : field === 'goal' ? previousState.goal ?? 'day-plan' : previousState[field];
    return normalized(before) !== normalized(state[field]);
  });
  if (changed.length) {
    next.selectedCandidateIds = next.selectedCandidateIds.filter(id => !previousIds.includes(rawId(id)));
    if (named) next.excludedCandidateIds = [...new Set([...next.excludedCandidateIds, ...named.targetIds])];
    if (named?.only) {
      next.selectedCandidateIds = named.requestedIds.filter(id => !next.excludedCandidateIds.includes(id));
      return { state: next, edit: { ...named, previousIds, retainedIds: [], changed, state: next, needsRevalidation: true } };
    }
    return { state: next, edit: { kind: 'invalidated', previousIds, changed, needsRevalidation: true, notice: 'The city, date or task changed; the previous stops must be researched again.' } };
  }
  // A generic follow-up such as "check this plan's costs" still refers to the
  // published plan. Seed retrieval with its ordered IDs before interpreting an
  // indexed edit; this preserves context without locking the model's selection.
  const excluded = new Set(next.excludedCandidateIds.map(rawId));
  next.selectedCandidateIds = previousIds.filter(id => !excluded.has(id));
  if (named) {
    next.excludedCandidateIds = [...new Set([...next.excludedCandidateIds, ...named.targetIds])];
    const retainedIds = named.retainedIds.filter(id => !next.excludedCandidateIds.includes(id));
    next.selectedCandidateIds = [...new Set([...retainedIds, ...named.requestedIds])].filter(id => !next.excludedCandidateIds.includes(id));
    return { state: next, edit: { ...named, previousIds, retainedIds, state: next, needsRevalidation: true } };
  }
  if (!operation) return { state: next, edit: null };
  if (operation.kind === 'ambiguous' || operation.index >= previousIds.length) {
    return { state: next, edit: { kind: 'invalid', previousIds, needsRevalidation: true, notice: operation.kind === 'ambiguous' ? 'Choose one numbered stop to modify at a time.' : 'That stop number is not in the previous plan.' } };
  }
  const targetId = previousIds[operation.index];
  const retainedIds = previousIds.filter((_, index) => index !== operation.index);
  const catalogIds = new Set([...array(catalog?.events), ...array(catalog?.places)].map(row => row.id));
  const missingIds = retainedIds.filter(id => !catalogIds.has(id));
  next.excludedCandidateIds = [...new Set([...next.excludedCandidateIds, targetId])];
  next.selectedCandidateIds = retainedIds.filter(id => !next.excludedCandidateIds.includes(id) && !next.excludedCandidateIds.includes(`event:${id}`) && !next.excludedCandidateIds.includes(`place:${id}`));
  return { state: next, edit: { ...operation, targetId, previousIds, retainedIds, missingIds, needsRevalidation: missingIds.length > 0,
    state: next, notice: missingIds.length ? 'Some previous web discoveries must be verified again before they can stay in this plan.' : null } };
}

/** Pure merge for BOTH create_plan and the final fallback. The engine checks
 * each current candidate again; stale web identity refs are not candidates.
 * proposed IDs can nominate a replacement, but cannot reorder surviving stops.
 * An empty selection MUST be treated by the caller as an explicitly empty edit,
 * not as permission to run the normal automatic three-stop selection again. */
function resolvePlanSelection({ edit, candidateIds, candidates, now = Date.now(), locale = 'zh-Hans' } = {}) {
  if (!edit || ['invalidated', 'invalid'].includes(edit.kind)) return { selectedIds: candidateIds === undefined ? undefined : ids(candidateIds), explicitSelection: false, needsRevalidation: !!edit?.needsRevalidation, missingIds: [], notice: edit?.notice || null };
  const rows = candidates instanceof Map ? [...candidates.values()] : array(candidates);
  const map = new Map(rows.filter(row => row && !row.isOrigin).map(row => [row.id, row]));
  const invalidIds = [], missingIds = [], valid = new Map();
  const eligible = id => {
    if (valid.has(id)) return valid.get(id);
    const row = map.get(id);
    if (!row) { missingIds.push(id); valid.set(id, false); return false; }
    const result = buildItinerary({ state: edit.state, candidates: [row], selectedIds: [id], now, locale });
    const fit = result.stops.some(stop => stop.entityId === id) && !result.checks.some(check => check.status === 'fail');
    if (!fit) invalidIds.push(id);
    valid.set(id, fit); return fit;
  };
  const retainedIds = edit.retainedIds.filter(eligible);
  let replacementId;
  if (edit.kind === 'replace') {
    const retainedCity = normalized(map.get(retainedIds[0])?.city || edit.state.city);
    const proposed = ids(candidateIds).filter(id => id !== edit.targetId && !edit.previousIds.includes(id));
    const other = rows.filter(row => !row.isOrigin && row.id !== edit.targetId && !edit.previousIds.includes(row.id)).map(row => row.id);
    // Keep the previous day's geographic cluster when route evidence is absent.
    const sameArea = id => !retainedCity || normalized(map.get(id)?.city) === retainedCity;
    replacementId = [...new Set([...proposed, ...other])].find(id => sameArea(id) && eligible(id));
  }
  const requestedIds = [];
  if (edit.named && edit.only) for (const name of edit.keepNames) {
    if (retainedIds.some(id => namesOf(map.get(id)).includes(name))) continue;
    const matches = [...map.values()].filter(row => !edit.targetIds.includes(row.id) && namesOf(row).includes(name) && eligible(row.id));
    // Do not turn two similarly named search discoveries into two visits.
    const published = matches.filter(row => row.origin !== 'web');
    const unambiguous = published.length === 1 ? published : matches;
    if (unambiguous.length === 1) requestedIds.push(unambiguous[0].id);
  }
  const selectedIds = edit.named ? [...new Set([...retainedIds, ...requestedIds.filter(eligible)])].slice(0, 6)
    : edit.previousIds.flatMap((id, index) => index === edit.index ? replacementId ? [replacementId] : [] : retainedIds.includes(id) ? [id] : []);
  const revalidate = [...new Set([...missingIds, ...invalidIds])];
  const unresolvedRequested = edit.named && edit.only && edit.keepNames.some(name => !selectedIds.some(id => namesOf(map.get(id)).includes(name)));
  const needsRevalidation = revalidate.length > 0 || unresolvedRequested || (edit.kind === 'replace' && !replacementId);
  return { selectedIds, explicitSelection: true, suppressAlternatives: !!(edit.named && edit.only), replacementId: replacementId || null, retainedIds,
    needsRevalidation, missingIds: [...new Set(missingIds)], invalidIds: [...new Set(invalidIds)],
    notice: needsRevalidation ? locale === 'en' ? 'Other usable stops retain their original order. A missing or incompatible stop needs fresh verification; no replacement was invented.'
      : locale === 'zh-Hant' ? '其餘可用站點保留原順序；缺少資料或不符合條件的站點仍需重新核實，未虛構替代地點。'
        : '其余可用站点保留原顺序；缺少资料或不符合条件的站点仍需重新核实，未虚构替代地点。' : null };
}

module.exports = { preparePlanEdit, resolvePlanSelection, requestedStopLimit };
