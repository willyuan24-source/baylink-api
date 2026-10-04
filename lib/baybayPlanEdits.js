const { buildItinerary } = require('./baybayPlan');

const array = value => Array.isArray(value) ? value : [];
const rawId = value => typeof value === 'string' ? value.replace(/^(?:event|place):/, '') : null;
const ids = values => [...new Set(array(values).map(rawId).filter(id => id && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,159}$/.test(id)))].slice(0, 6);
const normalized = value => String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();
const cloneState = state => ({ ...state, selectedCandidateIds: [...array(state?.selectedCandidateIds)], excludedCandidateIds: [...array(state?.excludedCandidateIds)] });

function requestedEdit(message) {
  const text = String(message || '');
  const replace = /换掉|換掉|替换|替換|换一|換一|换个|換個|換成|换成|\b(?:replace|swap|change)\b/i.test(text);
  const remove = /去掉|删掉|刪掉|删除|刪除|移除|不要|\b(?:remove|delete|drop|skip)\b/i.test(text);
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
 * catalog rows, never identity hints in a token, re-establish candidate facts.
 * resolvePlanSelection then merges against this turn's actual evidence store. */
function preparePlanEdit({ message, previousState = {}, state = {}, lastPlan, catalog } = {}) {
  const next = cloneState(state), previousIds = ids(lastPlan?.selectedIds);
  const operation = requestedEdit(message);
  if (!previousIds.length) return { state: next, edit: null };
  const changed = ['date', 'city', 'goal'].filter(field => {
    const before = field === 'date' ? previousState.date ?? lastPlan.date : field === 'goal' ? previousState.goal ?? 'day-plan' : previousState[field];
    return normalized(before) !== normalized(state[field]);
  });
  if (changed.length) {
    next.selectedCandidateIds = next.selectedCandidateIds.filter(id => !previousIds.includes(rawId(id)));
    return { state: next, edit: { kind: 'invalidated', previousIds, changed, needsRevalidation: true, notice: 'The city, date or task changed; the previous stops must be researched again.' } };
  }
  // A generic follow-up such as "check this plan's costs" still refers to the
  // published plan. Seed retrieval with its ordered IDs before interpreting an
  // indexed edit; this preserves context without locking the model's selection.
  const excluded = new Set(next.excludedCandidateIds.map(rawId));
  next.selectedCandidateIds = previousIds.filter(id => !excluded.has(id));
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
  const selectedIds = edit.previousIds.flatMap((id, index) => index === edit.index ? replacementId ? [replacementId] : [] : retainedIds.includes(id) ? [id] : []);
  const revalidate = [...new Set([...missingIds, ...invalidIds])];
  const needsRevalidation = revalidate.length > 0 || (edit.kind === 'replace' && !replacementId);
  return { selectedIds, explicitSelection: true, replacementId: replacementId || null, retainedIds,
    needsRevalidation, missingIds: [...new Set(missingIds)], invalidIds: [...new Set(invalidIds)],
    notice: needsRevalidation ? locale === 'en' ? 'Other usable stops retain their original order. A missing or incompatible stop needs fresh verification; no replacement was invented.'
      : locale === 'zh-Hant' ? '其餘可用站點保留原順序；缺少資料或不符合條件的站點仍需重新核實，未虛構替代地點。'
        : '其余可用站点保留原顺序；缺少资料或不符合条件的站点仍需重新核实，未虚构替代地点。' : null };
}

module.exports = { preparePlanEdit, resolvePlanSelection };
