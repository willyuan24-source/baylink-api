const { loadPlannerCatalog, eventOccursOn } = require('./planner');
const { bayAreaDate } = require('./eventEngagement');
const { normalizeContentContext } = require('./contentContextContract');
function safeSourceUrl(value) {
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.toString() : ''; } catch { return ''; }
}
const ID = /^[A-Za-z0-9_-]{1,160}$/;
const KINDS = ['guide', 'event', 'place', 'offer', 'opening'];
const invalid = () => Object.assign(new Error('Selected public content is invalid'), { status: 400 });
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const WEEKDAYS = { 'zh-Hans': '日一二三四五六', 'zh-Hant': '日一二三四五六' };
const EN_WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const EN_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** "10月10日（周六）" / "10月10日（週六）" / "Sat, Oct 10": readers and the model
 * see the weekday instead of a bare ISO date. Invalid dates add nothing. */
function dayLabel(value, locale) {
  if (typeof value !== 'string' || !ISO_DATE.test(value)) return '';
  const date = new Date(`${value}T12:00:00Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) return '';
  const month = date.getUTCMonth(), day = date.getUTCDate(), weekday = date.getUTCDay();
  if (locale === 'en') return `${EN_WEEKDAYS[weekday]}, ${EN_MONTHS[month]} ${day}`;
  return `${month + 1}月${day}日（${locale === 'zh-Hant' ? '週' : '周'}${WEEKDAYS[locale === 'zh-Hant' ? 'zh-Hant' : 'zh-Hans'][weekday]}）`;
}
function dateText({ date, start, end }, locale) {
  if (date) return dayLabel(date, locale);
  const first = dayLabel(start, locale), last = dayLabel(end, locale);
  if (!first) return last;
  return last && end !== start ? `${first}${locale === 'en' ? ' – ' : ' 至 '}${last}` : first;
}
function loadDiscoveryCatalog(value, english = false) {
  if (value) return value;
  for (const path of english ? ['../data/discoveries.en.json', '../data/discovery-context.en.json'] : ['../data/discoveries.json', '../data/discovery-context.json']) {
    try { return require(path); } catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
  }
  return { items: [] };
}
function createPublicContext({ catalog: inputCatalog, guideCatalog = [], englishGuideCatalog = [], discoveryCatalog, discoveryCatalogEn } = {}) {
  const catalog = loadPlannerCatalog(inputCatalog) || { events: [], places: [], guides: [] }, records = new Map();
  for (const [kind, rows] of [['event', catalog.events], ['place', catalog.places], ['guide', guideCatalog]]) for (const row of rows || []) records.set(`${kind}:${kind === 'guide' ? row.slug : row.id}`, { kind, id: kind === 'guide' ? row.slug : row.id, row });
  for (const row of loadDiscoveryCatalog(discoveryCatalog)?.items || []) if (['offer', 'opening'].includes(row.kind) && ID.test(row.id)) records.set(`${row.kind}:${row.id}`, { kind: row.kind, id: row.id, row });
  const englishGuides = englishGuideCatalog instanceof Map ? [...englishGuideCatalog.values()] : englishGuideCatalog;
  const english = new Map([...englishGuides.map(row => [`guide:${row.slug}`, row]), ...(loadDiscoveryCatalog(discoveryCatalogEn, true)?.items || []).map(row => [`${row.kind}:${row.id}`, row])]);
  function card({ kind, id, row: canonical }, today, date, locale) {
    const translation = locale === 'en' ? english.get(`${kind}:${id}`) : null;
    const row = { ...canonical, ...(translation ? Object.fromEntries(['title', 'summary', 'details', 'costLabel'].filter(key => translation[key] !== undefined).map(key => [key, translation[key]])) : {}) };
    const start = row.startDate || row.date, end = row.endDate || row.date;
    const edition = row.editionMonth || (kind === 'guide' ? String(id).match(/(20\d{2}-\d{2})(?:$|-)/)?.[1] : '');
    const temporalStatus = row.active === false || ['inactive', 'ended', 'expired'].includes(row.status) ? 'inactive' : date && date < today || end && end < today || edition && edition < today.slice(0, 7) || kind === 'event' && Array.isArray(row.occurrenceDates) && !row.occurrenceDates.some(value => value >= today) ? 'past' : date && date > today || start && start > today || kind === 'opening' && ['announced', 'coming-soon'].includes(row.status) ? 'upcoming' : start && end || kind === 'place' || row.status === 'open' ? 'current' : 'unknown';
    const url = kind === 'guide' ? `/guides/${id}` : kind === 'place' ? row.guideSlug && ID.test(row.guideSlug) ? `/guides/${row.guideSlug}` : '/explore' : `/${{ event: 'events', offer: 'offers', opening: 'openings' }[kind]}/${id}`;
    const dates = kind === 'guide' ? '' : dateText({ date, start, end }, locale);
    return { kind, id, title: String(row.title || row.name || id).slice(0, 300), url, summary: String(row.summary || row.description || '').slice(0, 1600), temporalStatus, ...(date ? { date } : {}), ...(start ? { startDate: start } : {}), ...(end ? { endDate: end } : {}), ...(dates ? { dateText: dates } : {}), ...(typeof row.dateLabel === 'string' && row.dateLabel.trim() && !(locale === 'en' && /[\u3400-\u9fff]/u.test(row.dateLabel)) ? { dateLabel: row.dateLabel.slice(0, 200) } : {}), ...(row.city ? { city: row.city } : {}), ...(typeof row.venue === 'string' && row.venue.trim() ? { venue: row.venue.slice(0, 200) } : {}), ...(row.costLabel || row.price ? { costLabel: row.costLabel || row.price } : {}), details: (row.details || row.plan || []).filter(value => typeof value === 'string').slice(0, 8), sourceUrl: safeSourceUrl(row.sourceUrl || row.officialUrl) || '', verifiedAt: row.verifiedAt || row.updatedAt || catalog.checkedAt };
  }
  function resolve({ context = {}, currentPath = '/', today = bayAreaDate(Date.now()), locale = 'zh-Hans' } = {}) {
    const parsed = normalizeContentContext(context, locale);
    const refs = parsed.references;
    let page;
    try { const url = new URL(currentPath, 'https://www.baylink.us'); const match = /^\/(guides|events|offers|openings)\/([A-Za-z0-9_-]+)\/?$/.exec(url.pathname); if (match && currentPath.startsWith('/') && !currentPath.startsWith('//')) page = { kind: { guides: 'guide', events: 'event', offers: 'offer', openings: 'opening' }[match[1]], id: match[2], ...(url.searchParams.get('date') ? { date: url.searchParams.get('date') } : {}) }; } catch { /* invalid paths add no authority */ }
    const selected = [], notices = [...parsed.notices], used = [];
    for (const ref of [...refs, ...(page && !parsed.explicitReferences ? [page] : [])]) {
      if (!ref || !KINDS.includes(ref.kind) || typeof ref.id !== 'string' || !ID.test(ref.id)) throw invalid();
      if (used.some(value => value.kind === ref.kind && value.id === ref.id)) continue;
      const record = records.get(`${ref.kind}:${ref.id}`);
      if (!record) { notices.push(locale === 'en' ? 'A selected item is no longer published.' : '选中项目尚未发布或已下架。'); continue; }
      let date;
      if (ref.date !== undefined) {
        if (ref.kind === 'event' && /^\d{4}-\d{2}-\d{2}$/.test(ref.date) && eventOccursOn(record.row, ref.date)) date = ref.date;
        else notices.push(locale === 'en' ? 'The selected date is not a published occurrence.' : '所选日期不属于已发布场次，未据此安排日期。');
      }
      used.push({ kind: ref.kind, id: ref.id, ...(date ? { date } : {}) });
      selected.push(card(record, today, date, locale));
      if (['past', 'inactive'].includes(selected.at(-1).temporalStatus)) notices.push(locale === 'en' ? 'This published item is past or inactive; use it as reference material.' : '选中项目已过期或暂停，仅供了解，不能当作当前可参加项目。');
      if (selected.length === 3) break;
    }
    return { contextReferences: selected, contextUsed: { references: used, ...(parsed.preferences ? { preferences: parsed.preferences } : {}), notices } };
  }
  return { resolve, records, card, catalog };
}
module.exports = { createPublicContext, loadDiscoveryCatalog };
