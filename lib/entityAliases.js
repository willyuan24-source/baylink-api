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
module.exports = { namedEntities, dateRangeFor, aliasesFor };
