const fs = require('fs');
const path = require('path');

// API-BB-9: the web's editor weekend picks (web src/data/weekend-picks.ts), exported by the web build as
// public/weekend-picks.json (lane WEB-PICKS-EXPORT) and copied here as data/weekend-picks.json by
// scripts/sync-editorial-catalogs.js:
//   { generatedAt, weekends: [{ start: Saturday, end: Sunday, picks: [{ id, kind, rank, dates, reason_zh, reason_en, elderFriendly }] }] }
// Picks keep the editor's order (rank); `dates` are the days of that weekend the event runs. A map
// { weekends: { "YYYY-MM-DD": ["id" | { id, dates }, ...] } } is read the same way. Until the file exists there are no
// picks: no boost and no error.
const DEFAULT_FILE = path.join(__dirname, '..', 'data', 'weekend-picks.json');
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const ID = /^[A-Za-z0-9_-]{1,160}$/;
const MAX_PICKS = 12;
const cache = new Map();
const addDays = (day, days) => new Date(Date.parse(`${day}T12:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
const weekdayOf = day => new Date(`${day}T12:00:00Z`).getUTCDay();
/** The Saturday of a day's weekend (a Sunday belongs to the day before). */
const saturdayOf = day => addDays(day, weekdayOf(day) === 0 ? -1 : 6 - weekdayOf(day));

/** One weekend's picks, in the editor's order: [{ id, dates|null }], invalid or repeated ids dropped. */
function weekendPicks(saturday, entries) {
  const picks = [];
  const rankOf = (entry, index) => (Number.isInteger(entry?.rank) ? entry.rank : index + 1);
  const ordered = entries.map((entry, index) => ({ entry, index })).sort((a, b) => rankOf(a.entry, a.index) - rankOf(b.entry, b.index) || a.index - b.index);
  for (const { entry } of ordered) {
    const id = typeof entry === 'string' ? entry : entry?.id;
    if (typeof id !== 'string' || !ID.test(id) || picks.some(pick => pick.id === id)) continue;
    if (entry && typeof entry === 'object' && entry.kind !== undefined && entry.kind !== 'event') continue;
    // A pick's own days, kept to its weekend; a pick without days counts on both.
    const dates = Array.isArray(entry?.dates) ? entry.dates.filter(day => typeof day === 'string' && DAY.test(day) && saturdayOf(day) === saturday) : null;
    if (dates && !dates.length) continue;
    picks.push({ id, dates });
    if (picks.length === MAX_PICKS) break;
  }
  return picks;
}

/** Saturday → ordered picks, from a parsed picks file (anything else gives none). */
function picksFrom(raw) {
  const entries = Array.isArray(raw?.weekends) ? raw.weekends.map(row => [row?.start || row?.weekend, Array.isArray(row?.picks) ? row.picks : row?.ids])
    : raw?.weekends && typeof raw.weekends === 'object' ? Object.entries(raw.weekends) : [];
  const picks = new Map();
  for (const [day, list] of entries) {
    if (typeof day !== 'string' || !DAY.test(day) || !Array.isArray(list)) continue;
    const saturday = saturdayOf(day);
    const ordered = weekendPicks(saturday, list);
    if (ordered.length && !picks.has(saturday)) picks.set(saturday, ordered);
  }
  return picks;
}

function readPicks(file) {
  try { return picksFrom(JSON.parse(fs.readFileSync(file, 'utf8'))); } catch { return new Map(); }
}

/** Saturday → ordered picks. The file is read once per path; `BAYLINK_WEEKEND_PICKS_FILE` overrides it (tests). */
function loadWeekendPicks(file = process.env.BAYLINK_WEEKEND_PICKS_FILE || DEFAULT_FILE) {
  if (!cache.has(file)) cache.set(file, readPicks(file));
  return cache.get(file);
}

/** The pick ids of the Saturday or Sunday in an asked day or weekend span, each with its 0-based rank, counting a pick
 *  only on the days it runs. Review of API-BB-9: a span longer than a weekend (Friday to Sunday, 3 days) has none, so a
 *  month ask ("十月带娃去哪") does not take the first two weekends' picks. */
const MAX_SPAN_DAYS = 3;
function picksForAsk({ date, dateRange } = {}, picks = loadWeekendPicks()) {
  const ranks = new Map();
  if (!picks.size) return ranks;
  const start = date || dateRange?.start, end = date || dateRange?.end || start;
  if (!start || !DAY.test(start) || !DAY.test(end) || end < start || end > addDays(start, MAX_SPAN_DAYS - 1)) return ranks;
  for (let day = start; day <= end; day = addDays(day, 1)) {
    if (![0, 6].includes(weekdayOf(day))) continue;
    (picks.get(saturdayOf(day)) || []).forEach(({ id, dates }, index) => {
      if ((!dates || dates.includes(day)) && (!ranks.has(id) || ranks.get(id) > index)) ranks.set(id, index);
    });
  }
  return ranks;
}

module.exports = { loadWeekendPicks, picksForAsk, picksFrom, saturdayOf };
