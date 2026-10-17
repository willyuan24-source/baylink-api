const fs = require('fs');
const path = require('path');

// API-BB-9: the web's editor weekend picks (web src/data/weekend-picks.ts), synced as data/weekend-picks.json once the
// web exports it (lane WEB-PICKS-EXPORT): { "version": 1, "weekends": { "2026-10-24": ["event-id", ...] } }, keyed by
// the weekend's Saturday, ids in the editor's order. An array of { "weekend": "YYYY-MM-DD", "ids": [...] } is read the
// same way. Until the file exists there are no picks: no boost and no error.
const DEFAULT_FILE = path.join(__dirname, '..', 'data', 'weekend-picks.json');
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const ID = /^[A-Za-z0-9_-]{1,160}$/;
const cache = new Map();
const addDays = (day, days) => new Date(Date.parse(`${day}T12:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
/** The Saturday of a day's weekend (a Sunday belongs to the day before). */
const saturdayOf = day => { const weekday = new Date(`${day}T12:00:00Z`).getUTCDay(); return addDays(day, weekday === 0 ? -1 : 6 - weekday); };

function readPicks(file) {
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return new Map(); }
  const entries = Array.isArray(raw?.weekends) ? raw.weekends.map(row => [row?.weekend || row?.start, row?.ids])
    : raw?.weekends && typeof raw.weekends === 'object' ? Object.entries(raw.weekends) : [];
  const picks = new Map();
  for (const [day, ids] of entries) {
    if (typeof day !== 'string' || !DAY.test(day) || !Array.isArray(ids)) continue;
    const ordered = [...new Set(ids.filter(id => typeof id === 'string' && ID.test(id)))].slice(0, 12);
    if (ordered.length) picks.set(saturdayOf(day), ordered);
  }
  return picks;
}

/** Saturday → ordered pick ids. The file is read once per path; `BAYLINK_WEEKEND_PICKS_FILE` overrides it (tests). */
function loadWeekendPicks(file = process.env.BAYLINK_WEEKEND_PICKS_FILE || DEFAULT_FILE) {
  if (!cache.has(file)) cache.set(file, readPicks(file));
  return cache.get(file);
}

/** The pick ids of every weekend an asked day or span (at most 16 days) touches, each with its 0-based rank. */
function picksForAsk({ date, dateRange } = {}, picks = loadWeekendPicks()) {
  const ranks = new Map();
  if (!picks.size) return ranks;
  const start = date || dateRange?.start, end = date || dateRange?.end || start;
  if (!start || !DAY.test(start) || !DAY.test(end) || end < start) return ranks;
  for (let day = start, guard = 0; day <= end && guard < 16; day = addDays(day, 1), guard++) {
    const weekday = new Date(`${day}T12:00:00Z`).getUTCDay();
    if (weekday !== 0 && weekday !== 6) continue;
    (picks.get(saturdayOf(day)) || []).forEach((id, index) => { if (!ranks.has(id) || ranks.get(id) > index) ranks.set(id, index); });
  }
  return ranks;
}

module.exports = { loadWeekendPicks, picksForAsk, saturdayOf };
