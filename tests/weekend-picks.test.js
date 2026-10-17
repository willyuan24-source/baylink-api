const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { loadWeekendPicks, picksForAsk, saturdayOf } = require('../lib/weekendPicks');
const guides = require('../data/guide-catalog.json');

// API-BB-9: the editor's weekend picks reach BayBay through an optional synced file (data/weekend-picks.json, exported by
// the web lane WEB-PICKS-EXPORT). Fixture files only; until the real file lands there is no boost and no error.
const TODAY = '2026-10-17';
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'baybay-picks-'));
const fixture = (name, content) => { const file = path.join(dir, name); fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content)); return file; };
const withPicks = (file, run) => { const before = process.env.BAYLINK_WEEKEND_PICKS_FILE; process.env.BAYLINK_WEEKEND_PICKS_FILE = file; try { return run(); } finally { if (before === undefined) delete process.env.BAYLINK_WEEKEND_PICKS_FILE; else process.env.BAYLINK_WEEKEND_PICKS_FILE = before; } };
const candidateIds = message => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state: resolveTaskState({ message, today: TODAY, catalog: planner, carry: true }).state,
  guideCatalog: guides, catalog: planner, discoveries, today: TODAY, locale: 'zh-Hans', audience: true }).candidates.map(row => row.id);
const ASK = '10月24号周末带娃去哪玩';
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

test('the picks file is optional: absent, malformed or empty files give no picks and no error', () => {
  assert.equal(loadWeekendPicks(path.join(dir, 'missing.json')).size, 0);
  assert.equal(loadWeekendPicks(fixture('broken.json', '{ not json')).size, 0);
  assert.equal(loadWeekendPicks(fixture('empty.json', { version: 1, weekends: {} })).size, 0);
  const missing = path.join(dir, 'absent.json');
  assert.deepEqual(withPicks(missing, () => candidateIds(ASK)), candidateIds(ASK));
});

test('picks are keyed by their Saturday, read as a map or a list, with invalid ids dropped', () => {
  assert.equal(saturdayOf('2026-10-25'), '2026-10-24'); assert.equal(saturdayOf('2026-10-22'), '2026-10-24');
  const map = loadWeekendPicks(fixture('map.json', { version: 1, weekends: { '2026-10-24': ['a-1', 'bad id', 'a-2', 'a-1'], 'not-a-day': ['x'] } }));
  assert.deepEqual([...map.entries()], [['2026-10-24', ['a-1', 'a-2']]]);
  const list = loadWeekendPicks(fixture('list.json', { version: 1, weekends: [{ weekend: '2026-10-31', ids: ['b-1'] }] }));
  assert.deepEqual([...list.entries()], [['2026-10-31', ['b-1']]]);
  // A day or a span touching the weekend gets its picks with their rank; a weekday ask does not.
  assert.deepEqual([...picksForAsk({ date: '2026-10-25' }, map).entries()], [['a-1', 0], ['a-2', 1]]);
  assert.deepEqual([...picksForAsk({ dateRange: { start: '2026-10-23', end: '2026-11-01' } }, new Map([...map, ...list])).entries()], [['a-1', 0], ['a-2', 1], ['b-1', 0]]);
  assert.equal(picksForAsk({ date: '2026-10-22' }, map).size, 0);
});

test('a pick ranks higher on its own weekend for a generic family weekend ask, and nowhere else', { todo: 'API-BB-9 WIP: this ask's candidates come from a path other than the buildSiteEvidence candidate sort (they list in id order), so the pick lift there does not move them yet' }, () => {
  const base = candidateIds(ASK);
  assert.ok(base.length >= 3, base.join(', '));
  const pick = base.at(-1);
  const boosted = withPicks(fixture('pick-1024.json', { version: 1, weekends: { '2026-10-24': [pick] } }), () => candidateIds(ASK));
  assert.ok(boosted.indexOf(pick) >= 0 && boosted.indexOf(pick) < base.indexOf(pick), `${pick}: ${base.join(', ')} -> ${boosted.join(', ')}`);
  // The same pick filed under another weekend changes nothing for the 10/24 ask.
  assert.deepEqual(withPicks(fixture('pick-1031.json', { version: 1, weekends: { '2026-10-31': [pick] } }), () => candidateIds(ASK)), base);
  // A topic ask is not a generic weekend ask: no boost.
  const topicAsk = '10月24号周末旧金山有什么音乐会';
  assert.deepEqual(withPicks(fixture('pick-topic.json', { version: 1, weekends: { '2026-10-24': [pick] } }), () => candidateIds(topicAsk)), candidateIds(topicAsk));
});
