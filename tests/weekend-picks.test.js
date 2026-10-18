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

// API-BB-9: the editor's weekend picks reach BayBay through an optional synced file (data/weekend-picks.json, the web's
// public/weekend-picks.json from lane WEB-PICKS-EXPORT). tests/fixtures/weekend-picks-web.json is that lane's export of
// the owner-approved 10/17–18, 10/24–25 and 10/31–11/1 picks (web commit f4efc007d). Until the real file lands there is
// no boost and no error.
const TODAY = '2026-10-17';
const WEB_FIXTURE = path.join(__dirname, 'fixtures', 'weekend-picks-web.json');
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'baybay-picks-'));
const fixture = (name, content) => { const file = path.join(dir, name); fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content)); return file; };
const withPicks = (file, run) => { const before = process.env.BAYLINK_WEEKEND_PICKS_FILE; process.env.BAYLINK_WEEKEND_PICKS_FILE = file; try { return run(); } finally { if (before === undefined) delete process.env.BAYLINK_WEEKEND_PICKS_FILE; else process.env.BAYLINK_WEEKEND_PICKS_FILE = before; } };
const candidateIds = message => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state: resolveTaskState({ message, today: TODAY, catalog: planner, carry: true }).state,
  guideCatalog: guides, catalog: planner, discoveries, today: TODAY, locale: 'zh-Hans', audience: true }).candidates.map(row => row.id);
const ASK = '10月24号周末带娃去哪玩';
const absent = path.join(dir, 'absent.json');
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

test('the picks file is optional: absent, malformed or empty files give no picks and no error', () => {
  assert.equal(loadWeekendPicks(path.join(dir, 'missing.json')).size, 0);
  assert.equal(loadWeekendPicks(fixture('broken.json', '{ not json')).size, 0);
  assert.equal(loadWeekendPicks(fixture('empty.json', { generatedAt: TODAY, weekends: [] })).size, 0);
  // The shipped data has no picks file yet (WEB-PICKS-EXPORT, then API-SYNC-3H): the default load is empty too.
  if (!process.env.BAYLINK_WEEKEND_PICKS_FILE && !fs.existsSync(path.join(__dirname, '..', 'data', 'weekend-picks.json'))) assert.deepEqual(withPicks(absent, () => candidateIds(ASK)), candidateIds(ASK));
});

test('the web export is read by its Saturday, in rank order, with each pick on the days it runs', () => {
  const picks = loadWeekendPicks(WEB_FIXTURE);
  assert.deepEqual([...picks.keys()], ['2026-10-17', '2026-10-24', '2026-10-31']);
  assert.deepEqual(picks.get('2026-10-24').map(pick => pick.id), ['r2-petaluma-lumafest-20261024', 'menlo-park-halloween-hoopla-2026',
    'sfpl-chinatown-creative-saturdays-fall-2026', 'acl-cherryland-chinese-storytimes-oct24-2026', 'san-jose-sjma-dia-muertos-community-2026']);
  for (const { id } of [...picks.values()].flat()) assert.ok(planner.events.some(row => row.id === id), `${id} is a catalog event`);
  // Saturday 10/31 has the Saturday-only picks; Sunday 11/1 only Fruitvale and Nidhi Chanani, which run that day.
  assert.deepEqual([...picksForAsk({ date: '2026-11-01' }, picks).keys()], ['nov2026-fruitvale-dia-muertos', 'smcl-foster-city-nidhi-chanani-2026']);
  assert.ok(!picksForAsk({ date: '2026-10-31' }, picks).has('nov2026-fruitvale-dia-muertos'));
  // A weekend span takes both days, each pick at its best rank; a weekday has none.
  assert.deepEqual(Object.fromEntries(picksForAsk({ dateRange: { start: '2026-10-31', end: '2026-11-01' } }, picks)), { 'mcm-halloween-spectacular-20261031': 0,
    'nov2026-fruitvale-dia-muertos': 1, 'sfpl-chinatown-creative-saturdays-fall-2026': 2, 'san-jose-avenida-altares-2026': 3, 'smcl-foster-city-nidhi-chanani-2026': 4 });
  assert.equal(picksForAsk({ date: '2026-10-22' }, picks).size, 0);
  // Review of API-BB-9: Friday to Sunday is still a weekend; a longer span (a week, a month) takes no picks.
  assert.deepEqual([...picksForAsk({ dateRange: { start: '2026-10-23', end: '2026-10-25' } }, picks).keys()], picks.get('2026-10-24').map(pick => pick.id));
  assert.equal(picksForAsk({ dateRange: { start: '2026-10-22', end: '2026-10-25' } }, picks).size, 0);
  assert.equal(picksForAsk({ dateRange: { start: '2026-10-01', end: '2026-10-31' } }, picks).size, 0);
});

test('a map of id lists is read too; invalid, repeated or non-event picks are dropped', () => {
  assert.equal(saturdayOf('2026-10-25'), '2026-10-24'); assert.equal(saturdayOf('2026-10-22'), '2026-10-24');
  const map = loadWeekendPicks(fixture('map.json', { weekends: { '2026-10-24': ['a-1', 'bad id', 'a-2', 'a-1', { id: 'p-1', kind: 'place' }], 'not-a-day': ['x'] } }));
  assert.deepEqual([...map.entries()], [['2026-10-24', [{ id: 'a-1', dates: null }, { id: 'a-2', dates: null }]]]);
  assert.deepEqual([...picksForAsk({ date: '2026-10-25' }, map).entries()], [['a-1', 0], ['a-2', 1]]);
  // A pick whose days all fall outside its weekend is not a pick.
  const off = loadWeekendPicks(fixture('off.json', { weekends: [{ start: '2026-10-24', end: '2026-10-25', picks: [{ id: 'b-1', kind: 'event', rank: 1, dates: ['2026-10-31'] }] }] }));
  assert.equal(off.size, 0);
});

// Review of API-BB-9: the baselines are computed with no picks file, so these tests still hold once API-SYNC-3H ships
// data/weekend-picks.json (with it, the default load already has the picks).
test('on its own weekend a pick ranks higher for a generic family weekend ask, and nowhere else', () => {
  const base = withPicks(absent, () => candidateIds(ASK));
  const boosted = withPicks(WEB_FIXTURE, () => candidateIds(ASK));
  // Before: the day's family records in id order (Cherryland storytime first). With the picks: Petaluma's LumaFest,
  // Menlo Park's Halloween Hoopla, Cherryland and SJMA lead, in the editor's order. API-BB-12: with no picks file LumaFest
  // can now come last, through the day recall (which no longer offers the adults' 华埠分馆周六午后 on a family ask); it does
  // not lead, and Hoopla is still not offered.
  assert.ok(!base.slice(0, 4).includes('r2-petaluma-lumafest-20261024') && !base.includes('menlo-park-halloween-hoopla-2026'), base.join(', '));
  assert.deepEqual(boosted.slice(0, 4), ['r2-petaluma-lumafest-20261024', 'menlo-park-halloween-hoopla-2026', 'acl-cherryland-chinese-storytimes-oct24-2026', 'san-jose-sjma-dia-muertos-community-2026'], boosted.join(', '));
  // The same picks filed under another weekend change nothing for the 10/24 ask.
  const elsewhere = fixture('picks-1031.json', { weekends: { '2026-10-31': loadWeekendPicks(WEB_FIXTURE).get('2026-10-24').map(pick => pick.id) } });
  assert.deepEqual(withPicks(elsewhere, () => candidateIds(ASK)), base);
  // A topic ask is not a generic weekend ask: no boost.
  const topicAsk = '10月24号周末旧金山有什么音乐会';
  assert.deepEqual(withPicks(WEB_FIXTURE, () => candidateIds(topicAsk)), withPicks(absent, () => candidateIds(topicAsk)));
  // Nor is a month ask: its span is longer than a weekend.
  const monthAsk = '10月带娃去哪玩';
  assert.deepEqual(withPicks(WEB_FIXTURE, () => candidateIds(monthAsk)), withPicks(absent, () => candidateIds(monthAsk)));
});

test('a city family ask takes the weekend\'s pick first among records of equal fit, and only on the day it runs', () => {
  const ask = '10月24号周末 San Jose 带娃去哪玩';
  const base = withPicks(absent, () => candidateIds(ask));
  const boosted = withPicks(WEB_FIXTURE, () => candidateIds(ask));
  assert.ok(base.indexOf('san-jose-sjma-dia-muertos-community-2026') > 0, base.join(', '));
  assert.equal(boosted[0], 'san-jose-sjma-dia-muertos-community-2026', boosted.join(', '));
  assert.deepEqual([...boosted].sort(), [...base].sort(), 'the pick reorders; it adds or removes nothing');
  // Sunday 11/1: Nidhi Chanani (Sunday-only) leads; Saturday's Marin Children's Museum Halloween is not lifted that day.
  const sunday = withPicks(WEB_FIXTURE, () => candidateIds('11月1号周日带娃去哪'));
  assert.equal(sunday[0], 'smcl-foster-city-nidhi-chanani-2026', sunday.join(', '));
  assert.ok(!sunday.includes('mcm-halloween-spectacular-20261031'), sunday.join(', '));
});
