const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog, eventOccursOn, active, admissionLowerBound } = require('../lib/planner');
const { loadEventCatalog } = require('../lib/eventEngagement');
const zh = require('../data/guide-catalog.json');
const en = require('../data/guide-catalog.en.json');

// API-SYNC-2 from web main c626e77d (Wave 3 + Wave 4: CNT-SUPPLY's sourced events, CNT-GUIDES pillar facts; pages read 10/12).
// Production loaders, shipped data files; no network.
const planner = loadPlannerCatalog();
const events = loadEventCatalog();
const event = id => planner.events.find(row => row.id === id);
const guide = (rows, slug) => rows.find(row => row.slug === slug).content;

test('CNT-SUPPLY events arrive with their confirmed sessions and prices in both catalogs', () => {
  const storytime = event('smcl-millbrae-chinese-storytime-oct-2026');
  assert.deepEqual(storytime.sessions, [{ date: '2026-10-18', start: '10:30', end: '11:00' }, { date: '2026-10-25', start: '10:30', end: '11:00' }]);
  assert.equal(eventOccursOn(storytime, '2026-10-25'), true);
  assert.equal(eventOccursOn(storytime, '2026-10-19'), false);
  const trot = event('sv-turkey-trot-2026');
  assert.equal(trot.sessions[0].start, '08:30');
  assert.equal(admissionLowerBound(trot), 27.5);
  const vintage = event('petaluma-vintage-market-nov15-2026');
  assert.equal(admissionLowerBound(vintage), 0);
  assert.equal(vintage.sessions[0].start, undefined, 'the November hours are not published yet');
  for (const id of ['sj-veterans-day-parade-2026', 'chsa-taiwanese-chinese-roots-seminar-2026', 'sv-turkey-trot-2026']) {
    assert.ok(active(event(id)), id);
    assert.deepEqual(events.get(id).occurrenceDates, event(id).occurrenceDates, id);
  }
});

test('BayBay guide facts from CNT-GUIDES: SSN on an immigrant visa, the DMV test in Chinese, applying for Medi-Cal', () => {
  const newcomer = guide(zh, 'bay-area-newcomer-first-month-checklist');
  assert.match(newcomer, /入境满 3 周还没收到/);
  assert.match(newcomer, /1-800-772-1213/);
  assert.match(guide(en, 'bay-area-newcomer-first-month-checklist'), /3 weeks after you were admitted/);
  assert.match(guide(zh, 'california-driver-license-id-preparation-guide'), /中文版加州驾驶手册和中文 C 类笔试练习题/);
  assert.match(guide(en, 'california-driver-license-id-preparation-guide'), /practice tests in Chinese/);
  assert.match(guide(zh, 'bay-area-medicare-hicap-medi-cal-guide'), /DHCS 列出四种申请 Medi-Cal 的方式/);
  assert.match(guide(en, 'bay-area-medicare-hicap-medi-cal-guide'), /four ways to apply for Medi-Cal/);
  for (const rows of [zh, en]) assert.match(guide(rows, 'bay-area-newcomer-first-month-checklist'), /800-300-1533.*800-339-8938/s);
});

test('Thrive City Thrill-O-Ween stays up on 10/24 (owner decision)', () => {
  const thrill = event('sf-thrive-thrill-o-ween-2026');
  assert.equal(thrill.status, undefined);
  assert.ok(active(thrill));
  assert.equal(eventOccursOn(thrill, '2026-10-24'), true);
});
