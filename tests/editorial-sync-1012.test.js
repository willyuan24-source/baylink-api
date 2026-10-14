const test = require('node:test');
const assert = require('node:assert/strict');
const { loadPlannerCatalog, eventOccursOn, active } = require('../lib/planner');
const { loadEventCatalog } = require('../lib/eventEngagement');
const { loadDiscoveryCatalog } = require('../lib/publicContext');

// API-SYNC from web main 5cd9f48c (Wave 2 overlay + CNT-HOTFIX, official pages read 10/12).
// Production loaders, shipped data files; no network.
const planner = loadPlannerCatalog();
const events = loadEventCatalog();
const event = id => planner.events.find(row => row.id === id);
const opening = (english, id) => loadDiscoveryCatalog(undefined, english).items.find(row => row.kind === 'opening' && row.id === id);

// Web CNT-HOTFIX-2 (H70, c10a856b): the official site no longer gives a brunch start date, so 10/17 is unconfirmed (call first)
// instead of "no brunch on 10/17". The 10/18 label stays.
test('Old Post Office brunch from 10/18, Saturday 10/17 unconfirmed, in both languages (audit G03, H70)', () => {
  const zh = opening(false, 'old-post-office-burlingame');
  const en = opening(true, 'old-post-office-burlingame');
  assert.match(zh.dateLabel, /早午餐 10\/18 起/);
  assert.match(zh.details[0], /10\/17 周六是否供应未能确认，去前先打 650-502-1000/);
  assert.doesNotMatch(zh.details[0], /10\/17 周六还没有早午餐/);
  assert.match(en.dateLabel, /brunch from Oct 18/);
  assert.match(en.details[0], /brunch on Saturday, Oct 17 is unconfirmed, so call \(650\) 502-1000/);
});

test('moved and unconfirmed dates agree across the planner and event catalogs', () => {
  const doja = event('sf-doja-cat-2026');
  // The interest loader now keeps confirmed days (API-STATUS).
  assert.deepEqual(events.get(doja.id), { id: doja.id, startDate: '2026-10-25', endDate: '2026-10-25', occurrenceDates: ['2026-10-25'] });
  assert.equal(eventOccursOn(doja, '2026-10-25'), true);
  assert.equal(eventOccursOn(doja, '2026-10-19'), false);
  const market = event('san-mateo-downtown-market-nov5-2026');
  assert.deepEqual(market.occurrenceDates, []);
  assert.equal(eventOccursOn(market, '2026-11-05'), false);
  const postponed = event('south-sf-state-of-city-2026');
  assert.equal(postponed.status, 'postponed');
  assert.deepEqual(postponed.occurrenceDates, []);
  assert.equal(eventOccursOn(postponed, '2026-10-27'), false);
});

test('Thrive City Thrill-O-Ween stays on 10/24 (owner decision 10/12)', () => {
  const thrill = event('sf-thrive-thrill-o-ween-2026');
  assert.equal(active(thrill), true);
  assert.equal(eventOccursOn(thrill, '2026-10-24'), true);
});
