// API-STATUS: the API honours the web overlay's editorial `status` and `price` that API-SYNC (#39) copied in.
// Real catalog rows (production loaders, shipped data files), a fixed Pacific clock, no network, no paid calls.
// Owner decision 10/12: Thrive City Thrill-O-Ween stays up; no row is cancelled in the data, so a cancellation is
// only ever an in-memory copy of a different real row.
const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { loadPlannerCatalog, active, eventOccursOn, admissionLowerBound, priceOf, recommend } = require('../lib/planner');
const { loadEventCatalog, signUpClosed } = require('../lib/eventEngagement');
const { loadOutingCatalog, validateOutingInput } = require('../lib/outings');
const { buildFastEvidence, buildSiteEvidence, modelItems } = require('../lib/baybayEvidence');
const { buildItinerary } = require('../lib/baybayPlan');
const { createPublicContext } = require('../lib/publicContext');
const { eventStatus, eventHalted, soldOut } = require('../lib/eventStatus');

const NOW = Date.parse('2026-10-12T19:00:00Z'); // Mon 2026-10-12 12:00 PDT
const TODAY = '2026-10-12';
const planner = loadPlannerCatalog();
const guides = require('../data/guide-catalog.json');
const discoveries = { ...require('../data/discoveries.json'), english: require('../data/discoveries.en.json') };
const row = id => {
  const found = planner.events.find(event => event.id === id);
  assert.ok(found, id);
  return found;
};
const NAPA = 'napa-harvest-after-dark-2026'; // sold_out (official page read 10/9)
const SOUTH_SF = 'south-sf-state-of-city-2026'; // postponed, occurrenceDates []
const SAN_MATEO = 'san-mateo-downtown-market-nov5-2026'; // no status, occurrenceDates []
const THRILL = 'sf-thrive-thrill-o-ween-2026'; // owner: stays up on 10/24
const DOJA = 'sf-doja-cat-2026';
const without = (value, ...keys) => Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
const oneRow = event => ({ ...planner, events: [event], places: [] });
const suggest = async (event, filters) => (await recommend({ body: { filters }, catalog: oneRow(event), now: () => NOW })).suggestions.map(item => item.eventId);

test('the synced statuses are the ones the web overlay defines, and Thrill-O-Ween has none', () => {
  assert.equal(row(SOUTH_SF).status, 'postponed');
  assert.equal(row(NAPA).status, 'sold_out');
  assert.equal(row(THRILL).status, undefined, 'owner decision 10/12: Thrill-O-Ween stays up');
  for (const event of planner.events) assert.ok(event.status === undefined || ['postponed', 'cancelled', 'sold_out'].includes(event.status), event.id);
});

test('status semantics on real rows: postponed and cancelled never occur and are not active; sold out still takes place', () => {
  const cases = [
    // [row, status, active, [date, occurs], halted, soldOut]
    [row(SOUTH_SF), 'postponed', false, ['2026-10-27', false], true, false],
    [row(NAPA), 'sold_out', true, ['2026-10-30', true], false, true],
    [row(THRILL), null, true, ['2026-10-24', true], false, false],
    [row(DOJA), null, true, ['2026-10-25', true], false, false],
    [{ ...row(DOJA), status: 'cancelled' }, 'cancelled', false, ['2026-10-25', false], true, false],
    [{ ...row(DOJA), status: 'canceled' }, 'cancelled', false, ['2026-10-25', false], true, false],
    // A cancelled row that still lists its day (the web lint forbids it) is still not a day out.
    [{ ...row(DOJA), status: 'cancelled', occurrenceDates: ['2026-10-25'] }, 'cancelled', false, ['2026-10-25', false], true, false],
    [{ ...row(SOUTH_SF), occurrenceDates: ['2026-10-27'] }, 'postponed', false, ['2026-10-27', false], true, false],
  ];
  for (const [event, status, isActive, [date, occurs], halted, full] of cases) {
    const label = `${event.id}:${event.status}`;
    assert.equal(eventStatus(event), status, label);
    assert.equal(active(event), isActive, label);
    assert.equal(eventOccursOn(event, date), occurs, label);
    assert.equal(eventHalted(event), halted, label);
    assert.equal(soldOut(event), full, label);
  }
});

test('the planner never suggests a sold-out, postponed or cancelled event; the same rows without a status are suggested', async () => {
  const cases = [
    [row(NAPA), { date: '2026-10-30' }, [], without(row(NAPA), 'status')],
    [row(SOUTH_SF), { date: '2026-10-27' }, [], { ...without(row(SOUTH_SF), 'status'), occurrenceDates: ['2026-10-27'] }],
    [row(SOUTH_SF), {}, [], null],
    [{ ...row(DOJA), status: 'cancelled' }, { date: '2026-10-25' }, [], row(DOJA)],
    [row(THRILL), { date: '2026-10-24' }, [THRILL], null],
  ];
  for (const [event, filters, expected, control] of cases) {
    assert.deepEqual(await suggest(event, filters), expected, `${event.id} ${JSON.stringify(filters)}`);
    if (control) assert.deepEqual(await suggest(control, filters), [control.id], `${control.id} without its status`);
  }
});

test('BayBay names a sold-out or postponed event with its status, never as a candidate or plan stop', () => {
  const evidence = (query, state = { goal: 'discover' }, locale = 'zh-Hans') => buildFastEvidence({ query, originalQuery: query, state, guideCatalog: guides, catalog: planner, discoveries, today: TODAY, locale });
  const cases = [
    // [question, state, locale, id, nearMiss reason, status label]
    ['21+ · Napa Harvest After Dark 面具晚宴 还能去吗', { goal: 'discover' }, 'zh-Hans', NAPA, 'sold_out', '已售罄', /Sold out/],
    ['21+ · Napa Harvest After Dark masquerade dinner tickets', { goal: 'discover', date: '2026-10-30' }, 'en', NAPA, 'sold_out', 'sold out', /Sold out/],
    ['South San Francisco 城市近况交流会什么时候', { goal: 'information' }, 'zh-Hans', SOUTH_SF, 'postponed', '已延期，新日期未公布', /Postponed with no confirmed new date/],
    ['South San Francisco城市近況交流會', { goal: 'information' }, 'zh-Hant', SOUTH_SF, 'postponed', '已延期，新日期未公佈', /Postponed/],
  ];
  for (const [query, state, locale, id, reason, label, note] of cases) {
    const site = evidence(query, state, locale);
    assert.ok(!site.candidates.some(candidate => candidate.id === id), `${query}: not a candidate`);
    assert.equal(site.nearMiss.find(ref => ref.id === id)?.reason, reason, query);
    const item = modelItems(site.items).find(entry => entry.page === `https://www.baylink.us/events/${id}`);
    assert.ok(item, `${query}: named in the evidence`);
    assert.equal(item.status, label, query);
    assert.match(item.note, note);
    assert.match(item.note, /never recommend it/);
  }
  // A dated question for the sold-out evening's own city gets no recommendation of it (it was the only candidate before).
  const napaEvening = evidence('10月30日 Napa 晚上有什么活动', { goal: 'discover', city: 'Napa', date: '2026-10-30' });
  assert.ok(!napaEvening.candidates.some(candidate => candidate.id === NAPA));
  assert.ok(!napaEvening.items.some(item => item.catalogId === NAPA));
  // The v1 retrieval keeps the same reasons for the agent's nearMiss notes.
  const v1 = buildSiteEvidence({ query: '21+ · Napa Harvest After Dark 面具晚宴', state: { goal: 'discover' }, guideCatalog: guides, catalog: planner, today: TODAY });
  assert.equal(v1.nearMiss.find(ref => ref.id === NAPA)?.reason, 'sold_out');
  assert.ok(!v1.candidates.some(candidate => candidate.id === NAPA));
});

test('a BayBay day plan rejects sold-out and postponed real rows with their own codes and keeps Thrill-O-Ween', () => {
  const cases = [
    [row(NAPA), { date: '2026-10-30', city: 'Napa' }, 'full'],
    [row(SOUTH_SF), { date: '2026-10-27', city: 'South San Francisco' }, 'postponed'],
    [row(SOUTH_SF), { city: 'South San Francisco' }, 'postponed'],
    [{ ...row(DOJA), status: 'cancelled' }, { date: '2026-10-25', city: 'San Francisco' }, 'closed'],
    [row(THRILL), { date: '2026-10-24', city: 'San Francisco' }, null],
  ];
  for (const [event, state, code] of cases) {
    for (const locale of ['zh-Hans', 'en']) {
      const plan = buildItinerary({ state, candidates: [event], selectedIds: [event.id], now: NOW, locale });
      if (code) {
        assert.deepEqual(plan.stops, [], event.id);
        assert.equal(plan.rejectedCandidates.find(item => item.entityId === event.id)?.code, code, event.id);
      } else assert.deepEqual(plan.stops.map(stop => stop.entityId), [event.id]);
    }
  }
  const postponed = buildItinerary({ state: { city: 'South San Francisco' }, candidates: [row(SOUTH_SF)], now: NOW, locale: 'en' });
  assert.equal(postponed.rejectedCandidates[0].message, 'Postponed; no new date is confirmed.');
});

test('the page being viewed carries its editorial status; postponed reads as inactive and loses its date', () => {
  const context = createPublicContext({ catalog: planner, guideCatalog: guides });
  const cases = [
    [`/events/${NAPA}`, 'sold_out', 'upcoming'],
    [`/events/${SOUTH_SF}`, 'postponed', 'inactive'],
    [`/events/${THRILL}`, undefined, 'upcoming'],
  ];
  for (const [currentPath, status, temporal] of cases) {
    const page = context.resolve({ currentPath, today: TODAY, locale: 'zh-Hans' }).contextReferences[0];
    assert.equal(page.eventStatus, status, currentPath);
    assert.equal(page.temporalStatus, temporal, currentPath);
    assert.equal(typeof page.costLabel, 'string', 'the overlay price object never stands in for the cost label');
  }
  const dated = context.resolve({ currentPath: `/events/${SOUTH_SF}?date=2026-10-27`, today: TODAY, locale: 'en' });
  assert.equal(dated.contextReferences[0].date, undefined);
  assert.ok(dated.contextUsed.notices.includes('The selected date is not a published occurrence.'));
});

test('event interest loader merges the planner status and keeps confirmed days', () => {
  const events = loadEventCatalog();
  assert.equal(events.size, require('../data/event-catalog.json').length);
  assert.equal(events.get(SOUTH_SF).status, 'postponed');
  assert.equal(events.get(NAPA).status, 'sold_out');
  assert.equal(events.get(THRILL).status, undefined);
  assert.deepEqual(events.get(SAN_MATEO).occurrenceDates, []);
  const cases = [
    // [event, today, reason]
    [events.get(SOUTH_SF), TODAY, 'EVENT_POSTPONED'],
    [events.get(SAN_MATEO), TODAY, 'EVENT_NO_CONFIRMED_DATE'],
    [events.get(NAPA), TODAY, null],
    [events.get(THRILL), TODAY, null],
    [events.get(THRILL), '2026-10-25', 'EVENT_ENDED'],
    [events.get('pleasanton-pumpkins-after-dark-2026'), '2026-10-30', null],
    [{ ...events.get('pleasanton-pumpkins-after-dark-2026'), occurrenceDates: ['2026-10-02'] }, TODAY, 'EVENT_ENDED'],
    [{ ...events.get(DOJA), status: 'cancelled' }, TODAY, 'EVENT_CANCELLED'],
  ];
  for (const [event, today, reason] of cases) assert.equal(signUpClosed(event, today), reason, `${event.id} ${today}`);
  // Supplied rows (tests) never read the planner file; they may carry a status themselves.
  const supplied = loadEventCatalog([{ id: SOUTH_SF, title: 'x', startDate: '2026-10-27', endDate: '2026-10-27' }, { id: 'gone', title: 'y', startDate: '2026-10-27', endDate: '2026-10-27', status: 'cancelled' }]);
  assert.equal(supplied.get(SOUTH_SF).status, undefined);
  assert.equal(supplied.get('gone').status, 'cancelled');
  assert.equal(loadEventCatalog([{ id: 'bad', title: 'x', startDate: '2026-10-27', endDate: '2026-10-27', occurrenceDates: ['2026-10-28'] }]), null);
  assert.equal(loadEventCatalog([{ id: 'bad', title: 'x', startDate: '2026-10-27', endDate: '2026-10-27', occurrenceDates: '2026-10-27' }]), null);
});

const SECRET = 'isolated-event-status-test-secret-with-32+-characters';
async function interestFixture(t, { catalog, interests = [] } = {}) {
  const models = createMemoryModels({ User: ['owner', 'other', 'third'].map(id => ({ id, nickname: id, email: `${id}@private.test`, accountStatus: 'active', password: 'private' })), EventInterest: interests });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, eventNow: () => NOW, ...(catalog ? { eventCatalog: catalog } : {}) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const put = async (id, body, { as = 'owner', headers = {}, query = '' } = {}) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/events/${id}/interest${query}`, { method: 'PUT',
      headers: { Authorization: `Bearer ${jwt.sign({ id: as, sessionIssuedAt: Date.now() }, SECRET, { algorithm: 'HS256', expiresIn: '1h' })}`, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  return { put, models };
}

test('出行意向: postponed events and days without a confirmed occurrence refuse new interest with a localized code', async t => {
  const { put, models } = await interestFixture(t); // the shipped catalogs, statuses from the planner catalog
  const join = { interested: true, lookingForBuddy: true };
  const cases = [
    // [event, options, status, code, message]
    [SOUTH_SF, {}, 409, 'EVENT_POSTPONED', /^活动已延期，新日期公布前暂不能登记想去或找搭子/],
    [SOUTH_SF, { headers: { 'Accept-Language': 'en-US,en;q=0.9' } }, 409, 'EVENT_POSTPONED', /^This event has been postponed\./],
    [SOUTH_SF, { query: '?locale=zh-Hant', headers: { 'Accept-Language': 'en-US' } }, 409, 'EVENT_POSTPONED', /^活動已延期/],
    [SAN_MATEO, {}, 409, 'EVENT_NO_CONFIRMED_DATE', /^这个活动还没有确认的举办日期/],
    [SAN_MATEO, { headers: { 'Accept-Language': 'en' } }, 409, 'EVENT_NO_CONFIRMED_DATE', /no confirmed date yet/],
    [SAN_MATEO, { headers: { 'Accept-Language': 'zh-TW' } }, 409, 'EVENT_NO_CONFIRMED_DATE', /^這個活動還沒有確認的舉辦日期/],
  ];
  for (const [id, options, status, code, message] of cases) {
    for (const body of [join, { interested: true, lookingForBuddy: false }]) {
      const result = await put(id, body, options);
      assert.equal(result.status, status, `${id} ${JSON.stringify(options)}`);
      assert.equal(result.data.code, code);
      assert.match(result.data.error, message);
    }
  }
  // Sold out still takes place: interest and buddy opt-in stay open, as for Thrill-O-Ween and a confirmed day.
  for (const id of [NAPA, THRILL, 'pleasanton-pumpkins-after-dark-2026']) {
    const result = await put(id, join, { as: 'other' });
    assert.equal(result.status, 200, id);
    assert.deepEqual(result.data.me, { interested: true, lookingForBuddy: true });
  }
  assert.deepEqual(models.EventInterest.rows.map(entry => entry.eventId).sort(), [NAPA, 'pleasanton-pumpkins-after-dark-2026', THRILL].sort());
});

test('出行意向: members can still leave a postponed or cancelled event; a cancelled one answers 410 EVENT_CANCELLED', async t => {
  const interests = [SOUTH_SF, 'gone'].map(eventId => ({ eventId, userId: 'owner', interested: true, lookingForBuddy: true }));
  const shipped = await interestFixture(t, { interests });
  // Leaving the buddy list keeps the private interest; withdrawing fully is always allowed.
  assert.deepEqual((await shipped.put(SOUTH_SF, { interested: true, lookingForBuddy: false })).data.me, { interested: true, lookingForBuddy: false });
  assert.deepEqual((await shipped.put(SOUTH_SF, { interested: false, lookingForBuddy: false })).data.me, { interested: false, lookingForBuddy: false });
  assert.equal((await shipped.put(SOUTH_SF, { interested: true, lookingForBuddy: false })).status, 409, 'no new interest once withdrawn');
  const catalog = [{ id: 'gone', title: 'Cancelled copy of a real row', startDate: '2026-10-25', endDate: '2026-10-25', status: 'cancelled' },
    { id: 'over', title: 'All confirmed days past', startDate: '2026-10-02', endDate: '2026-10-31', occurrenceDates: ['2026-10-02', '2026-10-03'] }];
  const supplied = await interestFixture(t, { catalog, interests });
  const cancelled = await supplied.put('gone', { interested: true, lookingForBuddy: true }, { as: 'other' });
  assert.equal(cancelled.status, 410);
  assert.equal(cancelled.data.code, 'EVENT_CANCELLED');
  assert.match(cancelled.data.error, /^活动已取消/);
  assert.match((await supplied.put('gone', { interested: true, lookingForBuddy: true }, { as: 'other', headers: { 'Accept-Language': 'en' } })).data.error, /^This event has been cancelled, so new sign-ups are closed\./);
  assert.equal((await supplied.put('gone', { interested: true, lookingForBuddy: false })).status, 200, 'the member keeps private interest while leaving the buddy list');
  assert.equal((await supplied.put('gone', { interested: false, lookingForBuddy: false })).status, 200);
  const over = await supplied.put('over', { interested: true, lookingForBuddy: false }, { as: 'other' });
  assert.deepEqual([over.status, over.data.code, over.data.error], [410, 'EVENT_ENDED', '活动已结束，不能再报名；仍可取消已有意向。']);
  assert.equal(supplied.models.EventInterest.rows.filter(entry => entry.userId === 'other').length, 0);
});

test('outings cannot be tied to a postponed or cancelled event; a sold-out evening can', () => {
  const outings = loadOutingCatalog();
  assert.equal(outings.get(SOUTH_SF).status, 'postponed');
  assert.equal(outings.get(NAPA).status, 'sold_out');
  const input = overrides => ({ title: '一起去看看', description: '公共场所集合', city: 'Napa', venue: 'Paraduxx 门口', capacity: 3, costNote: '各自购票',
    transport: 'own', language: 'any', startTime: '18:00', endTime: '21:00', ...overrides });
  const before = Date.parse('2026-10-12T19:00:00Z');
  const cases = [
    [outings, { eventId: SOUTH_SF, date: '2026-10-27' }, 'EVENT_POSTPONED'],
    [loadOutingCatalog([{ id: 'gone', title: 'Cancelled', startDate: '2026-10-25', endDate: '2026-10-25', status: 'cancelled' }]), { eventId: 'gone', date: '2026-10-25' }, 'EVENT_CANCELLED'],
    [outings, { eventId: NAPA, date: '2026-10-30' }, null],
  ];
  for (const [catalog, overrides, code] of cases) {
    if (code) assert.throws(() => validateOutingInput(input(overrides), catalog, before), error => error.code === code && error.status === 400, overrides.eventId);
    else assert.equal(validateOutingInput(input(overrides), catalog, before).eventId, overrides.eventId);
  }
});

test('saved plans refuse a postponed or cancelled stop (410 with a code) and keep a sold-out one (201)', async t => {
  const models = createMemoryModels({ User: [{ id: 'owner', email: 'owner@private.test', accountStatus: 'active', password: 'private' }] });
  const cancelledDoja = { ...row(DOJA), status: 'cancelled' };
  const catalog = { ...planner, events: [...planner.events.filter(event => event.id !== DOJA), cancelledDoja] };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET }, models, plannerCatalog: catalog, plannerNow: () => NOW });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const save = async (id, date) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/planner/plans`, { method: 'POST',
      headers: { Authorization: `Bearer ${jwt.sign({ id: 'owner' }, SECRET, { expiresIn: '1h' })}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Plan', date, stops: [{ kind: 'event', id }] }) });
    return { status: response.status, data: await response.json() };
  };
  const cases = [
    [SOUTH_SF, '2026-10-27', 410, 'EVENT_POSTPONED'],
    [DOJA, '2026-10-25', 410, 'EVENT_CANCELLED'],
    [NAPA, '2026-10-30', 201, undefined],
    [THRILL, '2026-10-24', 201, undefined],
  ];
  for (const [id, date, status, code] of cases) {
    const result = await save(id, date);
    assert.equal(result.status, status, id);
    assert.equal(result.data.code, code, id);
  }
});

test('budget checks read the overlay price before the planning amount and the cost-label parser (real rows)', () => {
  const cases = [
    // [id, lower bound with the overlay, legacy bound without it]
    ['pleasanton-pumpkins-after-dark-2026', 22.8, null], // age tiers $28.80 / $22.80 / under 4 free
    ['stanford-halloween-concert-2026', 27, 32], // public $32; 65+ or other students $27
    ['fremont-fog-diwali-mela-2026', 5, 0.22], // the parser took the $0.22 fee for a ticket
    ['half-moon-bay-pumpkin-festival-2026', 0, null], // free entry, extras paid
    ['nov2026-botanical-one-day-choir', 0, null], // Free–$75 tiers
    ['napa-tulocay-heritage-halloween-tour-2026', 45, 45],
    ['sf-opera-figaro-opening-2026', 30, 30],
    [DOJA, null, null], // no overlay price: unchanged
  ];
  for (const [id, bound, legacy] of cases) {
    assert.equal(admissionLowerBound(row(id)), bound, id);
    assert.equal(admissionLowerBound(without(row(id), 'price')), legacy, `${id} without price`);
  }
  for (const event of planner.events.filter(item => item.price)) {
    assert.equal(admissionLowerBound(event), event.price.free ? 0 : event.price.min ?? admissionLowerBound(without(event, 'price')), event.id);
  }
  // A malformed price is ignored; the quoted known price (priceOf) is unchanged by the overlay.
  for (const price of ['free', null, [], { min: -1 }, { min: Number.NaN }, { min: '20' }, { free: 'yes' }, { max: 40 }]) assert.equal(admissionLowerBound({ ...row('stanford-halloween-concert-2026'), price }), 32, JSON.stringify(price));
  assert.equal(priceOf(row('stanford-halloween-concert-2026')), 32);
});

test('planner and BayBay budgets follow the overlay lower bound (Stanford 65+ ticket, Pleasanton age tiers)', async () => {
  const stanford = row('stanford-halloween-concert-2026'), pleasanton = row('pleasanton-pumpkins-after-dark-2026');
  const cases = [
    // [event, date, per-person budget, suggested]
    [stanford, '2026-10-30', 30, true], // was rejected at $32
    [stanford, '2026-10-30', 25, false],
    [pleasanton, '2026-10-24', 20, false], // was kept as "unknown"
    [pleasanton, '2026-10-24', 25, true],
  ];
  for (const [event, date, budget, expected] of cases) {
    assert.deepEqual(await suggest(event, { date, budget }), expected ? [event.id] : [], `${event.id} $${budget}`);
    const site = buildSiteEvidence({ query: `${event.city} ${event.title}`, state: { goal: 'discover', city: event.city, date, budget }, guideCatalog: guides, catalog: planner, today: TODAY });
    assert.equal(site.candidates.some(candidate => candidate.id === event.id), expected, `BayBay ${event.id} $${budget}`);
  }
  // Kept only by the cheaper tier: never reported as a known budget match, and the general $32 stays visible.
  for (const [locale, text] of [['zh-Hans', /只有部分票种在预算内：最低 \$27，已知普通入场 \$32/], ['en', /Only some tickets fit this budget: from \$27, while the listed admission is \$32/]]) {
    const [tier] = (await recommend({ body: { filters: { date: '2026-10-30', budget: 30 }, locale }, catalog: oneRow(stanford), now: () => NOW })).suggestions;
    assert.equal(tier.budgetStatus, 'unknown', locale);
    assert.match(tier.unknowns.join(' '), text);
  }
  const [general] = (await recommend({ body: { filters: { date: '2026-10-30', budget: 40 } }, catalog: oneRow(stanford), now: () => NOW })).suggestions;
  assert.equal(general.budgetStatus, 'known');
  assert.doesNotMatch(general.unknowns.join(' '), /只有部分票种/);
});
