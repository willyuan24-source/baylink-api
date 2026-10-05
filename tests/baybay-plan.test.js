const test = require('node:test');
const assert = require('node:assert/strict');
const { buildItinerary, replaceItineraryStop } = require('../lib/baybayPlan');

const NOW = Date.parse('2026-10-04T16:00:00Z');
const DATE = '2026-10-05';
const SOURCE = 'https://example.org/visit';
const baseState = { date: DATE, city: 'Fremont', origin: 'Fremont station', startTime: '09:00', finishBy: '17:00', partySize: 2, childAges: [], travelMode: 'transit', budget: 100, budgetScope: 'total' };
const place = (id, fields = {}) => ({ id, kind: 'place', title: `Place ${id}`, city: 'Fremont', region: 'east-bay', officialUrl: SOURCE,
  sourceIds: [`source-${id}`], location: { lat: 37.55, lng: -121.98, precision: 'venue' },
  planning: { admissionUsd: 0, reservation: 'none', schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', validFrom: DATE, validThrough: DATE, dates: { [DATE]: [{ open: '10:00', close: '16:00' }] } } }, ...fields });
const event = (id, fields = {}) => ({ ...place(id), kind: 'event', startDate: DATE, endDate: DATE, ...fields });
const route = (from, to, time, durationMinutes = 15, fields = {}) => ({ from: { id: from }, to: { id: to }, durationMinutes, date: DATE, departureTime: time, checkedAt: new Date(NOW).toISOString(), travelMode: 'transit', provider: 'google-maps', ...fields });
const build = (candidates, state = {}, extra = {}) => buildItinerary({ candidates, state: { ...baseState, ...state }, now: NOW, ...extra });
const check = (plan, code) => plan.checks.filter(item => item.code === code);

test('opening windows stay distinct from suggested visits and preserve exact source', () => {
  const plan = build([place('museum')], {}, { travelEstimates: [route('origin', 'museum', '09:00'), route('museum', 'origin', '11:00')] });
  const stop = plan.stops[0];
  assert.equal(stop.startTime, '10:00');
  assert.equal(stop.endTime, '11:00');
  assert.equal(stop.timeStatus, 'suggested');
  assert.deepEqual(stop.openingWindows, [{ open: '10:00', close: '16:00' }]);
  assert.deepEqual(stop.sourceIds, ['source-museum']);
  assert.deepEqual(stop.sourceUrls, [SOURCE]);
  assert.match(stop.notes.join(' '), /不代表已预约/);
  assert.equal(plan.returnTime, '11:15');
  assert.equal(plan.status, 'needs_verification'); // Meals/transport are not zero.
  assert.ok(plan.budget.unknownItems.length);
});

test('missing route produces no fabricated sequential timetable', () => {
  const plan = build([place('a'), place('b')]);
  assert.equal(plan.stops[0].startTime, undefined);
  assert.equal(plan.stops[1].startTime, undefined);
  assert.equal(plan.stops[1].endTime, undefined);
  assert.equal(plan.returnTime, undefined);
  assert.equal(check(plan, 'travel_time').length, 2);
  assert.equal(check(plan, 'return_time')[0].status, 'unknown');
});

test('a route for another date, mode, departure time or expired check is not reused', () => {
  for (const fields of [{ date: '2026-10-06' }, { travelMode: 'drive' }, { departureTime: '12:00' }, { checkedAt: '2026-10-01T16:00:00Z' }, { checkedAt: '2026-10-05T16:00:00Z' }, { provider: undefined }, { durationMinutes: -5 }]) {
    const plan = build([place('a')], {}, { travelEstimates: [route('origin', 'a', '09:00', 15, fields)] });
    assert.equal(plan.stops[0].startTime, undefined, JSON.stringify(fields));
    assert.equal(check(plan, 'travel_time')[0].status, 'unknown');
  }
});

test('plannerTravel departureAt is interpreted in Pacific time', () => {
  const plan = build([place('a')], {}, { travelEstimates: [route('origin', 'a', null, 20, { date: undefined, departureAt: '2026-10-05T16:00:00.000Z' })] });
  assert.equal(plan.stops[0].startTime, '10:00');
  assert.equal(plan.stops[0].travelMinutes, 20);
});

test('known travel validates a fixed session, without implying a reservation', () => {
  const row = event('concert', { planning: { admissionUsd: 0, reservation: 'required', schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '12:00', end: '14:00' }] } } });
  const plan = build([row], {}, { travelEstimates: [route('origin', 'concert', '09:00'), route('concert', 'origin', '14:00')] });
  assert.equal(plan.stops[0].timeStatus, 'verified');
  assert.equal(plan.stops[0].startTime, '12:00');
  assert.equal(plan.stops[0].endTime, '14:00');
  assert.equal(check(plan, 'reservation')[0].status, 'unknown');
  assert.match(plan.stops[0].notes.join(' '), /尚未取得名额/);
});

test('a fixed session reached too late is a hard feasibility failure', () => {
  const row = event('show', { planning: { schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '09:10', end: '10:00' }] } } });
  const plan = build([row], {}, { travelEstimates: [route('origin', 'show', '09:00', 30)] });
  assert.equal(check(plan, 'session_unreachable')[0].status, 'fail');
  assert.equal(plan.status, 'needs_details');
});

test('missing session end cannot generate a start time for the next flexible stop', () => {
  const show = event('show', { planning: { schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '11:00' }] } } });
  const plan = build([show, place('park')], {}, { travelEstimates: [route('origin', 'show', '09:00'), route('show', 'park', '12:00')] });
  assert.equal(plan.stops[0].startTime, '11:00');
  assert.equal(plan.stops[0].endTime, undefined);
  assert.equal(plan.stops[1].startTime, undefined);
  assert.equal(check(plan, 'end_time')[0].status, 'unknown');
});

test('return-by hard constraint includes return travel', () => {
  const plan = build([place('a')], { finishBy: '11:10' }, { travelEstimates: [route('origin', 'a', '09:00'), route('a', 'origin', '11:00', 25)] });
  assert.equal(plan.returnTime, '11:25');
  assert.equal(check(plan, 'return_time')[0].status, 'fail');
  assert.equal(plan.status, 'needs_details');
});

test('known session end after required return is rejected even when route missing', () => {
  const row = event('late', { planning: { schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '16:00', end: '18:00' }] } } });
  const plan = build([row]);
  assert.equal(check(plan, 'finish_time')[0].status, 'fail');
  assert.equal(plan.status, 'needs_details');
});

test('closed dates, event mismatches, excluded cities and full events cannot enter either proposal', () => {
  const rows = [place('closed', { planning: { schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', dates: { [DATE]: [] } } } }), event('wrong-date', { startDate: '2026-10-06', endDate: '2026-10-06' }), event('sold-out', { availability: 'sold_out' }), place('bad-city', { city: 'San Francisco' }), place('good')];
  const plan = build(rows, { excludedCities: ['旧金山'] });
  assert.deepEqual(plan.stops.map(s => s.entityId), ['good']);
  assert.deepEqual(plan.rejectedCandidates.map(s => s.code), ['closed_on_date', 'date_mismatch', 'full', 'city_mismatch']);
  assert.deepEqual(plan.alternatives, []);
});

test('minimum age is checked against every known child and adult-only text', () => {
  const rows = [event('young-only', { planning: { minAge: 8 } }), event('adults', { summary: '21+ drinks evening' }), place('okay', { planning: { allAges: true } })];
  const plan = build(rows, { partySize: 4, childAges: [6, 12] });
  assert.deepEqual(plan.stops.map(s => s.entityId), ['okay']);
  assert.equal(plan.rejectedCandidates.filter(s => s.code === 'age_mismatch').length, 2);
});

test('membership-only and child-only free claims never become full-party zero admission', () => {
  for (const costLabel of ['Free for members; general admission unconfirmed', 'Children under 12 free; adults $20', '会员免费，普通票待核实', '5 岁及以下免费，成人票另计', 'Free admission with a $50 purchase.', 'Buy one ticket, get one free.', 'Free parking; general admission $30.']) {
    const row = place('discount', { cost: 'free', costLabel, planning: { admissionUsd: 0 } });
    const plan = build([row], { partySize: 3, childAges: [6] });
    assert.equal(plan.stops[0].admissionUsd, undefined, costLabel);
    assert.equal(plan.stops[0].admissionStatus, 'incomplete');
    assert.ok(plan.budget.unknownItems.length);
    assert.equal(build([row], { freeOnly: true, childAges: [6] }).stops.length, 0);
  }
});

test('conditional positive member price is not a verified general-admission cost', () => {
  const row = place('member', { costLabel: 'Members free; nonmember admission unknown', planning: { admissionUsd: 20 } });
  const plan = build([row]);
  assert.equal(plan.budget.knownTotalUsd, 0);
  assert.equal(plan.stops[0].admissionStatus, 'incomplete');
  assert.equal(plan.stops[0].admissionUsd, undefined);
});

test('sourced age tiers calculate eligible child free admission, adults stay paid', () => {
  const row = place('tiered', { costLabel: 'Children age 0–12 free; adults $20', planning: { admissionUsd: 20, admission: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', adultUsd: 20, children: [{ minAge: 0, maxAge: 12, usd: 0 }], feesIncluded: true } } });
  const plan = build([row], { partySize: 3, childAges: [6], budgetIncludes: 'admission' });
  assert.equal(plan.budget.knownTotalUsd, 40);
  assert.equal(plan.budget.knownPerPersonUsd, 20);
  assert.equal(plan.stops[0].admissionStatus, 'recorded');
  assert.equal(check(plan, 'budget')[0].status, 'pass');
  assert.equal(build([row], { partySize: 3, childAges: [6], freeOnly: true }).stops.length, 0);
});

test('unverified child tiers do not silently apply', () => {
  const row = place('tiered', { planning: { admissionUsd: 20, feesIncluded: true, admission: { adultUsd: 20, children: [{ minAge: 0, maxAge: 12, usd: 0 }] } } });
  const plan = build([row], { partySize: 3, childAges: [6] });
  assert.equal(plan.budget.knownTotalUsd, 40); // Verified adult subtotal only.
  assert.equal(plan.stops[0].admissionStatus, 'incomplete');
  assert.match(plan.budget.unknownItems.join(' '), /6 岁/);
});

test('unknown party size cannot be treated as a single ticket in a group budget', () => {
  const plan = build([place('paid', { planning: { admissionUsd: 40 } })], { partySize: null, budget: 50, budgetScope: 'total' });
  assert.equal(plan.budget.knownTotalUsd, 0);
  assert.equal(plan.budget.knownPerPersonUsd, 40);
  assert.equal(check(plan, 'budget')[0].status, 'unknown');
  assert.match(plan.budget.unknownItems.join(' '), /人数/);
});

test('known party admission already over budget is a hard failure; missing extras cannot hide it', () => {
  const plan = build([place('paid', { planning: { admissionUsd: 30 } })], { budget: 50, partySize: 2, budgetScope: 'total' });
  assert.equal(plan.budget.knownTotalUsd, 60);
  assert.equal(plan.budget.limitUsd, 50);
  assert.equal(check(plan, 'budget')[0].status, 'fail');
  assert.equal(plan.status, 'needs_details');
});

test('per-person budget is compared with applicable individual totals', () => {
  const plan = build([place('paid', { planning: { admissionUsd: 30, feesIncluded: true } })], { budget: 35, budgetScope: 'person', partySize: 4, budgetIncludes: 'admission' });
  assert.equal(plan.budget.knownTotalUsd, 120);
  assert.equal(plan.budget.knownPerPersonUsd, 30);
  assert.equal(check(plan, 'budget')[0].status, 'pass');
});

test('ticket fees and meals/transport stay unknown instead of being silently zero', () => {
  const plan = build([place('paid', { planning: { admissionUsd: 5 } })], { budget: 100 });
  assert.match(plan.budget.unknownItems.join(' '), /税费/);
  assert.match(plan.budget.unknownItems.join(' '), /餐饮、交通/);
  assert.equal(check(plan, 'budget')[0].status, 'unknown');
});

test('date change reevaluates event eligibility and every published time', () => {
  const row = event('monday-only');
  const first = build([row]);
  assert.equal(first.stops.length, 1);
  const second = build([row], { date: '2026-10-06', selectedCandidateIds: ['monday-only'] });
  assert.equal(second.stops.length, 0);
  assert.equal(second.status, 'needs_details');
  assert.equal(second.rejectedCandidates[0].code, 'date_mismatch');
  assert.match(second.notes[0], /移除/);
});

test('recurring events use confirmed occurrence dates, not the entire date range', () => {
  const row = event('weekly', { startDate: '2026-10-01', endDate: '2026-10-31', occurrenceDates: ['2026-10-06', '2026-10-13'] });
  assert.equal(build([row]).stops.length, 0);
});

test('one alternative is complete, nonrecursive and uses an eligible different final stop', () => {
  const plan = build(['a', 'b', 'c', 'd', 'e'].map(id => place(id)));
  assert.deepEqual(plan.stops.map(s => s.entityId), ['a', 'b', 'c']);
  assert.equal(plan.alternatives.length, 1);
  assert.deepEqual(plan.alternatives[0].stops.map(s => s.entityId), ['a', 'b', 'd']);
  assert.deepEqual(plan.alternatives[0].alternatives, []);
  assert.ok(plan.alternatives[0].checks.length);
});

test('a one-way day validates finishing at its last stop without a return leg or return warning', () => {
  const routes = [route('origin', 'a', '09:00'), route('a', 'origin', '11:00', 50)];
  const plan = build([place('a')], { returnToOrigin: false, finishBy: '11:10' }, { travelEstimates: routes });
  assert.equal(plan.constraints.returnToOrigin, false);
  assert.equal(plan.returnTime, undefined);
  assert.equal(plan.travelLegs.some(leg => leg.to === 'origin'), false);
  assert.equal(check(plan, 'return_time').length, 0);
  assert.equal(check(plan, 'finish_time')[0].status, 'pass');
  assert.match(check(plan, 'finish_time')[0].message, /11:00 结束/);
  assert.doesNotMatch(plan.checks.map(item => item.message).join(' '), /返回|回程/);
  assert.equal(check(build([place('a')], { returnToOrigin: true, finishBy: '11:10' }, { travelEstimates: routes }), 'return_time')[0].status, 'fail');
});

test('one-way final-stop overruns still fail and unknown finish times stay unknown', () => {
  const late = build([event('late', { planning: { schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', sessions: [{ date: DATE, start: '16:00', end: '18:00' }] } } })], { returnToOrigin: false });
  assert.equal(check(late, 'finish_time')[0].status, 'fail');
  assert.match(check(late, 'finish_time')[0].message, /结束时间/);
  assert.doesNotMatch(check(late, 'finish_time')[0].message, /返回|回程/);
  const unknown = build([place('a')], { returnToOrigin: false });
  assert.equal(check(unknown, 'finish_time')[0].status, 'unknown');
  assert.equal(check(unknown, 'return_time').length, 0);
  assert.equal(unknown.returnTime, undefined);
});

test('a requested stop limit bounds explicit and automatic plans, alternatives and handoff', () => {
  const rows = ['a', 'b', 'c', 'd'].map(id => place(id));
  for (const selectedIds of [undefined, ['a', 'b', 'c']]) {
    const plan = build(rows, { maxStops: 2 }, { selectedIds });
    assert.deepEqual(plan.stops.map(stop => stop.entityId), ['a', 'b']);
    assert.equal(plan.constraints.maxStops, 2);
    assert.deepEqual(plan.handoff.stops.map(stop => stop.id), ['a', 'b']);
    assert.ok(plan.alternatives.every(other => other.stops.length <= 2));
  }
});

test('without another destination, a shorter alternative reduces the number of stops', () => {
  const plan = build([place('a'), place('b')]);
  assert.deepEqual(plan.alternatives[0].stops.map(s => s.entityId), ['a']);
});

test('replacement recomputes budget, age, times and return constraints instead of reusing old timing', () => {
  const rows = [place('a'), place('b'), place('new', { planning: { admissionUsd: 80 } })];
  const first = build(rows, {}, { selectedIds: ['a', 'b'], travelEstimates: [route('origin', 'a', '09:00'), route('a', 'b', '11:00')] });
  const second = replaceItineraryStop({ plan: first, state: baseState, candidates: rows, stopId: 'place:b', replacementId: 'new', now: NOW });
  assert.deepEqual(second.stops.map(s => s.entityId), ['a', 'new']);
  assert.equal(second.stops[1].startTime, undefined);
  assert.equal(second.budget.knownTotalUsd, 160);
  assert.equal(check(second, 'budget')[0].status, 'fail');
  assert.notEqual(second.id, first.id);
});

test('replacement refuses a nonexistent stop and does not mutate input', () => {
  const rows = [place('a'), place('b')], input = JSON.stringify(rows), plan = build(rows);
  const previous = JSON.stringify(plan);
  assert.throws(() => replaceItineraryStop({ plan, state: baseState, candidates: rows, stopId: 'never', replacementId: 'a', now: NOW }), /Unknown/);
  replaceItineraryStop({ plan, state: baseState, candidates: rows, stopId: 'a', replacementId: 'b', now: NOW });
  assert.equal(JSON.stringify(rows), input);
  assert.equal(JSON.stringify(plan), previous);
});

test('web discoveries may be proposed with citations but are not forged into saved catalog IDs', () => {
  const rows = [place('site'), place('web-123', { origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Visit us in Fremont' }, officialUrl: undefined, sourceUrls: ['https://example.org/new'] })];
  const plan = build(rows);
  assert.equal(plan.stops[1].external, true);
  assert.deepEqual(plan.handoff.stops, [{ kind: 'place', id: 'site' }]);
  assert.deepEqual(plan.stops[1].sourceUrls, ['https://example.org/new', SOURCE]);
});

test('an arbitrary unsourced name, unsafe URL or malformed ID cannot enter a plan', () => {
  const plan = build([place('missing', { officialUrl: undefined }), place('javascript', { officialUrl: 'javascript:alert(1)' }), place('../bad'), { id: 'invented', title: 'Name from model' }]);
  assert.equal(plan.stops.length, 0);
  assert.equal(plan.status, 'needs_details');
});

test('source-less or out-of-validity hours cannot be promoted to usable time', () => {
  for (const field of [{ sourceUrl: undefined }, { verifiedAt: undefined }, { validThrough: '2026-10-04' }]) {
    const row = place('a'); Object.assign(row.planning.schedule, field);
    const plan = build([row], {}, { travelEstimates: [route('origin', 'a', '09:00')] });
    assert.equal(plan.stops[0].startTime, undefined);
    assert.equal(check(plan, 'opening_hours')[0].status, 'unknown');
  }
});

test('regular weekly hours do not mean selected-date opening confirmed', () => {
  const row = place('a', { planning: { admissionUsd: 0, reservation: 'none', schedule: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', weekly: { 1: [{ open: '10:00', close: '17:00' }] } } } });
  const plan = build([row], {}, { travelEstimates: [route('origin', 'a', '09:00')] });
  assert.equal(plan.stops[0].startTime, '10:00');
  assert.equal(check(plan, 'date_opening')[0].status, 'unknown');
});

test('last entry and closing time constrain flexible visits', () => {
  const row = place('a'); row.planning.schedule.dates[DATE] = [{ open: '10:00', close: '16:00', lastEntry: '14:30' }];
  const plan = build([row], { startTime: '14:30' }, { travelEstimates: [route('origin', 'a', '14:30', 15)] });
  assert.equal(check(plan, 'opening_window')[0].status, 'fail');
  assert.equal(plan.stops[0].startTime, undefined);
});

test('missing, impossible and past dates request details rather than silently using today', () => {
  for (const date of [null, '2026-02-30', '2026-10-03']) {
    const plan = build([place('a')], { date });
    assert.equal(check(plan, 'date')[0].status, 'fail');
    assert.equal(plan.status, 'needs_details');
  }
});

test('locale changes descriptions without changing deterministic facts', () => {
  const en = build([place('a')], {}, { locale: 'en' });
  const hant = build([place('a')], {}, { locale: 'zh-Hant' });
  assert.match(en.summary, /Suggested order/);
  assert.match(hant.summary, /建議順序/);
  assert.equal(en.stops[0].entityId, hant.stops[0].entityId);
});

test('repeated and excessive selected IDs do not duplicate a visit or exceed four stops', () => {
  const rows = ['a', 'b', 'c', 'd', 'e'].map(id => place(id));
  const plan = build(rows, {}, { selectedIds: ['a', 'a', 'place:a', 'b', 'c', 'd', 'e'] });
  assert.deepEqual(plan.stops.map(s => s.entityId), ['a', 'b', 'c', 'd']);
});

test('search-result and partially verified web discoveries are not eligible for automatic plans', () => {
  const rows = ['search-result', 'partial', undefined].map((verification, i) => place(`web-${i}`, { origin: 'web', verification, verifiedFacts: { city: 'Fremont' } }));
  const plan = build(rows);
  assert.equal(plan.stops.length, 0);
  assert.ok(plan.rejectedCandidates.every(row => row.code === 'web_unverified'));
});

test('web event must have verified city and exact occurrence date evidence', () => {
  const rows = [event('web-wrong', { origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Fremont' } }), event('web-ok', { origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Fremont', date: 'October 5, 2026' } })];
  const plan = build(rows);
  assert.deepEqual(plan.stops.map(s => s.entityId), ['web-ok']);
  assert.equal(plan.rejectedCandidates[0].code, 'web_unverified');
});

test('unavailable web ticket status cannot be included even when city/date are verified', () => {
  const row = event('web-full', { origin: 'web', verification: 'page-verified', verifiedFacts: { city: 'Fremont', date: 'October 5, 2026' }, availability: 'unavailable' });
  assert.equal(build([row]).rejectedCandidates[0].code, 'full');
});

test('sourced member-only tier is not applied without verified user eligibility', () => {
  const row = place('tier', { planning: { admission: { sourceUrl: SOURCE, verifiedAt: '2026-10-04', allAgesUsd: 0, eligibility: 'membership' } } });
  const plan = build([row]);
  assert.equal(plan.stops[0].admissionStatus, 'incomplete');
  assert.equal(build([row], { freeOnly: true }).stops.length, 0);
});

test('a recurring date range without actual occurrence evidence is excluded', () => {
  const row = event('weekly', { startDate: '2026-10-01', endDate: '2026-10-31', dateLabel: 'Every Friday', planning: {} });
  assert.equal(build([row]).rejectedCandidates[0].code, 'recurrence_unconfirmed');
});

test('day plans prefer the departure city and never silently combine distant Bay Area cities', () => {
  const rows = [place('novato', { city: 'Novato', region: 'north-bay' }), place('burlingame', { city: 'Burlingame', region: 'peninsula' }), place('fremont-a'), place('fremont-b')];
  const plan = build(rows, { city: null, origin: 'Fremont station', budget: 100, partySize: 3, childAges: [6] });
  assert.deepEqual(plan.stops.map(stop => stop.entityId), ['fremont-a', 'fremont-b']);
  assert.deepEqual([...new Set(plan.stops.map(stop => stop.city))], ['Fremont']);
  assert.equal(new Set(plan.alternatives[0].stops.map(stop => stop.city)).size, 1);
});

test('model-selected faraway IDs do not bypass the locality guard', () => {
  const rows = [place('fremont'), place('novato', { city: 'Novato' }), place('burlingame', { city: 'Burlingame' })];
  const plan = build(rows, { city: null }, { selectedIds: ['novato', 'burlingame', 'fremont'] });
  assert.deepEqual(plan.stops.map(stop => stop.entityId), ['fremont']);
  assert.equal(plan.rejectedCandidates.filter(item => item.code === 'cross_city_unverified').length, 2);
});

test('explicit multiple-city permission still needs a route at the actual calculated transfer time', () => {
  const rows = [place('a'), place('b', { city: 'Oakland' })];
  const without = build(rows, { city: null, allowMultipleCities: true }, { selectedIds: ['a', 'b'], travelEstimates: [route('origin', 'a', '09:00')] });
  assert.deepEqual(without.stops.map(stop => stop.entityId), ['a']);
  const withRoute = build(rows, { city: null, allowMultipleCities: true }, { selectedIds: ['a', 'b'], travelEstimates: [route('origin', 'a', '09:00'), route('a', 'b', '11:00', 50)] });
  assert.deepEqual(withRoute.stops.map(stop => stop.entityId), ['a', 'b']);
  assert.equal(withRoute.stops[1].startTime, '11:50');
});

test('an empty selectedIds array chooses defaults rather than returning an empty proposal', () => {
  assert.equal(build([place('a')], {}, { selectedIds: [] }).stops.length, 1);
});
