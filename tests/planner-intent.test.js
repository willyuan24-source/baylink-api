const test = require('node:test');
const assert = require('node:assert/strict');
const { inferFilters, validateFilters, recommend, loadPlannerCatalog, admissionLowerBound } = require('../lib/planner');

const TODAY = '2026-09-29';
const now = () => Date.parse(`${TODAY}T19:00:00Z`);
const event = (id, fields = {}) => ({ id, title: id, region: 'sf', city: 'San Francisco', category: 'family', cost: 'paid', startDate: '2026-10-01', endDate: '2026-10-01', planning: { admissionUsd: 20, setting: 'indoor' }, ...fields });
const catalog = events => ({ version: 1, checkedAt: TODAY, events, places: [], guides: [] });
const run = (events, body, ai) => recommend({ body, catalog: catalog(events), now, ai });

test('natural party parsing preserves every child age and handles after tomorrow and budget ceilings', () => {
  const filters = inferFilters('后天预算不超过80美元，两个大人和两个孩子，5岁和12岁，不开车', TODAY);
  assert.deepEqual(filters, { date: '2026-10-01', budget: 80, childAge: 5, childAges: [5, 12], partySize: 4 });
  assert.deepEqual(inferFilters('2 adults and kids aged 5 and 12, total budget $100', TODAY), { budget: 100, budgetScope: 'total', childAge: 5, childAges: [5, 12], partySize: 4 });
  assert.equal(inferFilters('day after tomorrow, budget at most $35 per person', TODAY).date, '2026-10-01');
  assert.equal(inferFilters('day after tomorrow, budget at most $35 per person', TODAY).budgetScope, 'person');
  assert.deepEqual(inferFilters('两个大人和两个五岁孩子，总预算80', TODAY), { budget: 80, budgetScope: 'total', childAge: 5, childAges: [5, 5], partySize: 4 });
  assert.deepEqual(inferFilters('2 adults and 2 five-year-old kids, total budget $100', TODAY), { budget: 100, budgetScope: 'total', childAge: 5, childAges: [5, 5], partySize: 4 });
  assert.deepEqual(inferFilters('5 and 12-year-old children', TODAY).childAges, [5, 12]);
  assert.equal(inferFilters('两大两小，总预算100', TODAY).partySize, 4);
  assert.equal(inferFilters('不超过80美元', TODAY).budget, 80);
  assert.equal(inferFilters('预算$1,000', TODAY).budget, 1000);
});

test('extended filters reject malformed ages, inconsistent party counts and unbounded choices', () => {
  for (const filters of [{ childAges: [5, 18] }, { childAges: Array(11).fill(5) }, { partySize: 0 }, { partySize: 51 }, { partySize: 1, childAges: [5, 12] }, { budgetScope: 'daily' }, { freeOnly: 'true' }, { topic: 'invented' }]) assert.throws(() => validateFilters(filters), error => error.status === 400);
  assert.deepEqual(validateFilters({ childAges: [5, 5], partySize: 4, budgetScope: 'total', freeOnly: true, topic: 'music' }), { childAges: [5, 5], partySize: 4, budgetScope: 'total', freeOnly: true, topic: 'music' });
});

test('multiple date alternatives and ranges require a choice, while a selected date resolves the request', async () => {
  for (const message of ['10月3日或者10月4日都可以', '10月3日到4日', '10/3, 10/4', 'Oct 3 or 4', 'October 3–4', '周六或周日', '明天或者后天']) {
    await assert.rejects(run([event('one')], { message }), /多个日期/);
  }
  const result = await run([event('one')], { message: '10月1日或10月2日', filters: { date: '2026-10-01' } });
  assert.equal(result.filters.date, '2026-10-01');
  assert.equal(result.suggestions[0].eventId, 'one');
  await assert.rejects(run([event('one')], { message: 'Oct 3 or 4', locale: 'en' }), /multiple dates/);
  assert.equal(inferFilters('2027年1月3日去SF', TODAY).date, '2027-01-03');
  assert.equal(inferFilters('October 3, 2027', TODAY).date, '2027-10-03');
  assert.equal(inferFilters('10月3日和12岁的孩子一起出行', TODAY).date, '2026-10-03');
});

test('negated settings and transport are not reversed by rules or AI', async () => {
  assert.equal(inferFilters('不要室内活动', TODAY).setting, 'outdoor');
  assert.equal(inferFilters('avoid outdoor events', TODAY).setting, 'indoor');
  assert.equal(inferFilters('不用开车去室内', TODAY).setting, 'indoor');
  assert.equal(inferFilters('没开车', TODAY).travelMode, undefined);
  assert.equal(inferFilters('我想听室内乐', TODAY).setting, undefined);
  assert.equal(inferFilters('我想听室内乐', TODAY).topic, 'music');
  assert.throws(() => inferFilters('不要室内也不要户外', TODAY), /同时排除/);
  const result = await run([event('inside'), event('outside', { planning: { setting: 'outdoor', admissionUsd: 10 } })], { message: '不要室内，不开车' }, async () => ({ filters: { setting: 'indoor', travelMode: 'drive' }, rankedEventIds: ['inside'] }));
  assert.equal(result.filters.travelMode, 'any');
  assert.deepEqual(result.suggestions.map(row => row.eventId), ['outside']);
  assert.match(result.notices.join(' '), /不开车/);
});

test('a home city is an origin while an explicit destination remains strict', async () => {
  const events = [event('sf'), event('fremont', { region: 'east-bay', city: 'Fremont' })];
  for (const message of ['我住在Fremont，想去San Francisco玩', 'I live in Fremont and want to visit San Francisco']) {
    const result = await run(events, { message });
    assert.equal(result.filters.city, 'San Francisco');
    assert.deepEqual(result.suggestions.map(row => row.eventId), ['sf']);
  }
});

test('every child age is checked, including older siblings and duplicate ages', async () => {
  const events = [event('young-only', { planning: { minAge: 2, maxAge: 10, admissionUsd: 0 } }), event('family'), event('teen-only', { planning: { minAge: 10, maxAge: 17, admissionUsd: 0 } })];
  const result = await run(events, { message: '带5岁和12岁的两个孩子', filters: { childAge: null } }, async () => ({ filters: { childAge: 5, childAges: [5] }, rankedEventIds: ['young-only', 'teen-only'] }));
  assert.deepEqual(result.filters.childAges, [5, 12]);
  assert.deepEqual(result.suggestions.map(row => row.eventId), ['family']);
  assert.match(result.suggestions[0].unknowns.join(' '), /每位儿童/);
  const noAge = await run([event('adult-family-word', { title: 'Family history evening', planning: { minAge: 18, admissionUsd: 0 } }), event('all-family')], { message: '两个大人和两个孩子一起去' });
  assert.deepEqual(noAge.suggestions.map(row => row.eventId), ['all-family']);
});

test('a total budget screens per-person admission only and does not become a trip-total promise', async () => {
  const events = [event('twenty'), event('thirty', { planning: { admissionUsd: 30 } }), event('unpriced', { planning: {} })];
  const result = await run(events, { message: '四人，总预算100', filters: { budgetScope: 'total' } });
  assert.equal(result.filters.partySize, 4);
  assert.deepEqual(result.suggestions.map(row => row.eventId), ['twenty', 'unpriced']);
  assert.deepEqual(result.suggestions.map(row => row.budgetStatus), ['known', 'unknown']);
  assert.match(result.notices.join(' '), /每人最多 \$25/);
  assert.match(result.notices.join(' '), /不包含餐饮、交通/);
  assert.match(result.suggestions[0].unknowns.join(' '), /整组实际总价待核/);
});

test('a total budget without party size never masquerades as a verified per-person ceiling', async () => {
  const result = await run([event('forty', { planning: { admissionUsd: 40 } })], { filters: { budget: 10, budgetScope: 'total' } });
  assert.equal(result.suggestions[0].budgetStatus, 'unknown');
  assert.match(result.notices.join(' '), /未按总额判断/);
});

test('only-free excludes unknown admission and paid tickets, without mistaking free parking for admission', async () => {
  const events = [event('free', { cost: 'free', planning: { admissionUsd: 0 } }), event('paid'), event('unknown', { planning: {} })];
  const result = await run(events, { message: '只要免费活动' }, async () => ({ filters: { freeOnly: false }, rankedEventIds: ['unknown'] }));
  assert.equal(result.filters.freeOnly, true);
  assert.deepEqual(result.suggestions.map(row => row.eventId), ['free']);
  assert.equal(inferFilters('预算100，需要免费停车', TODAY).freeOnly, undefined);
  const budgetOnly = await run(events, { filters: { budget: 0 } });
  assert.deepEqual(budgetOnly.suggestions.map(row => row.eventId), ['free', 'unknown']);
});

test('explicit comedy, music and sports requests remain hard filters even when AI ranks other subjects', async () => {
  const events = [event('comedy', { title: '脱口秀之夜' }), event('music', { title: '室内爵士音乐会' }), event('sports', { title: 'Giants vs Dodgers', kind: 'sports' }), event('plain')];
  for (const [message, id] of [['想看脱口秀', 'comedy'], ['想听音乐', 'music'], ['想看体育球赛', 'sports']]) {
    const result = await run(events, { message }, async () => ({ rankedEventIds: ['plain', 'comedy', 'sports'] }));
    assert.deepEqual(result.suggestions.map(row => row.eventId), [id]);
  }
  const absent = await run([event('unrelated')], { message: '想看脱口秀' });
  assert.deepEqual(absent.suggestions, []);
  const excluded = await run(events, { message: '不要音乐，想看脱口秀' });
  assert.deepEqual(excluded.suggestions.map(row => row.eventId), ['comedy']);
  await assert.rejects(run(events, { message: '想看脱口秀或者听音乐' }), /多个活动主题/);
});

test('hard filtering happens before AI payload truncation and preserves a matching catalog tail', async () => {
  const events = Array.from({ length: 180 }, (_, index) => event(`irrelevant-${index}`, { region: 'south-bay', city: 'San Jose' }));
  events.push(event('tail-comedy', { title: '脱口秀专场' }), event('tail-unknown', { title: '脱口秀待核', planning: {} }));
  let payload;
  const result = await run(events, { message: 'San Francisco 脱口秀，只要免费', filters: { freeOnly: true } }, async value => { payload = value; return { rankedEventIds: ['tail-comedy'] }; });
  assert.deepEqual(result.suggestions, []);
  assert.equal(payload, undefined, 'an empty hard-filter result does not spend an AI request');
  const withMatches = await run(events, { message: 'San Francisco 脱口秀，预算30' }, async value => { payload = value; return { rankedEventIds: ['tail-comedy'] }; });
  assert.deepEqual(payload.events.map(row => row.id), ['tail-comedy', 'tail-unknown']);
  assert.equal(withMatches.suggestions[0].eventId, 'tail-comedy');
  const manyMatches = [...Array.from({ length: 165 }, (_, index) => event(`a-${String(index).padStart(3, '0')}`)), event('z-unseen')];
  const cannotPromoteUnseen = await run(manyMatches, { message: 'San Francisco' }, async value => {
    assert.equal(value.events.length, 160);
    assert.ok(!value.events.some(row => row.id === 'z-unseen'));
    return { rankedEventIds: ['z-unseen'] };
  });
  assert.ok(!cannotPromoteUnseen.suggestions.some(row => row.eventId === 'z-unseen'));
});

test('rain, accessibility and clock-time requests disclose unverified facts without inventing routes', async () => {
  const result = await run([event('indoor'), event('outdoor', { planning: { setting: 'outdoor', admissionUsd: 0 } })], { message: '雨天轮椅出行，14:00到16:00' });
  assert.deepEqual(result.suggestions.map(row => row.eventId), ['indoor']);
  assert.match(result.notices.join(' '), /实际天气/);
  assert.match(result.notices.join(' '), /轮椅和无障碍条件尚未核实/);
  assert.match(result.notices.join(' '), /时段与游玩总时长尚未自动核实/);
});

test('real catalog family recommendations check both supplied ages, not only the youngest', async () => {
  const result = await recommend({ body: { message: 'Fremont 10月2日带5岁和12岁孩子' }, catalog: loadPlannerCatalog(), now });
  assert.deepEqual(result.filters.childAges, [5, 12]);
  const published = loadPlannerCatalog();
  for (const suggestion of result.suggestions) {
    const row = published.events.find(item => item.id === suggestion.eventId);
    assert.ok(row.planning.maxAge === undefined || row.planning.maxAge >= 12);
  }
});

test('clear admission lower bounds reject over-budget text without treating parking or eligibility prices as tickets', async () => {
  const ticket = event('ticket', { costLabel: '官方售票页显示 $27.24–$35.49，按日期/票种变化；停车 $15。是否有另加费用以结算为准。', planning: {} });
  assert.equal(admissionLowerBound(ticket), 27.24);
  const tooLow = await run([ticket], { filters: { budget: 10 } });
  assert.deepEqual(tooLow.suggestions, []);
  const possible = await run([ticket], { filters: { budget: 40 } });
  assert.equal(possible.suggestions[0].budgetStatus, 'unknown');
  assert.match(possible.suggestions[0].unknowns.join(' '), /不能认定符合预算/);
  for (const costLabel of ['停车 $20', '普通票待核；赞助 $1200', '入场 $20；儿童免费', '官网居民 $10，非居民 $20', '官方票价参考 $30', '官网 VIP $150', '官网每车 $25', '会员入场 $10']) assert.equal(admissionLowerBound(event('unclear', { costLabel, planning: {} })), null, costLabel);
  const real = loadPlannerCatalog().events.find(row => row.id === 'pleasanton-pumpkins-after-dark-2026');
  assert.equal(admissionLowerBound(real), 27.24);
});

test('automatically added nearby stops preserve free-only, remaining admission budget and every child age', async () => {
  const location = { lat: 37.77, lng: -122.42, precision: 'venue' };
  const main = event('main', { location });
  const place = (id, fields = {}) => ({ id, title: id, city: 'San Francisco', region: 'sf', location, ...fields });
  const recommendWithPlaces = (places, filters, currentEvent = main) => recommend({ body: { filters }, catalog: { ...catalog([currentEvent]), places }, now });
  const children = { childAges: [5, 12], budget: 25 };
  for (const candidate of [
    place('unknown'),
    place('too-expensive-together', { planning: { admissionUsd: 10 } }),
    place('too-young-for-sibling', { cost: 'free', planning: { maxAge: 10 } }),
    place('adult-only', { cost: 'free', planning: { minAge: 18 } }),
    place('adult-description', { cost: 'free', summary: 'Adults-only venue' }),
  ]) {
    const result = await recommendWithPlaces([candidate], children);
    assert.deepEqual(result.suggestions[0].placeIds, [], candidate.id);
  }
  const exactBudget = await recommendWithPlaces([place('five', { planning: { admissionUsd: 5 } })], children);
  assert.deepEqual(exactBudget.suggestions[0].placeIds, ['five']);
  assert.match(exactBudget.suggestions[0].unknowns.join(' '), /亲子适宜性尚未确认/);
  const freeMain = { ...main, cost: 'free', planning: { admissionUsd: 0 } };
  const freeOnly = await recommendWithPlaces([place('paid', { planning: { admissionUsd: 5 } }), place('free', { cost: 'free' })], { freeOnly: true }, freeMain);
  assert.deepEqual(freeOnly.suggestions[0].placeIds, ['free']);
  const unknownMain = { ...main, planning: {} };
  const unknownBudget = await recommendWithPlaces([place('five', { planning: { admissionUsd: 5 } }), place('free', { cost: 'free' })], { budget: 25 }, unknownMain);
  assert.deepEqual(unknownBudget.suggestions[0].placeIds, ['free']);
  const total = await recommendWithPlaces([place('ten', { planning: { admissionUsd: 10 } })], { budget: 100, partySize: 4, budgetScope: 'total' });
  assert.deepEqual(total.suggestions[0].placeIds, []);
});
