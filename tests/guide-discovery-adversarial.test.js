const test = require('node:test');
const assert = require('node:assert/strict');
const { buildChatWebRequest } = require('../lib/guideWebSearch');
const { buildGuideLocalRecommendations } = require('../lib/guideLocalRecommendations');
const { inferFilters } = require('../lib/planner');

const TODAY = '2026-10-04';
const ask = (message, options = {}) => buildChatWebRequest({ message, searchMode: 'site', locale: 'en', today: TODAY, ...options });
const history = content => [{ role: 'user', content }];
const event = (id, city = 'San Jose', date = TODAY, overrides = {}) => ({
  id, title: `${city} community event`, city, region: city === 'San Jose' ? 'south-bay' : city === 'San Francisco' ? 'sf' : 'east-bay',
  startDate: date, endDate: date, cost: 'free', costLabel: 'Free admission; registration required.',
  officialUrl: `https://example.org/${id}`, planning: { admissionUsd: 0 }, ...overrides,
});
const fixture = events => ({ version: 1, checkedAt: TODAY, guides: [], places: [], events });
const local = (request, catalog) => buildGuideLocalRecommendations({ message: request.input.query, searchContext: request.input, locale: 'en', today: TODAY, catalog });

test('complete slash dates keep their explicit year through builder and local recommendation', async () => {
  const catalog = fixture([event('wrong-year', 'San Jose', '2026-10-05'), event('right-year', 'San Jose', '2027-10-05')]);
  for (const date of ['10/05/2027', '2027/10/05', '10/5/2027', '2027/10/5', '2027-10-05', '2027年10月5日', 'October 5, 2027', 'Tuesday, 10/05/2027', '2027/10/05 (Tuesday)']) {
    const request = ask(`San Jose events on ${date}`);
    assert.equal(request.input?.date, '2027-10-05', date);
    const result = await local(request, catalog);
    assert.deepEqual(result.eventIds, ['right-year'], date);
  }
  for (const date of ['2027/02/29', '02/29/2027', '2027/13/05', '13/05/2027', 'Monday, 10/05/2027']) {
    const request = ask(`San Jose events on ${date}`);
    assert.ok(request.question, date);
    assert.equal(request.input, undefined, 'invalid full dates must not fall back to the current year');
  }
});

test('tomorrow and weekend boundary dates are explicit, while multiple dates ask in both modes', () => {
  for (const [text, today, date] of [
    ['tomorrow', '2026-10-04', '2026-10-05'], ['后天', '2026-10-04', '2026-10-06'],
    ['this weekend', '2026-10-04', '2026-10-04'], ['next weekend', '2026-10-04', '2026-10-10'],
    ['next weekend', '2026-10-10', '2026-10-17'], ['下周日', '2026-10-04', '2026-10-11'],
  ]) assert.equal(ask(`San Jose events ${text}`, { today }).input?.date, date, text);
  for (const searchMode of ['site', 'smart']) for (const text of ['October 5 or 6', '2027/10/05 or 2027/10/06', 'October 5-6']) {
    const request = ask(`San Jose events ${text}`, { searchMode });
    assert.equal(request.search, false);
    assert.ok(request.question, `${searchMode}: ${text}`);
    assert.equal(request.input, undefined);
  }
});

test('negative cities never become destinations; a positive replacement survives to the returned records', async () => {
  const catalog = fixture([event('sj'), event('oakland', 'Oakland'), event('sf', 'San Francisco')]);
  for (const message of [
    '今天不去Oakland，只去San Jose有什么活动？', 'Events in San Jose instead of Oakland today',
    '今天不要SF，改去SanJose有什么活动？', 'From Oakland to San Jose, events today',
    "I don't want to go to Oakland; events in San Jose today",
  ]) {
    const request = ask(message);
    assert.equal(request.input?.city, 'San Jose', message);
    assert.deepEqual((await local(request, catalog)).eventIds, ['sj'], message);
  }
  for (const searchMode of ['site', 'smart']) for (const message of ['今天不要San Francisco，有什么活动？', 'Events outside Oakland today', "I don't want to go to Oakland; events today", '别在Oakland，有什么活动？', 'Events in San Jose or Oakland today']) {
    const request = ask(message, { searchMode });
    assert.ok(request.question, `${searchMode}: ${message}`);
    assert.equal(request.input, undefined, 'ask for a destination rather than recommend the excluded city');
  }
  const switched = ask('不要舊金山，改去 Alameda，今天有什麼活動？', { locale: 'zh-Hant', history: history('SF free events tomorrow'), searchContext: { city: 'San Francisco', date: '2026-10-05' } });
  assert.equal(switched.input.city, 'Alameda');
  assert.equal(switched.input.date, TODAY);
  assert.deepEqual((await local(switched, fixture([event('alameda', 'Alameda'), event('sf', 'San Francisco')]))).eventIds, ['alameda']);
  const noFreeAlameda = await local(switched, fixture([event('paid-alameda', 'Alameda', TODAY, { cost: 'paid', costLabel: '$20', planning: { admissionUsd: 20 } }), event('sf', 'San Francisco')]));
  assert.ok(noFreeAlameda, 'removing the last eligible row must not discard the resolved destination or fall into AI');
  assert.equal(noFreeAlameda.filters.city, 'Alameda');
  assert.deepEqual(noFreeAlameda.eventIds, []);
  assert.deepEqual(noFreeAlameda.sources, []);
});

test('short public constraint followups keep the topic and update date or city instead of losing the input', async () => {
  const prior = history('San Jose free events today');
  const catalog = fixture([event('sj'), event('tomorrow', 'San Jose', '2026-10-05'), event('oct-ten', 'San Jose', '2026-10-10'), event('berkeley', 'Berkeley')]);
  for (const [message, city, date, ids] of [
    ['明天呢？', 'San Jose', '2026-10-05', ['tomorrow']], ['Tomorrow?', 'San Jose', '2026-10-05', ['tomorrow']],
    ['改成10月10日', 'San Jose', '2026-10-10', ['oct-ten']], ['改去Berkeley', 'Berkeley', TODAY, ['berkeley']],
    ['不限定城市，都可以', undefined, TODAY, ['berkeley', 'sj']],
  ]) {
    const request = ask(message, { history: prior });
    assert.equal(request.input?.city, city, message);
    assert.equal(request.input?.date, date, message);
    assert.match(request.input.query, /local events/);
    const result = await local(request, catalog);
    assert.deepEqual([...result.eventIds].sort(), [...ids].sort(), message);
  }
  assert.deepEqual(ask('明天我要考驾照', { history: prior }), { search: false, status: 'not_requested' });
});

test('past date context asks rather than silently changing the date or entering a current-day recommendation', () => {
  const prior = history('San Jose events October 3');
  for (const options of [{ history: prior }, { searchContext: { city: 'San Jose', date: '2026-10-03' } }]) {
    const request = ask('What events are there?', options);
    assert.ok(request.question);
    assert.match(request.question, /2026-10-03.*past/);
    assert.equal(request.input, undefined);
  }
  for (const message of ['San Jose events October 3', 'San Jose events yesterday', '昨天 San Jose 有什么活动？']) {
    const request = ask(message);
    assert.ok(request.question, message);
    assert.equal(request.input, undefined);
  }
  assert.equal(ask('Tomorrow?', { history: prior }).input.date, '2026-10-05');
  assert.equal(inferFilters('day before yesterday', TODAY).date, '2026-10-02');
});

test('explicitly clearing date or city beats prior turns even when UI sends an empty context', async () => {
  const prior = history('San Jose free events October 10');
  const catalog = fixture([event('sj', 'San Jose', '2026-10-10'), event('sf', 'San Francisco', '2026-10-10')]);
  for (const message of ['城市不限', '不限定城市，都可以', 'Any city', 'No city preference', '地区不限制']) {
    const request = ask(message, { history: prior, searchContext: {} });
    assert.equal(request.input.city, undefined, message);
    assert.equal(request.input.region, 'all', message);
    assert.equal(request.input.date, '2026-10-10', 'only the city was cleared');
    assert.deepEqual([...(await local(request, catalog)).eventIds].sort(), ['sf', 'sj']);
  }
  for (const message of ['日期不限', '哪天都可以', 'Any day', 'No date preference', '不限制日子']) {
    const request = ask(message, { history: prior, searchContext: {} });
    assert.ok(request.question, message);
    assert.match(request.question, /cleared the previous date/);
    assert.equal(request.input, undefined, 'the one-day catalog must not pretend an unrestricted request chose today');
  }
  const cleared = [...prior, ...history('Any day')];
  assert.ok(ask('What events are there?', { history: cleared, searchContext: {} }).question);
  assert.equal(ask('Tomorrow?', { history: cleared, searchContext: {} }).input.date, '2026-10-05');
});

test('free-only excludes age and membership offers in either wording order, while preserving real free entry', async () => {
  const catalog = fixture([
    event('free', 'San Jose', TODAY, { plan: ['Members receive free coffee; everyone is welcome.'] }),
    event('children', 'San Jose', TODAY, { costLabel: 'Free admission for children under 12; adults $20' }),
    event('members', 'San Jose', TODAY, { costLabel: 'Free for members; non-members $25' }),
    event('students', 'San Jose', TODAY, { costLabel: 'Free admission for eligible students with ID' }),
    event('card', 'San Jose', TODAY, { costLabel: 'Free for library card holders' }),
    event('plan-condition', 'San Jose', TODAY, { plan: ['Free admission for residents only; address proof required.'] }),
    event('purchase', 'San Jose', TODAY, { costLabel: 'Free with purchase of a $30 dinner' }),
    event('paid', 'San Jose', TODAY, { cost: 'paid', costLabel: '$20 admission', planning: { admissionUsd: 20 } }),
  ]);
  const result = await local(ask('Free San Jose events today'), catalog);
  assert.deepEqual(result.eventIds, ['free']);
  assert.match(result.answer, /registration required/);
});

test('accepting paid admission releases inherited free-only, and a retained budget still reaches the final matcher', async () => {
  const catalog = fixture([event('free'), event('paid', 'San Jose', TODAY, { cost: 'paid', costLabel: '$20 admission', planning: { admissionUsd: 20 } })]);
  for (const message of ['Paid events are okay too', '收费也可以，不用只找免费', 'Not only free events']) {
    const request = ask(message, { history: history('San Jose free events today') });
    assert.doesNotMatch(request.input.query, /free admission only|admission budget: USD 0/);
    const result = await local(request, catalog);
    assert.equal(result.filters.freeOnly, false);
    assert.deepEqual([...result.eventIds].sort(), ['free', 'paid']);
  }
  const request = ask('What events are there today?', { history: history('San Jose events under $10') });
  const result = await local(request, catalog);
  assert.equal(result.filters.budget, 10, 'serialized public budget is parsed rather than dropped at the local matcher');
  assert.deepEqual(result.eventIds, ['free']);
});
