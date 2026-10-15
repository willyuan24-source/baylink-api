// API-BB-5: dates families type, English asks against the Chinese catalog, and the other acceptance lines of
// the live check after API-BB-4B (10-15). Shipped data with a fixed day; no model, no network.
const test = require('node:test');
const assert = require('node:assert/strict');
const { askedDateRange } = require('../lib/entityAliases');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence } = require('../lib/baybayEvidence');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadDiscoveryCatalog } = require('../lib/publicContext');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const TODAY = '2026-10-14'; // Wednesday: this weekend is 10/17-18
const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const stateOf = (message, today = TODAY) => resolveTaskState({ message, today, carry: true });
const evidence = (message, locale = /[㐀-鿿]/.test(message) ? 'zh-Hans' : 'en') => buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message,
  state: stateOf(message).state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today: TODAY, locale, audience: true });
const itemIds = result => result.items.map(item => `${item.kind}:${item.id}`);

test('date spans: two days, the weekend of a day, the Nth weekend and a month', () => {
  const span = (message, today = TODAY) => { const value = askedDateRange(message, today); return value && [value.start, value.end]; };
  for (const [message, start, end] of [
    ['11月21日、22日有什么活动', '2026-11-21', '2026-11-22'], ['11月21日到22日', '2026-11-21', '2026-11-22'], ['11月21至22日', '2026-11-21', '2026-11-22'],
    ['11月21日到11月22日', '2026-11-21', '2026-11-22'], ['12月12日、13日', '2026-12-12', '2026-12-13'], ['November 21-22', '2026-11-21', '2026-11-22'],
    ['Nov 21 and 22', '2026-11-21', '2026-11-22'], ['11/21-22', '2026-11-21', '2026-11-22'], ['the weekend of December 5', '2026-12-05', '2026-12-06'],
    ['the December 5 weekend', '2026-12-05', '2026-12-06'], ['12月5日那个周末', '2026-12-05', '2026-12-06'], ['weekend of Dec 6', '2026-12-05', '2026-12-06'],
    ['weekend of December 3', '2026-12-05', '2026-12-06'], ['12月第一个周末', '2026-12-05', '2026-12-06'], ['十二月第二个周末', '2026-12-12', '2026-12-13'],
    ['11月最后一个周末', '2026-11-28', '2026-11-29'], ['first weekend of December', '2026-12-05', '2026-12-06'], ['last weekend of November', '2026-11-28', '2026-11-29'],
    ['12月有什么圣诞活动', '2026-12-01', '2026-12-31'], ['十二月份', '2026-12-01', '2026-12-31'], ['12月初', '2026-12-01', '2026-12-10'], ['12月底', '2026-12-21', '2026-12-31'],
    ['in December', '2026-12-01', '2026-12-31'], ['这个月有什么免费活动', '2026-10-14', '2026-10-31'], ['下个月', '2026-11-01', '2026-11-30'],
    ['1月有什么活动', '2027-01-01', '2027-01-31'], ['这周末', '2026-10-17', '2026-10-18'], ['下周末', '2026-10-24', '2026-10-25'],
  ]) assert.deepEqual(span(message), [start, end], message);
  // Not a span: one dated day, a baby's age in months, mooncakes, an age next to a date, a cup measure, "may" the verb.
  for (const message of ['12月5日东湾有什么适合孩子的活动', '3月大的宝宝可以去吗', '8月饼', '我们11月21日和22岁的儿子', '1/2 cup', 'in may we go', 'Oct 17, 2 adults']) assert.equal(span(message), null, message);
  // 12月中文活动 is December's Chinese-language events (中 is not 月中).
  assert.deepEqual(span('12月中文活动'), ['2026-12-01', '2026-12-31']);
  // 这周末 outranks a bare month in the same ask.
  assert.deepEqual(span('我1月回国，这周末带孩子去哪玩'), ['2026-10-17', '2026-10-18']);
});

test('task state: a span is one dateRange for an outing ask; a day plan still picks one day of two', () => {
  for (const [message, start, end] of [['11月21日、22日周末湾区有什么华人社区活动？', '2026-11-21', '2026-11-22'], ['12月第一个周末有什么亲子活动', '2026-12-05', '2026-12-06'],
    ['12月有什么圣诞活动', '2026-12-01', '2026-12-31'], ['周末带孩子去哪玩', '2026-10-17', '2026-10-18'], ['湾区周末有什么免费活动', '2026-10-17', '2026-10-18']]) {
    const { state, clarification } = stateOf(message);
    assert.equal(clarification, undefined, message);
    assert.equal(state.date, null, message);
    assert.deepEqual(state.dateRange, { start, end }, message);
  }
  assert.match(stateOf('11月21日、22日帮我排个旧金山一日游').clarification, /多个日期/);
  assert.deepEqual(stateOf('12月第一个周末帮我排个旧金山一日游').state.dateRange, { start: '2026-12-05', end: '2026-12-06' });
  // Weekends in general, a day already chosen in the conversation, and a past span.
  assert.equal(stateOf('周末一般去哪玩比较好').state.dateRange, undefined);
  const first = stateOf('下周末湾区有什么亲子活动').state;
  assert.deepEqual(resolveTaskState({ message: '周末有室内的吗', previous: first, today: TODAY, carry: true }).state.dateRange, { start: '2026-10-24', end: '2026-10-25' });
  assert.match(stateOf('October 5 or 6 family events').clarification, /已经过去/);
  // v1 (no carry) keeps its reading.
  assert.match(resolveTaskState({ message: '11月21日、22日周末湾区有什么华人社区活动？', today: TODAY }).clarification, /多个日期/);
});

test('English asks reach the Chinese catalog rows: L08 East Bay markets, a Pleasanton parade, Cantonese film', () => {
  const markets = evidence('Any farmers markets in the East Bay on Saturday morning?');
  for (const id of ['event:berkeley-downtown-saturday-farmers-market-2026', 'event:oakland-grand-lake-farmers-market-2026']) assert.ok(itemIds(markets).includes(id), itemIds(markets).join(', '));
  // The model sees the English name, not the Chinese title.
  const grandLake = markets.items.find(item => item.id === 'oakland-grand-lake-farmers-market-2026');
  assert.match(grandLake.title, /^Grand Lake Farmers Market/);
  assert.doesNotMatch(grandLake.title, /[㐀-鿿]/);
  assert.ok(itemIds(evidence('Any markets in the East Bay on Saturday?')).includes('event:berkeley-downtown-saturday-farmers-market-2026'));
  const parade = evidence('Are there any parades in Pleasanton on December 5?');
  assert.equal(itemIds(parade)[0], 'event:pleasanton-hometown-holiday-2026', itemIds(parade).join(', '));
  // "Are there any" is not a subject: no renter's checklist or doctor guide beside the parade.
  assert.ok(!parade.items.some(item => /move-in|doctor|uss-hornet/.test(item.id)), itemIds(parade).join(', '));
  assert.ok(itemIds(evidence('Any Cantonese film screenings in San Francisco on November 14?')).includes('event:sfpl-richmond-hk-film-hard-boiled-2026'));
  // Review: an English information ask is not matched by one incidental word, the asked city or a region word.
  for (const [message, stray] of [['What should I do if my child has a fever at night in San Jose?', /night-market|turkey-trot|thanksgiving/],
    ['How much is parking at the San Francisco Zoo?', /fort-mason|artspan/], ['Where can I buy a Christmas tree in the South Bay?', /spooktacular|sounds-of-south-asia|opera-sj|matilda/]]) {
    const ids = itemIds(evidence(message));
    assert.ok(!ids.some(id => id.startsWith('event:') && stray.test(id)), `${message}: ${ids.join(', ')}`);
  }
  // A Chinese ask keeps the Chinese title.
  const zh = evidence('这周六东湾有什么农夫市集？');
  assert.match(zh.items.find(item => item.id === 'oakland-grand-lake-farmers-market-2026').title, /[㐀-鿿]/);
});

test('live L04: the streamed lead never shows a count, so the result does not correct it', async () => {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const { createPublicContext } = require('../lib/publicContext');
  const lead = 'No free museum days are listed for this weekend, but two free options are open that weekend [[e1]].';
  const answer = { lead, points: [{ text: 'SFMOMA public spaces are free [[e1]].', cardIds: [] }, { text: 'The Exploratorium has a free day later [[e2]].', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' };
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_ENGINE: 'v2', BAYBAY_STATE_SECRET: 'api-bb-5-isolated-secret-0123456789' },
    catalog: planner, guideCatalog: guides, englishGuideCatalog: guidesEn, isTest: true, now: () => Date.parse('2026-10-14T19:00:00Z'),
    ai: async (payload, options) => {
      const text = JSON.stringify(answer);
      if (options?.onText) for (let index = 0; index < text.length; index += 3) options.onText(text.slice(index, index + 3));
      return { model: 'claude-sonnet-5-5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text }] }] };
    } });
  const events = [];
  const result = await assistant.run({ message: 'Are there any free museum days in San Francisco this weekend?', locale: 'en', currentPath: '/en', history: [], searchMode: 'site', webAccess: { allowed: false },
    pageContext: createPublicContext({ guideCatalog: guides }).resolve({ context: { currentPath: '/en' }, currentPath: '/en', today: TODAY, locale: 'en' }), onDraft: event => events.push(event) });
  const drafted = events.filter(event => event.field === 'lead').map(event => event.text).join('');
  assert.ok(drafted.length > 20, drafted);
  assert.doesNotMatch(drafted, /\btwo\b/i);
  assert.doesNotMatch(result.lead, /\btwo\b/i);
  assert.equal(result.corrected, false);
});

test('review: a streamed lead with people or a count is always a prefix of the result (zh and en, any chunking)', () => {
  const { createDraftWriter } = require('../lib/baybayProgress');
  const { leadConsistency } = require('../lib/baybayQuality');
  const points = [{ text: 'a', cardIds: ['x'] }, { text: 'b', cardIds: ['y'] }];
  for (const [lead, locale] of [['周六带两个孩子去奥克兰动物园。', 'zh-Hans'], ['周六有两场比赛，适合带两个孩子去看。', 'zh-Hans'], ['这周六可以去两家博物馆，再去公园。', 'zh-Hans'],
    ['一家三口可以去这两个地方', 'zh-Hans'], ['这周末东湾有 3 场适合孩子的活动', 'zh-Hans'], ['周六东湾有两场免费活动，适合孩子。', 'zh-Hant'],
    ['December 5 is packed with family events in Pleasanton.', 'en'], ['Two free events fit your Saturday.', 'en'], ['Kids aged three to five love these places.', 'en']]) {
    const final = leadConsistency({ lead, points }, { locale }).draft.lead;
    for (const chunk of [1, 2, 3, 5]) for (const batchChars of [1, 8]) {
      const writer = createDraftWriter({ emit: () => {}, locale, batchChars, setTimer: () => null, clearTimer: () => {} });
      for (let index = 0; index < lead.length; index += chunk) writer.text('lead', undefined, lead.slice(index, index + chunk));
      writer.done('lead'); writer.end({ complete: true });
      assert.equal(writer.sent().lead, final, `${lead} / ${chunk} / ${batchChars}`);
    }
  }
  // People and a non-option count stay as written.
  assert.equal(leadConsistency({ lead: '周六带两个孩子去奥克兰动物园。', points }).draft.lead, '周六带两个孩子去奥克兰动物园。');
  assert.equal(leadConsistency({ lead: '周六有两场比赛，适合带两个孩子去看。', points }).draft.lead, '周六有两场比赛，适合带两个孩子去看。');
});

test('review: holiday weekends, background months, ages beside a date and English weekday follow-ups', () => {
  // A weekend named after a holiday is not this weekend (10/17-18); its own words still find its events.
  for (const message of ['感恩节周末带孩子去哪玩', '感恩节周末湾区有什么免费活动', 'Thanksgiving weekend things to do with kids', '圣诞节周末去哪玩', '万圣节周末有什么活动', '国庆长周末带孩子去哪', '退伍军人节周末活动', 'long weekend ideas for families']) {
    const { state } = stateOf(message);
    assert.notDeepEqual(state.dateRange, { start: '2026-10-17', end: '2026-10-18' }, message);
    assert.notEqual(state.date, '2026-10-17', message);
  }
  for (const message of ['感恩节周末带孩子去哪玩', 'Thanksgiving weekend things to do with kids']) assert.ok(itemIds(evidence(message)).includes('event:sfpl-bernal-family-game-night-nov28-2026'), message);
  // A month that dates something else in the ask is not the outing's span.
  for (const message of ['我们3月搬来湾区，有什么适合孩子的活动', '宝宝3月出生的，现在有什么适合的活动', '我1月要回国，回国前想带孩子出去玩', '我12月去日本，这之前周末带孩子去哪玩', '五月天演唱会有什么活动', '12月天气怎么样']) {
    assert.equal(askedDateRange(message, TODAY), null, message);
    assert.equal(stateOf(message).state.dateRange, undefined, message);
  }
  const trip = askedDateRange('12月去旧金山玩什么', TODAY);
  assert.deepEqual([trip.start, trip.end], ['2026-12-01', '2026-12-31'], 'a Bay Area outing in December keeps its month');
  // A child's age beside a date is not the end of a span.
  for (const message of ['12/5 and 8 year old twins, what to do', 'Dec 6 and 7-year-old twins', 'Dec 6 and 7 yo twins']) assert.equal(askedDateRange(message, TODAY), null, message);
  // English weekday follow-ups inside a carried span: every spelling.
  const december = stateOf('first weekend of December, anything for kids in Oakland?').state;
  assert.deepEqual(december.dateRange, { start: '2026-12-05', end: '2026-12-06' });
  for (const [message, date] of [['What about Saturday?', '2026-12-05'], ['Can you plan Saturday for us?', '2026-12-05'], ['How about Sunday?', '2026-12-06'], ['What about Sat?', '2026-12-05'], ['And Sun?', '2026-12-06']]) {
    assert.equal(resolveTaskState({ message, previous: december, today: TODAY, carry: true }).state.date, date, message);
  }
  assert.equal(resolveTaskState({ message: 'What about this Saturday?', previous: december, today: TODAY, carry: true }).state.date, '2026-10-17');
});

test('review: "有没有室内的" carries indoor through a San Mateo conversation into the plan', () => {
  let state = stateOf('这周六带 3 岁和 7 岁的孩子在 San Mateo 玩，总预算 60 刀，下午 4 点前要回家').state;
  assert.deepEqual([state.city, state.date, state.childAges, state.budget, state.budgetScope, state.finishBy], ['San Mateo', '2026-10-17', [3, 7], 60, 'total', '16:00']);
  for (const message of ['那周日呢', '有没有室内的', '帮我排个周日半天的行程']) {
    state = resolveTaskState({ message, previous: state, today: TODAY, carry: true }).state;
    assert.deepEqual([state.city, state.date, state.childAges, state.budget, state.budgetScope, state.finishBy], ['San Mateo', '2026-10-18', [3, 7], 60, 'total', '16:00'], message);
    if (message !== '那周日呢') assert.equal(state.setting, 'indoor', message);
  }
  assert.equal(state.goal, 'day-plan');
  for (const message of ['有沒有室內的活動', '周日带孩子去哪，有没有室内的？']) assert.equal(stateOf(message).state.setting, 'indoor', message);
  assert.equal(stateOf('有没有户外的').state.setting, 'outdoor');
  assert.equal(stateOf('不要室内的').state.setting, 'outdoor');
});

test('review: English plan asks, a bare "back by 3", and kids-activities asks', () => {
  for (const message of ['Plan a Saturday for us by BART with two kids, back by 5pm', "Can you plan our Sunday? We'll take Caltrain.", 'We need a half-day plan for Sunday in Oakland', '周六想去两个地方，帮我排一下']) {
    assert.equal(stateOf(message).state.goal, 'day-plan', message);
  }
  for (const message of ['Plan a trip to Japan', 'Can you plan a visit to the DMV?']) assert.notEqual(stateOf(message).state.goal, 'day-plan', message);
  const outing = stateOf('Anything for kids in Oakland this Saturday?').state;
  const planned = resolveTaskState({ message: "ok plan it, we'll take Caltrain", previous: outing, today: TODAY, carry: true }).state;
  assert.deepEqual([planned.goal, planned.city, planned.date, planned.travelMode], ['day-plan', 'Oakland', '2026-10-17', 'transit']);
  assert.ok(planned.preferences.includes('rail:caltrain'));
  for (const [message, finishBy] of [['We are in Fremont on Saturday with our 6 year old, need to be back by 3', '15:00'], ['Saturday in Oakland with kids, done by 4', '16:00'],
    ['Back by 3:30 please, Saturday in Oakland with kids', '15:30'], ['Leave at 1pm, back by 5', '17:00'], ['Saturday in Oakland, back by 5pm', '17:00'], ['Saturday morning, back by 11', '11:00']]) {
    assert.equal(stateOf(message).state.finishBy, finishBy, message);
  }
  for (const message of ['What can kids do in the East Bay on December 5?', 'kids activities in San Jose this weekend', 'Any activities for toddlers in Palo Alto on Sunday?']) assert.equal(stateOf(message).state.goal, 'discover', message);
});

test('area fit: a San Jose ask is not led by San Francisco museums; a BART day plan keeps places BART cannot reach behind', () => {
  const { railServes, railSystemsIn } = require('../lib/baybayTransit');
  const sanJose = evidence('我妈七十岁不会英文，住 San Jose，想找中文的老人活动和美术馆');
  const cityOf = item => item.city || item.row?.city || null;
  assert.ok(sanJose.items.filter(item => ['event', 'place'].includes(item.kind)).every(item => cityOf(item) === 'San Jose'), sanJose.items.map(item => `${item.id} ${cityOf(item)}`).join(', '));
  assert.ok(!itemIds(sanJose).some(id => /sfmoma|exploratorium/.test(id)));
  // San Francisco (or no city) still names its museums.
  assert.ok(itemIds(evidence('旧金山有什么免费博物馆')).includes('place:venue-sfmoma'));
  const bart = stateOf('帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家').state;
  assert.equal(bart.travelMode, 'transit');
  assert.ok(bart.preferences.includes('rail:bart'));
  const plan = buildFastEvidence({ query: '帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家', originalQuery: '帮我排个周六的行程，我们坐 BART 去，下午 4 点前回家', state: bart, guideCatalog: guides, catalog: planner, discoveries, today: TODAY, locale: 'zh-Hans', audience: true });
  const rows = plan.candidates.map(row => ({ id: row.id, city: row.city }));
  assert.ok(rows.length >= 3, JSON.stringify(rows));
  for (const row of rows.slice(0, 6)) assert.ok(railServes(row.city, ['bart'], bart.date), JSON.stringify(row));
  assert.ok(!rows.some(row => /healdsburg|premium-outlets/.test(row.id)), JSON.stringify(rows));
  // The table: Livermore and Healdsburg have no BART station; Gilroy's Caltrain stop is weekday-only; driving clears the rail.
  assert.equal(railServes('Livermore', ['bart']), false); assert.equal(railServes('Healdsburg', ['bart', 'caltrain']), false);
  assert.equal(railServes('Gilroy', ['caltrain'], '2026-10-17'), false); assert.equal(railServes('Gilroy', ['caltrain'], '2026-10-16'), true);
  assert.deepEqual(railSystemsIn('不坐 BART，我们开车'), []);
  const drive = resolveTaskState({ message: '改成开车', previous: bart, today: TODAY, carry: true }).state;
  assert.ok(!drive.preferences.some(value => value.startsWith('rail:')), JSON.stringify(drive.preferences));
});

test('latency (live L01, D1): one round trip per quota claim, a slow spend read does not hold the turn, an idle keep-alive read', async () => {
  const { createBayBayAssistant, dbKeepAliveInterval } = require('../lib/baybayAgent');
  const calls = [], rows = new Map();
  const Quota = {
    updateOne: async () => { calls.push('updateOne'); return {}; },
    findOneAndUpdate: async ({ id, count }, update, options = {}) => {
      calls.push(`${options.upsert ? 'upsert' : 'claim'} ${id.split(':')[0]}`);
      let row = rows.get(id);
      if (!row && options.upsert) { row = { count: 0 }; rows.set(id, row); }
      else if (row && options.upsert && !(row.count < count.$lt)) throw Object.assign(new Error('E11000'), { code: 11000 });
      if (!row || !(row.count < count.$lt)) return null;
      row.count++; return { ...row };
    },
    findOne: (filter, projection) => { calls.push(`read ${filter.id.split(':')[0]} ${JSON.stringify(projection)}`); return { lean: async () => rows.get(filter.id) || null }; },
  };
  let budgetReads = 0, slowBudget = false;
  const budget = () => { budgetReads++; return new Promise(resolve => setTimeout(() => resolve({ level: 'ok', caps: { enforced: true }, day: TODAY }), slowBudget ? 1500 : 0)); };
  const answer = JSON.stringify({ lead: '可以。', points: [], candidateIds: [], followups: [], coverage: [], gap: '' });
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-5-isolated-secret-0123456789', BAYBAY_VISITOR_RUN_LIMIT: '2' },
    catalog: planner, guideCatalog: guides, isTest: false, now: () => Date.parse('2026-10-14T19:00:00Z'), Quota, budget,
    ai: async () => ({ model: 'claude-sonnet-5-5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: answer }] }] }) });
  const ask = message => assistant.run({ message, locale: 'zh-Hans', searchMode: 'site', ip: '192.0.2.10' });
  await ask('旧金山这周末有什么活动');
  assert.deepEqual(calls, ['upsert baybay-run', 'upsert baybay-agent'], 'a new visitor: one round trip per row (was upsert + claim each)');
  calls.length = 0;
  // A spend read that has turned slow: today's last known level answers, so the turn does not wait 1.5 s for it.
  slowBudget = true;
  const began = Date.now();
  const second = await ask('金门公园这周末有什么免费活动');
  assert.ok(Date.now() - began < 1400, `${Date.now() - began} ms`);
  assert.equal(second.notice, undefined);
  assert.deepEqual(calls, ['claim baybay-run', 'claim baybay-agent'], 'rows claimed before: the plain claim');
  // The share is used up: the claim is refused (E11000 on the upsert path after a restart is the same).
  calls.length = 0; slowBudget = false;
  const third = await ask('奥克兰这周末有什么活动');
  assert.equal(third.notice?.kind, 'ai_daily_budget');
  assert.ok(budgetReads >= 3);
  // Keep-alive: off by default in tests (only startWarmUp starts it), an indexed read of today's quota row when idle.
  assert.equal(dbKeepAliveInterval({}), 25000); assert.equal(dbKeepAliveInterval({ BAYBAY_DB_KEEPALIVE_MS: '100' }), 5000);
  assert.equal(dbKeepAliveInterval({ BAYBAY_DB_KEEPALIVE_MS: '0' }), 0); assert.equal(dbKeepAliveInterval({ BAYBAY_DB_KEEPALIVE: 'off' }), 0);
  calls.length = 0;
  assert.equal(assistant.startWarmUp({ log: () => {}, keepAliveMs: 30 }), true);
  for (let i = 0; i < 100 && !assistant.warmStatus().keepAlive.runs; i++) await new Promise(resolve => setTimeout(resolve, 20));
  assert.ok(assistant.warmStatus().keepAlive.runs >= 1, JSON.stringify(assistant.warmStatus()));
  assert.ok(calls.includes('read baybay-agent {"_id":1}'), calls.join(', '));
  assert.ok(!calls.some(call => /upsert|claim|updateOne/.test(call)), 'the keep-alive never writes');
});

// Fixture Anthropic transport (no network): the request bodies and a JSON answer per call.
function anthropicFixture({ respond, config = {} } = {}) {
  const { createBayBayAssistant } = require('../lib/baybayAgent');
  const { sseFor, sseResponse } = require('./support/anthropic-sse');
  const { createPublicContext } = require('../lib/publicContext');
  const sent = [];
  const message = text => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text }], usage: { input_tokens: 40, output_tokens: 60 } });
  const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-5-isolated-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000', ...config },
    guideCatalog: guides, catalog: planner, now: () => Date.parse('2026-10-14T19:00:00Z'), isTest: false, Quota: { findOneAndUpdate: async () => ({ count: 1 }), updateOne: async () => ({}) },
    fetchImpl: async (url, init) => {
      const body = JSON.parse(init.body); sent.push(body);
      const value = await respond(body, sent.length);
      if (value.ok !== undefined) return value;
      const answer = value.type === 'message' ? value : message(typeof value === 'string' ? value : JSON.stringify(value));
      // A streamed call (a capable client's lead) gets the same message as SSE events.
      return body.stream ? sseResponse(sseFor(answer)) : reply(answer);
    } });
  const page = locale => createPublicContext({ guideCatalog: guides }).resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale });
  const run = (text, extra = {}) => assistant.run({ message: text, locale: 'zh-Hans', currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false }, pageContext: page('zh-Hans'), ...extra });
  return { assistant, sent, run };
}
// The plan's first stop's own evidence ref, so the answer cites the plan as the plan guard requires.
const planAnswer = body => {
  const text = body.messages.map(row => (row.content || []).map(part => part.text || '').join('\n')).join('\n');
  const start = text.lastIndexOf('{"researchComplete"'), end = text.indexOf('\n', start);
  const plan = start >= 0 ? JSON.parse(text.slice(start, end > 0 ? end : undefined)) : {};
  const ref = plan.currentPlan?.stops?.[0]?.sourceIds?.[0] || 'e1';
  return { lead: '周六半天先逛唐人街，再去华埠分馆。', points: [{ text: `唐人街 [[${ref}]]`, cardIds: [] }, { text: `华埠分馆 [[${ref}]]`, cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' };
};

test('live L07: a new site day plan is one streamed call around the plan engine\'s plan; BAYBAY_DAY_PLAN_FAST=off keeps two rounds', async () => {
  const single = anthropicFixture({ respond: body => planAnswer(body) });
  const drafts = [];
  const result = await single.run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程', { onDraft: event => drafts.push(event) });
  assert.equal(result.route.path, 'agent');
  assert.equal(single.sent.length, 1, 'one model call');
  assert.equal(single.sent[0].tool_choice?.type, 'none');
  assert.equal(single.sent[0].stream, true, 'the call streams its lead');
  assert.ok(result.research.warnings.includes('day_plan_single_call'));
  assert.ok(result.assistantPlan?.stops?.length >= 2, JSON.stringify(result.assistantPlan?.stops));
  assert.ok(drafts.some(event => event.field === 'lead'), 'a streamed lead before the result');
  assert.equal(result.degraded, false);
  const agent = anthropicFixture({ config: { BAYBAY_DAY_PLAN_FAST: 'off' }, respond: (body, count) => count === 1 && body.tool_choice?.type === 'auto'
    ? { type: 'message', id: 'm', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 't1', name: 'search_site', input: { query: '唐人街' } }], usage: { input_tokens: 1, output_tokens: 1 } }
    : planAnswer(body) });
  await agent.run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程');
  assert.ok(agent.sent.length >= 2, `${agent.sent.length} calls`);
  assert.equal(agent.sent[0].tool_choice?.type, 'auto', 'BAYBAY_DAY_PLAN_FAST=off: a research round first');
});

test('live L07: a connection that closed under the request ("fetch failed") is retried once inside the call; its failure kind is connection', async () => {
  const { failureReason } = require('../lib/baybayQuality');
  let failures = 1;
  const flaky = anthropicFixture({ respond: async body => { if (failures-- > 0) throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'UND_ERR_SOCKET' } }); return planAnswer(body); } });
  const result = await flaky.run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程');
  assert.equal(result.degraded, false);
  assert.ok(!result.research.warnings.includes('model_unavailable'), JSON.stringify(result.research.warnings));
  assert.equal(flaky.sent.length, 2, 'the same request, sent again once');
  assert.deepEqual(flaky.sent[0], flaky.sent[1]);
  assert.deepEqual(failureReason(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } })), { kind: 'connection', socket: 'ECONNRESET' });
  assert.deepEqual(failureReason(Object.assign(new TypeError('fetch failed'), { cause: { code: 'SOMETHING_PRIVATE' } })), { kind: 'connection' });
  // An HTTP error is not retried by the adapter (the engine's own recovery handles a 529 once).
  let calls = 0;
  const overloaded = { ok: false, status: 529, clone() { return this; }, text: async () => '{}', json: async () => ({}) };
  const busy = anthropicFixture({ respond: async body => (++calls === 1 ? overloaded : planAnswer(body)) });
  const recovered = await busy.run('周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程');
  assert.equal(busy.sent.length, 2);
  assert.ok(recovered.research.warnings.includes('model_unavailable') && recovered.research.warnings.includes('final_synthesis_recovered'), JSON.stringify(recovered.research.warnings));
  // The recovery sends the final turn once, not twice.
  assert.equal(busy.sent[1].messages.filter(row => (row.content || []).some(part => /researchComplete/.test(part.text || ''))).length, 1);
});

test('live D2: the 12月5日 East Bay family ask sees the day\'s parade, book sale and storytimes', () => {
  for (const message of ['12月5日东湾有什么适合孩子的活动', 'Family things to do in the East Bay on December 5?', 'What can kids do in the East Bay on December 5?']) {
    const found = itemIds(evidence(message));
    for (const id of ['event:pleasanton-hometown-holiday-2026', 'event:ccclib-danville-friends-book-sale-dec5-2026', 'event:opl-main-family-storytime-2026']) assert.ok(found.includes(id), `${message}: ${found.join(', ')}`);
  }
});

test('multi-turn carry: ages, a per-person budget and a finish time survive follow-ups; dated offers keep to the asked day', async () => {
  const first = stateOf('这周六带 4 岁和 8 岁的孩子在 Fremont 玩，每人预算 20 刀以内，下午 5 点前要回家').state;
  assert.equal(first.goal, 'discover', 'an outing with the companions, a place and 玩');
  assert.deepEqual([first.city, first.date, first.childAges, first.budget, first.budgetScope, first.finishBy], ['Fremont', '2026-10-17', [4, 8], 20, 'person', '17:00']);
  assert.ok(!first.preferences.some(value => value.startsWith('time-of-day:')), '下午 5 点前 is a finish time, not an afternoon wish');
  const sunday = resolveTaskState({ message: '那周日呢？', previous: first, today: TODAY, carry: true }).state;
  const indoor = resolveTaskState({ message: '有室内的吗', previous: sunday, today: TODAY, carry: true }).state;
  const plan = resolveTaskState({ message: '帮我排个周日的行程，我们坐 BART 去', previous: indoor, today: TODAY, carry: true }).state;
  for (const state of [sunday, indoor, plan]) assert.deepEqual([state.city, state.date, state.childAges, state.budget, state.budgetScope, state.finishBy], ['Fremont', '2026-10-18', [4, 8], 20, 'person', '17:00']);
  assert.equal(indoor.setting, 'indoor'); assert.equal(plan.goal, 'day-plan'); assert.equal(plan.travelMode, 'transit'); assert.ok(plan.preferences.includes('rail:bart'));
  // Offers: IKEA's Wednesday-only kids' meals and a 12/5 workshop are not options on Sunday 10/18.
  const offers = buildFastEvidence({ query: '那周日呢？带孩子 免费 儿童 活动', originalQuery: '那周日呢？带孩子免费儿童活动', state: sunday, guideCatalog: guides, catalog: planner, discoveries, today: TODAY, locale: 'zh-Hans', audience: true });
  assert.ok(!itemIds(offers).some(id => /ikea-kids-eat-free-wednesdays|keepsakes-dec5/.test(id)), itemIds(offers).join(', '));
});

test('follow-ups and phrasings found by the unseen block M (API-BB-5)', () => {
  // A weekday follow-up inside a carried span is that span's weekday.
  const december = stateOf('12月第一个周末想带爸妈和 7 岁的孩子在东湾逛逛').state;
  assert.deepEqual(december.dateRange, { start: '2026-12-05', end: '2026-12-06' });
  const free = resolveTaskState({ message: '只要免费的', previous: december, today: TODAY, carry: true }).state;
  assert.equal(resolveTaskState({ message: '帮我排成周六半天，坐 BART', previous: free, today: TODAY, carry: true }).state.date, '2026-12-05');
  assert.equal(resolveTaskState({ message: '那周日呢', previous: free, today: TODAY, carry: true }).state.date, '2026-12-06');
  assert.equal(resolveTaskState({ message: '这周日呢', previous: free, today: TODAY, carry: true }).state.date, '2026-10-18', 'this week\'s Sunday stays this week');
  // Outing phrasings: 带娃出门, 带孩子去博物馆, anything for kids; not 出门买菜 or 出去看病.
  for (const message of ['周末想带娃出门，东湾有什么推荐？', '我住 San Jose，想带孩子去博物馆，有什么推荐？', 'Anything for kids in San Jose the weekend of November 21?']) assert.equal(stateOf(message).state.goal, 'discover', message);
  for (const message of ['带妈妈出门买菜', '带孩子出去看病']) assert.notEqual(stateOf(message).state.goal, 'discover', message);
  assert.deepEqual(stateOf('周末想带娃出门，东湾有什么推荐？').state.dateRange, { start: '2026-10-17', end: '2026-10-18' });
  // A month bounds an events ask; not "我1月要回国".
  assert.deepEqual(stateOf('12月有什么圣诞点灯或者游行？').state.dateRange, { start: '2026-12-01', end: '2026-12-31' });
  assert.equal(stateOf('我1月要回国，要带什么').state.dateRange, undefined);
  const parades = itemIds(evidence('12月有什么圣诞点灯或者游行？'));
  assert.equal(parades[0], 'event:pleasanton-hometown-holiday-2026', parades.join(', '));
  assert.ok(!parades.some(id => /halloween|veterans/.test(id)), parades.join(', '));
  // The San Jose museum ask from home is ordered from San Jose.
  const museums = evidence('我住 San Jose，想带孩子去博物馆，有什么推荐？').items.filter(item => ['event', 'place'].includes(item.kind));
  assert.equal(museums[0]?.city, 'San Jose', museums.map(item => `${item.id} ${item.city}`).join(', '));
});

test('block M dry run: 每人最多 15 刀, 3 点前要结束, 排周日半天 / 帮我排一下, English plan stops', async () => {
  const oakland = stateOf('这周六想带 5 岁和 10 岁的孩子在 Oakland 玩，每人最多 15 刀，3 点前要结束').state;
  assert.deepEqual([oakland.budget, oakland.budgetScope, oakland.finishBy], [15, 'person', '15:00']);
  assert.equal(resolveTaskState({ message: '3 点前要结束', today: TODAY }).state.finishBy, '03:00', 'v1 keeps its reading');
  assert.equal(stateOf('9 点前回家').state.finishBy, '09:00', '8-12 stay as written');
  assert.equal(stateOf('周六坐 Caltrain 带爸妈出去玩半天，帮我排一下').state.goal, 'day-plan');
  assert.equal(stateOf('帮我排周日半天，我们开车').state.goal, 'day-plan');
  assert.notEqual(stateOf('帮我安排一下预约').state.goal, 'day-plan');
  // An English plan names its stops in English.
  const english = anthropicFixture({ respond: body => planAnswer(body) });
  const result = await english.run('We are taking BART on Sunday with two kids, can you plan a half day?', { locale: 'en', currentPath: '/en' });
  assert.ok(result.assistantPlan?.stops?.length, JSON.stringify(result.research.warnings));
  for (const stop of result.assistantPlan.stops) assert.doesNotMatch(stop.title, /[㐀-鿿]{2}/, stop.title);
});
