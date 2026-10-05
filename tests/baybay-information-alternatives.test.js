const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { resolveTaskState, decodeTaskToken } = require('../lib/baybayState');
const { inferFilters } = require('../lib/planner');

const TODAY = '2026-10-05';
const NOW = Date.parse(`${TODAY}T19:00:00Z`);
const SECRET = 'isolated-information-alternatives-test';
const catalog = require('../data/planner-catalog.json');
const guideCatalog = require('../data/guide-catalog.json');
const north = '11月7、8号在北湾，带5岁孩子想看看自然，别推酒庄。Sugarloaf那边有合适的吗？';
const cities = 'Belvedere跟Tiburon有啥值得看的？各给点，不要把附近地方都说成在城里。';
const final = answer => ({ status: 'completed', model: 'fixture', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });
const resolve = (message, previous) => resolveTaskState({ message, previous, today: TODAY, catalog });
const assistant = ai => createBayBayAssistant({ config: { JWT_SECRET: SECRET }, catalog, guideCatalog, isTest: true, now: () => NOW, ai });

test('north-outdoors-child: date comparison reaches sourced synthesis and retains age without choosing a day', async () => {
  let input;
  const api = assistant(async payload => {
    input = JSON.parse(payload.input[0].content);
    const source = input.evidence.find(row => /Sugarloaf/i.test(row.text));
    assert.ok(source, 'the real site nature guide reaches synthesis');
    assert.ok(!payload.tools.some(row => row.name === 'create_plan'), 'comparing options does not ask for an itinerary');
    assert.match(payload.instructions, /智能检索/);
    assert.match(payload.instructions, /联网查/);
    return final(`11月7、8日分别核对自然项目的日期和年龄条件；不会把成人专场当作5岁儿童可参加的活动。 [[${source.id}]]`);
  });
  const result = await api.run({ message: north, searchMode: 'site' });
  assert.ok(input, 'must not return a one-day-plan clarification before the model');
  assert.equal(result.taskState.goal, 'information');
  assert.equal(result.taskState.region, 'north-bay');
  assert.equal(result.taskState.date, null);
  assert.equal(result.taskState.dateContextMonth, '2026-11');
  assert.deepEqual(result.taskState.childAges, [5]);
  assert.equal(result.assistantPlan, undefined);
  assert.equal(result.degraded, false);
  assert.ok(result.sources.length > 0);
  const token = decodeTaskToken(result.assistantSessionToken, { secret: SECRET, now: () => NOW });
  assert.deepEqual(token.state.childAges, [5]);
  assert.equal(token.state.dateContextMonth, '2026-11');
});

test('small-city-boundary and solano-river-no-swimming: both named cities remain information subjects', async () => {
  for (const message of [cities, 'Dixon和Rio Vista哪儿适合带娃在水边转转？不想钓鱼，也别给我已经结束的节。']) {
    let input;
    const result = await assistant(async payload => {
      input = JSON.parse(payload.input[0].content);
      const source = input.evidence.find(row => row.kind === 'guide');
      assert.ok(source, 'city information reaches the model with evidence');
      return final(`会分别说明两城本地地点与附近地点，不把附近景点归到城内。 [[${source.id}]]`);
    }).run({ message, searchMode: 'site' });
    assert.ok(input, message);
    assert.equal(result.taskState.goal, 'information');
    assert.equal(result.taskState.city, null, 'never silently choose the first city');
    assert.equal(result.assistantPlan, undefined);
    assert.equal(result.degraded, false);
    assert.ok(result.sources.length > 0);
  }
});

test('comparison hides create_plan and rejects an undeclared model plan call without losing sources', async () => {
  let rounds = 0;
  const result = await assistant(async payload => {
    assert.ok(!payload.tools.some(row => row.name === 'create_plan'));
    if (!rounds++) return { status: 'completed', model: 'fixture', output: [{ type: 'function_call', name: 'create_plan', call_id: 'not-requested', arguments: JSON.stringify({ candidateIds: ['pier39'] }) }] };
    const output = payload.input.find(row => row.type === 'function_call_output');
    assert.equal(JSON.parse(output.output).code, 'plan_not_requested');
    const input = JSON.parse(payload.input[0].content);
    return final(`会分别核对两城的本地地点，附近地点另作说明。 [[${input.evidence[0].id}]]`);
  }).run({ message: cities, searchMode: 'site' });
  assert.equal(rounds, 2);
  assert.equal(result.assistantPlan, undefined);
  assert.equal(result.degraded, false);
  assert.ok(result.sources.length);
});

test('site-only tool errors name the matching Simplified, Traditional and English UI controls', async () => {
  for (const [locale, labels] of [['zh-Hans', '智能检索 / 联网查'], ['zh-Hant', '智能檢索 / 聯網查'], ['en', 'Smart / Web']]) {
    let rounds = 0;
    const result = await assistant(async payload => {
      if (!rounds++) return { status: 'completed', model: 'fixture', output: [{ type: 'function_call', name: 'read_source', call_id: 'unavailable-read', arguments: JSON.stringify({ sourceId: 'any' }) }] };
      const output = JSON.parse(payload.input.find(row => row.type === 'function_call_output').output);
      assert.equal(output.code, 'site_only');
      assert.ok(output.error.includes(labels));
      return final(locale === 'en' ? 'The current answer uses the selected site snapshots.' : '当前答复使用所选的站内资料。');
    }).run({ message: cities, locale, searchMode: 'site' });
    assert.equal(rounds, 2);
    assert.equal(result.retrieval.webStatus, 'not_requested');
    assert.equal(result.assistantPlan, undefined);
  }
});

test('comparison keeps confirmed household context and signed followups without an arbitrary city or date filter', async () => {
  let calls = 0, followupInput;
  const api = assistant(async payload => {
    const input = JSON.parse(payload.input[0].content);
    calls++;
    if (calls === 3) followupInput = input;
    return final('会按已确认的家庭条件核对各个选项。');
  });
  const first = await api.run({ message: '我住 Fremont，两个大人带5岁孩子，总预算100美元，先只问资料，不排行程。', searchMode: 'site' });
  const comparison = await api.run({ message: north, searchMode: 'site', sessionToken: first.assistantSessionToken });
  const followup = await api.run({ message: '我们改成13号晚上了，孩子也去，就去那个Sips and Stars吧？', searchMode: 'site', sessionToken: comparison.assistantSessionToken,
    history: [{ role: 'user', content: north }, { role: 'assistant', content: comparison.answer }] });
  assert.equal(calls, 3, 'all informational turns can reach synthesis');
  for (const result of [comparison, followup]) {
    assert.deepEqual(result.taskState.childAges, [5]);
    assert.equal(result.taskState.partySize, 3);
    assert.equal(result.taskState.budget, 100);
    assert.equal(result.taskState.budgetScope, 'total');
    assert.equal(result.taskState.origin, 'Fremont');
    assert.equal(result.assistantPlan, undefined);
  }
  assert.ok(followupInput.recentConversation.some(turn => turn.content === north));
  assert.equal(comparison.taskState.date, null, 'neither comparison day was selected');
  assert.equal(followup.taskState.date, '2026-11-13', 'the explicit comparison month resolves the abbreviated correction');
  assert.equal(followup.taskState.dateContextMonth, undefined, 'a selected date replaces month-only context');
});

test('abbreviated date corrections never invent the month or retain it after a date clear', () => {
  const comparison = resolve(north).state;
  assert.equal(resolve('改成13号晚上了', comparison).state.date, '2026-11-13');
  assert.equal(resolve('改成13号晚上了').state.date, null);
  const crossMonth = resolve('10月31号或者11月1号，先比较一下两天的开放时间。').state;
  assert.equal(crossMonth.dateContextMonth, undefined);
  assert.equal(resolve('改成13号晚上了', crossMonth).state.date, null);
  const cleared = resolve('日期不限', comparison).state;
  assert.equal(cleared.dateContextMonth, undefined);
  assert.equal(resolve('改成13号晚上了', cleared).state.date, null);
  assert.equal(resolve('不要改成13号，继续比较原来的两天。', comparison).state.date, null);
  assert.ok(resolve('改成31号晚上了', comparison).clarification, 'November 31 must not be normalized into December');
  const staleUi = resolveTaskState({ message: '其他条件不变', previous: comparison, searchContext: { date: '2026-10-05' }, catalog, today: TODAY });
  assert.equal(staleUi.state.date, null);
  assert.equal(staleUi.state.dateContextMonth, '2026-11');
});

test('an explicit no-itinerary date comparison remains information despite mentioning activities', () => {
  const result = resolve('11月7、8日比较一下旧金山亲子活动，不安排行程。');
  assert.equal(result.state.goal, 'information');
  assert.equal(result.state.date, null);
  assert.equal(result.state.dateContextMonth, '2026-11');
  assert.equal(result.clarification, undefined);
  assert.ok(resolve('11月7、8日安排旧金山一日行程。').clarification);
});

test('the information exception does not suppress real plan choices, malformed dates, or outside-Bay-Area guards', () => {
  for (const message of ['11月7、8号在北湾，带5岁孩子安排一天', 'Belvedere和Tiburon，帮我安排一天']) assert.ok(resolve(message).clarification, message);
  assert.throws(() => inferFilters(north, TODAY), /多个日期/, 'legacy planner remains single-day by default');
  for (const message of ['2026-11-07或2026-11-99有哪些规则？', '11月31、32号的开放时间是什么？', '11月7、32号的开放时间是什么？', 'November 7 or 99, what are the opening rules?', '11月7日星期日的开放时间是什么？']) assert.ok(resolve(message).clarification, message);
  assert.ok(resolve('上海和北京有啥值得看的？各给点。').clarification);
});

test('caltrain-holiday-check: a Sunday timetable is not a second departure date', () => {
  for (const message of ['11月11号算假日，Caltrain是不是按周日跑？带5岁娃从半岛出发，先告诉我班表和票怎么查，别安排景点。', 'On November 11, does Caltrain run on the Sunday schedule? Tell me about the timetable, not an itinerary.']) {
    const result = resolve(message);
    assert.equal(result.clarification, undefined);
    assert.equal(result.state.date, '2026-11-11');
    assert.notEqual(result.state.goal, 'day-plan');
  }
  assert.equal(resolve('按周日出发，从Fremont到San Jose怎么走？').state.date, '2026-10-11', 'a departure weekday is still a real date');
});

test('november-family-negative-followup: rejecting purchase requirements is not a shopping goal', () => {
  const previous = resolve('11月7号那个周末想带5岁娃去旧金山晃晃，有什么不买东西也能参加的？别给我十月份过期的。').state;
  const next = resolve('别给晚上的，也不要必须先买东西的。白天挑两三个就好，不用排整天行程。', previous).state;
  assert.equal(next.goal, 'information');
  assert.equal(next.city, 'San Francisco');
  assert.equal(next.date, '2026-11-07');
  assert.deepEqual(next.childAges, [5]);
  assert.equal(resolve('我想先买东西，帮我看看有哪些购物选择。').state.goal, 'shopping');
});

test('sf-family-budget-two-stops and sf-drop-first-stop-followup preserve the actual casual plan and edited handoff', async () => {
  const message = '11月7日两个大人带5岁娃，上午10点从旧金山Ferry Building出发，先Exploratorium再Pier39。坐公交，下午3点必须结束，不回原点，最多这两站，总预算120美元。帮我排得松一点。';
  const stateResult = resolve(message);
  assert.equal(stateResult.state.goal, 'day-plan');
  assert.equal(stateResult.state.returnToOrigin, false);
  assert.deepEqual(stateResult.explicitCandidateIds, ['venue-exploratorium-daytime', 'pier39']);
  assert.ok(stateResult.state.preferences.includes('relaxed-pace'));
  for (const nonPlan of ['先比较 Exploratorium 再介绍 Pier39 的儿童门票，不排行程。', '别先Exploratorium再Pier39，也不用帮我排得松一点，只讲票价。']) assert.notEqual(resolve(nonPlan).state.goal, 'day-plan');
  const api = assistant(async payload => {
    const input = JSON.parse(payload.input[0].content);
    const source = input.evidence.find(row => /pier39\.com/.test(row.url));
    assert.ok(source);
    return final(`保留当前确认的地点；PIER39 公共步行区与自费项目分开核对，交通仍需核实。 [[${source.id}]]`);
  });
  const first = await api.run({ message, searchMode: 'site' });
  assert.deepEqual(first.assistantPlan.stops.map(stop => stop.entityId), ['venue-exploratorium-daytime', 'pier39']);
  for (const correction of ['没说第一站不去了，只是想晚点出发。', '不是第一站不去了，只是第一站想晚点到。', '你说“第一站先不去了”，但我没有这个意思。']) {
    const retained = await api.run({ message: correction, searchMode: 'site', sessionToken: first.assistantSessionToken });
    assert.deepEqual(retained.assistantPlan.stops.map(stop => stop.entityId), ['venue-exploratorium-daytime', 'pier39'], correction);
    assert.deepEqual(retained.taskState.excludedCandidateIds, [], correction);
  }
  const next = await api.run({ message: '第一站先不去了，就看海狮吧，不回原点，其他条件不变。', searchMode: 'site', sessionToken: first.assistantSessionToken });
  assert.deepEqual(next.assistantPlan.stops.map(stop => stop.entityId), ['pier39']);
  assert.deepEqual(next.assistantPlan.handoff.stops.map(stop => stop.id), ['pier39']);
  assert.deepEqual(next.assistantPlan.alternatives, []);
  assert.deepEqual(next.taskState.selectedCandidateIds, ['pier39']);
  assert.ok(next.taskState.excludedCandidateIds.includes('venue-exploratorium-daytime'));
  for (const result of [first, next]) {
    assert.equal(result.taskState.goal, 'day-plan');
    assert.equal(result.taskState.returnToOrigin, false);
    assert.equal(result.taskState.date, '2026-11-07');
    assert.equal(result.taskState.originCandidateId, 'venue-ferry-building');
    assert.equal(result.taskState.partySize, 3);
    assert.deepEqual(result.taskState.childAges, [5]);
    assert.equal(result.taskState.travelMode, 'transit');
    assert.equal(result.taskState.startTime, '10:00');
    assert.equal(result.taskState.finishBy, '15:00');
    assert.equal(result.taskState.maxStops, 2);
    assert.equal(result.taskState.budget, 120);
    assert.equal(result.taskState.budgetScope, 'total');
    assert.equal(result.degraded, false);
    assert.ok(!result.assistantPlan.unknowns.some(value => /回程交通|return trip/i.test(value)));
  }
});
