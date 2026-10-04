const test = require('node:test');
const assert = require('node:assert/strict');
const { bayAreaDate, searchScope, assertSearchScope, mentionedCities, canonicalCity } = require('../lib/bayAreaSearchScope');
const { requestSearch } = require('../lib/plannerWebSearch');
const now = () => Date.parse('2026-10-04T19:00:00Z');
const input = { query: '今天有什麼活動，地方好去？', locale: 'zh-Hant', date: '2026-10-04', region: 'all' };
function response(answer, city) {
  const text = `${answer} [source]${city ? `\nBAYLINK_CANDIDATES_V1\n${JSON.stringify([{ name: 'Official event [place]', city: `${city} [place]`, summary: null, timeSummary: null, priceSummary: null }])}\nEND_BAYLINK_CANDIDATES_V1` : ''}`;
  return { model: 'gpt-4.1-mini-2025-04-14', status: 'completed', output: [
    { type: 'web_search_call', status: 'completed', action: { type: 'search' } },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations: [...text.matchAll(/\[(?:source|place)\]/g)].map(match => ({ type: 'url_citation', url: 'https://www.sf.gov/events', title: 'Official events', start_index: match.index, end_index: match.index + match[0].length })) }] },
  ] };
}
const options = { isTest: true, now, lookup: async () => [{ address: '93.184.216.34' }], extractAi: async () => ({ candidates: [] }) };

test('scope resolves Pacific midnight and both DST offsets, not server UTC dates', () => {
  assert.equal(bayAreaDate(() => Date.parse('2026-10-04T06:59:59Z')), '2026-10-03');
  assert.equal(bayAreaDate(() => Date.parse('2026-10-04T07:00:00Z')), '2026-10-04');
  assert.equal(bayAreaDate(() => Date.parse('2026-12-04T07:59:59Z')), '2026-12-03');
  assert.equal(bayAreaDate(() => Date.parse('2026-12-04T08:00:00Z')), '2026-12-04');
});

test('whole Bay Area stays broad and explicit local city aliases are canonical', () => {
  const scope = searchScope(input, now);
  assert.equal(scope.city, null); assert.equal(scope.weekday, 'Sunday'); assert.equal(scope.country, 'US');
  assert.equal(canonicalCity('聖荷西'), 'San Jose');
  assert.deepEqual(mentionedCities('South San Francisco'), ['South San Francisco']);
  assert.equal(searchScope({ query: 'Oakland museums', city: 'Oakland' }, now).city, 'Oakland');
});

test('search uses California approximate location and exact Pacific date/weekday instructions, and reports provider model', async () => {
  let payload;
  const result = await requestSearch(input, { ...options, ai: async value => { payload = value; return response('舊金山灣區 2026-10-04 的選項，出發前核對官方安排。'); } });
  assert.deepEqual(payload.tools[0].user_location, { type: 'approximate', country: 'US', region: 'California', city: 'San Francisco', timezone: 'America/Los_Angeles' });
  assert.match(payload.instructions, /whole nine-county Bay Area/); assert.match(payload.instructions, /2026-10-04, Sunday/);
  assert.match(payload.instructions, /language is a display preference, never a location signal/);
  assert.equal(result.model, 'gpt-4.1-mini-2025-04-14'); assert.equal(result.configuredModel, 'gpt-4.1-mini');
  await requestSearch({ ...input, city: 'San Jose' }, { ...options, ai: async value => { assert.equal(value.tools[0].user_location.city, 'San Jose'); return response('San Jose options need venue confirmation.'); } });
});

test('a real-looking citation cannot make a Shanghai answer or foreign candidate acceptable', async () => {
  await assert.rejects(requestSearch(input, { ...options, ai: async () => response('今天（2026年10月4日），上海有多場精彩活動可供參與：') }), error => error.code === 'SEARCH_VERIFICATION_FAILED' && error.model === 'gpt-4.1-mini-2025-04-14');
  await assert.rejects(requestSearch(input, { ...options, ai: async () => response('湾区今日可选。', 'Shanghai') }), error => error.code === 'SEARCH_VERIFICATION_FAILED');
  assert.throws(() => assertSearchScope({ answer: 'Bay Area options include events in Shanghai.' }, input), /location\/date/);
});

test('reject wrong requested city, ungrounded city-wide absence, and today/weekday contradictions', () => {
  const local = { ...input, city: 'San Jose' }, scope = searchScope(local, now);
  for (const answer of ['今天旧金山有三个活动。', '今天没有特定的活動安排。', 'There are no events today in San Jose.', '每周三（今天）免费。', 'Today (Wednesday) admission is free.', '今天是周三，入场免费。', 'Today is Wednesday, and admission is free.', '2026-10-05 is today in San Jose.']) {
    assert.throws(() => assertSearchScope({ answer }, local, scope), /location\/date/, answer);
  }
  assert.throws(() => assertSearchScope({ answer: 'San Jose', candidates: [{ city: 'Oakland' }] }, local, scope), /location\/date/);
});

test('scope explanations, restaurant names, regular Wednesday rules and honest incomplete searches remain allowed', () => {
  for (const answer of ['范围是旧金山湾区，不是上海。', 'Shanghai Dumpling in San Francisco requires confirmation.', 'YBCA 常规每周三免费；2026-10-04 是周日，不能套用。', 'I could not verify any events in this lookup; that does not mean the city has none.']) {
    assert.doesNotThrow(() => assertSearchScope({ answer }, input, searchScope(input, now)), answer);
  }
  const tomorrow = searchScope({ ...input, date: '2026-10-05' }, now);
  assert.doesNotThrow(() => assertSearchScope({ answer: 'Today (Sunday) is October 4; your selected date is Monday October 5.' }, input, tomorrow));
  assert.throws(() => assertSearchScope({ answer: '今天（2025年10月4日），湾区推荐。' }, input, searchScope(input, now)), /location\/date/);
  const oakland = { ...input, city: 'Oakland' };
  assert.doesNotThrow(() => assertSearchScope({ answer: 'Oakland options for 2026-10-04.\nVisit Jack London Square.' }, oakland, searchScope(oakland, now)));
});
