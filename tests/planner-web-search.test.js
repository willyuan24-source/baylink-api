const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { registerPlannerWebSearch, validateSearchInput, safeUrl, checkedSourceUrl, extractSearchResult, requestSearch } = require('../lib/plannerWebSearch');
const { createMemoryModels } = require('./support/memory-models');
const { createApplication } = require('../server');
const NOW = Date.parse('2026-09-29T19:00:00Z');
const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
function raw(url = 'https://museum.org/visit') {
  const text = 'Public hours and prices need confirmation. [source]';
  return { status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search', sources: [{ type: 'url', url }] } },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations: [{ type: 'url_citation', url, title: 'Official visitor page', start_index: text.indexOf('[source]'), end_index: text.length }] }] }] };
}
async function fixture(t, options = {}) {
  const models = options.models || createMemoryModels();
  const app = express(); app.use(express.json());
  registerPlannerWebSearch(app, { Quota: models.PostTranslationQuota, checkRateLimit: () => true, ai: async () => raw(), isTest: true, now: () => NOW, lookup, ...options });
  const server = await new Promise(resolve => { const server = app.listen(0, '127.0.0.1', () => resolve(server)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const request = async body => {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/api/planner/web-search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json(), cacheControl: r.headers.get('cache-control') };
  };
  return { request, models };
}
test('only bounded explicit public queries and geography are accepted; private plans are rejected', () => {
  assert.deepEqual(validateSearchInput({ query: '  SF museum  ', date: '2026-10-03', city: ' SF ' }), { query: 'SF museum', locale: 'zh-Hans', date: '2026-10-03', city: 'SF' });
  for (const value of [null, [], {}, { query: 'x' }, { query: 'x'.repeat(501) }, { query: 'SF\0museum' }, { query: 'SF museum', plans: [] }, { query: 'SF museum', filters: {} }, { query: 'SF museum', city: '' }, { query: 'SF museum', region: '' }, { query: 'SF museum', date: '2026-02-30' }, { query: 'SF museum', locale: 'unknown' }]) assert.throws(() => validateSearchInput(value), error => error.status === 400);
});
test('source URLs reject credentials, non-web schemes, IP tricks, local names and private DNS', async () => {
  for (const url of ['javascript:alert(1)', 'file:///etc/passwd', 'https://user:pass@museum.org/', 'http://127.0.0.1', 'http://2130706433', 'http://0x7f000001', 'http://[::1]', 'http://[::ffff:127.0.0.1]', 'http://localhost/a', 'http://metadata.google.internal', 'http://venue.local', 'https://museum.org:8443/', 'https://museum.org\\@127.0.0.1/', 'https://museum.org/\n']) assert.equal(safeUrl(url), null, url);
  assert.equal(await checkedSourceUrl('https://museum.org/visit', async () => [{ address: '10.1.2.3' }]), null);
  assert.equal(await checkedSourceUrl('https://museum.org/visit', async () => [{ address: '93.184.216.34' }, { address: '127.0.0.1' }]), null);
  assert.equal(await checkedSourceUrl('https://museum.org/visit', async () => { throw Error('no DNS'); }), null);
  assert.equal(await checkedSourceUrl('https://museum.org/visit#hours', lookup), 'https://museum.org/visit');
});
test('only completed tool citations become sources, numbered in the answer without generated snippets', async () => {
  const result = await extractSearchResult(raw(), { lookup, now: () => NOW });
  assert.equal(result.answer, 'Public hours and prices need confirmation. [1]');
  assert.deepEqual(result.sources, [{ title: 'Official visitor page', url: 'https://museum.org/visit' }]);
  assert.equal(result.checkedAt, '2026-09-29T19:00:00.000Z');
  for (const value of [{ answer: 'Fake answer', sources: [{ url: 'https://museum.org' }] }, { ...raw(), status: 'incomplete' }, { ...raw(), output: raw().output.slice(1) }, raw('http://127.0.0.1')]) await assert.rejects(extractSearchResult(value, { lookup }), error => error.status === 503);
  const noCitations = raw(); noCitations.output[1].content[0].annotations = [];
  await assert.rejects(extractSearchResult(noCitations, { lookup }), error => error.status === 503);
});

test('real-style heading and citation debris is cleaned without losing text or rebinding sources', async () => {
  const text = '##[venue])\n\nGott’s Ferry Building：普通周六 10:00–22:00（非 10/3 当天保证）。[hours]\n地图位置（入口需核实）：[map]\n儿童规则（5–12 岁）仍需核实。([again])\n##\n)\n### 出发前再查临时调整';
  const annotations = [
    ['[venue]', 'https://www.gotts.com/locations', 'Gott’s official locations'],
    ['[hours]', 'https://www.gotts.com/locations', 'Gott’s official hours'],
    ['[map]', 'https://maps.google.com/', 'Google Maps'],
    ['[again]', 'https://maps.google.com/', 'Google Maps'],
  ].map(([marker, url, title]) => ({ type: 'url_citation', url, title, start_index: text.indexOf(marker), end_index: text.indexOf(marker) + marker.length }));
  const response = raw(); response.output[1].content[0] = { type: 'output_text', text, annotations };
  const result = await extractSearchResult(response, { lookup, now: () => NOW });
  assert.equal(result.answer, '[1]\n\nGott’s Ferry Building：普通周六 10:00–22:00（非 10/3 当天保证）。[1]\n地图位置（入口需核实）：[2]\n儿童规则（5–12 岁）仍需核实。([2])\n\n出发前再查临时调整');
  assert.deepEqual(result.sources, [
    { title: 'Gott’s official locations', url: 'https://www.gotts.com/locations' },
    { title: 'Google Maps', url: 'https://maps.google.com/' },
  ]);
  assert.equal(result.checkedAt, '2026-09-29T19:00:00.000Z');
});
test('provider request uses Responses web_search once, low context and no persisted conversation', async () => {
  let request;
  const input = validateSearchInput({ query: 'SF museums', locale: 'en' });
  const result = await requestSearch(input, { config: { OPENAI_API_KEY: 'isolated-test-placeholder' }, lookup, now: () => NOW,
    fetchImpl: async (url, options) => { request = { url, body: JSON.parse(options.body), signal: options.signal }; return { ok: true, json: async () => raw() }; },
  });
  assert.equal(request.url, 'https://api.openai.com/v1/responses');
  assert.equal(request.body.model, 'gpt-4.1-mini');
  assert.equal(request.body.store, false); assert.equal(request.body.tool_choice, 'required'); assert.equal(request.body.max_tool_calls, 1);
  assert.deepEqual(request.body.tools, [{ type: 'web_search', search_context_size: 'low', external_web_access: true }]);
  assert.equal(request.body.input, JSON.stringify(input)); assert.ok(request.signal instanceof AbortSignal);
  assert.match(request.body.instructions, /plain text: no Markdown headings/);
  assert.match(request.body.instructions, /recurring weekly schedule.*regular weekday hours, not confirmed hours for the requested date/);
  assert.match(request.body.instructions, /temporary changes.*official site/);
  assert.match(request.body.instructions, /retrieval time is not the source publication, update or confirmation date/);
  assert.equal(result.responseMode, 'web');
});
test('dated searches always append an application reminder in the requested language even if the model omits it', async () => {
  const response = raw(); const part = response.output[1].content[0];
  part.text = '因此 2026-10-03 营业 10:00–22:00。[source]';
  part.annotations[0].start_index = part.text.indexOf('[source]');
  part.annotations[0].end_index = part.text.length;
  const options = { ai: async () => response, lookup, now: () => NOW };
  const extracted = await extractSearchResult(response, options);
  const reminders = {
    'zh-Hans': 'BAYLINK 核对提醒：所选日期 2026-10-03 的实际营业、余票和临时调整仍需向来源确认；常规每周时段不保证当日营业。以上时间为网页查询结果，不是 BAYLINK 的当天确认。',
    'zh-Hant': 'BAYLINK 核對提醒：所選日期 2026-10-03 的實際營業、餘票和臨時調整仍需向來源確認；常規每週時段不保證當日營業。以上時間為網頁查詢結果，不是 BAYLINK 的當天確認。',
    en: "BAYLINK verification reminder: Confirm actual opening hours, ticket availability and temporary changes for your selected date 2026-10-03 with the sources; regular weekly hours do not guarantee opening that day. The times above are web-search results, not BAYLINK's confirmation for that day.",
  };
  for (const [locale, reminder] of Object.entries(reminders)) {
    const result = await requestSearch({ query: 'Gott’s hours', date: '2026-10-03', locale }, options);
    assert.deepEqual(result, { ...extracted, answer: `${extracted.answer}\n\n${reminder}` });
  }
  assert.deepEqual(await requestSearch({ query: 'Gott’s hours', locale: 'en' }, options), extracted);
});
test('same query cache preserves original checkedAt and same in-flight query spends only one call', async t => {
  let calls = 0; let time = NOW;
  const { request, models } = await fixture(t, { ai: async () => { calls++; await new Promise(resolve => setTimeout(resolve, 20)); return raw(); }, now: () => time });
  const results = await Promise.all([request({ query: 'SF museums' }), request({ query: 'SF museums' })]);
  assert.ok(results.every(row => row.status === 200 && row.data.cached === false)); assert.equal(calls, 1);
  time += 60000;
  const cached = await request({ query: 'SF museums' });
  assert.equal(cached.data.cached, true); assert.equal(cached.data.checkedAt, results[0].data.checkedAt); assert.equal(calls, 1);
  assert.equal(cached.cacheControl, 'no-store'); assert.equal(models.PostTranslationQuota.rows[0].count, 1);
  time += 600000;
  assert.equal((await request({ query: 'SF museums' })).data.cached, false); assert.equal(calls, 2);
});
test('atomic global daily allowance is shared across instances and failed calls consume their reservation', async t => {
  const models = createMemoryModels(); let calls = 0;
  const options = { models, config: { PLANNER_WEB_SEARCH_DAILY_LIMIT: '1' }, ai: async () => { calls++; throw Error('upstream denied'); } };
  const a = await fixture(t, options); const b = await fixture(t, options);
  assert.equal((await a.request({ query: 'SF museum' })).status, 503);
  assert.equal((await b.request({ query: 'Oakland museum' })).status, 429);
  assert.equal(calls, 1); assert.equal(models.PostTranslationQuota.rows[0].count, 1);
  assert.match(models.PostTranslationQuota.rows[0].id, /^planner-web-search:2026-09-29$/);
});
test('missing or disabled service returns 503 without quota spend; IP limits precede provider calls', async t => {
  for (const options of [{ ai: undefined }, { config: { OPENAI_WEB_SEARCH_ENABLED: 'false' } }, { config: { PLANNER_WEB_SEARCH_DAILY_LIMIT: '0' } }]) {
    const { request, models } = await fixture(t, options); const result = await request({ query: 'SF museums' });
    assert.equal(result.status, 503); assert.equal(result.data.ok, false); assert.equal('sources' in result.data, false); assert.equal(models.PostTranslationQuota.rows.length, 0);
  }
  let count = 0;
  const limited = await fixture(t, { checkRateLimit: () => false, ai: async () => { count++; return raw(); } });
  assert.equal((await limited.request({ query: 'SF museums' })).status, 429); assert.equal(count, 0);
});
test('provider and body timeouts are bounded and never produce pretend results', async t => {
  const { request } = await fixture(t, { config: { PLANNER_WEB_SEARCH_TEST_TIMEOUT_MS: 20 }, ai: () => new Promise(() => {}) });
  assert.equal((await request({ query: 'SF museums' })).status, 503);
  await assert.rejects(requestSearch({ query: 'SF museums' }, { config: { OPENAI_API_KEY: 'fixture' }, timeoutMs: 20, fetchImpl: async () => ({ ok: true, json: () => new Promise(() => {}) }) }), error => error.status === 503 || /timed out/.test(error.message));
});
test('application registers the real web route with isolated provider and DNS dependencies', async t => {
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-tests' }, models: createMemoryModels(), ai: { plannerWebSearch: async () => raw() }, plannerWebLookup: lookup, plannerNow: () => NOW });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${app.server.address().port}/api/planner/web-search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'SF museums' }) });
  assert.equal(response.status, 200); assert.equal((await response.json()).responseMode, 'web');
});
