const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { buildChatWebRequest } = require('../lib/guideWebSearch');
const { validateWebCandidates } = require('../lib/plannerWebLibrary');
const NOW = Date.parse('2026-10-01T19:00:00Z');
const SECRET = 'isolated-web-library-tests';
const candidate = { id: 'web-fixture', name: 'Museum', city: 'Oakland', summary: null, timeSummary: 'Regular weekly hours; date-specific changes unknown', priceSummary: null, sourceUrls: ['https://museumca.org/visit/'], checkedAt: '2026-10-01T19:00:00.000Z', requestedDate: '2026-10-03' };
function raw() {
  const text = 'Current conditions must be checked with the venue. [source]';
  return { status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search' } }, { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations: [{ type: 'url_citation', title: 'Museum visit', url: 'https://museumca.org/visit/', start_index: text.indexOf('[source]'), end_index: text.length }] }] }] };
}
async function fixture(t, options = {}) {
  const models = createMemoryModels({ User: ['owner', 'other'].map(id => ({ id, accountStatus: 'active', email: `${id}@fixture.test` })) });
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...options.config }, models, plannerNow: () => NOW,
    ai: { guideChat: options.guideChat, plannerWebSearch: options.search || (async () => raw()), plannerWebExtract: async () => ({ candidates: [] }) }, plannerWebLookup: async () => [{ address: '93.184.216.34' }], ...(options.guideCatalog ? { guideCatalog: options.guideCatalog } : {}) });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, body, as = path.startsWith('/ai/') ? 'owner' : undefined) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method: body === undefined ? 'GET' : path.includes('web-candidates') ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json', ...(as ? { Authorization: `Bearer ${jwt.sign({ id: as }, SECRET, { expiresIn: '1h' })}` } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, data: await response.json() };
  };
  return { request, models };
}

test('private candidate library is owner scoped, survives reload and rejects stale replacement', async t => {
  const { request } = await fixture(t);
  assert.equal((await request('/planner/web-candidates')).status, 401);
  const saved = await request('/planner/web-candidates', { candidates: [candidate], revision: 0 }, 'owner');
  assert.equal(saved.status, 200); assert.equal(saved.data.revision, 1);
  assert.deepEqual((await request('/planner/web-candidates', undefined, 'owner')).data, saved.data);
  assert.deepEqual((await request('/planner/web-candidates', undefined, 'other')).data, { candidates: [], revision: 0 });
  assert.equal((await request('/planner/web-candidates', { candidates: [], revision: 0 }, 'owner')).status, 409);
  assert.equal((await request('/planner/web-candidates', { candidates: [], revision: 1 }, 'owner')).status, 200);
});

test('candidate library preserves uncertainty and rejects fabricated structured facts or unsafe links', () => {
  assert.deepEqual(validateWebCandidates([candidate]), [candidate]);
  for (const changed of [{ latitude: 37 }, { verified: true }, { checkedAt: '2026-02-30' }, { requestedDate: '2026-02-30' }, { sourceUrls: ['http://127.0.0.1/'] }, { priceSummary: 0 }, { id: '<script>' }]) assert.throws(() => validateWebCandidates([{ ...candidate, ...changed }]));
  assert.throws(() => validateWebCandidates([candidate, candidate]));
  assert.throws(() => validateWebCandidates(Array.from({ length: 21 }, (_, i) => ({ ...candidate, id: `web-${i}` }))));
});

test('site mode never calls web; smart uses cited sources and shares planner cache and tool budget', async t => {
  let calls = 0;
  const { request, models } = await fixture(t, { search: async () => { calls++; return raw(); } });
  const query = 'Oakland museum opening hours';
  const site = await request('/ai/guide-chat', { message: query, locale: 'en', searchMode: 'site' });
  assert.equal(site.status, 200); assert.equal(calls, 0); assert.equal(site.data.retrieval.webStatus, 'not_requested');
  const smart = await request('/ai/guide-chat', { message: query, locale: 'en', searchMode: 'smart' });
  assert.equal(smart.status, 200); assert.equal(calls, 1); assert.equal(smart.data.retrieval.webStatus, 'completed');
  assert.equal(smart.data.sources.length, smart.data.retrieval.sourceCount); assert.match(smart.data.answer, /\[1\]/);
  assert.equal(smart.data.coverage.exhaustive, false); assert.equal(models.PostTranslationQuota.rows[0].count, 2);
  const again = await request('/ai/guide-chat', { message: query, locale: 'en', searchMode: 'web' });
  assert.equal(calls, 1); assert.equal(again.data.retrieval.cached, true);
  assert.equal(again.data.retrieval.checkedAt, smart.data.retrieval.checkedAt);
  assert.equal(smart.data.retrieval.requestedDate, '2026-10-01');
  const dated = await request('/ai/guide-chat', { message: 'Oakland museums on 2026-10-17', locale: 'en', searchMode: 'smart' });
  assert.equal(dated.data.retrieval.requestedDate, '2026-10-17');
});

test('web failures remain explicit without fabricated citations and invalid modes do not spend', async t => {
  let calls = 0;
  const { request } = await fixture(t, { search: async () => { calls++; throw Error('offline'); } });
  const failed = await request('/ai/guide-chat', { message: 'Latest Oakland museum hours', locale: 'en', searchMode: 'web' });
  assert.equal(failed.status, 200); assert.equal(failed.data.retrieval.webStatus, 'unavailable'); assert.equal(failed.data.sources, undefined);
  assert.match(failed.data.matchNote, /no new web facts/);
  assert.equal((await request('/ai/guide-chat', { message: 'Find museums', searchMode: 'anything' })).status, 400);
  assert.equal((await request('/ai/guide-chat', { message: 'Find museums', searchContext: { address: 'private' } })).status, 400);
  assert.equal(calls, 1);
});

test('follow-up web queries retain only public constraints, not private user or assistant history', () => {
  const history = [{ role: 'user', content: 'Oakland museums October 3 indoors under $30' }, { role: 'assistant', content: 'INVENTED SECRET assistant facts' }, { role: 'user', content: 'My address is private@example.com' }];
  const result = buildChatWebRequest({ message: 'Any more free ones?', history, searchMode: 'smart', locale: 'en', today: '2026-10-01' });
  assert.equal(result.search, true); assert.equal(result.input.city, 'Oakland'); assert.equal(result.input.date, '2026-10-03');
  assert.match(result.input.query, /museums/); assert.match(result.input.query, /indoor/); assert.doesNotMatch(JSON.stringify(result.input), /SECRET|private@example|assistant/);
  const missing = buildChatWebRequest({ message: 'Any more free ones?', history: [], searchMode: 'smart', locale: 'en', today: '2026-10-01' });
  assert.equal(missing.search, false); assert.ok(missing.question);
  const privateReply = buildChatWebRequest({ message: 'My booking confirmation is 650-123-4567', history, searchMode: 'web', locale: 'en', today: '2026-10-01' });
  assert.equal(privateReply.status, 'not_applicable');
});

test('max two tool calls reserve two units and cannot overspend a smaller remaining budget', async t => {
  let calls = 0;
  const { request, models } = await fixture(t, { config: { PLANNER_WEB_SEARCH_DAILY_LIMIT: '3' }, search: async () => { calls++; return raw(); } });
  assert.equal((await request('/planner/web-search', { query: 'Oakland museums' }, 'owner')).status, 200);
  assert.equal((await request('/planner/web-search', { query: 'Berkeley museums' }, 'owner')).status, 429);
  assert.equal(calls, 1); assert.equal(models.PostTranslationQuota.rows[0].count, 2);
});

test('unavailable smart web lookup preserves a successful grounded site AI answer', async t => {
  let guideCalls = 0;
  const answer = 'The published guide explains museum admission conditions. Keep this complete grounded answer when the web service is unavailable.';
  const { request } = await fixture(t, { search: async () => { throw Error('unavailable'); }, guideChat: async () => { guideCalls++; return { answer }; } });
  const result = await request('/ai/guide-chat', { message: 'Oakland museum hours', searchMode: 'smart', locale: 'en' });
  assert.equal(guideCalls, 1); assert.equal(result.data.answer, answer); assert.equal(result.data.responseMode, 'ai');
  assert.equal(result.data.retrieval.webStatus, 'unavailable'); assert.equal(result.data.sources, undefined);
});

test('a missing-context follow-up asks for clarification without claiming an AI outage or a completed search', async t => {
  const { request } = await fixture(t, { search: async () => assert.fail('clarification must not search the web') });
  const result = await request('/ai/guide-chat', { message: 'Any more free ones?', searchMode: 'smart', locale: 'en' });
  assert.equal(result.data.degraded, false); assert.equal(result.data.responseMode, 'search');
  assert.equal(result.data.retrieval.scope, 'none'); assert.equal(result.data.retrieval.webStatus, 'not_requested');
  assert.match(result.data.answer, /Which city or area/);
});

test('summarizing a specific guide in smart mode does not replace the article with web discovery', async t => {
  let searches = 0;
  const guide = { slug: 'museum-entry', url: '/guides/museum-entry', title: 'Oakland museum guide', summary: 'Published admission conditions', content: 'Public guidance on museum admission.', keywords: ['museum', 'Oakland'], categories: ['other'], updatedAt: '2026-10-01' };
  const { request } = await fixture(t, { guideCatalog: [guide], search: async () => { searches++; return raw(); }, guideChat: async () => ({ answer: 'Here are the published admission conditions from this museum guide.' }) });
  const result = await request('/ai/guide-chat', { message: 'Summarize this guide about visiting Oakland museums', searchMode: 'smart', locale: 'en', context: { currentPath: guide.url } });
  assert.equal(searches, 0); assert.equal(result.data.responseMode, 'ai'); assert.equal(result.data.retrieval.webStatus, 'not_requested');
  const siteQuestion = await request('/ai/guide-chat', { message: 'What free family crafts are in the current guides?', searchMode: 'smart', locale: 'en' });
  assert.equal(searches, 0); assert.equal(siteQuestion.data.responseMode, 'ai'); assert.equal(siteQuestion.data.retrieval.webStatus, 'not_requested');
});

test('museum admission prices remain eligible for smart web lookup instead of school routing', async t => {
  let searches = 0;
  const { request } = await fixture(t, { search: async () => { searches++; return raw(); } });
  const result = await request('/ai/guide-chat', { message: 'Oakland museum admission prices', searchMode: 'smart', locale: 'en' });
  assert.equal(searches, 1); assert.equal(result.data.retrieval.webStatus, 'completed'); assert.equal(result.data.responseMode, 'web');
});
