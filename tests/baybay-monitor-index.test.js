// BBENG-01: the source monitor's review status was joined to every evidence source by
// scanning all monitored rows (two URL parses per pair) on every question: 0.4-0.9 s
// of blocked event loop locally, 1-3 s on Render. It is now indexed once per refresh.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext } = require('../lib/publicContext');
const guides = require('../data/guide-catalog.json');

const NOW = Date.parse('2026-10-12T05:30:00Z');
const catalog = loadPlannerCatalog();
const publicContext = createPublicContext({ guideCatalog: guides });
const fast = { type: 'message', id: 'm', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 10 },
  content: [{ type: 'text', text: JSON.stringify({ lead: '可以。', points: [{ text: '示例。', cardIds: [] }], candidateIds: [], followups: [], coverage: [], gap: '' }) }] };
const QUESTION = '这周末旧金山有什么适合孩子的免费活动？';

function assistantWith(monitorStatus) {
  return createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture', BAYBAY_STATE_SECRET: 'private-test-task-secret-0123456789' },
    guideCatalog: guides, catalog, now: () => NOW, isTest: false, Quota: { updateOne: async () => ({}), findOneAndUpdate: async () => ({ count: 1 }) }, monitorStatus,
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => fast, clone() { return this; }, text: async () => '' }) });
}
const ask = assistant => assistant.run({ message: QUESTION, locale: 'zh-Hans', currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false },
  pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: '2026-10-11', locale: 'zh-Hans' }) });

test('review flags come from an index built once per monitor refresh; the first row for a URL decides', async () => {
  const urls = (await ask(assistantWith(async () => []))).evidence.map(row => row.url).filter(url => /^https:\/\//.test(url));
  assert.ok(urls.length >= 3, `${urls.length} absolute evidence URLs`);
  const [pendingFirst, noneFirst, utmVariant] = urls;
  let reads = 0;
  const counted = (url, reviewStatus) => ({ get url() { reads++; return url; }, reviewStatus });
  const filler = Array.from({ length: 1300 }, (_, index) => counted(`https://monitor.example/page-${index}`, index % 2 ? 'pending' : 'none'));
  const rows = [counted(pendingFirst, 'pending'), counted(pendingFirst, 'none'), counted(noneFirst, 'none'), counted(noneFirst, 'pending'),
    counted(`${utmVariant}${utmVariant.includes('?') ? '&' : '?'}utm_source=newsletter`, 'pending'), ...filler];
  let refreshes = 0;
  const assistant = assistantWith(async () => { refreshes++; return rows; });
  const first = await ask(assistant);
  const readsAfterFirst = reads;
  assert.ok(readsAfterFirst <= rows.length, `${readsAfterFirst} URL reads for ${rows.length} rows: one pass, not one per source`);
  const flag = url => first.evidence.find(row => row.url === url)?.needsReview;
  assert.equal(flag(pendingFirst), true);
  assert.ok(!flag(noneFirst), 'the first row for a URL decides');
  assert.equal(flag(utmVariant), true, 'URLs are compared in canonical form (tracking parameters dropped)');
  const second = await ask(assistant);
  assert.equal(reads, readsAfterFirst, 'a question within the refresh window reads no monitor row');
  assert.equal(refreshes, 1);
  assert.deepEqual(second.evidence.map(row => [row.url, !!row.needsReview]), first.evidence.map(row => [row.url, !!row.needsReview]));
});
