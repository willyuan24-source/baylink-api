const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const NOW = Date.parse('2026-10-04T19:00:00Z');
function web(answer) {
  const text = `${answer} [official]`;
  return { model: 'gpt-4.1-mini-2025-04-14', status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search' } },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations: [{ type: 'url_citation', title: 'Official tourism page', url: 'https://www.shanghai.gov.cn/', start_index: text.indexOf('[official]'), end_index: text.length }] }] }] };
}
async function fixture(t, overrides = {}) {
  let chatCalls = 0, searchCalls = 0, chatInput, searchInput;
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: 'isolated-baybay-geography', OPENAI_MODEL: 'configured-chat-model', OPENAI_WEB_SEARCH_MODEL: 'configured-web-model', OPENAI_API_KEY: 'never-include-this-secret' }, models: createMemoryModels(), plannerNow: () => NOW,
    ai: { guideChat: async input => { chatCalls++; chatInput = input; return { model: 'provider-chat-snapshot', choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ answer: 'Here is the published information about using BAYLINK and its local guides.' }) } }] }; }, plannerWebSearch: async input => { searchCalls++; searchInput = input; return overrides.web?.(input) || web('今天（2026年10月4日），上海有多場精彩活動可供參與：'); }, plannerWebExtract: async () => ({ candidates: [] }) },
    plannerWebLookup: async () => [{ address: '93.184.216.34' }], ...overrides.options });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  return { ask: async body => { const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/guide-chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); assert.equal(response.status, 200); const data = await response.json(); assert.doesNotMatch(JSON.stringify(data), /never-include-this-secret/); return data; }, counts: () => ({ chatCalls, searchCalls, chatInput, searchInput }) };
}

test('the exact screenshot request rejects cited Shanghai and keeps date-filtered Bay Area records', async t => {
  const f = await fixture(t);
  const result = await f.ask({ message: '今天有什麼活動，地方好去？', locale: 'zh-Hant', searchMode: 'smart' });
  assert.equal(result.responseMode, 'catalog'); assert.equal(result.retrieval.webStatus, 'verification_failed');
  assert.equal(result.retrieval.requestedDate, '2026-10-04'); assert.equal(result.retrieval.city, null);
  assert.match(result.answer, /站內記錄/); assert.doesNotMatch(result.answer, /上海|周三（今天）/);
  assert.ok(result.catalogSources.length); assert.equal(result.sources, undefined);
  assert.equal(f.counts().chatCalls, 0); assert.equal(f.counts().searchCalls, 1);
  assert.equal(result.retrieval.rejectedWebModel, 'gpt-4.1-mini-2025-04-14');
});

test('site-only Sunday free events do not call models or turn a Wednesday offer into today', async t => {
  const f = await fixture(t);
  const result = await f.ask({ message: '今天旧金山有什么免费活动？', locale: 'zh-Hans', searchMode: 'site' });
  assert.equal(result.responseMode, 'catalog'); assert.equal(result.retrieval.webStatus, 'not_requested');
  assert.equal(result.retrieval.city, 'San Francisco'); assert.ok(result.catalogSources.length);
  assert.doesNotMatch(result.answer, /YBCA|周三（今天）|11:00.?20:00|飞行表演|飛行表演/);
  assert.equal(f.counts().chatCalls, 0); assert.equal(f.counts().searchCalls, 0);
});

test('a city-wide no-events claim falls back to actual San Jose records instead of surviving as a successful lookup', async t => {
  const f = await fixture(t, { web: () => web('San Jose 今天没有特定的活動安排。') });
  const result = await f.ask({ message: '今天 San Jose 有什么活动？', locale: 'zh-Hans', searchMode: 'smart' });
  assert.equal(result.responseMode, 'catalog'); assert.equal(result.retrieval.webStatus, 'verification_failed');
  assert.equal(result.retrieval.city, 'San Jose'); assert.ok(result.catalogSources.length);
  assert.doesNotMatch(result.answer, /今天没有|今天沒有/); assert.match(result.answer, /Little Italy|Santana/);
});

test('explicit outside destinations are explained in all three modes without silently changing them', async t => {
  const f = await fixture(t);
  for (const searchMode of ['smart', 'web', 'site']) {
    const result = await f.ask({ message: '今天中国上海有什么活动？', locale: 'zh-Hans', searchMode });
    assert.match(result.answer, /目的地不在服务范围/); assert.equal(result.retrieval.scope, 'none');
  }
  assert.equal(f.counts().chatCalls, 0); assert.equal(f.counts().searchCalls, 0);
});

test('site discovery inherits the destination on a complete next question and honors a new city', async t => {
  const f = await fixture(t);
  const history = [{ role: 'user', content: '今天在San Jose找活动' }, { role: 'assistant', content: 'Untrusted suggestion: Shanghai.' }];
  const followup = await f.ask({ message: '今天有什么活动，地方好去？', history, locale: 'zh-Hans', searchMode: 'site' });
  assert.equal(followup.retrieval.city, 'San Jose'); assert.equal(followup.responseMode, 'catalog');
  const changed = await f.ask({ message: '改去旧金山找免费活动', history, locale: 'zh-Hans', searchMode: 'site' });
  assert.equal(changed.retrieval.city, 'San Francisco'); assert.doesNotMatch(changed.answer, /Shanghai|上海|Little Italy/);
});

test('text restart clears old history, public filters and stale outing token at the API boundary', async t => {
  const f = await fixture(t);
  const result = await f.ask({ message: '重新开始，今天湾区有什么活动？', searchMode: 'site', history: [{ role: 'user', content: '今天上海有什么活动' }, { role: 'assistant', content: '上海建议' }], searchContext: { city: 'Shanghai', date: '2026-10-10' }, outingSearchToken: 'invalid.old-token' });
  assert.equal(result.responseMode, 'catalog'); assert.equal(result.retrieval.requestedDate, '2026-10-04');
  assert.equal(result.retrieval.city, null); assert.doesNotMatch(result.answer, /上海/);
});

test('normal guide responses report actual provider model separately from deployment configuration', async t => {
  const f = await fixture(t);
  const result = await f.ask({ message: 'Please explain how to use BAYLINK and its guides.', locale: 'en', searchMode: 'site' });
  assert.equal(result.responseMode, 'ai'); assert.equal(result.retrieval.model, 'provider-chat-snapshot');
  assert.equal(result.retrieval.configuredModel, 'configured-chat-model');
  assert.equal(f.counts().chatInput.currentDatePacific, '2026-10-04');
  assert.equal(f.counts().chatInput.searchScope.country, 'US');
});
