const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const member = require('./support/member-session');
const draft = { title: 'Looking for a used desk', description: 'I am looking for a used desk in Fremont for under $100. Please share its dimensions and a pickup time.', category: 'used', type: 'client', area: 'Fremont', budget: '$100', timeInfo: '', quickTags: ['Desk'], safetyTip: '', coverSuggestion: '' };
const completed = extra => ({ type: 'message', model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify(draft) }], ...extra });
async function fixture(t, config = {}, response = completed()) {
  const calls = [], models = createMemoryModels({ User: [member.user] });
  const app = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: member.SECRET, BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-claude', OPENAI_API_KEY: 'fixture-openai', ANTHROPIC_WORKSPACE_ID: 'fixture-workspace', ...config }, models,
    postAssistFetch: async (url, options) => { calls.push({ url, ...options, body: JSON.parse(options.body) }); return { ok: true, json: async () => response }; },
  });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.io.close(resolve)));
  return { calls, models, ask: async (authenticated = true, body = {}) => {
    const result = await fetch(`http://127.0.0.1:${app.server.address().port}/api/ai/post-assist`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(authenticated ? member.headers() : {}) }, body: JSON.stringify({ intent: 'Looking for a used desk in Fremont for under $100.', language: 'en', ...body }) });
    return { status: result.status, data: await result.json() };
  } };
}
test('post assistant uses Claude directly and produces only an editable draft for a member', async t => {
  const f = await fixture(t);
  assert.equal((await f.ask(false)).status, 401);
  assert.equal(f.calls.length, 0);
  const result = await f.ask();
  assert.equal(result.status, 200);
  assert.equal(result.data.draft.title, draft.title);
  assert.equal(result.data.draft.description, draft.description);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, 'https://api.anthropic.com/v1/messages');
  assert.equal(f.calls[0].headers['anthropic-workspace-id'], 'fixture-workspace');
  assert.equal(f.calls[0].body.model, 'claude-opus-5-5');
  assert.equal(f.calls[0].body.messages.length, 1);
  assert.equal(f.models.Post.rows.length, 0);
  assert.equal(f.models.Message.rows.length, 0);
  assert.doesNotMatch(JSON.stringify(result.data), /fixture-claude|fixture-openai/);
});
test('post assistant rejects absent, expired and unknown Claude configuration without OpenAI fallback', async t => {
  for (const config of [{ ANTHROPIC_API_KEY: '' }, { ANTHROPIC_USE_UNTIL: '2000-01-01T00:00:00Z' }, { ANTHROPIC_USE_UNTIL: 'bad-date' }, { BAYBAY_AI_PROVIDER: 'anthropi' }]) {
    const f = await fixture(t, config);
    assert.equal((await f.ask()).status, 503);
    assert.equal(f.calls.length, 0);
  }
});
test('refused, truncated and malformed Claude drafts cannot become successful posts', async t => {
  for (const response of [completed({ stop_reason: 'max_tokens' }), completed({ stop_reason: 'refusal' }), completed({ content: [{ type: 'text', text: '{}' }] }), completed({ content: [{ type: 'text', text: 'not JSON' }] })]) {
    const f = await fixture(t, {}, response);
    const result = await f.ask();
    // Existing field validation rejects incomplete drafts instead of publishing or inventing their content.
    assert.equal(result.status, 502);
    assert.equal(result.data.draft, undefined);
    assert.equal(f.models.Post.rows.length, 0);
  }
});
test('post drafting retains the default OpenAI request and rejects unfinished output', async t => {
  const f = await fixture(t, { BAYBAY_AI_PROVIDER: undefined }, { choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(draft) } }] });
  assert.equal((await f.ask()).status, 200);
  assert.equal(f.calls[0].url, 'https://api.openai.com/v1/chat/completions');
  const unfinished = await fixture(t, { BAYBAY_AI_PROVIDER: undefined }, { choices: [{ finish_reason: 'length', message: { content: JSON.stringify(draft) } }] });
  assert.equal((await unfinished.ask()).status, 502);
});
