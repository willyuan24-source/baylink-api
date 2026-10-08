const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { encodeTaskToken, resolveTaskState } = require('../lib/baybayState');
const member = require('./support/member-session');
const NOW = Date.parse('2026-10-05T19:00:00Z');
const query = 'San Francisco public library card eligibility';
const guestAccess = { authenticated: false, allowed: false, reason: 'auth_required' };
const final = answer => ({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] });
const invoke = (name, args, call_id = 'tool') => ({ type: 'function_call', name, call_id, arguments: JSON.stringify(args) });
function raw() {
  const text = 'LIVE-WEB-MARKER. San Francisco library membership rules are available on the official site. [source]';
  return { status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search' } }, { type: 'message', role: 'assistant', content: [{ type: 'output_text', text,
    annotations: [{ type: 'url_citation', title: 'San Francisco library cards', url: 'https://sfpl.org/services/library-cards', start_index: text.indexOf('[source]'), end_index: text.length }] }] }] };
}
async function fixture(t, options = {}) {
  const models = createMemoryModels({ User: [member.user, { id: 'other', accountStatus: 'active' }, { id: 'banned', isBanned: true }, { id: 'suspended', accountStatus: 'suspended' }] });
  const calls = { web: 0, reads: 0, routes: 0, weather: 0, model: [] };
  const application = createApplication({ config: { NODE_ENV: 'test', JWT_SECRET: member.SECRET, OPENAI_API_KEY: 'fixture-key', ...options.config }, models, plannerNow: () => NOW,
    ai: { baybay: async payload => { calls.model.push(payload); const context = JSON.parse(payload.input[0].content); return options.ai ? options.ai(payload, context, calls) : final(`站内资料参考。${context.evidence[0] ? ` [[${context.evidence[0].id}]]` : ''}`); },
      guideChat: async () => ({ answer: 'SITE-SNAPSHOT-MARKER: check the published guide for recorded conditions.' }),
      plannerWebSearch: async () => { calls.web++; return raw(); }, plannerWebExtract: async () => ({ candidates: [] }) },
    plannerWebLookup: async () => [{ address: '93.184.216.34', family: 4 }],
    baybaySourceFetch: async () => { calls.reads++; return { text: 'San Francisco library card rules. Apply through the official library website; eligibility conditions still apply.' }; },
    baybayFetch: async () => { calls.weather++; throw Error('unexpected weather'); },
    plannerTravelCompute: async () => { calls.routes++; return { routes: [{ duration: '600s', distanceMeters: 1000 }] }; },
  });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (path, body, token) => {
    const response = await fetch(`http://127.0.0.1:${application.server.address().port}/api${path}`, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const text = await response.text();
    const events = response.headers.get('Content-Type')?.includes('event-stream') ? text.trim().split('\n\n').filter(part => part.startsWith('event:')).map(part => ({ event: part.split('\n')[0].slice(7), data: JSON.parse(part.split('\n').find(line => line.startsWith('data: ')).slice(6)) })) : [];
    return { status: response.status, data: events.length ? events.find(item => item.event === 'result')?.data : JSON.parse(text), events, text };
  };
  return { request, models, calls, token: member.token() };
}

test('capabilities describe actual guest/member access and do not spend external quota', async t => {
  const f = await fixture(t);
  const guest = await f.request('/ai/baybay-capabilities');
  assert.deepEqual(guest.data.webAccess, guestAccess); assert.deepEqual(guest.data.tools, ['site', 'plans']); assert.equal(guest.data.routeEstimates, false);
  const signed = await f.request('/ai/baybay-capabilities', undefined, f.token);
  assert.equal(signed.data.webAccess.allowed, true); assert.ok(signed.data.tools.includes('web'));
  assert.equal(f.models.PostTranslationQuota.rows.length, 0); assert.equal(f.calls.web, 0);
});

test('guest cannot force smart/web through JSON, SSE, body flags, or undeclared external tool calls', async t => {
  let sentHidden = false;
  const f = await fixture(t, { ai: async (payload, context) => {
    assert.deepEqual((payload.tools || []).map(item => item.name), ['search_site', 'create_plan']);
    // Guests keep site-only evidence, but the answer is not a sign-up pitch.
    assert.match(payload.instructions, /Do not mention signing in, logging in, accounts, registration, quotas or search modes/);
    assert.doesNotMatch(payload.instructions, /suggest switching to Smart or Web|enables live web lookup|signing in is required/);
    if (!sentHidden) { sentHidden = true; return { status: 'completed', output: [invoke('search_web', { query }), invoke('read_source', { sourceId: context.evidence[0]?.id }, 'read'), invoke('get_weather', { candidateId: 'pier39' }, 'weather'), invoke('get_route', { fromId: 'pier39', toId: 'exploratorium', time: '10:00' }, 'route'), invoke('verify_candidate', {}, 'verify')] }; }
    return final(`请按站内资料确认；登录后可联网查询。 [[${context.evidence[0].id}]]`);
  } });
  for (const [searchMode, stream] of [['web', false], ['smart', true]]) {
    const result = await f.request('/ai/guide-chat', { message: query, locale: 'en', assistantVersion: 2, searchMode, stream, isRegistered: true, userId: 'web-member', webAccess: { allowed: true } });
    assert.equal(result.status, 200); assert.equal(result.data.retrieval.requestedMode, searchMode); assert.equal(result.data.retrieval.effectiveMode, 'site');
    if (searchMode === 'web') {
      // An explicit web request without a session still reports that sign-in is required.
      assert.equal(result.data.retrieval.webStatus, 'auth_required'); assert.deepEqual(result.data.retrieval.webAccess, guestAccess);
    } else {
      // A guest who never signed in is not "signed out": no auth_required label.
      assert.notEqual(result.data.retrieval.webStatus, 'auth_required');
      assert.deepEqual(result.data.retrieval.webAccess, { authenticated: false, allowed: false, reason: 'guest' });
    }
    assert.doesNotMatch(result.data.answer, /登录后可联网查询/, 'a guest answer never carries the login pitch');
    assert.ok(result.data.research.warnings.includes('guest_login_pitch_removed'));
    assert.ok(result.data.evidence.every(source => !['page-read', 'search-result', 'api'].includes(source.verification)));
    assert.doesNotMatch(result.text, /LIVE-WEB-MARKER/);
  }
  assert.deepEqual([f.calls.web, f.calls.reads, f.calls.routes, f.calls.weather], [0, 0, 0, 0]);
  assert.ok(f.models.PostTranslationQuota.rows.every(row => !/^planner-(web-search|travel):/.test(row.id)));
});

test('expired, forged, revoked, banned and deleted login sessions are guests while site answers still work', async t => {
  const f = await fixture(t);
  const revoked = jwt.sign({ id: member.user.id }, member.SECRET, { expiresIn: '1h', jwtid: 'revoked' });
  f.models.RevokedSession.rows.push({ tokenHash: crypto.createHash('sha256').update(revoked).digest('hex') });
  const tokens = ['forged', jwt.sign({ id: member.user.id }, member.SECRET, { expiresIn: -1 }), revoked,
    ...['banned', 'suspended', 'deleted'].map(id => jwt.sign({ id }, member.SECRET, { expiresIn: '1h' }))];
  for (const token of tokens) {
    const result = await f.request('/ai/guide-chat', { message: '今天旧金山有什么免费活动？', searchMode: 'web' }, token);
    assert.equal(result.status, 200); assert.equal(result.data.retrieval.effectiveMode, 'site'); assert.equal(result.data.retrieval.webStatus, 'auth_required');
  }
  assert.equal(f.calls.web, 0); assert.equal(f.models.PostTranslationQuota.rows.length, 0);
});

test('membership is revalidated before shared web cache/in-flight/quota, and valid members retain quota limits', async t => {
  const f = await fixture(t, { config: { PLANNER_WEB_SEARCH_DAILY_LIMIT: '2' } });
  const body = { message: query, locale: 'en', searchMode: 'web' };
  const first = await f.request('/ai/guide-chat', body, f.token);
  assert.equal(first.data.retrieval.webStatus, 'completed'); assert.equal(f.calls.web, 1);
  const quota = f.models.PostTranslationQuota.rows.find(row => /^planner-web-search:/.test(row.id)); assert.equal(quota.count, 2);
  const guest = await f.request('/ai/guide-chat', body);
  assert.equal(guest.data.retrieval.webStatus, 'auth_required'); assert.doesNotMatch(guest.text, /LIVE-WEB-MARKER/);
  const directGuest = await f.request('/planner/web-search', { query, locale: 'en' });
  assert.equal(directGuest.status, 401); assert.equal(directGuest.data.code, 'auth_required'); assert.equal(f.calls.web, 1); assert.equal(quota.count, 2);
  const cached = await f.request('/ai/guide-chat', body, jwt.sign({ id: 'other' }, member.SECRET, { expiresIn: '1h' }));
  assert.equal(cached.data.retrieval.cached, true); assert.equal(cached.data.retrieval.webAccess.allowed, true); assert.equal(f.calls.web, 1);
  const exhausted = await f.request('/ai/guide-chat', { ...body, message: 'San Francisco public library printing prices' }, f.token);
  assert.equal(exhausted.data.retrieval.failureCode, 'web_daily_limit'); assert.equal(exhausted.data.retrieval.webAccess.allowed, true); assert.equal(f.calls.web, 1);
});

test('authenticated v2 members can use current web and source reading, without changing tool quotas', async t => {
  let read = false;
  const f = await fixture(t, { ai: async (_payload, context) => {
    const source = context.evidence.find(item => item.verification === 'search-result');
    if (!read && source) { read = true; return { status: 'completed', output: [invoke('read_source', { sourceId: source.id })] }; }
    return final(`请参考已读取的官网条件。 [[${context.evidence.find(item => item.verification === 'page-read')?.id || context.evidence[0].id}]]`);
  } });
  const result = await f.request('/ai/guide-chat', { message: query, assistantVersion: 2, searchMode: 'web', locale: 'en' }, f.token);
  assert.equal(result.data.retrieval.webStatus, 'completed'); assert.equal(result.data.retrieval.effectiveMode, 'web');
  assert.equal(f.calls.web, 1); assert.equal(f.calls.reads, 1); assert.ok(result.data.evidence.some(source => source.verification === 'page-read'));
});

test('member task-memory replay after logout cannot reintroduce web-only sources, facts or stops', async t => {
  const f = await fixture(t);
  const state = resolveTaskState({ message: '11月7日在旧金山安排半天，两个大人带5岁孩子，总预算120美元', today: '2026-10-05' }).state;
  state.selectedCandidateIds = ['web-member-only'];
  const assistantSessionToken = encodeTaskToken({ state, lastPlan: { title: 'Member web plan', date: state.date, candidateIds: ['web-member-only'], selectedIds: ['web-member-only'], selectedRefs: [{ id: 'web-member-only', title: 'LIVE-WEB-MARKER', city: 'San Francisco', sourceUrl: 'https://example.org/member-only', previousKind: 'place' }] } }, { secret: member.SECRET, now: () => NOW });
  const result = await f.request('/ai/guide-chat', { message: '按之前条件继续', searchMode: 'smart', assistantVersion: 2, assistantSessionToken });
  assert.equal(result.status, 200); assert.equal(result.data.retrieval.effectiveMode, 'site'); assert.equal(result.data.taskState.budget, 120);
  assert.doesNotMatch(JSON.stringify(f.calls.model), /LIVE-WEB-MARKER|example\.org\/member-only/);
  assert.ok(!result.data.assistantPlan?.stops.some(stop => /web-member-only/.test(stop.id)));
  assert.equal(f.calls.web, 0);
});

test('guest keeps a sourced half-day plan; signed-in continuation preserves its conditions', async t => {
  const f = await fixture(t);
  const message = '11月7日两个大人带5岁孩子，10点从旧金山Ferry Building出发，只去PIER39看海狮，坐公交，15点前结束，不回原点，总预算120美元。帮我安排半天，不要加别的站。';
  const guest = await f.request('/ai/guide-chat', { message, assistantVersion: 2, searchMode: 'site' });
  assert.equal(guest.data.retrieval.webStatus, 'not_requested'); assert.equal(guest.data.assistantPlan.stops.length, 1); assert.match(guest.data.assistantPlan.stops[0].id, /pier39/);
  const next = await f.request('/ai/guide-chat', { message: '保留这些条件，只说明还有什么要核实', assistantVersion: 2, searchMode: 'site', assistantSessionToken: guest.data.assistantSessionToken }, f.token);
  assert.equal(next.data.taskState.date, '2026-11-07'); assert.equal(next.data.taskState.partySize, 3); assert.equal(next.data.taskState.budget, 120); assert.equal(next.data.taskState.returnToOrigin, false);
  assert.equal(next.data.retrieval.webAccess.allowed, true); assert.equal(f.calls.web, 0);
});

test('route endpoint and capability use the same verified membership before paid quota, with site planning untouched', async t => {
  const f = await fixture(t);
  const body = { from: { kind: 'place', id: 'pier39' }, to: { kind: 'place', id: 'golden-gate' }, date: '2026-11-07', time: '12:00', travelMode: 'walk', locale: 'en' };
  assert.equal((await f.request('/planner/travel-capabilities')).data.available, false);
  assert.equal((await f.request('/planner/travel-capabilities', undefined, f.token)).data.available, true);
  const guest = await f.request('/planner/travel-estimate', body); assert.equal(guest.status, 401); assert.equal(guest.data.code, 'auth_required');
  assert.equal(f.calls.routes, 0); assert.equal(f.models.PostTranslationQuota.rows.length, 0);
  const signed = await f.request('/planner/travel-estimate', body, f.token); assert.equal(signed.status, 200, JSON.stringify(signed.data)); assert.equal(f.calls.routes, 1);
  f.models.User.findOne = () => { throw Error('database secret'); };
  const failed = await f.request('/planner/web-search', { query, locale: 'en' }, f.token); assert.equal(failed.status, 401); assert.equal(failed.data.code, 'auth_required'); assert.doesNotMatch(failed.text, /database secret/); assert.equal(f.calls.web, 0);
});
