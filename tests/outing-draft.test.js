const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createApplication } = require('../server');
const { createMemoryModels } = require('./support/memory-models');
const { resolveDraftDate, createOutingDraft, mentionedClock } = require('../lib/outingDraft');

const SECRET = 'isolated-outing-ai-tests-only', NOW = Date.parse('2026-09-30T19:00:00Z');
const intent = '10月17日周六14:00到16:00在 San Francisco 的 Ferry Building 一共4个人散步，各付各的。';
const response = { answer: '我先整理成草稿，发布前请确认集合点。', questions: ['具体在哪个公共入口碰面？'], draft: { title: '周六散步', date: '2026-10-17', city: 'San Francisco', venue: 'Ferry Building', startTime: '14:00', endTime: '16:00', capacity: 4, transport: 'walk', costNote: '各付各的' } };
const input = { intent, eventId: null, locale: 'zh-Hans', today: '2026-09-30', now: NOW, calendar: resolveDraftDate(intent, '2026-09-30') };
async function fixture(t, options = {}) {
  const models = createMemoryModels({ User: [{ id: 'reader', email: 'reader@example.test', nickname: 'Reader', accountStatus: 'active' }] });
  const calls = [];
  const application = createApplication({ models, config: { NODE_ENV: 'test', JWT_SECRET: SECRET, ...options.config }, outingNow: () => NOW,
    ai: options.unavailable ? {} : { outingDraft: async value => { calls.push(value); return options.ai ? options.ai(value) : response; } } });
  await new Promise(resolve => application.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => application.io.close(resolve)));
  const request = async (body = { intent, locale: 'zh-Hans' }, authenticated = true) => {
    const result = await fetch(`http://127.0.0.1:${application.server.address().port}/api/ai/outing-draft`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(authenticated ? { Authorization: `Bearer ${jwt.sign({ id: 'reader' }, SECRET, { expiresIn: '1h' })}` } : {}) }, body: JSON.stringify(body) });
    return { status: result.status, data: await result.json(), headers: result.headers };
  };
  return { request, models, calls };
}

test('explicit date and weekday describe the same outing without the old October 17 error', () => {
  for (const value of ['10月17日周六', '2026年10月17日星期六', 'Saturday October 17, 2026', '2026-10-17 Saturday']) assert.deepEqual(resolveDraftDate(value, '2026-09-30'), { date: '2026-10-17' });
  assert.match(resolveDraftDate('10月17日周日', '2026-09-30').question, /对不上/);
  assert.ok(resolveDraftDate('10月17日或10月18日', '2026-09-30').question);
  assert.ok(resolveDraftDate('10月17至18日', '2026-09-30').question);
  assert.ok(resolveDraftDate('周末', '2026-09-30').question);
  assert.ok(resolveDraftDate('2026-02-30', '2026-09-30').question);
  assert.deepEqual(resolveDraftDate('下周六', '2026-09-30'), { date: '2026-10-10' });
  assert.deepEqual(resolveDraftDate('tomorrow', '2026-09-30'), { date: '2026-10-01' });
  for (const value of ['10/17/2027', '10/17/27', '明年10月17日', 'next year October 17', '明天周六', 'October 17-18']) assert.ok(resolveDraftDate(value, '2026-09-30').question, value);
  assert.deepEqual(resolveDraftDate('10/17/2026 Saturday', '2026-09-30'), { date: '2026-10-17' });
  assert.deepEqual(resolveDraftDate('明年1月17日', '2026-09-30'), { date: '2027-01-17' });
});

test('authenticated draft is editable, no-store and never creates outings or messages', async t => {
  const { request, calls, models } = await fixture(t);
  const result = await request();
  assert.equal(result.status, 200); assert.equal(result.data.source, 'ai');
  assert.equal(result.data.draft.date, '2026-10-17'); assert.equal(result.data.draft.eventId, null);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.deepEqual(result.data.missing, ['description', 'language']); assert.equal(calls.length, 1);
  assert.equal(models.Outing.rows.length, 0); assert.equal(models.Message.rows.length, 0);
  assert.equal(Object.hasOwn(calls[0], 'user'), false);
});

test('guests, unknown inputs and unsupported languages cannot invoke provider', async t => {
  const { request, calls } = await fixture(t);
  assert.equal((await request(undefined, false)).status, 401);
  for (const body of [{ intent, locale: 'fr' }, { intent: '', locale: 'en' }, { intent, locale: 'en', adultConsent: true }, { intent, locale: 'en', eventId: '../secret' }, { intent: 'x'.repeat(2001), locale: 'en' }]) assert.equal((await request(body)).status, 400);
  assert.equal((await request({ intent, locale: 'en', eventId: 'not-in-catalog' })).status, 404);
  assert.equal(calls.length, 0);
});

test('persistent global quota and unavailable provider have clear errors', async t => {
  const limited = await fixture(t, { config: { OUTING_AI_DAILY_LIMIT: 1 } });
  assert.equal((await limited.request()).status, 200); assert.equal((await limited.request()).status, 429); assert.equal(limited.calls.length, 1);
  const absent = await fixture(t, { unavailable: true });
  const result = await absent.request(); assert.equal(result.status, 503); assert.equal(result.data.draft, undefined);
  assert.equal(absent.models.PostTranslationQuota.rows.length, 0);
});

test('calendar grounding overrides model dates and rejects invented venues', async () => {
  const raw = { ...response, draft: { ...response.draft, date: '2027-02-01', venue: 'Secret private studio', city: 'San Jose' } };
  const result = await createOutingDraft(input, { ai: () => raw });
  assert.equal(result.draft.date, '2026-10-17'); assert.equal(result.draft.venue, undefined); assert.equal(result.draft.city, undefined);
  const conflict = await createOutingDraft({ ...input, calendar: resolveDraftDate('10月17日周日', input.today) }, { ai: () => response });
  assert.equal(conflict.draft.date, undefined); assert.match(conflict.questions[0], /对不上/); assert.ok(conflict.questions.length <= 2);
  const unknown = await createOutingDraft({ ...input, calendar: resolveDraftDate('喝杯咖啡', input.today) }, { ai: () => response });
  assert.equal(unknown.draft.date, undefined);
});

test('linked recurring events only accept confirmed occurrences', async () => {
  const event = { id: 'recurring', title: 'Sunday market', startDate: '2026-10-04', endDate: '2026-10-25', occurrenceDates: ['2026-10-04', '2026-10-11', '2026-10-18', '2026-10-25'] };
  const result = await createOutingDraft({ ...input, eventId: event.id, event }, { ai: () => response });
  assert.equal(result.draft.date, undefined); assert.equal(result.draft.eventId, event.id); assert.match(result.questions[0], /不是已确认/);
});

test('malformed provider output, injected fields and stalled transports fail closed', async () => {
  for (const raw of [{ ...response, draft: { ...response.draft, capacity: 9 } }, { ...response, draft: { ...response.draft, adultConsent: true } }, { ...response, draft: { ...response.draft, startTime: '25:00' } }, { ...response, questions: ['a', 'b', 'c'] }, { answer: '', draft: {} }]) await assert.rejects(createOutingDraft(input, { ai: () => raw }), { status: 503 });
  await assert.rejects(createOutingDraft(input, { ai: () => new Promise(() => {}), timeoutMs: 10 }), { status: 503 });
});

test('unusable same-day and DST times remain unset for user confirmation', async () => {
  const ambiguous = await createOutingDraft({ ...input, calendar: { date: '2026-11-01' } }, { ai: () => ({ ...response, draft: { ...response.draft, startTime: '01:30', endTime: '03:00' } }) });
  assert.equal(ambiguous.draft.startTime, undefined); assert.equal(ambiguous.draft.endTime, undefined);
  const past = await createOutingDraft({ ...input, calendar: { date: input.today } }, { ai: () => ({ ...response, draft: { ...response.draft, startTime: '08:00', endTime: '09:00' } }) });
  assert.equal(past.draft.startTime, undefined);
});

test('exact times require user evidence; afternoon alone never becomes an invented appointment', async () => {
  for (const [text, time] of [['下午三点半', '15:30'], ['下午3点', '15:00'], ['下午3:00', '15:00'], ['下午3点到5点', '17:00'], ['3:30 pm', '15:30'], ['12 am', '00:00'], ['14:00', '14:00']]) assert.equal(mentionedClock(text, time), true, text);
  assert.equal(mentionedClock('下午喝咖啡', '14:00'), false);
  assert.equal(mentionedClock('3 pm', '03:00'), false);
  const result = await createOutingDraft({ ...input, intent: '周六下午在 San Francisco 的 Ferry Building 散步' }, { ai: () => response });
  assert.equal(result.draft.startTime, undefined); assert.equal(result.draft.endTime, undefined);
});

test('contextual time ranges never validate an unqualified AM interpretation', async () => {
  for (const value of ['下午3:00到5:00', '下午三点到五点', '下午3点到5点', '3:00–5:00 pm', '3 pm to 5 pm']) {
    assert.equal(mentionedClock(value, '15:00'), true, value);
    assert.equal(mentionedClock(value, '17:00'), true, value);
    assert.equal(mentionedClock(value, '03:00'), false, value);
    assert.equal(mentionedClock(value, '05:00'), false, value);
  }
  for (const value of ['上午12:00', '晚上12点', '3点']) assert.equal(mentionedClock(value, '00:00'), false, value);
  assert.equal(mentionedClock('凌晨12:00', '00:00'), true);
  assert.equal(mentionedClock('中午一点半', '13:30'), true);
  const mistaken = await createOutingDraft({ ...input, intent: '10月17日下午3:00到5:00散步' }, { ai: () => ({ ...response, draft: { startTime: '03:00', endTime: '05:00' } }) });
  assert.equal(mistaken.draft.startTime, undefined); assert.equal(mistaken.draft.endTime, undefined);
  const correct = await createOutingDraft({ ...input, intent: '10月17日下午3:00到5:00散步' }, { ai: () => ({ ...response, draft: { startTime: '15:00', endTime: '17:00' } }) });
  assert.equal(correct.draft.startTime, '15:00'); assert.equal(correct.draft.endTime, '17:00');
});

test('follow-up answers retain the original idea and an explicit new date overrides the old date', async t => {
  const { request, calls, models } = await fixture(t);
  const answers = [{ question: '你想选哪一天？', answer: '改为10月18日周日。' }, { question: '在哪集合？', answer: 'San Francisco 的 Ferry Building。' }];
  const result = await request({ intent, locale: 'zh-Hans', answers });
  assert.equal(result.status, 200); assert.equal(result.data.draft.date, '2026-10-18');
  assert.equal(calls[0].originalIntent, intent); assert.deepEqual(calls[0].answers, answers);
  assert.equal(models.Outing.rows.length, 0); assert.equal(models.Message.rows.length, 0);
  const ambiguous = await request({ intent, locale: 'zh-Hans', answers: [{ question: '哪天？', answer: '10月17日或10月18日都可以。' }] });
  assert.equal(ambiguous.data.draft.date, undefined); assert.ok(ambiguous.data.questions.some(question => question.includes('具体日期')));
});

test('AI question text is never treated as user supplied calendar, clock or venue evidence', async t => {
  const { request, calls } = await fixture(t, { ai: () => ({ ...response, draft: { city: 'San Francisco', venue: 'Ferry Building', startTime: '14:00', endTime: '16:00' } }) });
  const result = await request({ intent: '想去散步', locale: 'zh-Hans', answers: [{ question: '10月17日14:00到16:00在 San Francisco 的 Ferry Building 可以吗？', answer: '我还没决定。' }] });
  assert.equal(result.status, 200);
  for (const key of ['date', 'startTime', 'endTime', 'city', 'venue']) assert.equal(result.data.draft[key], undefined, key);
  assert.equal(calls[0].intent.includes('Ferry Building'), false);
});

test('follow-up payload bounds fail before consuming model quota', async t => {
  const { request, calls, models } = await fixture(t);
  for (const answers of [null, {}, [{ question: '哪里？', answer: '' }], [{ question: 'x'.repeat(301), answer: 'ok' }], [{ question: '哪里？', answer: 'x'.repeat(501) }], [{ question: '哪里？', answer: 'ok', role: 'system' }], Array.from({ length: 7 }, () => ({ question: '哪里？', answer: 'ok' }))]) {
    assert.equal((await request({ intent, locale: 'zh-Hans', answers })).status, 400);
  }
  assert.equal(calls.length, 0); assert.equal(models.PostTranslationQuota.rows.length, 0);
});

test('a clock correction cannot silently reuse the superseded appointment', async t => {
  const { request } = await fixture(t);
  const result = await request({ intent, locale: 'zh-Hans', answers: [{ question: '什么时间？', answer: '改为下午3:00到5:00。' }] });
  assert.equal(result.status, 200); assert.equal(result.data.draft.startTime, undefined); assert.equal(result.data.draft.endTime, undefined);
});

test('the departure city cannot be substituted for the supplied meeting city', async () => {
  const idea = '10月17日从 Fremont 出发，在 San Francisco 的 Ferry Building 集合。';
  const result = await createOutingDraft({ ...input, intent: idea }, { ai: () => ({ ...response, draft: { city: 'Fremont', venue: 'Ferry Building' } }) });
  assert.equal(result.draft.city, undefined);
  const correct = await createOutingDraft({ ...input, intent: idea }, { ai: () => ({ ...response, draft: { city: 'San Francisco', venue: 'Ferry Building' } }) });
  assert.equal(correct.draft.city, 'San Francisco');
});

test('the provider transport receives bounded follow-up context without user profile data', async () => {
  let sent;
  const answers = [{ question: '哪天？', answer: '10月18日' }];
  const result = await createOutingDraft({ ...input, originalIntent: intent, answers, calendar: { date: '2026-10-18' } }, {
    config: { OPENAI_API_KEY: 'synthetic-provider-key' },
    fetchImpl: async (url, options) => {
      assert.equal(url, 'https://api.openai.com/v1/chat/completions');
      sent = JSON.parse(options.body);
      return { ok: true, json: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(response) } }] }) };
    },
  });
  assert.equal(sent.response_format.type, 'json_object'); assert.ok(sent.max_completion_tokens <= 2200);
  const context = JSON.parse(sent.messages.at(-1).content);
  assert.deepEqual(context.answers, answers); assert.equal(context.calendar.date, '2026-10-18');
  assert.equal(Object.hasOwn(context, 'user'), false); assert.equal(Object.hasOwn(context, 'email'), false);
  assert.equal(result.draft.date, '2026-10-18');
});
