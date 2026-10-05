const test = require('node:test');
const assert = require('node:assert/strict');
const { assertSearchScope, searchScope } = require('../lib/bayAreaSearchScope');
const { fallbackExcerpt } = require('../lib/baybayExcerpt');
const { createBayBayAssistant } = require('../lib/baybayAgent');

test('an explicitly scoped information comparison can start with the user home city', () => {
  const input = { query: '我住 Fremont，比较 SFPL 和 San Mateo 图书馆资格', city: 'San Francisco', allowedAnswerCities: ['Fremont', 'San Mateo'] };
  const scope = searchScope(input, () => Date.parse('2026-10-05T03:00:00Z'));
  assert.doesNotThrow(() => assertSearchScope({ answer: 'Fremont 居民先用自己的 AC Library 卡；SFPL 的门票资格另有居住要求。' }, input, scope));
  assert.throws(() => assertSearchScope({ answer: 'Oakland 居民的专属福利如下。' }, input, scope), /location\/date/);
  assert.throws(() => assertSearchScope({ answer: 'Fremont 居民', candidates: [{ city: 'Fremont' }] }, input, scope), /location\/date/);
  assert.throws(() => assertSearchScope({ answer: 'Events in Shanghai today.' }, input, scope), /location\/date/);
});

test('ordinary city search still rejects substitution and caller comparison cities must be known', () => {
  const input = { query: 'San Francisco 免费活动', city: 'San Francisco', allowedAnswerCities: ['Shanghai', null] };
  const scope = searchScope(input, () => Date.parse('2026-10-05T03:00:00Z'));
  assert.throws(() => assertSearchScope({ answer: 'Fremont 有这些免费活动。' }, input, scope), /location\/date/);
});

test('fallback library excerpts keep eligibility sentences complete and identify omitted content', () => {
  const eligibility = '须有有效图书证，借博物馆门票还需符合发卡馆的居住地及年龄要求。';
  const text = `${eligibility}\n\n${'影片的观看额度以当前登录账户及片库规则为准。'.repeat(25)}\n官网入口：https://library.example.test/cards`;
  const excerpt = fallbackExcerpt(text, 450);
  assert.ok(excerpt.startsWith(eligibility));
  assert.match(excerpt, /。 …$/);
  assert.ok(excerpt.length <= 452);
  assert.doesNotMatch(excerpt, /当前登 …|官网入口：[\s]*$/);
  assert.equal(fallbackExcerpt('没有句号的很长条件'.repeat(80)), '');
});

test('the real cross-library request keeps its focused answer and rejected answers are labelled degraded', async () => {
  const message = '我住 Fremont，只有 Alameda County Library 图书证。想免费打印文件、用 Kanopy 看电影、借博物馆门票。请区分我现在能用的资源、需要另办 SFPL 或 San Mateo County Libraries 卡的资源，以及是否有居住地、年龄或 eCard 限制。给官方入口，不要把整个湾区的资格混在一起。';
  let answer = 'Fremont 居民应区分 AC Library 的服务与另办 SFPL 卡的资格，不能把各馆门票条件混用。';
  const assistant = createBayBayAssistant({ config: { JWT_SECRET: 'isolated-information-audit-fixture' }, isTest: true,
    now: () => Date.parse('2026-10-05T03:00:00Z'), guideCatalog: require('../data/guide-catalog.json'),
    ai: async () => ({ model: 'audit-fixture', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups: [] }) }] }] }) });
  const result = await assistant.run({ message, searchMode: 'site' });
  assert.equal(result.answer, answer);
  assert.equal(result.degraded, false);
  assert.ok(!result.research.warnings.includes('answer_scope_rejected'));
  answer = 'Events in Shanghai today.';
  const rejected = await assistant.run({ message, searchMode: 'site' });
  assert.equal(rejected.degraded, true);
  assert.ok(rejected.research.warnings.includes('answer_scope_rejected'));
  assert.doesNotMatch(rejected.answer, /Events in Shanghai|当前登 \[/);
  assert.match(rejected.answer, /资料摘录/);
});
