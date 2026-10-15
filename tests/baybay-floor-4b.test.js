// H72 rest (audit 10-13, BB-1013-06), API-BB-4B: answers without a model (paused here) come from
// the matching pillar guide by topic with its official contacts; professional and how-to questions
// get no event, offer or opening cards; English floors stay English. $0: no provider is called.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { createPublicContext } = require('../lib/publicContext');
const guides = require('../data/guide-catalog.json');
const englishGuides = require('../data/guide-catalog.en.json');

const NOW = Date.parse('2026-10-14T19:00:00Z'), TODAY = '2026-10-14';
const CJK = /[㐀-鿿]/;
let calls = 0;
const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_ENGINE: 'v2', BAYBAY_PAUSED: 'true', BAYBAY_STATE_SECRET: 'api-bb-4b-floor-secret-0123456789ab' },
  guideCatalog: guides, englishGuideCatalog: englishGuides, now: () => NOW, isTest: true, fetchImpl: async () => { calls++; throw new Error('paused: no provider call'); } });
const publicContext = createPublicContext({ guideCatalog: guides });
const ask = (message, locale = 'zh-Hans') => assistant.run({ message, locale, currentPath: '/', history: [], searchMode: 'site', webAccess: { allowed: false },
  pageContext: publicContext.resolve({ context: { currentPath: '/' }, currentPath: '/', today: TODAY, locale }) });
const entityCards = result => (result.localMatches || []).filter(card => ['event', 'offer', 'opening', 'place'].includes(card.kind));

test('how-to and professional questions without a model get their guide or template, and no event, offer or opening card', async () => {
  for (const [message, locale, needle] of [
    ['加州驾照笔试可以用中文考吗？去 DMV 要先预约吗？', 'zh-Hans', /中文/], ['Can I take the California driving written test in Chinese?', 'en', /Chinese/],
    ['房东不退押金怎么办？', 'zh-Hans', /加州法院自助中心/], ['My landlord will not return my security deposit. What can I do?', 'en', /California Courts Self-Help/],
    ['刚拿绿卡，SSN 怎么申请？要带什么？', 'zh-Hans', /1-800-772-1213/], ['How do I sign up for Medicare when I turn 65?', 'en', /1-800-434-0222/],
  ]) {
    const result = await ask(message, locale);
    assert.equal(result.degraded, true, message);
    assert.match(result.answer, needle, message);
    assert.deepEqual(entityCards(result), [], `${message}: ${(result.localMatches || []).map(card => card.id)}`);
    if (locale === 'en') assert.doesNotMatch(result.answer, CJK, `${message}: English stays English`);
  }
  assert.equal(calls, 0);
});

test('a Medi-Cal question starts with how to apply for Medi-Cal (DHCS), not with Medicare counseling', async () => {
  const zh = await ask('我爸妈 68 岁刚拿绿卡来湾区，可以申请 Medi-Cal 吗？去哪里申请？');
  assert.equal(zh.safety?.topic, 'insurance');
  assert.ok(zh.answer.startsWith('DHCS 列出四种申请 Medi-Cal 的方式'), zh.answer.slice(0, 80));
  const en = await ask('My parents are 68 and just got green cards. Can they get Medi-Cal?', 'en');
  assert.ok(en.answer.startsWith('DHCS lists four ways to apply for Medi-Cal'), en.answer.slice(0, 80));
  assert.doesNotMatch(en.answer, CJK);
  // A Medicare question keeps HICAP first.
  assert.match((await ask('我妈 65 岁了，Medicare 怎么申请？')).answer, /^Medicare 问题可从加州老龄部/);
});

test('a child fever without a model: 911 first, then the site doctor guide\'s advice-line step, cited; never an event card', async () => {
  const zh = await ask('孩子发烧 39 度要去急诊吗？');
  assert.ok(zh.answer.startsWith('如果有人正处于危险或突然身体不适，请立即拨打 911'), zh.answer.slice(0, 60));
  assert.match(zh.answer, /使用保险卡上的医疗咨询电话/);
  assert.ok(zh.sources.some(source => source.url === '/guides/bay-area-first-doctor-insurance-network-guide'), JSON.stringify(zh.sources));
  assert.deepEqual(entityCards(zh), []);
  const en = await ask('My 3-year-old has a fever of 102. Should I go to the ER?', 'en');
  assert.ok(en.answer.startsWith('If someone is in danger or suddenly unwell, call 911 now.'));
  assert.match(en.answer, /medical advice line/);
  assert.doesNotMatch(en.answer, CJK);
  // A stroke sign or a sudden change keeps 911/211 alone (SAFETY-2).
  const sudden = await ask('我爸突然发烧，手脚不太灵活，说话有点怪');
  assert.doesNotMatch(sudden.answer, /医疗咨询电话/);
});

test('an outing ask without a model still lists the day\'s records as cards', async () => {
  const result = await ask('这周六旧金山有什么适合全家的免费活动？');
  assert.ok(entityCards(result).length > 0, JSON.stringify(result.localMatches));
});
