// R0 (eval C-MEDICARE): a guarded professional answer explains general,
// non-personal program facts first, then the official channel, then says the
// personal choice depends on the person's situation. It still never gives a
// personal eligibility or choice verdict. Deterministic, $0.
const test = require('node:test');
const assert = require('node:assert/strict');
const { professionalGuard, professionalInstructions, professionalResponse, professionalTopics } = require('../lib/safetyRouting');

const instructionsFor = message => professionalInstructions(professionalGuard(professionalTopics(message), 'zh-Hans'));
// Amounts, percentages, years, durations and counted credits change or are
// personal; the prompt's background must carry none of them.
const UNSTABLE_NUMBERS = /\$|%|\b(?:19|20)\d\d\b|\d+\s*(?:days?|weeks?|months?|years?|quarters?|credits?|天|个月|年)\b|\b\d{1,3}(?:,\d{3})+\b/i;

test('the guard asks for the general explanation first, then the official channel, then the personal-situation caveat', () => {
  const text = instructionsFor('Medicare A 部分和 B 部分有什么区别？我该选哪个？');
  assert.match(text, /Professional-topic guard \(medicare\)/);
  assert.match(text, /never a refusal or a one-line redirect/);
  const explain = text.indexOf('(1) explain the general, non-personal facts'), channel = text.indexOf('(2) name the relevant official contact'), caveat = text.indexOf('(3) say plainly that the personal choice or decision depends on their own situation');
  assert.ok(explain > 0 && channel > explain && caveat > channel, 'explain -> official channel -> personal caveat');
  assert.match(text, /HICAP 免费 Medicare 咨询 1-800-434-0222/);
  assert.match(text, /cite its evidence entry with \[\[source-id\]\] instead of writing its URL/);
  // General Medicare facts the model may explain.
  assert.match(text, /Part A \(A 部分\) is hospital insurance: inpatient hospital stays, skilled nursing facility care/);
  assert.match(text, /most people pay no Part A premium because they or their spouse paid Medicare taxes long enough while working/);
  assert.match(text, /Part B \(B 部分\) is medical insurance: doctors' services, outpatient care, preventive services/);
  assert.match(text, /monthly premium/);
  assert.match(text, /A and B are not two options to choose between: most people have both/);
  assert.match(text, /Part C \(Medicare Advantage\)/); assert.match(text, /Part D is prescription drug coverage/);
});

test('the guard still forbids personal verdicts, identifiers and invented numbers', () => {
  for (const message of ['Medicare A 部分和 B 部分有什么区别？我该选哪个？', '有没有免费报税的地方，VITA 要带什么？', '绿卡面试要准备什么']) {
    const text = instructionsFor(message);
    assert.match(text, /Do not decide this person's individual eligibility, which option, plan, part or filing choice they should pick/, message);
    assert.match(text, /Do not state or imply that this person qualifies or does not qualify/, message);
    assert.match(text, /你符合 \/ 你不符合 \/ 你有资格 \/ 你应该选/, message);
    assert.match(text, /tell the user not to send them/, message);
    assert.match(text, /Do not invent fees, premiums, income limits, processing times, deadlines, dates or eligibility rules that are not in the evidence/, message);
    const background = text.slice(text.indexOf('General background'));
    assert.ok(background.length > 200, `${message}: has background`);
    assert.doesNotMatch(background, UNSTABLE_NUMBERS, message);
  }
});

test('tax (VITA) and immigration (USCIS) guards carry the same principle with their own general facts', () => {
  const tax = instructionsFor('有没有免费报税的地方，VITA 要带什么？');
  assert.match(tax, /Professional-topic guard \(tax\)/);
  assert.match(tax, /IRS VITA／TCE 免费报税点查询 800-906-9887/);
  assert.match(tax, /VITA \(Volunteer Income Tax Assistance\) offers free basic tax-return preparation by IRS-certified volunteers/);
  assert.match(tax, /TCE \(Tax Counseling for the Elderly/);
  assert.match(tax, /photo ID; Social Security cards or ITIN letters/);
  assert.match(tax, /CalFile/);
  assert.match(tax, /decided with the preparer/);
  assert.doesNotMatch(tax, /- medicare:|- immigration:/, 'only the asked topic\'s background');

  const immigration = instructionsFor('绿卡面试要准备什么');
  assert.match(immigration, /Professional-topic guard \(immigration\)/);
  assert.match(immigration, /USCIS 官方网站 \(https:\/\/www\.uscis\.gov\/\)/);
  assert.match(immigration, /naturalization \(Form N-400\)/);
  assert.match(immigration, /sealed medical exam \(Form I-693\)/);
  assert.match(immigration, /only the parts that match the question/);
  assert.match(immigration, /Forms, filing fees and processing times are published on uscis\.gov and change/);
  assert.match(immigration, /Only a licensed attorney or a DOJ-accredited representative/);
  assert.match(immigration, /decided by USCIS/);

  // Topics without background keep the principle and contacts only.
  const legal = instructionsFor('房东要驱逐我，我该怎么办');
  assert.match(legal, /Professional-topic guard \(legal\)/);
  assert.match(legal, /\(1\) explain the general, non-personal facts/);
  assert.doesNotMatch(legal, /General background/);
});

test('the deterministic Medicare template explains the parts when asked, without a personal verdict', () => {
  const zh = professionalResponse('Medicare A 部分和 B 部分有什么区别？我该选哪个？', 'zh-Hans');
  assert.match(zh.answer, /^Medicare 一般这样分：A 部分（Part A）是住院保险/);
  assert.match(zh.answer, /B 部分（Part B）是医疗保险/);
  assert.match(zh.answer, /A 和 B 通常不是二选一，多数人两部分都有/);
  assert.match(zh.answer, /1-800-434-0222/);
  assert.doesNotMatch(zh.answer, /你(?:应该|應該)(?:只)?选|你(?:符合|不符合|有资格|没有资格|沒有資格)/);
  assert.match(professionalResponse('Medicare A 部分和 B 部分有什麼區別？', 'zh-Hant').answer, /^Medicare 一般這樣分：A 部分（Part A）是住院保險/);
  const en = professionalResponse('What is the difference between Medicare Part A and Part B?', 'en');
  assert.match(en.answer, /^How Medicare is generally organized: Part A is hospital insurance/);
  assert.doesNotMatch(en.answer, /[㐀-鿿]/u);
  assert.doesNotMatch(en.answer, /\byou (?:qualify|should choose)\b/i);
  // A HICAP location question keeps the original preparation answer only.
  assert.match(professionalResponse('HICAP 在哪里，咨询前准备什么？', 'zh-Hans').answer, /^Medicare 问题可从加州老龄部官方页面找所在县的 HICAP/);
});
