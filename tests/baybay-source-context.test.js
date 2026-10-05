const test = require('node:test');
const assert = require('node:assert/strict');
const { sourceContextText } = require('../lib/baybayAgent');

test('official eligibility paragraphs survive compact synthesis without losing companion and exhibition restrictions', () => {
  const eligibility = 'City Museum offer eligibility: one general admission per eligible cardholder. Companions without a card are not included. Special exhibitions must be purchased separately. Bring valid photo identification.';
  const text = ['Museum program', ...Array.from({ length: 20 }, (_, i) => `Exhibition ${i}: ${'An introduction to the collection. '.repeat(4)}`),
    'Next eligible weekend is October 3 and 4.', 'Eligibility and terms', eligibility, 'Museum hours', 'Wednesday Closed'].join('\n');
  const result = sourceContextText(text, 'City Museum cardholder with a friend, eligibility and special exhibitions?');
  assert.ok(result.length <= 1800); assert.ok(result.includes(eligibility));
  assert.match(result, /October 3 and 4/); assert.match(result, /Wednesday Closed/);
  assert.ok(result.split('\n\n').every(paragraph => text.split('\n').map(line => line.trim()).includes(paragraph)));
});

test('short source text is unchanged and an oversized paragraph is never presented as a complete rule', () => {
  const small = 'Museum hours\nWednesday Closed'; assert.equal(sourceContextText(small, 'hours'), small);
  const long = `Admission eligibility ${'explanation '.repeat(250)}only cardholders qualify.`;
  const result = sourceContextText(`Museum program\n${long}`, 'admission eligibility');
  assert.equal(result, 'Museum program'); assert.ok(!result.includes('Admission eligibility'));
});

test('Chinese child-meal questions retain English age, purchase and date restrictions among unrelated same-brand deals', () => {
  const terms = 'Offer valid 10/7/26-10/28/26. IKEA Family Members only. Dine-in purchases Wednesdays only from October 7, 2026 through October 28, 2026. Limit: two kids entrees for kids aged 12 and under only per adult entree purchased. Each child must be present at time of purchase. Same transaction required.';
  const content = ['IKEA offer terms', ...Array.from({ length: 14 }, (_, i) => `IKEA Family member offer ${i}. Admission to the furniture discount program requires IKEA Family membership. ${'Selection varies by store. '.repeat(6)}`), '2 free kids entrees with purchase of 1 adult entree', terms].join('\n');
  const result = sourceContextText(content, 'IKEA Emeryville 周三带8岁和13岁的孩子吃饭，儿童餐免费吗？必须堂食和孩子在场吗？');
  assert.ok(result.length <= 1800); assert.ok(result.includes(terms));
  assert.ok(result.split('\n\n').every(paragraph => content.split('\n').map(line => line.trim()).includes(paragraph)));
});

test('family admission questions retain adult prices with their table labels and child eligibility', () => {
  const rules = 'Children age 12 and under receive free admission. Include all guests in the ticket order; special event tickets are not included.';
  const lines = ['Museum visit', ...Array.from({ length: 16 }, (_, i) => `Membership offer ${i}: admission discounts require valid membership. ${'Consult member terms before visiting. '.repeat(4)}`),
    'Admission', 'All-inclusive ticket', 'Adult 18-64', '$25', 'Senior 65+', '$22', 'Child 12 & Under', 'Free*', rules,
    ...Array.from({ length: 8 }, (_, i) => `Child activity ${i}: museum play and crafts for children aged 6 and under. ${'Check the gallery schedule. '.repeat(3)}`)];
  const content = lines.join('\n');
  const excerpt = sourceContextText(content, '两名成人带6岁孩子，不开车，想去Oakland Museum of California，全家门票加公共交通总预算150美元。');
  assert.ok(excerpt.length <= 1800);
  assert.ok(excerpt.includes('Adult 18-64\n$25'));
  assert.ok(excerpt.includes('Child 12 & Under\nFree*'));
  assert.ok(excerpt.includes(rules));
  assert.ok(excerpt.split(/\n+/).every(line => lines.map(source => source.trim()).includes(line)));
});

test('prices cannot survive compaction without their ticket tier or inherit a nonadjacent amount', () => {
  const prefix = Array.from({ length: 20 }, (_, i) => `Admission information ${i}. ${'Read the whole eligibility rule. '.repeat(3)}`);
  const adult = `Adult ${'limited eligibility '.repeat(4)}`;
  const value = [...prefix, adult, '$25', 'Child 12 & Under', 'Ask the desk', '$8'].join('\n');
  const result = sourceContextText(value, '成人门票多少钱？', 80);
  assert.ok(result.length <= 80);
  assert.ok(!result.includes('$25'));
  assert.ok(!result.includes('Child 12 & Under\n$8'));
});
