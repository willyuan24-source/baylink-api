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
