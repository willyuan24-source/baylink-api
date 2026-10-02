const test = require('node:test');
const assert = require('node:assert/strict');
const { selectConversationGuides } = require('../lib/guideConversation');

const guide = (slug, title, keywords, content = '') => ({
  slug, url: `/guides/${slug}`, title, keywords, content,
  summary: '免费散步与周末步行路线。', categories: ['other'],
});
const sf = guide('sf-walk', '旧金山海边散步', ['San Francisco', '免费', '散步']);
const east = guide('east-walk', '东湾免费散步与周末路线', ['Oakland', 'Berkeley', '免费', '散步', '周末', '路线'], '从旧金山坐车来东湾；散步路线均在 Oakland 和 Berkeley。');
const allBay = guide('all-bay-walks', '全湾区免费散步', ['南湾', '东湾', '半岛', '北湾', '免费'], '旧金山与其他湾区城市的公开路线。');
const catalog = [east, allBay, sf];
const history = content => [{ role: 'user', content }, { role: 'assistant', content: '先看已发布攻略。' }];

test('an explicit San Francisco discovery excludes East Bay-only guides despite incidental mentions', () => {
  for (const message of ['旧金山免费散步', 'San Francisco 免费散步', 'SF 免费散步']) {
    const selected = selectConversationGuides(catalog, message, 'other');
    assert.equal(selected[0]?.slug, sf.slug, message);
    assert.ok(!selected.some(item => item.slug === east.slug), message);
    assert.ok(selected.some(item => item.slug === allBay.slug), 'Bay-wide sources remain eligible');
  }
});

test('published Chinese and English San Francisco walking results stay geographically relevant', () => {
  for (const [file, message] of [
    ['../data/guide-catalog.json', '旧金山免费散步'],
    ['../data/guide-catalog.en.json', 'San Francisco free walks'],
  ]) {
    const selected = selectConversationGuides(require(file), message, 'other', '/', [], '2026-10-02');
    assert.ok(selected.length, message);
    assert.match(`${selected[0].title} ${selected[0].keywords.join(' ')}`, /旧金山|San Francisco/i, message);
    assert.ok(!selected.some(item => /stanford|alameda|east-bay|oakland|berkeley/.test(item.slug)), message);
  }
});

test('Bay-wide discovery and explicit cross-area comparisons retain multiple areas', () => {
  for (const message of ['全湾区免费散步', '旧金山和 Oakland 免费散步', '从旧金山出发，全湾区都可以，免费散步', 'Anywhere in the Bay Area from SF, 免费散步']) {
    const selected = selectConversationGuides(catalog, message, 'other');
    assert.ok(selected.some(item => item.slug === east.slug), message);
    assert.ok(selected.some(item => item.slug === sf.slug), message);
  }
});

test('departure cities do not override explicit destinations or constrain open-ended trips', () => {
  for (const message of ['从东湾去旧金山免费散步', 'From Oakland to San Francisco 免费散步']) {
    const selected = selectConversationGuides(catalog, message, 'other');
    assert.equal(selected[0]?.slug, sf.slug, message);
    assert.ok(!selected.some(item => item.slug === east.slug), message);
  }
  assert.ok(selectConversationGuides(catalog, '旧金山出发去哪里免费散步', 'other').some(item => item.slug === east.slug));
});

test('short follow-ups use the latest destination while unrelated article context does not override it', () => {
  const selected = selectConversationGuides(catalog, '旧金山呢？', 'other', east.url, history('Oakland 免费散步'));
  assert.equal(selected[0]?.slug, sf.slug);
  assert.ok(!selected.some(item => item.slug === east.slug));
  assert.ok(!selectConversationGuides(catalog, '旧金山免费散步', 'other', east.url).some(item => item.slug === east.slug));
});

test('explicit reading retains the selected article even when it mentions another destination', () => {
  const archived = { ...east, slug: 'east-walk-2026-09', url: '/guides/east-walk-2026-09', editionMonth: '2026-09' };
  const selected = selectConversationGuides([sf, archived], '总结这篇攻略，旧金山出发的注意事项', 'other', archived.url, [], '2026-10-02');
  assert.equal(selected[0]?.slug, archived.slug);
});
