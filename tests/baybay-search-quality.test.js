const test = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');

const final = (answer, followups = []) => ({ model: 'fixture-model', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ answer, candidateIds: [], followups }) }] }] });
const settings = extra => ({ config: { BAYBAY_STATE_SECRET: 'test-search-quality-secret' }, catalog: { version: 1, events: [], places: [], guides: [] }, isTest: true, now: () => Date.parse('2026-10-04T19:00:00Z'), ...extra });

test('guide cards follow the actual cited answer rather than unrelated earlier retrieval matches', async () => {
  const guide = (slug, title) => ({ slug, title, url: `/guides/${slug}`, keywords: ['Muir Woods', 'parking'], content: `${title}\n\nMuir Woods parking reservation information.`, updatedAt: '2026-10-04' });
  const service = createBayBayAssistant(settings({ guideCatalog: [guide('all-discounts', 'Discount overview'), guide('muir-parking', 'Muir Woods parking')],
    ai: async payload => { const context = JSON.parse(payload.input[0].content); const source = context.evidence.find(row => row.url === '/guides/muir-parking'); assert.ok(source); return final(`停车需要单独预约。 [[${source.id}]]`, ['帮我整理停车预约步骤']); },
  }));
  const result = await service.run({ message: 'Muir Woods parking reservation information', searchMode: 'site' });
  assert.deepEqual(result.suggestedGuides.map(row => row.slug), ['muir-parking']);
  assert.deepEqual(result.followups, ['帮我整理停车预约步骤']);
});

test('source failures expose only safe diagnostic codes and do not erase grounded evidence', async () => {
  let round = 0;
  const service = createBayBayAssistant(settings({
    webSearch: async () => ({ answer: 'A source lead.', sources: [{ title: 'Museum hours', url: 'https://museum.example.org/visit' }], candidates: [], checkedAt: '2026-10-04' }),
    sourceFetch: async () => { throw Object.assign(new Error('Sensitive provider detail should never be returned'), { code: 'http-403' }); },
    ai: async payload => {
      if (!round++) return { model: 'fixture-model', status: 'completed', output: [{ type: 'function_call', name: 'read_source', call_id: 'source-read', arguments: JSON.stringify({ sourceId: JSON.parse(payload.input[0].content).evidence.find(row => row.url === 'https://museum.example.org/visit').id }) }] };
      const outcome = JSON.parse(payload.input.find(row => row.type === 'function_call_output').output);
      assert.equal(outcome.code, 'source_forbidden'); assert.equal(outcome.retryable, false);
      assert.ok(!JSON.stringify(outcome).includes('Sensitive provider'));
      return final('本次未能读取官网，因此开放时间仍待确认。');
    },
  }));
  const result = await service.run({ message: '核实旧金山博物馆开放时间', searchMode: 'web' });
  assert.ok(result.research.steps.some(row => row.tool === 'read_source' && row.code === 'source_forbidden'), JSON.stringify(result.research));
  assert.equal(result.retrieval.webStatus, 'completed');
});

test('an answer grounded only in an official web page does not append unrelated uncited guide cards', async () => {
  const service = createBayBayAssistant(settings({
    guideCatalog: [{ slug: 'other-museum-deals', title: 'Museum offers and other outings', url: '/guides/other-museum-deals', keywords: ['museum', 'admission'], content: 'Museum admission offers and other attractions to visit in San Francisco.', updatedAt: '2026-10-04' }],
    webSearch: async () => ({ answer: 'Official museum admission information.', sources: [{ title: 'Museum official admissions', url: 'https://museum.example.org/visit' }], candidates: [], checkedAt: '2026-10-04' }),
    ai: async payload => { const context = JSON.parse(payload.input[0].content); const source = context.evidence.find(row => row.url === 'https://museum.example.org/visit'); assert.ok(source); return final(`Please check the selected museum's ticket rules. [[${source.id}]]`); },
  }));
  const result = await service.run({ message: 'San Francisco museum admission prices', searchMode: 'web' });
  assert.deepEqual(result.sources.map(row => row.url), ['https://museum.example.org/visit']);
  assert.deepEqual(result.suggestedGuides, []);
});
