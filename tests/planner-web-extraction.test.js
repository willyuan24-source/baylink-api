const test = require('node:test');
const assert = require('node:assert/strict');
const { extractWebCandidates, validateExtractedCandidates } = require('../lib/plannerWebExtraction');
const { requestSearch, extractSearchResult } = require('../lib/plannerWebSearch');

const ANSWER = "Gott's Roadside at San Francisco Ferry Building has regular Saturday hours of 10:00 AM to 10:00 PM; temporary changes still need checking. [1]";
const result = { answer: ANSWER, sources: [{ title: 'Official location', url: 'https://www.gotts.com/location/sfferrybuilding/' }] };
const fact = text => ({ text, evidenceQuote: ANSWER, sourceNumber: 1 });
const record = () => ({ name: fact("Gott's Roadside"), city: fact('San Francisco'), summary: null, timeSummary: fact('regular Saturday hours of 10:00 AM to 10:00 PM; temporary changes still need checking.'), priceSummary: null });
const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
function searchResponse(text = ANSWER.replace('[1]', '[source]')) {
  return { status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search' } },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations: [{ type: 'url_citation', title: result.sources[0].title, url: result.sources[0].url, start_index: text.indexOf('[source]'), end_index: text.indexOf('[source]') + 8 }] }] }] };
}

test('exact cited answer excerpts become cards without inventing text or exposing evidence as source snippets', () => {
  const cards = validateExtractedCandidates({ candidates: [record()] }, result);
  assert.equal(cards.length, 1); assert.equal(cards[0].name, "Gott's Roadside"); assert.equal(cards[0].city, 'San Francisco');
  assert.equal(cards[0].timeSummary, record().timeSummary.text); assert.equal(cards[0].priceSummary, null);
  assert.deepEqual(cards[0].sourceUrls, [result.sources[0].url]);
  assert.deepEqual(Object.keys(cards[0]).sort(), ['id', 'name', 'city', 'summary', 'timeSummary', 'priceSummary', 'sourceUrls'].sort());
  assert.deepEqual(validateExtractedCandidates({ candidates: [record(), record()] }, result), cards);
});

test('uncited, changed, mismatched or invented evidence cannot create a field or a named place', () => {
  const valid = record();
  const bad = [
    { ...valid, name: fact('Invented cafe') },
    { ...valid, name: { ...valid.name, sourceNumber: 2 } },
    { ...valid, name: { ...valid.name, evidenceQuote: ANSWER.replace('[1]', '') } },
    { ...valid, name: { ...valid.name, evidenceQuote: ANSWER.replace('Saturday', 'Sunday') } },
    { ...valid, name: { ...valid.name, evidenceQuote: 'Official location [1]' } },
    { ...valid, coordinates: { lat: 1, lng: 2 } },
  ];
  assert.deepEqual(validateExtractedCandidates({ candidates: bad }, result), []);
  const [card] = validateExtractedCandidates({ candidates: [{ ...valid, city: fact('旧金山'), timeSummary: fact('Open on October 3 from 10 AM to 10 PM'), priceSummary: fact('Free admission') }] }, result);
  assert.equal(card.city, null); assert.equal(card.timeSummary, null); assert.equal(card.priceSummary, null);
});

test('extraction uses one bounded text-only JSON request with an independent chat model', async () => {
  const calls = [];
  const extracted = await extractWebCandidates(result, { config: { OPENAI_API_KEY: 'isolated-test-placeholder', OPENAI_MODEL: 'gpt-4o-mini', OPENAI_WEB_SEARCH_MODEL: 'web-only-model' }, fetchImpl: async (url, options) => {
    calls.push({ url, payload: JSON.parse(options.body), signal: options.signal });
    return { ok: true, json: async () => ({ choices: [{ finish_reason: 'stop', message: { content: JSON.stringify({ candidates: [record()] }) } }] }) };
  } });
  assert.equal(extracted.status, 'ready'); assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.openai.com/v1/chat/completions');
  const payload = calls[0].payload;
  assert.equal(payload.model, 'gpt-4o-mini'); assert.equal(payload.store, false); assert.equal(payload.max_completion_tokens, 1400);
  assert.deepEqual(payload.response_format, { type: 'json_object' }); assert.equal(payload.tools, undefined);
  assert.deepEqual(JSON.parse(payload.messages[1].content), { answer: ANSWER, sources: [{ sourceNumber: 1, title: 'Official location' }] });
  assert.ok(calls[0].signal instanceof AbortSignal);
});

test('safe statuses distinguish no candidate, unsupported evidence and extraction failure', async () => {
  for (const [raw, status] of [[{ candidates: [] }, 'none'], [{ candidates: [{ name: fact('Invented') }] }, 'unverified'], [{ fake: [] }, 'unavailable']]) {
    assert.deepEqual(await extractWebCandidates(result, { ai: async () => raw }), { candidates: [], status });
  }
  assert.equal((await extractWebCandidates(result, { ai: async () => { throw Error('provider failed'); } })).status, 'unavailable');
  assert.equal((await extractWebCandidates(result, { ai: () => new Promise(() => {}), timeoutMs: 10 })).status, 'unavailable');
  let calls = 0;
  for (const body of [{ choices: [{ finish_reason: 'length', message: { content: '{}' } }] }, { choices: [{ finish_reason: 'stop', message: { content: 'broken' } }] }]) {
    assert.equal((await extractWebCandidates(result, { config: { OPENAI_API_KEY: 'fixture' }, fetchImpl: async () => { calls++; return { ok: true, json: async () => body }; } })).status, 'unavailable');
  }
  assert.equal(calls, 2, 'one attempt for each invocation, never an automatic retry');
});

test('slow, failing and unverified extraction preserve a successful search answer and citations', async () => {
  for (const extractAi of [async () => { throw Error('no formatter'); }, () => new Promise(() => {}), async () => ({ candidates: [{ name: fact('Invented') }] })]) {
    const response = await requestSearch({ query: "Gott's Roadside", locale: 'en' }, { ai: async () => searchResponse(), extractAi, lookup, extractTimeoutMs: 120 });
    assert.equal(response.ok, true); assert.equal(response.answer, ANSWER); assert.deepEqual(response.sources, result.sources);
    assert.ok(['unavailable', 'unverified'].includes(response.candidateStatus));
  }
});

test('extraction is skipped when the remaining search deadline is too short', async () => {
  let calls = 0;
  const response = await requestSearch({ query: "Gott's Roadside" }, { ai: async () => searchResponse(), extractAi: async () => { calls++; return { candidates: [record()] }; }, lookup, timeoutMs: 250 });
  assert.equal(response.ok, true); assert.equal(response.answer, ANSWER); assert.equal(calls, 0); assert.equal(response.candidateStatus, 'unavailable');
});

test('hand-written citation numbers are not usable as extraction evidence', async () => {
  const response = await extractSearchResult(searchResponse('Invented place [1]. Real venue [source]'), { lookup });
  assert.equal(response.answer, 'Invented place . Real venue [1]');
  assert.deepEqual(validateExtractedCandidates({ candidates: [{ name: { text: 'Invented place', evidenceQuote: 'Invented place [1]', sourceNumber: 1 } }] }, response), []);
});
