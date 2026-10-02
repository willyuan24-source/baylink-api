const test = require('node:test');
const assert = require('node:assert/strict');
const { requestSearch } = require('../lib/plannerWebSearch');
const { needsSourceFacts, validateSourceFacts, sourceConditions, groundSearchFacts } = require('../lib/plannerWebFacts');
const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
const sources = [
  { title: 'Oakland Museum of California visit', url: 'https://museumca.org/visit/' },
  { title: 'Oakland Zoo hours and pricing', url: 'https://www.oaklandzoo.org/hours-and-pricing/' },
  { title: 'Oakland Zoo programs and events', url: 'https://www.oaklandzoo.org/programs-and-events/' },
];
const museum = 'Oakland Museum of California\nOakland\nWednesday–Sunday: 11 am–5 pm\nAdults $25; seniors $22; students and educators with valid ID $18\nChildren 12 and under are free.\nPlease consult the visitor page for temporary changes.';
const venue = 'Oakland Zoo\nOakland\nOpen daily 9:30 am–4 pm\nAdmissions closes\n2:00 pm\nLast tickets sold\n1:30 pm\nAdults: prices vary by day\nBoo at the Zoo runs on weekends October 17–November 1.\nPlease check the selected date for availability.';
const response = text => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: text });
const record = (override = {}) => ({ sourceNumber: 1, name: 'Oakland Museum of California', city: 'Oakland', regularHours: 'Wednesday–Sunday: 11 am–5 pm', admission: 'Adults $25; seniors $22; students and educators with valid ID $18', lastEntry: null, lastTicketSale: null, conditions: [], ...override });
function searchResponse() {
  const text = '2026-10-17 OMCA will be open 11–5 [museum]. Oakland Zoo will be open 9:30–4 [zoo]. Boo at the Zoo October 17–November 1 [event].';
  const annotations = ['[museum]', '[zoo]', '[event]'].map((marker, i) => ({ type: 'url_citation', ...sources[i], start_index: text.indexOf(marker), end_index: text.indexOf(marker) + marker.length }));
  return { status: 'completed', output: [{ type: 'web_search_call', status: 'completed', action: { type: 'search' } }, { type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations }] }] };
}

test('only visiting-hours and admission questions use fact formatting; dated discovery remains broad', () => {
  for (const query of ['Oakland 博物馆门票和营业时间', 'museum hours and admission', '入場截止', 'last entry']) assert.equal(needsSourceFacts({ query }), true);
  for (const query of ['湾区10月活动和新店', 'free local events', 'Find a local cafe']) assert.equal(needsSourceFacts({ query, date: '2026-10-17' }), false);
});

test('production-shaped museum answer is rebuilt from its actual source, excludes zoos and never confirms a future date', async () => {
  const fetched = []; let extraction;
  const result = await requestSearch({ query: '10月17日周六 Oakland 博物馆门票和营业时间', date: '2026-10-17', locale: 'zh-Hans' }, {
    ai: async () => searchResponse(), extractAi: async payload => { extraction = payload; return { places: [record()] }; }, lookup,
    sourceFetch: async url => { fetched.push(url.href); return response(museum); },
  });
  assert.deepEqual(fetched, [sources[0].url]);
  assert.deepEqual(result.sources, [sources[0]]);
  assert.doesNotMatch(result.answer, /Oakland Zoo|Boo at|will be open|2026-10-17.*11–5/);
  assert.match(result.answer, /2026-10-17 当日营业与余票：尚未单独核实/);
  assert.match(result.answer, /原文常规时段：Wednesday–Sunday: 11 am–5 pm \[1\]/);
  assert.match(result.answer, /valid ID/); assert.match(result.answer, /入场截止：本次未核实/);
  assert.deepEqual([...new Set(result.answer.match(/\[\d+\]/g))], ['[1]']);
  assert.equal(result.candidates.length, 1); assert.match(result.candidates[0].timeSummary, /尚未单独核实/);
  assert.match(result.candidates[0].priceSummary, /valid ID/); assert.equal(result.candidates[0].summary, null);
  assert.equal(extraction.store, false); assert.equal(extraction.tools, undefined);
  const content = JSON.parse(extraction.messages[1].content);
  assert.equal(content.sources[0].text, museum); assert.equal('answer' in content, false);
});

test('missing source text discards guessed hours and prices while retaining source links and explicit unknowns', async () => {
  let extractions = 0;
  for (const locale of ['en', 'zh-Hans', 'zh-Hant']) {
    const result = await requestSearch({ query: 'Oakland museum hours', date: '2026-10-17', locale }, {
      ai: async () => searchResponse(), extractAi: async () => { extractions++; return { places: [record()] }; }, lookup,
      sourceFetch: async () => { throw Error('source blocked'); },
    });
    assert.equal(result.factsStatus, 'sources-only'); assert.deepEqual(result.candidates, []);
    assert.doesNotMatch(result.answer, /11–5|9:30|\$25|will be open|Oakland Zoo/);
    assert.match(result.answer, /2026-10-17/); assert.match(result.answer, /not independently confirmed|尚未单独核实|尚未單獨核實/);
    assert.deepEqual(result.sources, [sources[0]]);
  }
  assert.equal(extractions, 0);
});

test('facts must match their own fetched page, including labelled cutoff and actual name', () => {
  const pages = [{ sourceNumber: 1, text: museum }];
  const [fact] = validateSourceFacts({ places: [record({ city: 'San Francisco', lastEntry: 'Wednesday–Sunday: 11 am–5 pm', admission: 'Adults $5', conditions: ['Children 12 and under are free.', 'Free every Saturday'] })] }, pages, { query: 'museum hours' });
  assert.equal(fact.city, null); assert.equal(fact.lastEntry, null); assert.equal(fact.admission, null);
  assert.deepEqual(fact.conditions, ['Children 12 and under are free.']);
  for (const row of [record({ sourceNumber: 2 }), record({ name: 'Invented museum' }), record({ privateField: 'discard' })]) assert.deepEqual(validateSourceFacts({ places: [row] }, pages, { query: 'museum hours' }), []);
  assert.deepEqual(validateSourceFacts({ places: [record({ name: 'Oakland Zoo' })] }, [{ sourceNumber: 1, text: venue }], { query: 'museum hours' }), []);
});

test('actual last entry, last ticket sale and weekend eligibility survive formatter omissions', async () => {
  const result = await groundSearchFacts({ answer: 'untrusted hours', sources: [sources[1]] }, { query: 'Oakland Zoo hours and tickets', date: '2026-10-17', locale: 'en' }, {
    lookup, sourceFetch: async () => response(venue), ai: async () => ({ places: [record({ name: 'Oakland Zoo', regularHours: 'Open daily 9:30 am–4 pm', admission: 'Adults: prices vary by day' })] }),
  });
  assert.match(result.answer, /Entry cutoff：Admissions closes 2:00 pm \[1\]/);
  assert.match(result.answer, /Last ticket sale：Last tickets sold 1:30 pm \[1\]/);
  assert.match(result.answer, /on weekends October 17–November 1/);
  assert.match(result.candidates[0].timeSummary, /2:00 pm.*1:30 pm/);
  assert.match(result.candidates[0].priceSummary, /on weekends/);
});

test('admissions opening, venue closure and ambiguous shop cutoffs never become a last-entry time', () => {
  for (const text of ['Admissions opens\n9:30 am\nZoo closes\n4 pm', 'Cafe\nLast entry 3 pm', 'Last entry 2 pm\nAnother venue\nLast entry 3 pm']) assert.equal(sourceConditions(text).lastEntry, null);
  assert.equal(sourceConditions('Museum\nLast entry\n4:30 pm').lastEntry, 'Last entry 4:30 pm');
});

test('private DNS and cross-host redirects cannot supply facts', async () => {
  let requests = 0; let extractions = 0;
  const base = { answer: 'discard', sources: [sources[0]] };
  const options = { ai: async () => { extractions++; return { places: [record()] }; }, sourceFetch: async () => { requests++; return { status: 302, headers: { location: 'https://another.org/page' }, body: '' }; } };
  const blocked = await groundSearchFacts(base, { query: 'museum hours' }, { ...options, lookup: async () => [{ address: '127.0.0.1', family: 4 }] });
  assert.equal(requests, 0); assert.equal(blocked.factsStatus, 'sources-only');
  const redirected = await groundSearchFacts(base, { query: 'museum hours' }, { ...options, lookup });
  assert.equal(requests, 1); assert.equal(extractions, 0); assert.equal(redirected.factsStatus, 'sources-only');
});

test('multiple source reads start in parallel and re-use one extraction inside the shared deadline', async () => {
  let active = 0; let maximum = 0; let extractions = 0;
  await groundSearchFacts({ sources: sources.slice(0, 2) }, { query: 'venue hours' }, { deadline: Date.now() + 3000, lookup,
    sourceFetch: async () => { active++; maximum = Math.max(maximum, active); await new Promise(resolve => setTimeout(resolve, 20)); active--; return response(museum); },
    ai: async () => { extractions++; return { places: [] }; },
  });
  assert.equal(maximum, 2); assert.equal(extractions, 1);
});

test('exhausted shared deadline skips all new work, and hung source transport cannot extend it', async () => {
  const input = { query: 'museum hours', date: '2026-10-17', locale: 'en' };
  const base = { sources: [sources[0]], answer: 'will be open' };
  let calls = 0;
  const expired = await groundSearchFacts(base, input, { deadline: Date.now(), lookup, sourceFetch: async () => { calls++; throw Error('must skip'); } });
  assert.equal(calls, 0); assert.equal(expired.factsStatus, 'sources-only');
  const start = Date.now();
  const bounded = await groundSearchFacts(base, input, { deadline: Date.now() + 750, lookup, sourceFetch: () => new Promise(() => {}) });
  assert.ok(Date.now() - start < 1400); assert.equal(bounded.factsStatus, 'sources-only');
});
