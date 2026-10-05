const test = require('node:test');
const assert = require('node:assert/strict');
const { admissionFactsFor, withAdmissionFacts, admissionRuleFromQuote } = require('../lib/baybayFacts');
const { buildItinerary } = require('../lib/baybayPlan');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { createEvidenceStore, verifiedCandidate } = require('../lib/baybayTools');
const catalog = require('../data/planner-catalog.json');
const guides = require('../data/guide-catalog.json');
const snapshots = require('../data/admission-facts.json');
const NOW = Date.parse('2026-10-04T16:00:00Z'), today = '2026-10-04';
const state = { goal: 'day-plan', city: 'San Francisco', date: '2026-10-10', partySize: 3, childAges: [5], budget: 120, budgetScope: 'total', travelMode: 'transit', returnToOrigin: false };
const museum = () => ({ ...catalog.places.find(row => row.id === 'venue-exploratorium-daytime'), kind: 'place', sourceIds: ['source-visit'], evidenceId: 'old-local-id' });
const row = admission => ({ id: 'test', title: 'Example Museum', cost: 'unknown', officialUrl: 'https://example.org/visit', planning: { admission } });
const sourced = extra => ({ sourceUrl: 'https://example.org/visit', verifiedAt: today, feesIncluded: true, ...extra });

test('audited price snapshots have an exact published quote and official reference', () => {
  for (const snapshot of snapshots) {
    const guide = guides.find(item => item.url === snapshot.guideUrl);
    assert.ok(guide, snapshot.candidateId);
    assert.ok(guide.content.includes(snapshot.sourceQuote), snapshot.candidateId);
    assert.ok(guide.sources.some(source => source.url === snapshot.sourceUrl));
    assert.equal(guide.updatedAt, snapshot.verifiedAt);
  }
});

test('real Exploratorium party calculation is shared by evidence, candidates and main card', () => {
  const evidence = buildSiteEvidence({ query: 'Exploratorium 儿童门票', state, catalog, guideCatalog: guides, today });
  const candidate = evidence.candidates.find(item => item.id === museum().id);
  assert.ok(candidate);
  const store = createEvidenceStore(evidence), stored = store.candidates.get(candidate.id);
  const facts = withAdmissionFacts(stored, state, { today }).admissionFacts;
  const plan = buildItinerary({ candidates: [stored], state, now: NOW });
  assert.equal(candidate.admissionFacts.knownTotalUsd, 109.85);
  assert.deepEqual(plan.stops[0].admissionFacts, facts);
  assert.equal(plan.budget.knownTotalUsd, 109.85);
  assert.equal(plan.budget.admissionFacts[0].knownTotalUsd, 109.85);
  assert.deepEqual(facts.breakdown.map(item => [item.category, item.quantity, item.unitUsd, item.subtotalUsd]), [['adult', 2, 39.95, 79.9], ['child', 1, 29.95, 29.95]]);
  assert.equal(facts.basis, 'catalog-snapshot');
  assert.equal(facts.status, 'partial');
  assert.equal(facts.applicability.dateStatus, 'regular-unconfirmed');
  assert.equal(facts.applicability.feesIncluded, null);
  assert.ok(facts.sourceIds.every(id => store.sources.has(id)));
  assert.match(plan.budget.unknownItems.join(' '), /所选日期|票务附加费/);
  assert.match(plan.budget.unknownItems.join(' '), /餐|交通/);
});

test('a known snapshot subtotal over the group limit fails even though fees remain unknown', () => {
  const plan = buildItinerary({ candidates: [museum()], state: { ...state, budget: 100 }, now: NOW });
  assert.equal(plan.budget.knownTotalUsd, 109.85);
  assert.ok(plan.checks.some(check => check.code === 'budget' && check.status === 'fail'));
});

test('a fresh snapshot survives a future visit across evidence, cards and a PIER-only follow-up without confirming future prices', () => {
  const currentDay = '2026-10-05', now = Date.parse(`${currentDay}T16:00:00Z`);
  const future = { ...state, date: '2026-11-07', selectedCandidateIds: ['venue-exploratorium-daytime', 'pier39'] };
  const evidence = buildSiteEvidence({ query: 'Exploratorium 和 PIER39 公共区', state: future, catalog, guideCatalog: guides, today: currentDay });
  const store = createEvidenceStore(evidence);
  const candidates = future.selectedCandidateIds.map(id => store.candidates.get(id));
  assert.ok(candidates.every(Boolean));
  const plan = buildItinerary({ candidates, selectedIds: future.selectedCandidateIds, state: future, now });
  assert.deepEqual(plan.stops.map(stop => stop.entityId), future.selectedCandidateIds);
  assert.deepEqual(plan.stops.map(stop => stop.admissionFacts.knownTotalUsd), [109.85, 0]);
  assert.equal(plan.budget.knownTotalUsd, 109.85);
  for (const stop of plan.stops) {
    assert.equal(stop.admissionFacts.status, 'partial');
    assert.equal(stop.admissionFacts.basis, 'catalog-snapshot');
    assert.equal(stop.admissionFacts.applicability.dateStatus, 'regular-unconfirmed');
    assert.ok(stop.admissionFacts.sourceIds.every(id => store.sources.has(id)));
    assert.ok(stop.admissionFacts.unknowns.some(text => /所选日期|所選日期/.test(text)));
  }
  assert.match(plan.budget.unknownItems.join(' '), /餐|交通/);
  const retained = buildItinerary({ candidates: [candidates[1]], selectedIds: ['pier39'], state: { ...future, selectedCandidateIds: ['pier39'] }, now });
  assert.deepEqual(retained.handoff.stops.map(stop => stop.id), ['pier39']);
  assert.equal(retained.stops[0].admissionFacts.knownTotalUsd, 0);
  assert.equal(retained.budget.knownTotalUsd, 0);
  assert.doesNotMatch(retained.stops[0].admissionFacts.unknowns.join(' '), /不能当作免费/);
  assert.match(retained.budget.unknownItems.join(' '), /餐|交通/);
});

test('PIER 39 public access stays zero in evidence, main card and a retained follow-up without pricing optional experiences', () => {
  const raw = catalog.places.find(row => row.id === 'pier39');
  const evidence = buildSiteEvidence({ query: 'PIER 39 公共区和海狮', state: { ...state, selectedCandidateIds: ['pier39'] }, catalog, guideCatalog: guides, today });
  const store = createEvidenceStore(evidence), candidate = store.candidates.get(raw.id);
  assert.ok(candidate);
  const facts = withAdmissionFacts(candidate, state, { today }).admissionFacts;
  assert.equal(facts.knownTotalUsd, 0); assert.equal(facts.knownPerPersonUsd, 0);
  assert.equal(facts.basis, 'catalog-snapshot'); assert.equal(facts.status, 'partial');
  assert.equal(facts.sourceUrl, raw.officialUrl); assert.ok(facts.sourceIds.every(id => store.sources.has(id)));
  assert.deepEqual(facts.breakdown.map(row => [row.category, row.quantity, row.unitUsd]), [['all-ages', 3, 0]]);
  assert.match(facts.note, /Public pedestrian areas/); assert.match(facts.note, /Aquarium, cruises, rides, food/);
  assert.match(facts.note, /excluded/);
  for (const selectedState of [state, { ...state, partySize: 4, childAges: [5, 8], selectedCandidateIds: ['pier39'] }]) {
    const plan = buildItinerary({ candidates: [candidate], selectedIds: ['pier39'], state: selectedState, now: NOW });
    assert.equal(plan.stops[0].admissionUsd, 0);
    assert.equal(plan.stops[0].admissionFacts.knownTotalUsd, 0);
    assert.equal(plan.budget.knownTotalUsd, 0);
    assert.doesNotMatch(plan.stops[0].admissionFacts.unknowns.join(' '), /不能当作免费|do not count it as free/);
    assert.match(plan.budget.unknownItems.join(' '), /餐|交通/);
  }
  for (const changed of [{ ...raw, id: 'aquarium-pier39' }, { ...raw, officialUrl: 'https://www.pier39.com/attractions/' }]) {
    assert.equal(withAdmissionFacts(changed, state, { today }).admissionFacts.knownTotalUsd, null);
  }
  const expired = withAdmissionFacts(candidate, { ...state, date: '2026-12-10' }, { today: '2026-12-10' });
  assert.equal(expired.admissionFacts.knownTotalUsd, null);
});

test('snapshot cannot survive a changed source, web identity, historical visit or stale answer-date clock', () => {
  const attached = withAdmissionFacts(museum(), state, { today });
  for (const input of [{ ...museum(), officialUrl: 'https://example.org/other' }, { ...museum(), origin: 'web' }]) assert.equal(admissionFactsFor(input, state, { today }).facts.knownTotalUsd, null);
  for (const [date, currentDay] of [['2026-10-01', today], ['2026-12-10', '2026-12-10']]) for (const input of [museum(), attached]) {
    const result = admissionFactsFor(input, { ...state, date }, { today: currentDay });
    assert.equal(result.facts.knownTotalUsd, null, `${date}: ${!!input.planning.admission}`);
  }
});

test('the thirty-day snapshot guard uses today and cannot be bypassed by an attached rule or an earlier visit', () => {
  const attached = withAdmissionFacts(museum(), state, { today });
  const future = { ...state, date: '2026-11-07' };
  for (const input of [museum(), attached]) {
    const lastFresh = admissionFactsFor(input, future, { today: '2026-11-01' }).facts;
    assert.equal(lastFresh.knownTotalUsd, 109.85);
    assert.equal(lastFresh.applicability.dateStatus, 'regular-unconfirmed');
    assert.equal(admissionFactsFor(input, future, { today: '2026-11-02' }).facts.knownTotalUsd, null);
    assert.equal(admissionFactsFor(input, state, { today: '2026-11-02' }).facts.knownTotalUsd, null, 'An old trip cannot revive an actually stale snapshot.');
    assert.equal(admissionFactsFor(input, future).facts.knownTotalUsd, null, 'Missing current-date evidence fails closed.');
  }
  const stale = admissionFactsFor(attached, future, { today: '2026-11-02' }).facts;
  assert.equal(stale.applicability.dateStatus, 'unconfirmed');
  assert.match(stale.unknowns.join(' '), /快照需要重新核对/);
  assert.doesNotMatch(stale.unknowns.join(' '), /不适用于所选日期/);
});

test('a casual visit question can retain all-ages free access before the party count is known', () => {
  const candidate = { ...catalog.places.find(row => row.id === 'pier39'), kind: 'place', sourceIds: ['pier-source'] };
  const incompleteParty = { ...state, partySize: null };
  const facts = withAdmissionFacts(candidate, incompleteParty, { today }).admissionFacts;
  assert.equal(facts.status, 'partial');
  assert.equal(facts.partySize, null);
  assert.equal(facts.knownTotalUsd, 0);
  assert.equal(facts.knownPerPersonUsd, 0);
  assert.deepEqual(facts.breakdown, []);
  assert.equal(facts.applicability.dateStatus, 'regular-unconfirmed');
  assert.match(facts.unknowns.join(' '), /是否开放及适用/);
  assert.equal(withAdmissionFacts(candidate, { ...incompleteParty, date: '2026-12-10' }, { today: '2026-12-10' }).admissionFacts.knownTotalUsd, null);
  const paid = admissionFactsFor(row(sourced({ allAgesUsd: 20, regularAdmission: true })), incompleteParty).facts;
  assert.equal(paid.knownTotalUsd, null);
  assert.equal(paid.knownPerPersonUsd, 20);
  const member = admissionFactsFor(row(sourced({ allAgesUsd: 0, eligibility: 'members', regularAdmission: true })), incompleteParty).facts;
  assert.equal(member.status, 'unknown');
  assert.equal(member.knownTotalUsd, null);
});

test('unknown child age or adult price never turns a child-only free tier into a free party', () => {
  const childrenOnly = { ...row(sourced({ children: [{ minAge: 0, maxAge: 12, usd: 0 }] })), cost: 'free' };
  childrenOnly.planning.admissionUsd = 0;
  const missingAdult = admissionFactsFor(childrenOnly, state);
  assert.equal(missingAdult.facts.status, 'unknown');
  assert.equal(missingAdult.facts.knownTotalUsd, null);
  const missingChild = admissionFactsFor(row(sourced({ adultUsd: 20 })), state);
  assert.equal(missingChild.facts.knownTotalUsd, 40);
  assert.equal(missingChild.facts.status, 'partial');
  assert.match(missingChild.unknowns.join(' '), /5 岁/);
});

test('overlapping child tiers, eligibility and out-of-date rules retain unknowns', () => {
  const overlap = admissionFactsFor(row(sourced({ adultUsd: 20, children: [{ minAge: 0, maxAge: 8, usd: 0 }, { minAge: 5, maxAge: 12, usd: 10 }] })), state);
  assert.equal(overlap.facts.knownTotalUsd, 40);
  assert.equal(overlap.facts.status, 'partial');
  for (const rule of [sourced({ allAgesUsd: 0, eligibility: 'membership' }), sourced({ allAgesUsd: 0, dates: ['2026-10-09'] }), sourced({ allAgesUsd: 0, validThrough: 'not-a-date' })]) {
    assert.equal(admissionFactsFor(row(rule), state).facts.status, 'unknown');
  }
});

test('sourced group admission applies only inside its party cap and date window', () => {
  const group = row(sourced({ scope: 'group', groupUsd: 55, maxPartySize: 4, validFrom: '2026-10-01', validThrough: '2026-10-31' }));
  assert.equal(admissionFactsFor(group, state).facts.knownTotalUsd, 55);
  assert.equal(admissionFactsFor(group, state).facts.applicability.dateStatus, 'date-specific');
  assert.equal(admissionFactsFor(group, { ...state, partySize: 5 }).facts.knownTotalUsd, null);
  assert.equal(admissionFactsFor(group, { ...state, date: '2026-11-01' }).facts.knownTotalUsd, null);
});

function verified(quote, { text, candidate = museum() } = {}) {
  const store = createEvidenceStore({ candidates: [candidate] }), stored = store.candidates.get(candidate.id);
  const source = store.addSource({ ...store.sources.get(stored.sourceIds[0]), text: text || `Exploratorium in San Francisco. ${quote}`, checkedAt: '2026-10-04T16:00:00Z', verification: 'page-read' });
  const result = verifiedCandidate({ candidate: stored, source, state, today, proofs: { name: 'Exploratorium', admission: quote } });
  assert.equal(result.error, undefined);
  return { result, source, store };
}

test('exact readable adult and age-tier prices supersede the catalog snapshot', () => {
  const quote = 'General admission: Adults ages 18–64 $42.50; Children ages 4–17 $31.50; Children 3 and under free.';
  const { result, source } = verified(quote, { candidate: withAdmissionFacts(museum(), state, { today }) });
  assert.equal(result.admissionFacts.knownTotalUsd, 116.5);
  assert.equal(result.admissionFacts.basis, 'page-read');
  assert.ok(result.admissionFacts.sourceIds.includes(source.id));
  assert.equal(result.planning.admission.sourceQuote, quote);
  const plan = buildItinerary({ candidates: [result], state, now: NOW });
  assert.equal(plan.budget.knownTotalUsd, 116.5);
  const younger = admissionFactsFor(result, { ...state, childAges: [3] });
  assert.equal(younger.facts.knownTotalUsd, 85);
});

test('new ambiguous or conditional admission clears old snapshot and cannot revive it', () => {
  const snapshot = withAdmissionFacts(museum(), state, { today });
  for (const quote of ['Members: Adults $10; Children ages 4–17 free.', 'General admission $20; seniors $15; members free.', 'Children under 12 free.', 'See current ticket prices at checkout.', 'Sunday admission: Adults $10; Children ages 4–17 free.', 'Buffet: Adults $20; Children ages 4–17 $10.']) {
    const { result } = verified(quote, { candidate: snapshot });
    assert.equal(result.admissionFacts.knownTotalUsd, null, quote);
    assert.equal(result.planning.admission, null, quote);
  }
  const { result } = verified('Adults $10; Children ages 4–17 free.', { candidate: snapshot, text: 'Exploratorium in San Francisco. Member prices: Adults $10; Children ages 4–17 free.' });
  assert.equal(result.admissionFacts.knownTotalUsd, null);
  const adjacent = verified('General admission: Adults $10; Children ages 4–17 free.', { candidate: snapshot, text: 'Exploratorium in San Francisco. General admission: Adults $10; Children ages 4–17 free. This offer is only for members.' });
  assert.equal(adjacent.result.admissionFacts.knownTotalUsd, null);
});

test('a copied search snippet or invented proof never becomes structured admission', () => {
  const source = { url: museum().officialUrl, text: 'Adults $20; Children ages 4–17 $10.', checkedAt: today, verification: 'search-result' };
  assert.equal(admissionRuleFromQuote({ quote: source.text, source }), null);
  assert.equal(admissionRuleFromQuote({ quote: 'Adults $1', source: { ...source, verification: 'page-read' } }), null);
});

test('simple group quotation has a deterministic party cap; amount alone does not', () => {
  const { result } = verified('Family admission $60 for up to 4 people.');
  assert.equal(result.admissionFacts.knownTotalUsd, 60);
  assert.equal(admissionFactsFor(result, { ...state, partySize: 5 }).facts.knownTotalUsd, null);
  assert.equal(verified('Family admission $60.').result.admissionFacts.knownTotalUsd, null);
});

test('follow-up party changes recalculate facts from the same source, without stale totals', () => {
  const attached = withAdmissionFacts(museum(), state, { today });
  const next = withAdmissionFacts(attached, { ...state, partySize: 4, childAges: [3, 5] }, { today });
  assert.equal(next.admissionFacts.knownTotalUsd, 109.85);
  assert.equal(next.admissionFacts.breakdown.find(item => item.age === 3).subtotalUsd, 0);
  assert.equal(next.admissionFacts.partySize, 4);
});

test('source-ID remapping and catalog refresh preserve newer page-read facts', () => {
  const { result, store } = verified('General admission: Adults $45; Children ages 4–17 $30.');
  store.addCandidate(result);
  store.addCandidate(withAdmissionFacts(museum(), state, { today }));
  const candidate = withAdmissionFacts(store.candidates.get(result.id), state, { today });
  assert.equal(candidate.admissionFacts.knownTotalUsd, 120);
  assert.equal(candidate.admissionFacts.basis, 'page-read');
  assert.ok(candidate.admissionFacts.sourceIds.every(id => store.sources.has(id)));
});
