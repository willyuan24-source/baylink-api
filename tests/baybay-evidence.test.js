const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSiteEvidence } = require('../lib/baybayEvidence');
const { validateTaskState } = require('../lib/baybayState');
const TODAY = '2026-10-04';
const event = (id, overrides = {}) => ({ id, title: 'San Jose family museum event', city: 'San Jose', region: 'south-bay', startDate: TODAY, endDate: TODAY, cost: 'free', costLabel: 'Free admission for everyone.', officialUrl: `https://example.org/events/${id}`, summary: 'An all-ages museum event for families.', planning: { admissionUsd: 0, allAges: true }, ...overrides });
const fixture = (events = [], places = []) => ({ version: 1, checkedAt: TODAY, events, places, guides: [] });
const guide = (slug, title, content) => ({ slug, title, content, url: `/guides/${slug}`, updatedAt: TODAY, sources: [{ title: 'Publisher', url: 'https://example.org/info' }] });
const search = (query, rest = {}) => buildSiteEvidence({ query, state: validateTaskState({ city: 'San Jose', date: TODAY }), today: TODAY, ...rest });

test('paragraph retrieval matches a user need across languages and returns the supporting passage', () => {
  const guideCatalog = [
    guide('museum', 'San Jose museum guide', 'The museum has an accessible entrance, wheelchair access, elevators and benches for resting between galleries.\n\nMembership tickets cost more and have a separate benefit schedule.'),
    guide('unrelated', 'San Jose restaurants', 'This restaurant has six different spicy noodle bowls available at lunchtime and dinner.'),
  ];
  const result = search('带老人，不想走太多', { guideCatalog, catalog: fixture() });
  assert.equal(result.guides[0].slug, 'museum'); assert.match(result.guides[0].text, /wheelchair access/);
  assert.equal(result.guides[0].verification, 'site-record'); assert.equal(result.guides[0].verifiedLive, false);
  assert.ok(result.sources.some(source => source.evidenceId === result.guides[0].evidenceId));
});

test('guide references are ranked across the entire source list with direct paragraph links first', () => {
  const article = guide('benefits', 'Bay Area museum benefits', 'San Francisco\n\nde Young visitor benefits depend on the program and ticket category. Check the museum rules at https://example.org/visit before using any pass.');
  const bank = { title: 'Bank of America: Museums on Us eligibility', url: 'https://about.bankofamerica.com/en/making-an-impact/museums-on-us-partners' };
  const other = { title: 'Redwood Books library borrowing eligibility', url: 'https://example.org/library-eligibility' };
  article.sources = [...Array.from({ length: 24 }, (_, i) => ({ title: `Unrelated retailer ${i}`, url: `https://example.org/retailer-${i}` })), bank, other,
    { title: 'Museum visitor rules', url: 'https://example.org/visit/' }, { title: 'Unsafe Bank of America eligibility', url: 'https://user:secret@example.org/private' }];
  const guideCatalog = [article], catalog = fixture();
  const first = search('de Young Bank of America benefits', { guideCatalog, catalog, state: { city: 'San Francisco', goal: 'information' } });
  assert.equal(first.guides[0].sourceUrls[0].url, 'https://example.org/visit');
  assert.equal(first.guides[0].sourceUrls[1].url, bank.url);
  assert.ok(first.guides.every(row => row.sourceUrls.length <= 8 && !('_guideSources' in row)));
  assert.equal(first.guides[0].sourceUrls.filter(source => /example.org\/visit\/?$/.test(source.url)).length, 1);
  assert.ok(first.guides[0].sourceUrls.every(source => !source.url.includes('secret')));
  first.guides[0].sourceUrls[1].title = 'mutated result';
  const second = search('de Young Redwood Books library borrowing eligibility', { guideCatalog, catalog, state: { city: 'San Francisco', goal: 'information' } });
  assert.equal(second.guides[0].sourceUrls[1].url, other.url);
  const again = search('de Young Bank of America eligibility', { guideCatalog, catalog, state: { city: 'San Francisco', goal: 'information' } });
  assert.equal(again.guides[0].sourceUrls[1].title, bank.title);
});

test('a general program reference survives while another city museum facts stay excluded', () => {
  const article = guide('museum-benefits', 'Bay Area museum benefits', 'San Francisco\n\nde Young museum visitors should check the applicable benefit rules and ticket category before choosing a ticket.\n\nMountain View\n\nThe Computer History Museum provides Bank of America cardholder admission subject to its own venue rules.');
  const bank = { title: 'Bank of America benefit program eligibility', url: 'https://about.bankofamerica.com/en/making-an-impact/museums-on-us-partners' };
  article.sources = [{ title: 'Mountain View museum admission rules', url: 'https://computerhistory.org/plan-your-visit/discounts/' }, bank];
  const result = search('de Young Bank of America museum benefit', { guideCatalog: [article], catalog: fixture(), state: { city: 'San Francisco', goal: 'information' } });
  assert.ok(result.guides.length);
  assert.ok(result.guides.every(row => !row.text.includes('Computer History Museum')));
  assert.ok(result.guides.some(row => row.sourceUrls.some(source => source.url === bank.url)));
  assert.ok(result.guides.every(row => row.sourceUrls.every(source => !source.url.includes('computerhistory.org'))));
  assert.ok(result.guides.every(row => row.verification === 'site-record' && row.verifiedLive === false));
  assert.deepEqual(result.candidates, []);
});

test('the actual de Young eligibility question retrieves the official bank reference at source index 111', () => {
  const guideCatalog = require('../data/guide-catalog.json'), catalog = require('../data/planner-catalog.json');
  const freebies = guideCatalog.find(row => row.slug === 'bay-area-freebies-deals-2026-10');
  const bank = freebies.sources.find(source => source.url.includes('bankofamerica.com'));
  assert.ok(freebies.sources.indexOf(bank) > 100);
  const query = '我住Fremont，今天是2026年10月4日。我有一张 Bank of America 借记卡，同行成年朋友没有卡，今天去旧金山 de Young 能两个人都免费吗？这项优惠包括特别展吗？请核实官网，只回答优惠资格和适用日期，不安排路线。';
  const result = search(query, { guideCatalog, catalog, state: { city: 'San Francisco', origin: 'Fremont', date: TODAY, goal: 'information', partySize: 2 } });
  assert.ok(result.guides.some(row => row.sourceUrls.some(source => source.url === bank.url)));
  assert.ok(result.guides.every(row => !row.text.includes('COMPUTER HISTORY MUSEUM') && !row.text.includes('Mountain View，1401')));
  const { createEvidenceStore } = require('../lib/baybayTools');
  const store = createEvidenceStore(result);
  const source = [...store.sources.values()].find(row => row.url === bank.url);
  assert.ok(source?.id); assert.equal(source.verification, 'catalog'); assert.equal(source.text, '');
});

test('city sections in a general utilities article do not leak other cities contact numbers', () => {
  const guideCatalog = [guide('utilities', '湾区各城市水电网办理', 'Oakland\n\nOakland water utilities contact is 510-555-0100. This utility serves the Oakland service area.\n\nSan Jose\n\nSan Jose water utilities contact is 408-555-0100. Confirm the exact service address with the utility.')];
  const result = search('水电开户', { guideCatalog, catalog: fixture() });
  assert.ok(result.guides.length); assert.ok(result.guides.some(row => row.text.includes('408-555-0100')));
  assert.ok(result.guides.every(row => !row.text.includes('510-555-0100')));
});

test('county/city directory layout does not confuse Alameda County with the city of Alameda', () => {
  const guideCatalog = [guide('utilities', '湾区101城水电联络大全', 'Alameda\nNewark\nWater: Alameda County Water District, phone 510-668-4200, serving Fremont, Newark and Union City.\nhttps://acwd.org/start\n\nAlameda\nAlameda\nWater: East Bay Municipal Utility District, phone 866-403-2683. Use the address lookup to confirm service.\nhttps://www.ebmud.com/customers/start-service\n\nAlameda\nLivermore\nWater: Livermore Municipal Water, phone 925-960-4320. Check your address before calling.')];
  const result = search('Alameda 水电网开户', { guideCatalog, catalog: fixture(), state: { city: 'Alameda', goal: 'newcomer' } });
  assert.ok(result.guides.length); assert.ok(result.guides.every(row => !/510-668-4200|925-960-4320/.test(row.text)));
  assert.match(result.guides[0].text, /866-403-2683/);
  assert.equal(result.guides[0].sourceUrls[0].url, 'https://www.ebmud.com/customers/start-service');
});

test('a guide inherits verified catalog location even when its title only names a landmark', () => {
  const guideCatalog = [guide('presidio-picnic', 'Presidio picnic', 'The wheelchair accessible paths and resting benches make this an option for visitors who want limited walking.')];
  const catalog = fixture([], [{ id: 'presidio', title: 'Presidio', city: 'San Francisco', region: 'sf', guideSlug: 'presidio-picnic', officialUrl: 'https://presidio.gov/visit' }]);
  assert.deepEqual(search('少走路，无障碍', { guideCatalog, catalog }).guides, []);
});

test('a precise origin is returned separately from destination candidates without using a city center', () => {
  const origin = { id: 'gate', title: 'Golden Gate Bridge Welcome Center', city: 'San Francisco', region: 'sf', officialUrl: 'https://presidio.gov/visit', location: { precision: 'venue', label: 'Golden Gate Bridge Welcome Center', lat: 37.80779, lng: -122.47484 } };
  const catalog = fixture(Array.from({ length: 8 }, (_, i) => event(`destination-${i}`)), [origin]);
  const result = search('museum', { catalog, state: { goal: 'day-plan', city: 'San Jose', date: TODAY, originCandidateId: 'gate' } });
  assert.equal(result.candidates.length, 6); assert.equal(result.originCandidate.id, 'gate');
  assert.deepEqual(result.originCandidate.location, origin.location); assert.equal(result.originCandidate.kind, 'place');
  assert.ok(result.candidates.every(candidate => candidate.city === 'San Jose'));
  assert.equal(search('museum', { catalog, state: { origin: 'Fremont' } }).originCandidate, undefined);
  assert.equal(search('museum', { catalog: fixture([], [{ ...origin, location: { ...origin.location, precision: 'city' } }]), state: { originCandidateId: 'gate' } }).originCandidate, undefined);
  assert.equal(search('museum', { catalog: fixture([], [{ ...origin, location: { ...origin.location, lat: 0 } }]), state: { originCandidateId: 'gate' } }).originCandidate, undefined);
});

test('the real Tech origin remains available for routing without becoming a duplicate destination stop', () => {
  const catalog = require('../data/planner-catalog.json');
  const tech = catalog.places.find(row => row.id === 'san-jose');
  assert.equal(tech.location.label, 'The Tech Interactive');
  assert.equal(tech.location.precision, 'venue');
  const result = search('San Jose museums family day plan', { catalog, state: { goal: 'day-plan', city: 'San Jose', date: '2026-10-10', origin: 'The Tech Interactive', originCandidateId: tech.id } });
  assert.equal(result.originCandidate.id, tech.id);
  assert.deepEqual(result.originCandidate.location, tech.location);
  assert.ok(result.candidates.length > 0);
  assert.ok(result.candidates.every(row => row.id !== tech.id));
});

test('explicit named real destinations retain requested order ahead of other suggestions', () => {
  const catalog = require('../data/planner-catalog.json');
  const { resolveTaskState } = require('../lib/baybayState');
  const query = '2026-10-10 从 The Tech Interactive 出发，早上9点开车，两位成人，想去 San Jose 的 King Library 和 San José Museum of Art，17点前回出发点，总预算100美元。请安排并核算车程。';
  const { state } = resolveTaskState({ message: query, catalog, today: TODAY });
  const result = search(query, { catalog, state });
  assert.deepEqual(result.candidates.slice(0, 2).map(row => row.id), ['venue-sj-king-library', 'venue-sjma']);
  assert.ok(result.candidates.every(row => row.id !== 'san-jose')); assert.equal(result.originCandidate.id, 'san-jose');
  assert.ok(result.sources.filter(source => source.sourceKind === 'site-catalog').every(source => source.titleOrigin === 'candidate'));
});

test('explicit selections bypass query shorthand only, retaining hard date and eligibility checks', () => {
  const catalog = fixture([event('chosen'), event('future', { startDate: '2026-10-05', endDate: '2026-10-05' }), event('members', { costLabel: 'Free for members; non-members $25.' })]);
  const result = search('SJMA', { catalog, state: { city: 'San Jose', date: TODAY, goal: 'day-plan', freeOnly: true, selectedCandidateIds: ['future', 'members', 'chosen'] } });
  assert.deepEqual(result.candidates.map(row => row.id), ['chosen']);
});

test('explicit city filters never turn similarly named or neighboring cities into local matches', () => {
  const catalog = fixture([event('sj'), event('sf', { city: 'San Francisco', region: 'sf' }), event('ss', { city: 'South San Francisco', region: 'peninsula' }), event('alameda', { city: 'Alameda', region: 'east-bay' })]);
  const result = search('free events', { catalog });
  assert.deepEqual(result.candidates.map(row => row.id), ['sj']);
  assert.deepEqual(search('free events', { catalog, state: { city: 'Berkeley', date: TODAY } }).candidates, []);
});

test('dated records require exact occurrences and exclude cancelled or ambiguous recurring events', () => {
  const catalog = fixture([
    event('correct'), event('next-day', { startDate: '2026-10-05', endDate: '2026-10-05' }),
    event('wrong-occurrence', { startDate: '2026-10-01', endDate: '2026-10-30', occurrenceDates: ['2026-10-05'] }),
    event('unconfirmed-recurrence', { startDate: '2026-10-01', endDate: '2026-10-30', dateLabel: 'Every Friday' }),
    event('cancelled', { cancelled: true }),
  ]);
  assert.deepEqual(search('museum events', { catalog }).candidates.map(row => row.id), ['correct']);
});

test('all free filters reject eligibility-only claims and do not claim unknown admission as zero', () => {
  const catalog = fixture([
    event('everyone'), event('members', { costLabel: 'Free for members; non-members $25.' }),
    event('children', { costLabel: 'Free admission for children under 12; adults $20.' }),
    event('unknown', { cost: 'unknown', costLabel: 'Tickets required, pricing not yet announced', planning: { admissionUsd: null } }),
  ]);
  const result = search('free museum events', { catalog, state: { city: 'San Jose', date: TODAY, freeOnly: true } });
  assert.deepEqual(result.candidates.map(row => row.id), ['everyone']);
  const unknown = search('museum events', { catalog }).candidates.find(row => row.id === 'unknown');
  assert.equal(unknown.planning.admissionUsd, null); assert.equal(unknown.cost, 'unknown');
});

test('known child age restrictions and total admission budget reject impossible options', () => {
  const catalog = fixture([
    event('family'), event('adult-only', { planning: { minAge: 18, admissionUsd: 0 } }),
    event('costly', { cost: 'paid', costLabel: 'General admission $40', planning: { admissionUsd: 40 } }),
  ]);
  const result = search('museum', { catalog, state: { city: 'San Jose', date: TODAY, childAges: [6], partySize: 3, budget: 100, budgetScope: 'total' } });
  assert.deepEqual(result.candidates.map(row => row.id), ['family']);
});

test('selected candidates are preserved and rejected candidates stay out of alternatives', () => {
  const catalog = fixture(Array.from({ length: 12 }, (_, index) => event(`event-${String(index).padStart(2, '0')}`)));
  const result = search('museum', { catalog, state: { city: 'San Jose', date: TODAY, selectedCandidateIds: ['event:event-11'], excludedCandidateIds: ['event:event-00', 'event-01'] } });
  assert.equal(result.candidates.length, 6); assert.equal(result.candidates[0].id, 'event-11');
  assert.ok(result.candidates.every(row => !['event-00', 'event-01'].includes(row.id)));
});

test('site records never masquerade as live official facts; directory links carry an explicit limitation', () => {
  const catalog = fixture([event('directory', { officialUrl: 'https://example.org/events', verifiedAt: '2026-10-01', planning: { admissionUsd: 0, durationMinutes: 60 } })]);
  const result = search('museum', { catalog });
  const row = result.candidates[0]; assert.equal(row.sourceSpecificity, 'directory');
  assert.equal(row.verifiedLive, false); assert.equal(row.verification, 'site-record'); assert.equal(row.recordedAt, '2026-10-01');
  assert.equal(row.catalogDateMatch, true); assert.ok(row.requiresVerification.includes('availability'));
  assert.equal(row.planning.durationMinutes, 60); assert.equal(result.sources[0].verifiedLive, false);
});

test('retrieval output is bounded and stable, unsafe source links are dropped', () => {
  const guideCatalog = Array.from({ length: 10 }, (_, index) => guide(`guide-${index}`, 'San Jose museum guide', Array.from({ length: 5 }, (_, part) => `Museum accessibility paragraph ${part}: wheelchair accessible galleries and convenient entrance help visitors move comfortably. ${index}`).join('\n\n')));
  const catalog = fixture([event('javascript', { officialUrl: 'javascript:alert(1)' }), event('userinfo', { officialUrl: 'https://user:pass@example.org/event' }), event('good')]);
  const a = search('museum accessibility', { guideCatalog, catalog }); const b = search('museum accessibility', { guideCatalog, catalog });
  assert.equal(a.guides.length, 8); assert.ok(a.guides.every(row => row.text.length <= 1730));
  assert.ok(a.guides.filter(row => row.slug === 'guide-0').length <= 3);
  assert.deepEqual(a.guides.map(row => row.evidenceId), b.guides.map(row => row.evidenceId));
  assert.deepEqual(a.candidates.map(row => row.id), ['good']);
});

test('unknown catalog data fails closed without inventing candidates or current conditions', () => {
  assert.deepEqual(search('anything', { catalog: { events: 'invalid' } }).candidates, []);
  const result = search('museum', { catalog: fixture([], [{ id: 'place', title: 'Museum', city: 'San Jose', region: 'south-bay', officialUrl: 'https://example.org/museum', planning: { admissionUsd: null } }]) });
  assert.equal(result.candidates[0].kind, 'place'); assert.equal(result.candidates[0].catalogDateMatch, false);
  assert.ok(result.candidates[0].requiresVerification.includes('opening-hours'));
});

test('a named venue question cannot inject unrelated city festivals into evidence', () => {
  const catalog = fixture([event('sf-festival', { title: 'San Francisco weekly arts festival', city: 'San Francisco', region: 'sf', summary: 'Admission 门票信息请参照售票网站' })]);
  const result = search('SFMOMA 平常週三開館嗎？门票多少？', { catalog, state: { city: 'San Francisco', goal: 'information' } });
  assert.deepEqual(result.candidates, []);
  const generic = search('San Jose water utility account opening', { catalog: fixture([event('festival')]), state: { city: 'San Jose', goal: 'newcomer' } });
  assert.deepEqual(generic.candidates, []);
});

test('warm guide indexing reuses immutable text while applying each query city and exclusions afresh', () => {
  let reads = 0;
  const article = guide('utilities', '湾区水电 utilities', '');
  Object.defineProperty(article, 'content', { get() { reads++; return 'Alameda\nAlameda\nWater utility EBMUD customer contact 866-403-2683 and address service lookup.\n\nAlameda\nNewark\nWater utility ACWD customer contact 510-668-4200 and address service lookup.'; } });
  const guideCatalog = [article], catalog = fixture();
  const first = search('water utility', { guideCatalog, catalog, state: { city: 'Alameda', goal: 'newcomer' } });
  assert.ok(reads > 0); const coldReads = reads;
  assert.ok(first.guides.every(row => !row.text.includes('510-668-4200')));
  // Returned objects must not grant callers mutation access to the cached index.
  first.guides[0].cities.push('San Jose'); first.guides[0].sourceUrls[0].url = 'https://bad.invalid';
  const second = search('water utility account', { guideCatalog, catalog, state: { city: 'Newark', goal: 'newcomer' } });
  assert.equal(reads, coldReads, 'warm queries must not reread/reparse the article');
  assert.ok(second.guides.some(row => row.text.includes('510-668-4200')));
  assert.ok(second.guides.every(row => !row.text.includes('866-403-2683')));
  const back = search('water utility', { guideCatalog, catalog, state: { city: 'Alameda', goal: 'newcomer' } });
  assert.deepEqual(back.guides[0].cities, ['Alameda']); assert.notEqual(back.guides[0].sourceUrls[0].url, 'https://bad.invalid');
  const excluded = search('water utility', { guideCatalog, catalog, state: { excludedCities: ['Alameda'], goal: 'newcomer' } });
  assert.ok(excluded.guides.every(row => !row.text.includes('866-403-2683')));
});

test('warm candidate tokens never cache date, free eligibility or rejection decisions', () => {
  const catalog = fixture([event('today'), event('tomorrow', { startDate: '2026-10-05', endDate: '2026-10-05' }), event('paid', { cost: 'paid', costLabel: 'General admission $30', planning: { admissionUsd: 30 } })]);
  const today = search('museum', { catalog, state: { city: 'San Jose', date: TODAY, goal: 'day-plan' } });
  assert.deepEqual(new Set(today.candidates.map(row => row.id)), new Set(['today', 'paid']));
  const free = search('museum', { catalog, state: { city: 'San Jose', date: TODAY, freeOnly: true, goal: 'day-plan' } });
  assert.deepEqual(free.candidates.map(row => row.id), ['today']);
  const next = search('museum', { catalog, state: { city: 'San Jose', date: '2026-10-05', goal: 'day-plan' } });
  assert.deepEqual(next.candidates.map(row => row.id), ['tomorrow']);
  const removed = search('museum', { catalog, state: { city: 'San Jose', date: TODAY, excludedCandidateIds: ['today'], goal: 'day-plan' } });
  assert.deepEqual(removed.candidates.map(row => row.id), ['paid']);
});

test('replacing an immutable guide or location catalog snapshot creates a fresh index', () => {
  const guideCatalog = [guide('venue', 'Museum guide', 'The museum has wheelchair accessible galleries, elevators and benches for resting.')];
  const sf = fixture([], [{ id: 'venue', title: 'Museum', city: 'San Francisco', region: 'sf', guideSlug: 'venue', officialUrl: 'https://example.org/museum' }]);
  const sj = fixture([], [{ ...sf.places[0], city: 'San Jose', region: 'south-bay' }]);
  assert.deepEqual(search('wheelchair museum', { guideCatalog, catalog: sf }).guides, []);
  assert.ok(search('wheelchair museum', { guideCatalog, catalog: sj }).guides.length);
  const revised = [guide('venue', 'Museum guide', 'Newly revised wheelchair access details provide a different entrance for visitors to these galleries.')];
  assert.match(search('wheelchair museum', { guideCatalog: revised, catalog: sj }).guides[0].text, /Newly revised/);
});
test('the complete multi-library question retains printing, films and separate pass eligibility', () => {
  const { buildSiteEvidence } = require('../lib/baybayEvidence');
  const result = buildSiteEvidence({
    query: '我住 Fremont，只有 Alameda County Library 图书证。想免费打印文件、用 Kanopy 看电影、借博物馆门票。请区分我现在能用的资源、需要另办 SFPL 或 San Mateo County Libraries 卡的资源，以及是否有居住地、年龄或 eCard 限制。给官方入口，不要把整个湾区的资格混在一起。',
    state: { goal: 'information', city: null, origin: 'Fremont' }, guideCatalog: require('../data/guide-catalog.json'), today: '2026-10-04',
  });
  const text = result.guides.map(guide => guide.text).join('\n');
  for (const expected of ['10 页黑白', '每天最多 25 页', 'SFPL 官方 Movies & TV 页面提供 Kanopy 入口', '15 岁', '16 岁', 'eCard', 'SF 居民']) assert.ok(text.includes(expected), expected);
  const sources = result.guides.flatMap(guide => guide.sourceUrls.map(source => source.url));
  for (const url of ['https://aclibrary.org/faq/print-scan-fax/', 'https://smcl.org/printanywhere/', 'https://sfpl.org/research-learn/elibrary/bay-beats-movies-tv', 'https://smcl.org/faq/museum-passes-discover-go/']) assert.ok(sources.includes(url), url);
  assert.ok(result.guides.length <= 8);
  assert.ok(text.includes('每月 30 tickets'));
  assert.ok(text.includes('本次未找到 AC 卡适用的 Kanopy 官方入口'));
});

test('multi-subject comparisons preserve different provider facts without weakening city filters', () => {
  const repeated = Array.from({ length: 7 }, (_, index) => `East Gallery admission\nEast Gallery admission ticket prices apply to regular museum visitors. Ticket admission note ${index}: consult official ticket eligibility conditions.`);
  const wanted = [
    'East Gallery hours\nEast Gallery opening hours are 10 AM to 4 PM; special closures need checking.',
    'East Gallery transit\nEast Gallery public transit visitors use the northern entrance near the bus station.',
    'West Gallery admission\nWest Gallery general admission costs $18; discounts depend on the ticket type.',
    'West Gallery hours\nWest Gallery opens at noon; the last entry is at 4 PM before the 5 PM close.',
    'West Gallery transit\nWest Gallery public transit visitors should confirm the bus service on their selected day.',
  ];
  const content = [...repeated, ...wanted].join('\n\n');
  const result = search('compare East Gallery and West Gallery admission ticket prices, opening hours and public transit', {
    state: { goal: 'information', city: 'San Jose' }, catalog: fixture(),
    guideCatalog: [guide('gallery-comparison', 'San Jose gallery visit reference', content), guide('gallery-repeat', 'San Jose second gallery guide', content), guide('other-city', 'Oakland gallery visit reference', 'West Gallery hours\nOakland-only branch opens at 6 AM. Its Oakland admission policy is unrelated to the San Jose branches.')],
  });
  const text = result.guides.map(item => item.text).join('\n');
  for (const part of wanted) assert.ok(text.includes(part), part);
  assert.doesNotMatch(text, /Oakland-only/);
  assert.ok(result.guides.length <= 8);
  assert.equal(new Set(result.guides.map(item => item.text)).size, result.guides.length);
});
