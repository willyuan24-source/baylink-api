// API-BB-8: the fixes from the API-BB-7 live check (10-17, api bc0ee27) and its independent read. Shipped data with the
// live check's clock; a fixture provider that replays the live answers as the model wrote them; no network.
const test = require('node:test');
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createBayBayAssistant } = require('../lib/baybayAgent');
const { loadPlannerCatalog } = require('../lib/planner');
const { createPublicContext, loadDiscoveryCatalog } = require('../lib/publicContext');
const { resolveTaskState } = require('../lib/baybayState');
const { buildFastEvidence, modelItems } = require('../lib/baybayEvidence');
const { normalizeGuideQuery } = require('../lib/guideLocale');
const { leadConsistency, leadStopOrder, pointRepairs, stopNames } = require('../lib/baybayQuality');
const { createDraftWriter } = require('../lib/baybayProgress');
const { sseFor, sseResponse } = require('./support/anthropic-sse');
const guides = require('../data/guide-catalog.json');
const guidesEn = require('../data/guide-catalog.en.json');

const planner = loadPlannerCatalog();
const discoveries = { ...loadDiscoveryCatalog(), english: loadDiscoveryCatalog(undefined, true) };
const LIVE = '2026-10-17T08:13:00-07:00';

function fixture({ now = LIVE, respond } = {}) {
  const sent = [];
  const message = text => ({ type: 'message', id: 'msg-fixture', model: 'claude-sonnet-5-5', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text }], usage: { input_tokens: 40, output_tokens: 60 } });
  const reply = value => ({ ok: true, status: 200, json: async () => value, clone() { return this; }, text: async () => JSON.stringify(value) });
  const today = new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Los_Angeles' }).format(new Date(now));
  const assistant = createBayBayAssistant({ config: { BAYBAY_AI_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'fixture-anthropic-only', BAYBAY_STATE_SECRET: 'api-bb-8-isolated-secret-0123456789', BAYBAY_DAILY_RUN_LIMIT: '1000' },
    guideCatalog: guides, englishGuideCatalog: guidesEn, catalog: planner, now: () => Date.parse(now), isTest: false, Quota: { findOneAndUpdate: async () => ({ count: 1 }), updateOne: async () => ({}) },
    fetchImpl: async (url, init) => {
      sent.push(init.body);
      const body = JSON.parse(init.body);
      const answer = message(JSON.stringify(respond(JSON.parse(body.messages[0].content[0].text))));
      return body.stream ? sseResponse(sseFor(answer)) : reply(answer);
    } });
  const run = (text, { locale = /[㐀-鿿]/.test(text) ? 'zh-Hans' : 'en', ...extra } = {}) => assistant.run({ message: text, locale, currentPath: locale === 'en' ? '/en' : '/', history: [], searchMode: 'site', webAccess: { allowed: false },
    pageContext: createPublicContext({ guideCatalog: guides }).resolve({ context: { currentPath: locale === 'en' ? '/en' : '/' }, currentPath: locale === 'en' ? '/en' : '/', today, locale }), ...extra });
  const user = () => JSON.parse(JSON.parse(sent[0]).messages[0].content[0].text);
  return { run, user };
}
const refOf = (user, pattern, kind) => (user.evidence || []).find(item => (!kind || item.kind === kind) && pattern.test(item.title))?.ref;
const fast = (message, locale, today = '2026-10-16') => {
  const state = resolveTaskState({ message, today, carry: true, catalog: planner }).state;
  const site = buildFastEvidence({ query: normalizeGuideQuery(message), originalQuery: message, state, guideCatalog: locale === 'en' ? guidesEn : guides, catalog: planner, discoveries, today, locale, audience: true });
  return { state, site, model: modelItems(site.items) };
};

// The L08 answer exactly as the model wrote it on 10-17 (its 698 output characters are this draft: no [[ref]] at all).
const L08 = 'Any farmers markets in the East Bay on Saturday morning?';
const l08Draft = user => {
  const grand = refOf(user, /Grand Lake/), berkeley = refOf(user, /Downtown Berkeley/);
  return { lead: 'Yes, two East Bay farmers markets run on Saturday mornings: Grand Lake in Oakland and Downtown Berkeley.',
    points: [{ text: 'Grand Lake Farmers Market, Splash Pad Park, Oakland: every Saturday 9am-2pm, rain or shine, with 100+ stalls. It takes CalFresh EBT, Market Match and WIC.', cardIds: [grand] },
      { text: 'Downtown Berkeley Saturday Farmers\' Market, Center St & Martin Luther King Jr. Way: every Saturday 10am-2:30pm, with California farms selling direct.', cardIds: [berkeley] }],
    candidateIds: [grand, berkeley], followups: [], coverage: [], gap: 'Confirm today\'s hours and any stall changes on each market\'s official page.' };
};
// The L07 answer as the model wrote it on 10-17: the market point cites nothing; the lead names Ferry Building first.
const L07 = '周六想带爸妈在旧金山玩半天，坐公交，帮我排个行程';
const l07Draft = user => {
  const stops = user.currentPlan?.stops || [];
  const stop = id => stops.find(row => row.id === id);
  return { lead: '周六半天可以逛渡轮大厦、农夫市集，再去唐人街，全程搭公交。',
    points: [{ text: '先到 Ferry Plaza 农夫市集逛约 1 小时，逛市集免费，吃的买的另付；周六有市集，具体摊位以官方为准。', cardIds: [] },
      { text: `再进 Ferry Building 大厅休息、约 1 小时，入场费用未确认，餐饮购物另计；在外会合请约定具体入口。 [[${stop('venue-ferry-building')?.refs[0]}]]`, cardIds: [] },
      { text: `最后去唐人街与 North Beach 约 1 小时，把午饭和小店安排在这里，步行逛街不收费。 [[${stop('chinatown')?.refs[0]}]]`, cardIds: [] },
      { text: `爸妈若是 SF 居民且 65 岁以上，可申请免费 Muni，含缆车，但审批要数周，不含 BART；本周六多半赶不上。 [[${refOf(user, /65\+/)}]]`, cardIds: [] }],
    candidateIds: stops.map(row => row.id), followups: [], coverage: [], gap: '出发地和出发时间还没定，各段公交路线和时间请先用 Transit 或 Muni 官方查询确认。' };
};

describe('API-BB-8 item 1: a point that names a record keeps its source', () => {
  it('live L08 (en): the model cited nothing; both market points get their market as a source', async () => {
    const { run } = fixture({ respond: l08Draft });
    const result = await run(L08, { locale: 'en' });
    assert.equal(result.sources.length, 2, JSON.stringify(result.sources));
    assert.match(result.points[0].text, /WIC\. \[1\]$/);
    assert.match(result.points[1].text, /selling direct\. \[2\]$/);
    assert.deepEqual(result.points.map(point => point.cardIds), [['event:oakland-grand-lake-farmers-market-2026'], ['event:berkeley-downtown-saturday-farmers-market-2026']]);
    assert.equal(result.retrieval.sourceCount, 2);
    assert.ok(result.research.warnings.includes('answer_point_citation_restored'));
    assert.match(result.answer, /\[1\][\s\S]*\[2\]/, 'the legacy answer is numbered too');
  });

  it('zh-Hans and zh-Hant: an uncited market point gets its market as a source, with no space before the marker', async () => {
    for (const [message, locale] of [['东湾周六上午有农夫市集吗？', 'zh-Hans'], ['東灣週六上午有農夫市集嗎？', 'zh-Hant']]) {
      const respond = user => {
        const markets = (user.evidence || []).filter(item => item.kind === 'event' && /市集/.test(item.title)).slice(0, 2);
        return { lead: '有，东湾周六上午有农夫市集。', points: markets.map(item => ({ text: `${item.title.split('：')[0]}，${item.when}。`, cardIds: [item.ref] })), candidateIds: markets.map(item => item.ref), followups: [], coverage: [], gap: '' };
      };
      const { run } = fixture({ respond });
      const result = await run(message, { locale });
      assert.equal(result.sources.length, 2, `${locale}: ${JSON.stringify(result.sources)}`);
      for (const [index, point] of result.points.entries()) assert.match(point.text, new RegExp(`。\\[${index + 1}\\]$`), `${locale}: ${point.text}`);
    }
  });

  it('every repair step keeps the sources: the lead count, the listing window, the 12-hour clock', async () => {
    const respond = user => {
      const grand = refOf(user, /Grand Lake/), berkeley = refOf(user, /Downtown Berkeley/);
      return { lead: 'Yes, two East Bay farmers markets run on Saturday mornings.',
        points: [{ text: `Grand Lake in Oakland runs every Saturday 9:00-14:00 starting Sat, Oct 17 [[${grand}]], rain or shine.`, cardIds: [grand] },
          { text: `Downtown Berkeley runs 10:00-14:30 [[${berkeley}]].`, cardIds: [berkeley] }], candidateIds: [grand, berkeley], followups: [], coverage: [], gap: '' };
    };
    const { run } = fixture({ respond });
    const result = await run(L08, { locale: 'en' });
    for (const warning of ['answer_listing_window_repaired', 'answer_english_clock_repaired', 'answer_lead_scope_repaired']) assert.ok(result.research.warnings.includes(warning), `${warning}: ${result.research.warnings}`);
    assert.ok(!result.research.warnings.includes('answer_point_citation_restored'), 'nothing to restore');
    assert.equal(result.sources.length, 2);
    assert.match(result.points[0].text, /9am–2pm/);
    assert.doesNotMatch(result.points[0].text, /starting/);
    assert.match(result.points[0].text, /\[1\]/);
    assert.match(result.points[1].text, /10am–2:30pm \[2\]/);
  });

  it('live L06 (part of the day): the cited points keep their two sources', async () => {
    const respond = user => {
      const coyote = refOf(user, /Coyote Hills/, 'place'), sucre = refOf(user, /Sucré/);
      return { lead: '周日下午可以先去 Coyote Hills 走湿地短线，再去 Mission Blvd 喝下午茶。', points: [{ text: `Coyote Hills 可看鸟、走湿地短线。 [[${coyote}]]`, cardIds: [coyote] },
        { text: 'Sucré d’Amour Café & Sushi 在 Mission Blvd，有下午茶和寿司。', cardIds: [sucre] }], candidateIds: [coyote, sucre], followups: [], coverage: [], gap: '' };
    };
    const { run } = fixture({ respond });
    const result = await run('周日下午想在 Fremont 带爸妈散散步，有什么好去处？');
    assert.ok(result.taskState.preferences.includes('time-of-day:afternoon'));
    assert.equal(result.sources.length, 2);
    assert.match(result.points[1].text, /寿司。\[2\]$/);
  });

  it('pointRepairs: cardIds refs, a plan stop, nothing citable, already cited', () => {
    const citable = ref => ['e1', 'e2', 's-abc'].includes(ref);
    const draft = { lead: 'x', points: [{ text: 'Grand Lake runs Saturdays.', cardIds: ['e1'] }, { text: '格兰湖周六有市集。', cardIds: ['e2'] }, { text: 'Already [[e2]].', cardIds: ['e1'] },
      { text: 'Nothing to cite.', cardIds: ['e9'] }, { text: '', cardIds: ['e1'] }], gap: '' };
    const en = pointRepairs(draft, { citable, locale: 'en' });
    assert.equal(en.cited, 2);
    assert.deepEqual(en.draft.points.map(point => point.text), ['Grand Lake runs Saturdays. [[e1]]', '格兰湖周六有市集。 [[e2]]', 'Already [[e2]].', 'Nothing to cite.', '']);
    assert.equal(pointRepairs(draft, { citable, locale: 'zh-Hans' }).draft.points[1].text, '格兰湖周六有市集。[[e2]]');
    const stops = [{ title: 'Ferry Plaza 农夫市集：海边逛一圈', refs: ['s-abc'], clock: { kind: 'hours', text: '8:00–14:00' } }, { title: 'Ferry Building · 公共大厅与外部会合点', refs: ['e9'] }];
    const plan = pointRepairs({ lead: 'x', points: [{ text: '先逛 Ferry Plaza 农夫市集约 1 小时。', cardIds: [] }, { text: '再去渡轮大厦。', cardIds: [] }, { text: 'Muni 免费。', cardIds: [] }], gap: '' }, { citable, stops, locale: 'zh-Hans' });
    assert.deepEqual(plan.stopOf, [0, 1, -1]);
    assert.equal(plan.draft.points[0].text, '先逛 Ferry Plaza 农夫市集约 1 小时。开放时段 8:00–14:00。[[s-abc]]');
    assert.equal(plan.draft.points[1].text, '再去渡轮大厦。', 'its only ref is not citable');
    assert.deepEqual(pointRepairs({ lead: 'x', points: [{ text: 'Shop at Ferry Plaza from 8am. [[s-abc]]', cardIds: [] }], gap: '' }, { citable, stops, locale: 'en' }).draft.points[0].text, 'Shop at Ferry Plaza from 8am. [[s-abc]]', 'a point with a time and a citation is left alone');
    assert.equal(pointRepairs({ lead: 'x', points: [{ text: 'Shop at Ferry Plaza [[s-abc]]', cardIds: [] }], gap: '' }, { citable, stops: [{ ...stops[0], clock: { kind: 'hours', text: '8am–2pm' } }], locale: 'en' }).draft.points[0].text,
      'Shop at Ferry Plaza. Open 8am–2pm. [[s-abc]]', 'the clock goes before the trailing citation');
  });
});

describe('API-BB-8 item 2: a catalog count names its scope', () => {
  const points = n => Array.from({ length: n }, (_, index) => ({ text: `点 ${index}`, cardIds: [`e${index + 1}`] }));
  it('live L08: "two East Bay farmers markets" are the ones BAYLINK lists (en end to end)', async () => {
    const { run } = fixture({ respond: l08Draft });
    const result = await run(L08, { locale: 'en' });
    assert.equal(result.lead, 'Yes, two East Bay farmers markets listed on BAYLINK run on Saturday mornings: Grand Lake in Oakland and Downtown Berkeley.');
    assert.ok(result.research.warnings.includes('answer_lead_scope_repaired'));
  });

  it('zh-Hans, zh-Hant and en: a count that says that many exist is attributed; one that refers back, or names its scope, is not', () => {
    const cases = [
      ['东湾周六有两个农夫市集：Grand Lake 和 Berkeley 市中心。', 'zh-Hans', 2, '东湾周六有 BAYLINK 收录的两个农夫市集：Grand Lake 和 Berkeley 市中心。'],
      ['東灣週六有兩個農夫市集：Grand Lake 和 Berkeley 市中心。', 'zh-Hant', 2, '東灣週六有 BAYLINK 收錄的兩個農夫市集：Grand Lake 和 Berkeley 市中心。'],
      ['这周末 San Jose 有三个图书馆活动。', 'zh-Hans', 3, '这周末 San Jose 有 BAYLINK 收录的三个图书馆活动。'],
      ['There are three free museums in San Francisco this Saturday.', 'en', 3, 'There are three free museums listed on BAYLINK in San Francisco this Saturday.'],
      ['这两个市集周六都开。', 'zh-Hans', 2, '这两个市集周六都开。'],
      ['BAYLINK lists two East Bay farmers markets for Saturday.', 'en', 2, 'BAYLINK lists two East Bay farmers markets for Saturday.'],
      ['BAYLINK 收录了两个东湾周六农夫市集。', 'zh-Hans', 2, 'BAYLINK 收录了两个东湾周六农夫市集。'],
      ['Here are three ideas for a rainy Saturday.', 'en', 3, 'Here are three ideas for a rainy Saturday.'],
    ];
    for (const [lead, locale, n, expected] of cases) assert.equal(leadConsistency({ lead, points: points(n) }, { locale }).draft.lead, expected, lead);
    // A count that differs from the points still loses its number, as before.
    assert.equal(leadConsistency({ lead: 'Yes, two East Bay farmers markets run on Saturday mornings.', points: points(3) }, { locale: 'en' }).draft.lead, 'Yes, East Bay farmers markets run on Saturday mornings.');
  });

  it('the streamed lead ends exactly as the attributed lead (zh-Hans, zh-Hant, en)', () => {
    for (const [lead, locale] of [['Yes, two East Bay farmers markets run on Saturday mornings: Grand Lake in Oakland and Downtown Berkeley.', 'en'], ['东湾周六有两个农夫市集：Grand Lake 和 Berkeley 市中心。', 'zh-Hans'], ['東灣週六有兩個農夫市集。', 'zh-Hant']]) {
      const final = leadConsistency({ lead, points: points(2) }, { locale }).draft.lead;
      assert.notEqual(final, lead, lead);
      for (const chunk of [1, 3]) {
        const shown = [];
        const writer = createDraftWriter({ emit: () => {}, locale, batchChars: 1, setTimer: () => null, clearTimer: () => {} });
        for (let index = 0; index < lead.length; index += chunk) { writer.text('lead', undefined, lead.slice(index, index + chunk)); shown.push(writer.sent().lead); }
        writer.done('lead');
        writer.end({ complete: true, points: points(2) });
        assert.equal(writer.sent().lead, final, `${lead} / chunk ${chunk}`);
        for (const text of shown) assert.ok(final.startsWith(text), `"${text}" is not a prefix of "${final}"`);
      }
    }
  });
});

describe('API-BB-8 item 3: hours that matter to the ask', () => {
  it('live L09: on a family ask King Library leads with its children\'s area hours (zh-Hans, zh-Hant, en); a day it opens with the building is unchanged', () => {
    for (const [message, locale, expected] of [
      ['这周末如果下雨，San Jose 有什么室内亲子活动？', 'zh-Hans', '周六 儿童区 10:00 起（全馆 8:00–18:00）；周日 13:00–18:00'],
      ['這週末下雨，San Jose 有什麼室內親子活動？', 'zh-Hant', '週六 兒童區 10:00 起（全館 8:00–18:00）；週日 13:00–18:00'],
      ['It might rain this weekend. Any indoor things to do with kids in San Jose?', 'en', 'Saturday children\'s area from 10am (building 8am–6pm); Sunday 1–6pm'],
    ]) {
      const { state, model } = fast(message, locale);
      assert.equal(state.family, true);
      const king = model.find(item => /King, Jr\. Library/.test(item.title));
      assert.equal(king?.when, expected, `${locale}: ${JSON.stringify(king)}`);
    }
  });

  it('an ask without children keeps the building\'s hours', () => {
    const { state, model } = fast('这周末 San Jose 的图书馆几点开门？', 'zh-Hans');
    assert.notEqual(state.family, true);
    assert.equal(model.find(item => /King, Jr\. Library/.test(item.title))?.when, '周六 8:00–18:00；周日 13:00–18:00');
  });

  it('live L06: Sucré\'s record says it usually opens at noon on Sundays; a Sunday ask gives that (zh-Hans, zh-Hant, en); a Saturday ask does not', () => {
    for (const [message, locale, expected] of [
      ['周日下午想在 Fremont 带爸妈散散步，有什么好去处？', 'zh-Hans', '记录：周日通常中午开门'],
      ['週日下午想在 Fremont 帶爸媽散散步，有什麼好去處？', 'zh-Hant', '記錄：週日通常中午開門'],
      ['Sunday afternoon walk with my parents in Fremont, where should we go?', 'en', 'On record: Sunday, usually opens at noon'],
    ]) {
      const sucre = fast(message, locale, '2026-10-17').model.find(item => /Sucré/.test(item.title));
      assert.equal(sucre?.when, expected, `${locale}: ${JSON.stringify(sucre)}`);
    }
    const saturday = fast('周六下午想在 Fremont 带爸妈散散步，有什么好去处？', 'zh-Hans').model.find(item => /Sucré/.test(item.title));
    assert.ok(saturday, 'still in the evidence');
    assert.equal(saturday.when, undefined);
  });

  it('a range in the record ("周二至周日 16:00–22:00 试营业") is not read as one opening time', () => {
    const parlour = fast('这周日 Oakland 有什么新开的店？', 'zh-Hans').model.find(item => /Game Parlour/.test(item.title));
    assert.ok(parlour, 'in the evidence');
    assert.equal(parlour.when, undefined);
  });
});

describe('API-BB-8 item 4: a place\'s guide card is a city guide, not a how-to guide', () => {
  it('live L06 / L07: the Coyote Hills and Chinatown cards carry guideType leisure, guideCategory city and typeLabel; an event card does not (zh-Hans, zh-Hant, en)', async () => {
    for (const [message, locale, label] of [['周日下午想在 Fremont 带爸妈散散步，有什么好去处？', 'zh-Hans', '城市指南'], ['週日下午想在 Fremont 帶爸媽散散步，有什麼好去處？', 'zh-Hant', '城市指南'], ['Sunday afternoon walk with my parents in Fremont, where should we go?', 'en', 'City guide']]) {
      const quick = [];
      const respond = user => { const coyote = refOf(user, /Coyote Hills/, 'place'); return { lead: 'Coyote Hills.', points: [{ text: `Coyote Hills [[${coyote}]]`, cardIds: [coyote] }], candidateIds: [coyote], followups: [], coverage: [], gap: '' }; };
      const { run } = fixture({ respond });
      const result = await run(message, { locale, onQuickCard: cards => { quick.push(...cards); } });
      const card = result.localMatches.find(row => row.id === 'fremont-coyote-hills-short-walk-guide');
      assert.deepEqual({ kind: card?.kind, guideType: card?.guideType, guideCategory: card?.guideCategory, typeLabel: card?.typeLabel }, { kind: 'guide', guideType: 'leisure', guideCategory: 'city', typeLabel: label }, locale);
      const preview = quick.find(row => row.id === 'fremont-coyote-hills-short-walk-guide');
      if (preview) assert.equal(preview.typeLabel, label, 'the streamed preview card too');
    }
    const { run } = fixture({ respond: l07Draft });
    const result = await run(L07);
    const chinatown = result.localMatches.find(row => row.id === 'sf-chinatown-north-beach-walk-guide');
    assert.equal(chinatown?.typeLabel, '城市指南');
    const market = result.localMatches.find(row => row.kind === 'event');
    assert.equal(market?.guideType, undefined);
    assert.equal(market?.typeLabel, undefined);
  });
});

describe('API-BB-8 item 5: the evidence fits the asked city and the family', () => {
  it('live L09: no San Francisco offer without a city (Randall Museum) and no evening concert (Rush) in the evidence (zh-Hans, zh-Hant, en)', async () => {
    for (const [message, locale] of [['这周末如果下雨，San Jose 有什么室内亲子活动？', 'zh-Hans'], ['這週末下雨，San Jose 有什麼室內親子活動？', 'zh-Hant'], ['It might rain this weekend. Any indoor things to do with kids in San Jose?', 'en']]) {
      const respond = user => { const first = (user.evidence || []).find(item => item.kind === 'place'); return { lead: 'x', points: [{ text: `${first.title} [[${first.ref}]]`, cardIds: [first.ref] }], candidateIds: [], followups: [], coverage: [], gap: '' }; };
      const { run, user } = fixture({ respond });
      const result = await run(message, { locale });
      const titles = [...(user().evidence || []).map(item => item.title), ...result.evidence.map(row => row.title)];
      assert.ok(!titles.some(title => /Randall/.test(title)), `${locale}: Randall`);
      assert.ok(!titles.some(title => /Rush/.test(title)), `${locale}: Rush`);
    }
  });

  it('live L06: the Cable Car Museum offer (no city, 1201 Mason Street) is not evidence for a Fremont walk', () => {
    const { model } = fast('周日下午想在 Fremont 带爸妈散散步，有什么好去处？', 'zh-Hans', '2026-10-17');
    assert.ok(!model.some(item => /Cable Car/.test(item.title)), model.map(item => item.title).join(' | '));
  });

  it('an ask that names the venue still gets the offer', () => {
    assert.ok(fast('旧金山 Randall Museum 周六免费吗？', 'zh-Hans').model.some(item => /Randall/.test(item.title)));
    assert.ok(fast('Is the Cable Car Museum in San Francisco free?', 'en').model.some(item => /Cable Car/i.test(item.title)));
  });

  it('an evening concert stays a candidate for an ask without children, and for a family evening ask', () => {
    const rush = message => (fast(message, 'zh-Hans').site.candidates || []).some(row => /Rush/.test(row.title));
    assert.equal(rush('周六 San Jose 有什么活动？'), true);
    assert.equal(rush('周六晚上带孩子在 San Jose 有什么活动？'), true);
    assert.equal(rush('周六带孩子在 San Jose 有什么活动？'), false);
  });
});

describe('API-BB-8 item 6: a plan\'s lead and points follow its stops', () => {
  it('live L07: the lead names the stops in visiting order; the market point gets its source, clock time and card', async () => {
    const { run, user } = fixture({ respond: l07Draft });
    const result = await run(L07);
    assert.deepEqual(result.assistantPlan.stops.map(stop => stop.entityId), ['ferry-plaza-farmers-market-2026-autumn', 'venue-ferry-building', 'chinatown']);
    assert.equal(user().currentPlan.stops[0].hours, '08:00–14:00', 'the model is given the market\'s hours');
    assert.equal(result.lead, '周六半天可以逛农夫市集、渡轮大厦，再去唐人街，全程搭公交。');
    assert.equal(result.points[0].text, '先到 Ferry Plaza 农夫市集逛约 1 小时，逛市集免费，吃的买的另付；周六有市集，具体摊位以官方为准。开放时段 8:00–14:00。[1]');
    assert.deepEqual(result.points[0].cardIds, ['event:ferry-plaza-farmers-market-2026-autumn']);
    assert.deepEqual(result.points[2].cardIds, ['guide:sf-chinatown-north-beach-walk-guide']);
    assert.deepEqual(result.points[3].cardIds, []);
    assert.equal(result.sources.length, 4);
    assert.match(result.sources[0].url, /ferry-plaza-farmers-market/);
    for (const warning of ['answer_lead_order_repaired', 'answer_point_citation_restored', 'answer_plan_point_time_added']) assert.ok(result.research.warnings.includes(warning), warning);
  });

  it('a lead that compares or swaps stops keeps its own order', async () => {
    const { run } = fixture({ respond: user => ({ ...l07Draft(user), lead: '周六半天先选渡轮大厦还是农夫市集，再去唐人街。' }) });
    const result = await run(L07);
    assert.equal(result.lead, '周六半天先选渡轮大厦还是农夫市集，再去唐人街。');
    assert.ok(!result.research.warnings.includes('answer_lead_order_repaired'));
  });

  it('leadStopOrder: zh-Hant and en leads follow the stop order; a lead in order, naming one stop, or naming a stop twice is unchanged', () => {
    const stops = [{ title: 'Ferry Plaza 农夫市集：海边逛一圈', aliases: ['Ferry Plaza Farmers Market: A Waterfront Stroll', 'Ferry Plaza 農夫市集：海邊逛一圈'] },
      { title: 'Ferry Building · 公共大厅与外部会合点', aliases: ['Ferry Building · 公共大廳與外部會合點'] }, { title: '唐人街与 North Beach', aliases: ['San Francisco Chinatown', 'Chinatown & North Beach'] }];
    assert.equal(leadStopOrder('週六半天可以逛渡輪大廈、農夫市集，再去唐人街。', stops).lead, '週六半天可以逛農夫市集、渡輪大廈，再去唐人街。');
    assert.equal(leadStopOrder('Start at the Ferry Building, then Ferry Plaza Farmers Market and Chinatown.', stops).lead, 'Start at the Ferry Plaza Farmers Market, then Ferry Building and Chinatown.');
    for (const lead of ['先逛农夫市集，再去渡轮大厦和唐人街。', '周六可以去唐人街。', '先去唐人街，再去渡轮大厦，最后回唐人街吃饭。']) assert.deepEqual(leadStopOrder(lead, stops), { lead, repaired: false }, lead);
    assert.ok(stopNames(stops[1]).includes('渡轮大厦'));
    assert.ok(!stopNames(stops[2]).includes('san francisco'), 'a city is not a stop name');
  });
});

test('API-BB-8: the fixture replays reach the model once per ask', async () => {
  const { run } = fixture({ respond: l08Draft });
  const result = await run(L08, { locale: 'en' });
  assert.equal(result.research.modelResponses.length, 1);
});
