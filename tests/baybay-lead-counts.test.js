// API-BB-5 (captain decision, 10-15): one table for the lead count rule (lib/baybayQuality.js leadConsistency and
// leadDraftText while the lead streams). Every lead is checked with a matching and a different number of points:
// the final lead reads as a sentence (no dangling numeral or connector, nothing cut mid-phrase), the streamed lead
// (batchChars 1, chunks of 1 and 2 characters) ends exactly as the final lead, and a lead whose count is not a
// plain count of the options (no count, a range, an approximation, a qualifier, a date, a time, an age, a price, a
// line, people, a duration) is byte-identical. Real leads come from the live checks after API-FIX5 (10-14) and
// API-BB-4B (10-15). No model, no network.
// Run on 3fe0801 (every stated count of 2-6 options removed, matching or not), 11 of the first 117 leads failed and
// at least nine were damaged ("有两场或更多" -> "有或更多", "活动有两场" -> "活动有", "兩個鐘", "坐两站 BART", a Saturday
// and a Sunday count, "There is one free event" -> "There is free event"), so the rule is 74f5b50's again: a count
// goes only when it differs from the points, and only a plain one (lib/baybayQuality.js section (e)).
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDraftWriter } = require('../lib/baybayProgress');
const { leadConsistency } = require('../lib/baybayQuality');

const pointsOf = n => Array.from({ length: n }, (_, index) => ({ text: `第 ${index + 1} 项`, cardIds: [`e${index + 1}`] }));
const localeOf = lead => !/[㐀-鿿]/.test(lead) ? 'en' : /[週兩這費動蘭個場項選擇處種條館們鐘覽東灣]/.test(lead) ? 'zh-Hant' : 'zh-Hans';

// [lead] states no count of the options; [lead, count, stripped] states `count` options and reads `stripped` without it.
const TABLE = {
  'live leads (API-FIX5 10-14, API-BB-4B 10-15)': [
    ['周六在 San Mateo 带孩子，首选 Coyote Point 海滨加科学馆。'],
    ['这周末有粤语、国语的中文活动，周六在旧金山，周日在 Millbrae。'],
    ['一般来说，68岁新拿绿卡的长辈可以提交 Medi-Cal 申请，是否获批由官方审核。'],
    ['No full free museum day falls on Oct 17-18, but two free options are open that weekend.', 2, 'No full free museum day falls on Oct 17-18, but free options are open that weekend.'],
    ['可以用中文考笔试，而且现场笔试需要先预约。'],
    ['周日下午可以去 Irvington 农夫市集逛逛，或走 Coyote Hills 的湿地短线。'],
    ['周六半天可先逛唐人街，再去华埠分馆，全程免费项目。'],
    ['BAYLINK has no East Bay Saturday market listing; the closest Saturday morning markets are in the North Bay.'],
    ['雨天可优先考虑 Berryessa 分馆周六活动，或带孩子去市中心图书馆。'],
    ['第一周先开通水电、存好求助电话，再安排办 SSN 和驾照。'],
    ['这周六东湾可去 Berkeley 或 Oakland Grand Lake 农夫市集，Pleasanton 也有。'],
    ['周六在 San Mateo 带 6 岁和 9 岁孩子，首选 Coyote Point 海滨加科学馆。'],
    ['这周末有粤语故事会和普通话英语会话俱乐部，两场都在10月17至18日。'],
    ['能不能获批要由 Medi-Cal 按收入、资产和身份审核，但可以直接申请。'],
    ['No full free museum day is listed for Oct 17-18, but two free options are open that weekend.', 2, 'No full free museum day is listed for Oct 17-18, but free options are open that weekend.'],
    ['周日下午带爸妈散步，可选 Central Park 湖边步道或 Coyote Hills 湿地短线。'],
    ['周六半天可先逛 Ferry Building，再去唐人街，两站各约一小时。'],
    ["BAYLINK has no East Bay Saturday-morning farmers market listed for Oct 17, so I can't name one."],
    ['雨天可以考虑圣何塞市中心图书馆，以及 Apple Store 的免费亲子课。'],
    ['第一周先办水电开户、手机，再备好社安号、驾照和图书馆卡等后续事项。'],
  ],
  'exact counts': [
    ['周六东湾有两场免费活动，适合孩子。', 2, '周六东湾有免费活动，适合孩子。'],
    ['周六有三项免费活动。', 3, '周六有免费活动。'],
    ['这周末东湾有 3 场适合孩子的活动。', 3, '这周末东湾有适合孩子的活动。'],
    ['有 2 场免费活动适合孩子。', 2, '有免费活动适合孩子。'],
    ['有5个免费活动。', 5, '有免费活动。'],
    ['一家三口可以去这两个地方。', 2, '一家三口可以去这些地方。'],
    ['周六可以去两个地方。', 2, '周六可以去这些地方。'],
    ['两场免费活动都在奥克兰。', 2, '免费活动都在奥克兰。'],
    ['有四个免费的亲子活动。', 4, '有免费的亲子活动。'],
    ['这三场活动都免费。', 3, '这些活动都免费。'],
    ['周六 Oakland 两场活动都免费。', 2, '周六 Oakland 活动都免费。'],
    ['這週末有兩場免費活動。', 2, '這週末有免費活動。'],
    ['有兩個地方可以去。', 2, '有這些地方可以去。'],
    ['這三場活動都免費。', 3, '這些活動都免費。'],
    ['Two free events fit your Saturday.', 2, 'Free events fit your Saturday.'],
    ['There are two free events this weekend.', 2, 'There are free events this weekend.'],
    ['Yes, two free South Bay family events are listed for Sat, Oct 17.', 2, 'Yes, free South Bay family events are listed for Sat, Oct 17.'],
    ['These three places are free on Saturday.', 3, 'These places are free on Saturday.'],
    ['Here are three ideas for a rainy Saturday.', 3, 'Here are ideas for a rainy Saturday.'],
    ['Saturday, Dec 5 has two free events.', 2, 'Saturday, Dec 5 has free events.'],
    ['Four family festivals run this weekend.', 4, 'Family festivals run this weekend.'],
    ['有两个不错的去处。', 2, '有不错的去处。'],
    ['两场中文讲座都在图书馆。', 2, '中文讲座都在图书馆。'],
    ['那两个地方周日都开门。', 2, '那些地方周日都开门。'],
    ['周六 Oakland 有 2 场活动。', 2, '周六 Oakland 有活动。'],
    ['There are two kid-friendly events this weekend.', 2, 'There are kid-friendly events this weekend.'],
    ['No free museum day this weekend. Two free events fit Saturday.', 2, 'No free museum day this weekend. Free events fit Saturday.'],
    ['There are two great free events in Oakland this Saturday.', 2, 'There are great free events in Oakland this Saturday.'],
    ['可以考虑这三个地方。', 3, '可以考虑这些地方。'],
    ['两场适合 5 岁孩子的活动都在周六。', 2, '适合 5 岁孩子的活动都在周六。'],
    ['週六可以去兩個地方。', 2, '週六可以去這些地方。'],
    ['這週末東灣有 3 場適合孩子的活動。', 3, '這週末東灣有適合孩子的活動。'],
    ['那兩家博物館週六都免費。', 2, '那些博物館週六都免費。'],
    ['星期六兩場活動都適合孩子。', 2, '星期六活動都適合孩子。'],
  ],
  'zh-Hant leads that keep their numbers': [
    ['這週兩三場免費活動都在奧克蘭。'], ['有兩到三個地方可以去。'], ['有兩個以上的選擇。'], ['這週末有三個左右的免費活動。'], ['其中兩個地方免費。'], ['只有兩場活動是免費的。'],
    ['週六帶兩個孩子去奧克蘭動物園。'], ['逛兩個小時就夠了。'], ['12月5日這天 Pleasanton 有聖誕遊行。'], ['週六兩場、週日三場免費活動。'], ['週六和週日各有兩場免費活動。'],
  ],
  'weekday prefixes': [
    ['这周两场免费活动都在奥克兰。', 2, '这周免费活动都在奥克兰。'],
    ['本周两个地方都免费，适合下雨天。', 2, '本周这些地方都免费，适合下雨天。'],
    ['這週兩場免費活動都在奧克蘭。', 2, '這週免費活動都在奧克蘭。'],
    ['周六两场免费活动都在奥克兰。', 2, '周六免费活动都在奥克兰。'],
    ['星期六两场活动都适合孩子。', 2, '星期六活动都适合孩子。'],
    ['礼拜六有两场免费活动。', 2, '礼拜六有免费活动。'],
    ['周日三个地方都可以去。', 3, '周日这些地方都可以去。'],
    ['这周六三个地方都可以去，都在 BART 沿线。', 3, '这周六这些地方都可以去，都在 BART 沿线。'],
    ['週日兩個地方都免費。', 2, '週日這些地方都免費。'],
    ['这周末两场活动都免费。', 2, '这周末活动都免费。'],
  ],
  ranges: [
    ['这周末有两三场免费活动。'], ['這週末有兩三場免費活動。'], ['这周两三场免费活动都在奥克兰。'], ['本周两到三个地方都适合带孩子。'], ['推荐两到三个地方。'],
    ['有两个到三个地方可以去。'], ['有两场或三场免费活动。'], ['有2-3个活动适合孩子。'], ['有2－3个活动适合孩子。'], ['有2—3个活动适合孩子。'], ['有3、4个活动适合孩子。'],
    ['奥克兰有三五个好去处。'], ['有两、三个地方可以去。'], ['附近有三四个公园可以去。'], ['有十二三个活动。'], ['周六两三个地方都可以去。'],
    ['There are two or three free events this weekend.'], ['Two to three free events fit your Saturday.'], ['There are 2-3 free events this weekend.'], ['Two or three places are free on Saturday.'],
  ],
  approximations: [
    ['这周末有三个左右的免费活动。'], ['有两个以上的选择。'], ['有三场上下的免费活动。'], ['有十多个免费活动。'], ['有好几个免费活动。'], ['有几个地方可以去。'],
    ['有二十多场活动。'], ['附近有两个及以上的免费活动。'], ['有两场或更多免费活动。'], ['周六有两个多的选择。'],
    ['There are about three free events.'], ['There are a few free events.'], ['There are more than two free events.'], ['There are two or more free events.'], ['There are over three free events this weekend.'],
  ],
  qualifiers: [
    ['其中两个地方免费。'], ['前两个地方都免费。'], ['另外两个地方要门票。'], ['至少两个地方免费。'], ['有大约三场活动适合孩子。'], ['只有两场活动是免费的。'], ['最多三个地方可以去。'],
    ['一共有两场免费活动。'], ['每周两场免费活动。'], ['周六只有一场免费活动。'],
    ['The first two places are free.'], ['There are only two free events.'], ['At least two places are free.'], ['The other two events need tickets.'], ['There is one free event this weekend.'],
  ],
  'numbers that are not counts': [
    ['十二月第一个周末，奥克兰有亲子活动。'], ['12月5日 Pleasanton 有圣诞游行和点灯活动。'], ['周六下午3点前可以逛完这些地方。'], ['适合2岁到5岁孩子的免费活动在图书馆。'],
    ['门票 $20，3 岁以下免费。'], ['坐2号线就能到活动现场。'], ['逛两个小时就够，适合带孩子的活动都在附近。'], ['两个孩子都适合这些免费活动。'], ['一家三口可以去这些地方。'],
    ['十二个活动都在奥克兰。'], ['这周六 10 点有免费活动。'], ['周六两点开始的活动适合孩子。'], ['两个周末都有市集活动。'], ['第 2 站去公园。'], ['第2站是华埠分馆，逛两个半小时。'],
    ['周六带两个孩子去奥克兰动物园。'], ['逛兩個鐘就能看完這些展覽。'], ['坐两站 BART 就到这些免费活动。'],
    ['December 5 is packed with family events in Pleasanton.'], ['Kids aged 3 to 5 love these places.'], ['Kids aged three to five love these places.'],
    ['Tickets are $20 for adults and free for kids under 2.'], ['Spend two hours at the events.'], ['Bring your two-year-old to these free events.'], ['The Line 2 bus stops near these events.'],
    ['The two kids will love these free events.'],
  ],
  'counts that are not one plain count of the options': [
    ['两场都免费。'], ['适合孩子的免费活动有两场'], ['周六可以去的地方有三个'], ['周六有两场免费活动，周日有三场。'], ['Saturday has two free events and Sunday has three.'],
    ['周六有两场比赛，适合带两个孩子去看。'], ['周六两场、周日三场免费活动。'], ['有两场/三场免费活动。'], ['Two free events on Saturday and three on Sunday.'],
    ['周六和周日各有两场免费活动。'], ['两场需要门票，其余都免费。'], ['Two events need tickets; the rest are free.'], ['这两个都免费，适合带孩子。'], ['Two of the events are free.'],
  ],
};

// What a final lead must never read like once a count is taken out of it.
const DANGLING = [
  [/(?<![周週初]|星期|礼拜|禮拜)[两兩二三四五六七八九几幾\d][免活地选選展市节節去处處亲親适適好]/u, 'a numeral that lost its measure word'],
  [/(?:^|[有去到在是])\s*(?:或|及|和|与|與|、|到|至|－|—|-|~|～|以上|以下|左右|上下|多)/u, 'a connector or approximation left without its number'],
  [/(?:有|和|或|及|与|與)\s*[。．.!！?？]?$/u, 'a sentence cut after its verb or connector'],
  [/\b(?:has|have|are|is|and|or|to|of)\s*[.!?]?$/i, 'an English sentence cut after its verb or connector'],
  [/\b(?:is|was)\s+(?!(?:a|an|the|one|this|that|its|their|our|your|no)\b)(?:[a-z-]+\s+){0,3}(?:event|option|place|choice|activity|festival|idea|pick)\b(?!s)/i, 'a singular noun without its article'],
  [/ {2}|^\s|\s[，。、；,.;!?]/u, 'stray spacing'],
];

function stream(lead, locale, chunk, points) {
  const events = [], shown = [];
  const writer = createDraftWriter({ emit: event => events.push(event), locale, batchChars: 1, setTimer: () => null, clearTimer: () => {} });
  for (let index = 0; index < lead.length; index += chunk) { writer.text('lead', undefined, lead.slice(index, index + chunk)); shown.push(writer.sent().lead); }
  writer.done('lead'); shown.push(writer.sent().lead);
  points.forEach((point, index) => { writer.text('point', index, point.text); writer.done('point', index); });
  writer.end({ complete: true, points });
  return { sent: writer.sent().lead, events: events.filter(event => event.field === 'lead').map(event => event.text).join(''), shown };
}

let leads = 0;
for (const [section, rows] of Object.entries(TABLE)) {
  for (const [lead, count, stripped] of rows) {
    leads++;
    const locale = localeOf(lead);
    test(`lead counts / ${section}: ${lead}`, () => {
      for (const n of count ? [count, count + 1] : [2, 3]) {
        const points = pointsOf(n);
        const expected = stripped !== undefined && count !== n ? stripped : lead;
        const final = leadConsistency({ lead, points }, { locale }).draft.lead;
        assert.equal(final, expected, `${lead} / ${n} points`);
        if (final !== lead) for (const [pattern, why] of DANGLING) assert.doesNotMatch(final, pattern, `${why}: ${final}`);
        for (const chunk of [1, 2]) {
          const { sent, events, shown } = stream(lead, locale, chunk, points);
          assert.equal(sent, final, `streamed / ${n} points / chunk ${chunk}`);
          assert.equal(events, final, `draft events / ${n} points / chunk ${chunk}`);
          for (const text of shown) assert.ok(final.startsWith(text), `the draft "${text}" is not a prefix of "${final}"`);
        }
      }
    });
  }
}

test('the lead count table covers at least 60 leads', () => assert.ok(leads >= 60, String(leads)));
