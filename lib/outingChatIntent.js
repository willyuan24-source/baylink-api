const { CITY_ALIASES, normalizeCity } = require('./outingSearch');
const { resolveDraftDate } = require('./outingDraft');
const { loadPlannerCatalog } = require('./planner');
const { issueOutingSearchToken, readOutingSearchToken } = require('./outingSearchToken');

const DAY = 86400000;
const addDays = (date, days) => new Date(Date.parse(`${date}T12:00:00Z`) + days * DAY).toISOString().slice(0, 10);
const bayDay = now => new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const catalog = loadPlannerCatalog();
const knownCities = new Set((catalog ? [...catalog.events, ...catalog.places] : []).flatMap(row => String(row.city || '').split(/\s*\/\s*/))
  .filter(city => city.length <= 80 && /^[\p{L}][\p{L} .'-]*$/u.test(city) && !/\bcounty\b/i.test(city)));
const cityGroups = [...CITY_ALIASES, ...[...knownCities].filter(city => !CITY_ALIASES.some(group => group.some(alias => normalizeCity(alias) === normalizeCity(city)))).map(city => [city])];
const blockedTopic = /租房|租屋|室友|合租|住房|维修|維修|修理|清洁|清潔|保洁|保潔|搬家|接送|接机|接機|送机|送機|翻译|翻譯|招聘|求职|求職|找工作|学区|學區|入学|入學|学校|學校|年级|年級|亲子|親子|带娃|帶娃|孩子|儿童|兒童|宝宝|寶寶|\d+\s*[岁歲]|\b(?:roommates?|rent(?:al|ing)?|housing|repair|cleaning|moving services?|airport|pickup|translation|hiring|jobs?|schools?|enrollment|districts?|kids?|children|child|family|parents?)\b/i;
const directSearch = /(?:找|寻|尋|有|想|需要|看看).{0,16}(?:搭子|搭伴|同行|小队|小隊)|(?:搭子|同行|小队|小隊).{0,10}(?:有吗|有嗎|哪里|哪裡|搜索|搜尋)|(?:有人|有谁|有誰).{0,30}一起|(?:找|寻找|尋找).{0,4}(?:人|朋友|伙伴|夥伴).{0,8}一起|\b(?:find|looking for|join|show|browse|search|any|available)\b.{0,45}\b(?:budd(?:y|ies)|companions?|groups?|meetups?|people to|people for)\b|\b(?:find|looking for)\s+(?:someone|somebody)\s+(?:to\s+)?(?:join|walk|hike|go|meet|practi[cs]e)\b|\banyone\b.{0,35}\b(?:join|together|walk|hike|go|coffee)\b/i;
const excludeSearch = /(?:不|别|別)(?:想|要|用)?(?:找|看|搜)?.{0,4}(?:搭子|小队|小隊|同行)|(?:不想|不要|不用|别|別).{0,4}(?:找|寻找|尋找).{0,4}(?:人|朋友|伙伴|夥伴).{0,8}一起|(?:发起|發起|创建|創建|组织|組織|发布|發布).{0,8}(?:小队|小隊|同行)|\b(?:host|create|organize)\b.{0,20}\b(?:group|outing|meetup)\b|\b(?:don['’]t|do not|not looking to)\s+(?:want to\s+)?(?:find|join|search|browse)\b/i;
const adviceRequest = /(?:搭子|小队|小隊|同行|找人一起).{0,14}(?:更安全|安全吗|安全嗎|注意什么|注意什麼|需要验证|需要驗證|需要认证|需要認證|怎么加入|怎麼加入|如何加入)|(?:如何|怎么|怎麼)(?:加入|申请|申請|退出|举报|舉報).{0,8}(?:小队|小隊|同行)|\b(?:how (?:do I|can I|to) (?:join|apply)|is it safe to join|do I need (?:phone )?verification)\b.{0,30}\b(?:groups?|outings?|meetups?)\b/i;
const newTopic = /换个话题|換個話題|换话题|換話題|(?:帮我|幫我|请|請)(?:解释|解釋|写|寫|总结|總結)|天气|天氣|\b(?:weather|new topic|change (?:the )?subject|explain|write (?:me |a |an )|summari[sz]e)\b/i;
const dateHint = /20\d{2}-\d{2}-\d{2}|\d{1,2}\s*(?:月|\/)\s*\d{1,2}|(?:周|週|星期)[日天一二三四五六末]|今天|明天|后天|後天|日期|改天|另一天|未来|未來|接下来|接下來|\b(?:date|today|tomorrow|weekends?|sun(?:day)?|mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|sat(?:urday)?|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may(?=\s+\d{1,2}(?:st|nd|rd|th)?\b)|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|next\s+(?:7|seven)\s+days)\b/i;
const allCities = /全湾|全灣|湾区都|灣區都|城市不限|不限城市|哪里都|哪裡都|任何城市|\b(?:anywhere|all cities|any city|anywhere in the bay|whole bay area)\b/i;
const allDates = /不限日期|日期不限|哪天都|任何日期|随时|隨時|\b(?:any date|any day|anytime|all dates|no date preference)\b/i;
const allAvailability = /满员也|滿員也|候补也|候補也|不限名额|不限名額|\b(?:include full|include waitlist|any availability)\b/i;
const allTopics = /不限主题|不限主題|任何主题|任何主題|什么活动都|甚麼活動都|\bany (?:topic|activity)\b/i;
const broadLocation = /东湾|東灣|南湾|南灣|北湾|北灣|半岛|半島|附近|\b(?:east bay|south bay|north bay|peninsula|nearby|near me)\b/i;
const practiceWords = /练(?:练|习)?英[语文]|練(?:練|習)?英[語文]|英语练习|英文练习|英語練習|英文練習|英语角|英語角|\b(?:practi[cs](?:e|ing) English|English (?:practice|conversation))\b/gi;
const topicWords = new RegExp(`看展|散步|徒步|咖啡|电影|電影|羽毛球|桌游|桌遊|${practiceWords.source}|\\b(?:hik(?:e|ing)|walk(?:ing)?|coffee|movies?|badminton|board games?|museums?)\\b`, 'gi');
const activityInterest = /想|希望|打算|有[兴興]趣|适合|適合|推荐|推薦|\b(?:want|would like|interested in|hope to|recommend|options for|places to)\b/i;
const copy = locale => locale === 'en' ? {
  city: 'Which city should the group meet in? You can also say “anywhere in the Bay Area.”',
  date: 'Which date works for you? You can also say “this weekend” or “any date.”',
  conflict: 'The date and weekday do not match. Which date did you mean?', range: 'Choose a future date within the next 180 days.',
  ready: 'I have organized your search conditions. The cards will load real BAYLINK outings; joining still needs the host’s approval.',
  unsupported: 'Budget, transport, gender and other personal preferences are not automatic filters here; confirm those in each outing’s details.',
  topics: 'Excluded or multiple activity themes have not been applied as filters. Review the actual outing descriptions before choosing.',
} : locale === 'zh-Hant' ? {
  city: '你希望在哪個城市集合？也可以說「全灣都可以」。', date: '你想參加哪一天？也可以說「本週末」或「不限日期」。',
  conflict: '日期和星期對不上，你想選哪一天？', range: '請選未來 180 天內的一天。',
  ready: '已整理你的查找條件。卡片會讀取 BAYLINK 真實小隊，加入仍需發起人確認。',
  unsupported: '預算、交通、性別與其他個人偏好尚未自動篩選，請在小隊詳情中逐項確認。',
  topics: '排除或多選的活動主題尚未用於篩選，請先查看真實小隊說明再選擇。',
} : {
  city: '你希望在哪个城市集合？也可以说“全湾都可以”。', date: '你想参加哪一天？也可以说“本周末”或“不限日期”。',
  conflict: '日期和星期对不上，你想选哪一天？', range: '请选择未来 180 天内的一天。',
  ready: '已整理你的查找条件。卡片会读取 BAYLINK 真实小队，加入仍需发起人确认。',
  unsupported: '预算、交通、性别与其他个人偏好尚未自动筛选，请在小队详情中逐项确认。',
  topics: '排除或多选的活动主题尚未用于筛选，请先查看真实小队说明再选择。',
};

function citiesIn(text, includeNegated = false) {
  const matches = [];
  for (const aliases of cityGroups) for (const alias of aliases) {
    const pattern = /[a-z]/i.test(alias) ? `(?<![a-z])${escape(alias).replace(/\s+/g, '\\s+')}(?![a-z])` : escape(alias);
    for (const found of text.matchAll(new RegExp(pattern, 'giu'))) matches.push({ city: aliases[0], index: found.index, end: found.index + found[0].length });
  }
  // Keep longest aliases first: South San Francisco must not also become SF.
  const accepted = [];
  for (const hit of matches.sort((a, b) => (b.end - b.index) - (a.end - a.index))) if (!accepted.some(other => hit.index < other.end && hit.end > other.index)) accepted.push(hit);
  return accepted.sort((a, b) => a.index - b.index).filter(hit => {
    const before = text.slice(Math.max(0, hit.index - 35), hit.index), after = text.slice(hit.end, hit.end + 15);
    if (/(?:从|從|住在|家在|出发地[：:]?|出發地[：:]?|\bfrom|\bleaving|\bdeparting|\blive in|\bbased in)\s*$/i.test(before) || /^\s*(?:出发|出發|→|to\b)/i.test(after)) return false;
    return includeNegated || !/(?:不在|不去|不要|不是|\bnot|\binstead of)\s*$/i.test(before);
  });
}

function calendarFor(text, today, locale) {
  if (allDates.test(text)) return { known: true, filters: {} };
  if (/(?:未来|未來|接下来|接下來)(?:的)?\s*(?:7|七)\s*天|\bnext\s+(?:7|seven)\s+days\b/i.test(text)) return { known: true, filters: { dateFrom: today, dateTo: addDays(today, 6) } };
  if (/(?:周|週)末|\bweekend\b/i.test(text)) {
    // Exact dates remain authoritative even when described as a weekend.
    if (/20\d{2}-\d{2}-\d{2}|\d{1,2}\s*(?:月|\/)\s*\d{1,2}|(?:周|週|星期)[日天一二三四五六]|\b(?:saturday|sunday|jan\w*|feb\w*|mar\w*|apr\w*|may|jun\w*|jul\w*|aug\w*|sep\w*|oct\w*|nov\w*|dec\w*)\s+\d/i.test(text)) {
      const resolved = resolveDraftDate(text, today, locale);
      return resolved.date ? { known: true, filters: { date: resolved.date } } : { known: false, question: resolved.question };
    }
    const weekday = new Date(`${today}T12:00:00Z`).getUTCDay();
    const next = /下(?:周|週)|下个|下個|\bnext\b/i.test(text);
    const start = next ? addDays(today, 7 - ((weekday + 6) % 7) + 5) : weekday === 0 ? today : addDays(today, (6 - weekday + 7) % 7);
    return { known: true, filters: { dateFrom: start, dateTo: addDays(start, !next && weekday === 0 ? 0 : 1) } };
  }
  const resolved = resolveDraftDate(text, today, locale);
  if (resolved.date && /本(?:周|週|星期)|这(?:周|週)|這(?:周|週)|\bthis\s+(?:mon|tue|wed|thu|fri|sat|sun)/i.test(text)
    && !/20\d{2}-\d{2}-\d{2}|\d{1,2}\s*(?:月|\/)\s*\d{1,2}/.test(text)) {
    const monday = addDays(today, -((new Date(`${today}T12:00:00Z`).getUTCDay() + 6) % 7));
    if (resolved.date > addDays(monday, 6)) return { known: false, question: copy(locale).date };
  }
  return resolved.date ? { known: true, filters: { date: resolved.date } } : { known: false, question: resolved.question };
}

function languageUpdate(text) {
  if (/语言不限|語言不限|不限语言|不限語言|\bany language\b/i.test(text)) return null;
  const mentions = [...text.matchAll(/中文|英文|\b(?:chinese|english)\b/gi)];
  if (!mentions.length) return undefined;
  const positive = mentions.filter(hit => {
    const before = text.slice(Math.max(0, hit.index - 35), hit.index), after = text.slice(hit.index + hit[0].length, hit.index + hit[0].length + 30);
    return !/(?:不(?:用|要|想|需要|必|限(?:制)?)?|无需|無需|不会|不會|不懂|别|別)(?:只|仅|僅)?(?:限|限定|限制|用|说|說)?\s*$|\b(?:not|no|without|instead of|don['’]t(?:\s+(?:want|need|require|speak))?|do not(?:\s+(?:want|need|require|speak))?)\s*$/i.test(before)
      && !/^\s*(?:(?:is|are)\s+)?(?:not (?:required|necessary|needed)|不需要|不用|不限)/i.test(after);
  });
  const languages = new Set(positive.map(hit => /中文|chinese/i.test(hit[0]) ? 'zh' : 'en'));
  // Removing a language restriction is not an instruction to require the other language.
  return languages.size === 1 ? [...languages][0] : null;
}

/** Only user words create filters. An assistant's proposed city/date is never evidence. */
function outingChatIntent({ message, history = [], locale = 'zh-Hans', now = Date.now(), secret, continuationToken }) {
  const today = bayDay(now), words = copy(locale);
  // Restore only validated structured facts. Replaying the truncated history
  // would otherwise reintroduce superseded cities, dates or exclusions.
  const previous = continuationToken === undefined ? null : readOutingSearchToken(continuationToken, secret, now);
  let active = !!previous, cityKnown = previous?.cityKnown || false, dateKnown = previous?.dateKnown || false, filters = previous?.filters || { sort: 'soonest' },
    dateQuestion = previous?.dateIssue ? words[previous.dateIssue] : undefined, unsupported = previous?.unsupported || false, unsupportedTopics = previous?.unsupportedTopics || false, pendingActivity = null;
  if ((filters.date || filters.dateTo || filters.dateFrom || today) < today) {
    delete filters.date; delete filters.dateFrom; delete filters.dateTo; dateKnown = false; dateQuestion = words.range;
  }
  const reset = () => { active = false; cityKnown = false; dateKnown = false; filters = { sort: 'soonest' }; dateQuestion = undefined; unsupported = false; unsupportedTopics = false; pendingActivity = null; };
  for (const raw of previous ? [message] : [...history.filter(item => item.role === 'user').map(item => item.content), message]) {
    // Inline answer chips may echo a question containing alternatives; only the answer is evidence.
    const text = String(raw).split(/我的回答\s*[：:]|我的回答是\s*[：:]?|my answer\s*:/i).at(-1).trim().normalize('NFKC');
    if (blockedTopic.test(text) || excludeSearch.test(text) || adviceRequest.test(text) || (!directSearch.test(text) && newTopic.test(text))) { reset(); continue; }
    const cities = citiesIn(text), hasDate = dateHint.test(text) || allDates.test(text);
    const hasCity = citiesIn(text, true).length > 0 || allCities.test(text) || broadLocation.test(text) || /城市|集合地|\bcity\b/i.test(text);
    const topicMatches = [...text.matchAll(topicWords)];
    const topics = topicMatches.filter(hit => !/(?:不|不要|不想|不去|别|別)(?:喝|去|参加|參加)?\s*$|\b(?:do not|don['’]t|not|no|avoid)(?:\s+(?:want|like|drink|go|to|have|do|any|some)){0,4}\s*$/i.test(text.slice(Math.max(0, hit.index - 40), hit.index)));
    const topicNames = topics.map(hit => hit[0].replace(practiceWords, 'English practice'));
    // The activity being learned is not a requirement that the whole meetup
    // operate only in that language; bilingual practice groups may fit too.
    const language = languageUpdate(text.replace(practiceWords, ''));
    const followup = hasDate || hasCity || language !== undefined || allAvailability.test(text) || allTopics.test(text)
      || /^(?:改|換|换|只看|不限|那|那么|那麼|actually\b|instead\b|change\b|only\b|any\b)/i.test(text)
      || /有空位|还有名额|還有名額|候补|候補|\b(?:open seats|available places)\b/i.test(text) || topicMatches.length > 0;
    if (directSearch.test(text)) {
      // A normal information question may establish a local activity before
      // the user asks for a platform group. Only user-stated city/topic carry
      // across this boundary; assistant suggestions and inferred dates do not.
      if (!active && pendingActivity && !newTopic.test(text)) {
        Object.assign(filters, pendingActivity); cityKnown = !!pendingActivity.city;
      }
      pendingActivity = null; active = true;
    } else if (!active) {
      reset();
      const unique = [...new Set(cities.map(hit => hit.city))];
      if (activityInterest.test(text) && topics.length === topicMatches.length && new Set(topicNames).size === 1) {
        pendingActivity = { ...(unique.length === 1 ? { city: unique[0] } : {}), q: topicNames[0] };
      }
      continue;
    } else if (!followup) { reset(); continue; }
    if (hasCity) {
      delete filters.city;
      const unique = [...new Map(cities.map(hit => [normalizeCity(hit.city), hit.city])).values()];
      cityKnown = allCities.test(text) || unique.length === 1;
      if (!allCities.test(text) && unique.length === 1) filters.city = unique[0];
    }
    if (hasDate) {
      delete filters.date; delete filters.dateFrom; delete filters.dateTo;
      const resolved = calendarFor(text, today, locale); dateKnown = resolved.known; dateQuestion = resolved.question;
      if (resolved.filters) Object.assign(filters, resolved.filters);
    }
    if (language === null) delete filters.language;
    else if (language !== undefined) filters.language = language;
    if (allAvailability.test(text)) delete filters.seats;
    else if (/只看.{0,5}(?:空位|名额|名額)|还有(?:空位|名额)|還有(?:空位|名額)|\b(?:open seats|available places|only open)\b/i.test(text)) filters.seats = 'open';
    if (allTopics.test(text)) { delete filters.q; unsupportedTopics = false; }
    else if (topics.length < topicMatches.length || new Set(topicNames.map(topic => topic.toLowerCase())).size > 1) { delete filters.q; unsupportedTopics = true; }
    else if (topicNames.length) { filters.q = topicNames[0]; unsupportedTopics = false; }
    if (/预算|預算|免费|免費|不开车|不開車|公共交通|地铁|地鐵|男女|男生|女生|\$|\b(?:budget|free|transit|no car|driv(?:e|ing)|women|men|female|male)\b/i.test(text)) unsupported = true;
  }
  if (!active) return null;
  const missing = [...(!cityKnown ? ['city'] : []), ...(!dateKnown ? ['date'] : [])];
  let question = missing[0] === 'city' ? words.city : missing[0] === 'date' ? dateQuestion || words.date : undefined;
  if (missing[0] === 'date' && !dateQuestion && filters.q === 'English practice') question = locale === 'en'
    ? `Which date should I check for English-practice groups${filters.city ? ` in ${filters.city}` : ''}? For ongoing options, say “any date”; then I can search public BAYLINK outings.`
    : locale === 'zh-Hant' ? `想查${filters.city || ''}哪天的英語練習小隊？若想找常態活動，可說「不限日期」；確認後再查站內公開小隊。`
      : `想查${filters.city || ''}哪天的英语练习小队？若想找常态活动，可说“不限日期”；确认后再查站内公开小队。`;
  const outingSearch = { source: 'site-search', state: missing.length ? 'needs_clarification' : 'ready', filters, missing, ...(question ? { question } : {}) };
  if (secret) outingSearch.continuationToken = issueOutingSearchToken({ filters, cityKnown, dateKnown, unsupported, unsupportedTopics,
    ...(!dateKnown && dateQuestion ? { dateIssue: /对不上|對不上|do not match/i.test(dateQuestion) ? 'conflict' : /180/.test(dateQuestion) ? 'range' : 'date' } : {}) }, secret, now);
  return { ok: true, responseMode: 'outing-search', degraded: false, answer: [missing.length ? question : words.ready, unsupported ? words.unsupported : '', unsupportedTopics ? words.topics : ''].filter(Boolean).join('\n'),
    outingSearch, suggestedGuides: [], suggestedActions: [], interactiveCards: [], matchingPosts: [] };
}

module.exports = { outingChatIntent };
