const MAX_HISTORY_MESSAGES = 8;
const { REGIONS, detectLocation, literalPattern } = require('./postSearch');
const citySearchAliases = require('../data/city-search-aliases.json');
const segmenter = new Intl.Segmenter('zh', { granularity: 'word' });
const normal = value => String(value || '').normalize('NFKC').toLowerCase();
const guideEditionMonth = guide => guide.editionMonth || String(guide.slug || '').match(/(20\d{2}-(?:0[1-9]|1[0-2]))(?:$|-)/)?.[1] || '';
const CAMPUS_VISIT_PATTERN = /散步|看展|半日游|半日遊|一日游|一日遊|游览|遊覽|参观|參觀|步行|逛|周末|\b(?:weekend|outing|stroll|walk(?:ing)?|exhibits?|exhibitions?|tours?|visits?|visiting)\b/i;
function isSchoolRequest(message) {
  const text = String(message || '');
  // A school can be a workplace or service destination, not the subject of enrollment.
  if (/招聘|招工|招老师|招老師|求职|求職|找工作|维修|維修|修理|保洁|保潔|清洁服务|清潔服務|接送服务|接送服務|\b(?:hiring|recruiting|jobs?|repair|maintenance|cleaning)\b/i.test(text)) return false;
  // Admission to a visitor venue is not school admission. Keep explicit
  // educational applications/enrollment authoritative in mixed questions.
  // Retrieval aliases may already have translated "museum" without translating
  // "admission". Normalize venue nouns locally so both input paths agree.
  const venueText = text.replace(/博物馆|博物館/g, ' museum ').replace(/动物园|動物園/g, ' zoo ').replace(/水族馆|水族館/g, ' aquarium ');
  const educationApplication = /学区|學區|入学|入學|招生|申请大学|申請大學|\b(?:enroll?(?:ment|ing)?|enrolment|kindergarten|school districts?)\b|\b(?:school|college|university)\s+(?:admissions?|applications?)\b|\badmissions?\s+(?:to|for|at)\s+(?:(?:a|the)\s+)?(?:school|college|university)\b(?!\s+(?:museum|gallery))|\b(?:school|college|university)\s+application\b/i.test(venueText);
  const venueAdmission = /\b(?:museum|zoo|aquarium|theme park|amusement park|venue|concert|festival|gallery)(?:['’]s)?\s+(?:(?:general|adult|child|family|free|discounted)\s+)?(?:admissions?|entry|tickets?)\b|\b(?:admissions?|entry|tickets?)(?:\s+(?:fees?|prices?|costs?))?\s+(?:to|at|for)\s+[^.!?\n]{0,60}\b(?:museum|zoo|aquarium|theme park|amusement park|venue|concert|festival|gallery)\b/i.test(venueText);
  if (venueAdmission && !educationApplication) return false;
  if (/学区|學區|入学|入學|上学|上學|转学|轉學|转校|轉校|择校|擇校|看校|年级|年級|招生|\b(?:enroll(?:ment|ing)?|admissions?|school districts?|kindergarten|k[–-]?12|sfusd|ousd|busd|fusd|mdusd|srvusd)\b/i.test(text)) return true;
  if (/(?:学校|學校|大学|大學|学院|學院).{0,8}(?:申请|申請|报名|報名)|(?:申请|申請|报读|報讀).{0,12}(?:学校|學校|大学|大學|学院|學院)|\b(?:school|college|university) applications?\b|\bapply(?:ing)? to (?:a |the )?(?:school|college|university)\b/i.test(text)) return true;
  // Campus sightseeing must remain eligible for existing attraction and art-walk guides.
  if (CAMPUS_VISIT_PATTERN.test(text)) return false;
  return /学校|學校|校区|校區|大学|大學|学院|學院|幼儿园|幼兒園|幼稚園|\b(?:schools?|campus|colleges?|universit(?:y|ies))\b/i.test(text);
}
const isSchoolGuide = guide => guide.category === 'education' || (guide.categories || []).includes('education') ||
  /学校与学区|學校與學區|schools?\s*&\s*districts?/i.test((guide.keywords || []).join(' ')) ||
  /(?:^|-)school-(?:district|enrollment)(?:-|$)/.test(guide.slug || '');

function conversationTopic(message) {
  if (isSchoolRequest(message)) return 'school';
  const topics = [
    ['library', /图书馆|library/i], ['museum', /博物馆|museum/i],
    ['translation', /翻译|口译|translation/i], ['work', /兼职|招聘|求职|找工作|hiring|job/i],
    ['roommate', /室友|合租|roommate/i], ['repair', /维修|修理|水管|电工|repair/i],
    ['moving', /搬家|搬运|moving/i], ['cleaning', /清洁|打扫|保洁|cleaning/i],
    ['ride', /接送|接机|送机|机场|airport|pickup/i], ['used', /二手|闲置|卖东西|出售|secondhand/i],
    ['rent', /租房|租屋|出租|月租|房源|找房|求租|押金|租约|studio|housing|apartment/i],
    ['leisure', /周末|亲子|带娃|手工|优惠|福利|免费|领取|散步|看展|半日游|一日游|游览|参观|步行|weekend|freebie|\b(?:outing|stroll|walk(?:ing)?|exhibits?|exhibitions?|tours?|visits?|visiting)\b/i],
    ['newcomer', /刚来|第一个月|落地|新移民/i],
  ];
  return topics.find(([, expression]) => expression.test(message))?.[0] || '';
}

function followsPreviousRequest(message, previous) {
  if (!previous) return false;
  const topic = conversationTopic(message);
  const previousTopic = conversationTopic(previous);
  if (topic && previousTopic && topic !== previousTopic) return false;
  // A complete first-person request can change buyer/seller direction even within the same topic.
  if (topic && /我(?:们)?(?:想|要|需要|打算)?(?:在.{0,20})?(?:找|租|买|雇|提供|承接|出租|出售)/.test(message)) return false;
  const location = detectLocation(message);
  if (location && !location.ambiguous) {
    const remainder = location.aliases.reduce((text, alias) => text.replace(new RegExp(literalPattern(alias), 'gi'), ''), message);
    if (/^[\s呢吗?？!！。]*$/.test(remainder)) return true;
  }
  return /^(?:那(?:么)?|如果|这样|这些|这个|那个|它们|它|再|还有|好[，,的吧]|嗯|预算|月预算|月租|价格|时间|地点|我从|我在|不(?:想)?开车|不开车|孩子|带.{0,5}岁)|(?:的话呢|怎么写帖|怎么联系|需要预约|哪些不需要消费|哪些需要会员)|^(?:帮我|请)(?:把|列出|整理|按|继续)|^哪些(?:信息|内容|条件|不需要|需要)/i.test(message.trim());
}

function resolveConversationRequest(message, history = []) {
  let previous = '';
  const merge = (current, prior) => {
    if (!followsPreviousRequest(current, prior)) return current;
    let inherited = prior;
    if (detectLocation(current)) {
      const aliases = [...new Set(REGIONS.flatMap(region => region.aliases))].sort((a, b) => b.length - a.length);
      for (const alias of aliases) inherited = inherited.replace(new RegExp(literalPattern(alias), 'gi'), ' ');
    }
    if (/预算|月租|每月|\$|\d.*(?:以内|以下)/i.test(current)) {
      inherited = inherited.replace(/(?:月租|每月|月预算|预算)\s*(?:不超过|最多|上限|低于|少于)?\s*(?:\$|USD)?\s*\d[\d,.]*\s*(?:美元|美金|USD)?\s*(?:以内|以下|之内|封顶)?/gi, ' ')
        .replace(/\$\s*\d[\d,.]*\s*(?:\/月|per month|monthly)?\s*(?:以内|以下)?/gi, ' ');
    }
    return `${inherited.trim()}\n${current}`.slice(-2500);
  };
  for (const item of history) if (item.role === 'user') previous = merge(item.content, previous);
  return message.trim() ? merge(message, previous) : previous;
}

function normalizeGuideHistory(value) {
  if (value === undefined) return { ok: true, history: [] };
  if (!Array.isArray(value) || value.length > MAX_HISTORY_MESSAGES || value.length % 2 !== 0) {
    return { ok: false, error: '对话上下文最多保留最近 4 轮完整问答，请开启新对话后重试' };
  }
  const history = [];
  for (let index = 0; index < value.length; index++) {
    const item = value[index];
    const expectedRole = index % 2 === 0 ? 'user' : 'assistant';
    const limit = expectedRole === 'user' ? 500 : 1200;
    if (!item || item.role !== expectedRole || typeof item.content !== 'string' || !item.content.trim() || item.content.trim().length > limit) {
      return { ok: false, error: '对话上下文格式无效，请开启新对话后重试' };
    }
    history.push({ role: expectedRole, content: item.content.trim() });
  }
  return { ok: true, history };
}

function guideTerms(message) {
  const text = normal(message);
  const schoolRequest = isSchoolRequest(text);
  const ignored = new Set(['湾区', '我想', '想要', '帮我', '请问', '一下', '什么', '哪些', '根据', '站内', '攻略', '指南', '可以', '需要', '一个', '一些', '最新', '提醒', '方向', '比较', '几个', '先看', '区分', '不要', '内容', '问题', '补充', '给我']);
  for (const word of ['the', 'and', 'for', 'with', 'from', 'into', 'about', 'this', 'that', 'these', 'those', 'what', 'which', 'where', 'when', 'how', 'why', 'who', 'can', 'could', 'would', 'should', 'will', 'do', 'does', 'did', 'is', 'are', 'am', 'be', 'to', 'of', 'in', 'on', 'at', 'an', 'it', 'my', 'our', 'your', 'you', 'we', 'me', 'us', 'please', 'help', 'want', 'need', 'find', 'show', 'some', 'any', 'get', 'try', 'start']) ignored.add(word);
  const terms = [...segmenter.segment(text)].filter(part => part.isWordLike).map(part => part.segment).filter(term => term.length >= 2 && !ignored.has(term));
  if (/斯坦福|史丹佛/.test(text)) terms.push('stanford');
  if (schoolRequest) terms.push('学校与学区', '学区', '入学');
  if (!schoolRequest && /周末|去哪里|去处|玩一天|路线|weekend/.test(text)) terms.push('周末', '路线', '半天');
  if (!schoolRequest && /亲子|带娃|儿童|孩子|手工/.test(text)) terms.push('亲子', '儿童', '免费', '手工');
  if (!schoolRequest && /省钱|优惠|福利|freebie|领取/.test(text)) terms.push('优惠', '免费', '福利');
  if (/刚来|第一个月|新移民/.test(text)) terms.push('刚来', '第一个月', '落地');
  return [...new Set(terms)].slice(0, 35);
}

function guideDestination(message) {
  // An origin or an open Bay-wide request must not become a destination filter.
  if (/全湾区|全灣區|整个湾区|整個灣區|湾区.{0,12}(?:都可以|不限|任何)|\banywhere in (?:the )?bay area\b/i.test(message)) return null;
  let destination = message;
  const aliases = [...new Set(REGIONS.flatMap(region => region.aliases))].sort((a, b) => b.length - a.length);
  for (const alias of aliases) {
    const place = literalPattern(alias);
    destination = destination.replace(new RegExp(`(?:从|從|\\bfrom\\s+)${place}(?:\\s*(?:出发|出發))?|${place}\\s*(?:出发|出發)`, 'gi'), ' ');
  }
  const location = detectLocation(destination);
  if (!location || location.ambiguous) return null;
  const region = REGIONS.find(item => item.name === location.label || item.aliases.includes(location.label));
  if (!region) return null;
  const places = /^(?:旧金山|San Francisco|SF)$/i.test(location.label) ? ['旧金山', 'San Francisco', 'SF'] : location.aliases;
  return { region, places };
}

function selectConversationGuides(catalog, message, category, currentPath = '/', history = [], today = '') {
  const terms = guideTerms(message);
  const previous = resolveConversationRequest('', history);
  const priorTerms = followsPreviousRequest(message, previous) ? guideTerms(resolveConversationRequest(message, history)) : [];
  const article = catalog.find(guide => guide.url === currentPath);
  const effectiveRequest = resolveConversationRequest(message, history);
  const effectiveTopic = conversationTopic(effectiveRequest);
  const destination = effectiveTopic === 'school' ? null : guideDestination(effectiveRequest);
  const locationTerms = new Set(destination ? guideTerms(destination.places.join(' ')) : []);
  const subjectTerms = destination ? guideTerms(effectiveRequest).filter(term => !locationTerms.has(term)) : [];
  const schoolLocation = effectiveTopic === 'school' ? detectLocation(resolveConversationRequest(message, history)) : null;
  // Keep city/region phrases intact: segmentation can split 东湾 or San Mateo into misleading fragments.
  const schoolPlaceTerms = !schoolLocation || schoolLocation.ambiguous ? [] : schoolLocation.label === 'San Francisco'
    ? ['旧金山', 'San Francisco', 'SF']
    : schoolLocation.label === '中半岛' ? ['中半岛', '半岛', 'Peninsula'] : [schoolLocation.label];
  const articleTopic = article ? conversationTopic(`${article.title} ${article.summary || ''}`) : '';
  const explicitArticle = /这篇|本文|这份|当前(?:文章|攻略)|正在读|\b(?:this|current) (?:article|guide)\b/i.test(message);
  const referenceArticle = !!article && (explicitArticle ||
    !effectiveTopic || (!!articleTopic && articleTopic === effectiveTopic));
  const currentMonth = today.slice(0, 7);
  const ranked = catalog.filter(guide => {
    // A child's enrollment question must not be expanded into family freebies or rentals.
    if (effectiveTopic === 'school' && !isSchoolGuide(guide)) return false;
    if (destination && !(explicitArticle && guide.url === currentPath)) {
      // Published title/keywords describe scope; a passing mention in the body does not.
      const scope = `${guide.title} ${(guide.keywords || []).join(' ')}`;
      const regions = REGIONS.filter(region => region.aliases.some(alias => new RegExp(literalPattern(alias), 'i').test(scope)));
      const bayWide = /湾区|灣區|\bbay area\b/i.test(guide.title) || /^bay-area-/.test(guide.slug || '');
      if (!bayWide && regions.length && !regions.includes(destination.region)) return false;
    }
    const editionMonth = guideEditionMonth(guide);
    // An explicitly opened archived article stays readable; general discovery excludes old editions.
    return !currentMonth || !editionMonth || editionMonth >= currentMonth || (referenceArticle && guide.url === currentPath);
  }).map(guide => {
    const title = normal(guide.title);
    const summary = normal(guide.summary);
    const keywords = normal((guide.keywords || []).join(' '));
    // Rank all published text so offers appended to a long edition stay reachable.
    // The separate source-excerpt limit still bounds what is sent to the provider.
    const content = normal(guide.content);
    const sectionTitles = content.split(/\n\s*\n/).filter(block => block.includes('\n'))
      .map(block => block.split('\n')[0].trim()).filter(heading => heading.length <= 180).join('\n');
    const scoreTerms = words => words.reduce((score, term) => score + (title.includes(term) ? 9 : keywords.includes(term) ? 5 : sectionTitles.includes(term) ? 5 : summary.includes(term) ? 4 : content.includes(term) ? 1 : 0), 0);
    // Geography alone cannot turn an unrelated local article into an answer to a specific topic.
    if (subjectTerms.length && !scoreTerms(subjectTerms) && !(explicitArticle && guide.url === currentPath)) return { guide, score: 0 };
    let score = scoreTerms(terms);
    if (destination?.places.some(place => new RegExp(literalPattern(place), 'i').test(`${guide.title} ${(guide.keywords || []).join(' ')}`))) score += 14;
    if (schoolPlaceTerms.some(place => new RegExp(literalPattern(place), 'i').test(`${guide.title} ${(guide.keywords || []).join(' ')}`))) score += 30;
    else if (schoolPlaceTerms.some(place => new RegExp(literalPattern(place), 'i').test(`${guide.summary || ''} ${guide.content || ''}`))) score += 25;
    // Previous user context assists short follow-ups without crowding out a new explicit subject.
    if (priorTerms.length) score += scoreTerms(priorTerms) * 0.55;
    if (category !== 'other' && (guide.categories || []).includes(category)) score += 4;
    if (currentMonth && (guide.slug || '').includes(currentMonth) && score > 0) score += 3;
    if (referenceArticle && guide.url === currentPath && currentPath.startsWith('/guides/')) score += 1000;
    return { guide, score };
  }).filter(item => item.score > 0).sort((a, b) => b.score - a.score || String(b.guide.updatedAt || '').localeCompare(String(a.guide.updatedAt || '')));
  const strongest = ranked.find(item => item.guide.url !== currentPath)?.score || 0;
  return ranked.filter(item => (referenceArticle && item.guide.url === currentPath) || item.score >= Math.max(4, strongest * 0.4)).slice(0, 3).map(item => item.guide);
}

function groundedGuideFallback(selected, today = '') {
  if (!selected.length) return undefined;
  const summaries = selected.slice(0, 3).map((guide, index) => {
    const edition = guideEditionMonth(guide);
    const archived = edition && today && edition < today.slice(0, 7) ? `（${edition} 归档，不能视为当前可参加或领取）` : '';
    return `${index + 1}. ${guide.title}${archived}：${String(guide.summary || '打开攻略查看已整理的步骤与官方来源。').slice(0, 220)}`;
  });
  const verification = selected.some(isSchoolGuide)
    ? '城市不等于学区，请自行在官方地址查询工具核对各年级学区；申请学年、材料、分配与参观安排请向官方确认。不要在对话中提交孩子姓名、出生日期、证件或完整住址；这些摘要不代表实时查询结果。'
    : '活动日期、免费领取门槛、名额和价格请按文中的官方来源确认；这些摘要不代表实时查询结果。';
  return `暂时无法生成个性化方案，先给你这些已发布攻略的摘要：\n\n${summaries.join('\n\n')}\n\n下方可打开原文。${verification}`.slice(0, 1200);
}

function platformSourceExcerpt(content, message) {
  const paragraphs = content.split(/\n\s*\n/);
  const records = new Map();
  for (const [index, text] of paragraphs.entries()) {
    const match = text.match(/^Platform: ([^\r\n|]+) \| ([a-z0-9]+(?:[-_][a-z0-9]+)*)\r?\n/i);
    if (match) records.set(index, { name: match[1].trim(), id: normal(match[2]) });
  }
  if (!records.size) return null;

  const platformAliases = {
    uber: ['优步', '優步'],
    'uber-eats': ['UberEats', 'Uber 外卖', 'Uber 外賣', '优食', '優食'],
    hungrypanda: ['Hungry Panda', 'Hungry Panada', 'HungryPanada', '熊猫外卖', '熊貓外賣'],
    fantuan: ['Fantuan Delivery', '饭团', '飯團', '饭团外卖', '飯團外賣'],
    dealmoon: ['北美省钱快报', '北美省錢快報', '省钱快报', '省錢快報'],
    doordash: ['Door Dash'],
    grubhub: ['Grub Hub'],
    'too-good-to-go': ['TooGoodToGo'],
    opentable: ['Open Table'],
    nextdoor: ['Next Door'],
    'facebook-marketplace': ['Facebook Marketplace', 'FB Marketplace', '脸书市集', '臉書市集'],
    'buy-nothing': ['BuyNothing'],
    slickdeals: ['Slick Deals'],
    gasbuddy: ['Gas Buddy'],
    dothebay: ['Do The Bay'],
    'google-maps': ['Google Maps', '谷歌地图', '谷歌地圖'],
    'apple-maps': ['Apple Maps', '苹果地图', '蘋果地圖'],
    'transit-app': ['Transit App'],
    'bart-official': ['BART', 'BART App'],
    '511-sf-bay': ['511'],
    'bay-wheels': ['Bay Wheels', 'Lyft Bike', 'Lyft Bikes'],
    'watch-duty': ['WatchDuty'],
    'sf-standard': ['San Francisco Standard', 'SF Standard'],
  };
  const aliases = [...records.values()].flatMap(({ name, id }) =>
    [name, id, id.replace(/[-_]+/g, ' '), ...(platformAliases[id] || [])].map(alias => ({ id, alias })))
    .sort((a, b) => b.alias.length - a.alias.length);
  const requested = new Set();
  let remaining = normal(message);
  // Consume long names first: Uber Eats alone must not also select Uber.
  // Bound Latin/digit edges while allowing Chinese next to a brand name.
  for (const { id, alias } of aliases) {
    const value = normal(alias);
    const literal = literalPattern(value).replace(/^\\b/, '').replace(/\\b$/, '');
    const pattern = `${/^[a-z0-9_]/.test(value) ? '(?<![a-z0-9_])' : ''}${literal}${/[a-z0-9_]$/.test(value) ? '(?![a-z0-9_])' : ''}`;
    remaining = remaining.replace(new RegExp(pattern, 'gi'), () => { requested.add(id); return ' '; });
  }
  if (content.length <= 9000 && !requested.size) return content;

  const terms = guideTerms(message);
  const firstRecord = records.keys().next().value;
  // Never seed the excerpt with the beginning of an unrelated platform record.
  const introduction = paragraphs.slice(0, firstRecord).join('\n\n').slice(0, 1000);
  const prefix = `${introduction}\n[以下为相关段落摘录，未包含的条件请查原文]\n`;
  const ranked = paragraphs.map((text, index) => ({ text, index,
    score: terms.filter(term => normal(text).includes(term)).length +
      (requested.has(records.get(index)?.id) ? 100 : 0),
  })).filter(item => item.index >= firstRecord &&
    (!requested.size || !records.has(item.index) || requested.has(records.get(item.index).id)))
    .filter(item => item.score > 0).sort((a, b) => b.score - a.score || a.index - b.index);
  const selected = [];
  let length = prefix.length;
  for (const item of ranked) {
    const addition = item.text.length + (selected.length ? 2 : 0);
    // Sources and limitations stay attached, even when a record cannot fit.
    if (length + addition > 9000) continue;
    selected.push(item); length += addition;
  }
  return prefix + selected.sort((a, b) => a.index - b.index).map(item => item.text).join('\n\n');
}

function guideSourceExcerpt(guide, message) {
  const content = String(guide.content || '');
  const platformExcerpt = platformSourceExcerpt(content, message);
  if (platformExcerpt !== null) return platformExcerpt;
  if (content.length <= 9000) return content;
  const terms = guideTerms(message);
  // Exported offer blocks keep title, date, conditions and source together between blank lines.
  const blocks = content.split(/\n\s*\n/);
  const paragraphs = blocks.length > 1 ? blocks : content.split(/\n+/);
  // Directory records have explicit city metadata. Only that line identifies
  // a record; nearby attractions, providers and boundary notes may name other cities.
  const cityParagraphs = new Map();
  for (const [index, text] of paragraphs.entries()) {
    const match = text.match(/^(?:San Francisco|San Mateo|Santa Clara|Alameda|Contra Costa|Marin|Napa|Sonoma|Solano)(?: County)?\r?\n([^\r\n]+)\r?\n/);
    if (match && /^(?:Water|Electricity|Waste):/m.test(text)) cityParagraphs.set(index, match[1].trim());
    const profile = text.match(/^City guide: ([^\r\n|]+) \| (?:San Francisco|San Mateo|Santa Clara|Alameda|Contra Costa|Marin|Napa|Sonoma|Solano)\r?\n/);
    if (profile) cityParagraphs.set(index, profile[1].trim());
  }
  const cityAliases = {
    ...citySearchAliases,
    'San Francisco': ['SF', '旧金山', '舊金山', '三藩市'],
    'South San Francisco': ['SSF', '南旧金山', '南舊金山', '南三藩市'],
    'Palo Alto': ['帕洛阿尔托', '帕洛阿爾托', '帕罗奥图', '帕羅奧圖'],
    'East Palo Alto': ['East PA', 'EPA', '东帕洛阿尔托', '東帕洛阿爾托', '东帕罗奥图', '東帕羅奧圖'],
  };
  const cities = [...new Set(cityParagraphs.values())];
  const aliases = cities.flatMap(city => [city, ...(cityAliases[city] || [])].map(alias => ({ city, alias })))
    .sort((a, b) => b.alias.length - a.alias.length);
  const requestedCities = new Set();
  let remaining = normal(message);
  // Consume the longest names first so East Palo Alto does not also select Palo
  // Alto, while an explicit comparison naming both cities still selects both.
  for (const { city, alias } of aliases) {
    const pattern = new RegExp(`${literalPattern(normal(alias))}(?!\\s*(?:county\\b|县|縣))`, 'gi');
    remaining = remaining.replace(pattern, () => { requestedCities.add(city); return ' '; });
  }
  // Shopping exports identify the venue on the first line, followed by
  // city | region | kind. Cities and nearby venues mentioned in the body are
  // context, not aliases for this venue.
  const shoppingParagraphs = new Map();
  for (const [index, text] of paragraphs.entries()) {
    const match = text.match(/^([^\r\n]+)\r?\n[^\r\n|]+\s*\|\s*(?:Peninsula|South Bay|East Bay|San Francisco|North Bay)\s*\|\s*(?:outlet|mall|lifestyle|district)\r?\n/);
    if (match) shoppingParagraphs.set(index, match[1].trim());
  }
  const shoppingAliases = {
    'Westfield Valley Fair': ['Valley Fair'],
    'Stanford Shopping Center': ['Stanford', '斯坦福购物中心', '史丹佛購物中心'],
    'San Francisco Premium Outlets': ['Livermore outlets', 'Livermore outlet', 'Livermore 奥特莱斯', '利弗莫尔奥特莱斯'],
    'Japantown / Japan Center': ['Japantown', 'Japan Center'],
  };
  const shoppingNames = [...new Set(shoppingParagraphs.values())]
    .flatMap(name => [name, ...(shoppingAliases[name] || [])].map(alias => ({ name, alias })))
    .sort((a, b) => b.alias.length - a.alias.length);
  const requestedShops = new Set();
  remaining = normal(message);
  for (const { name, alias } of shoppingNames) {
    let pattern = literalPattern(normal(alias));
    // JavaScript word boundaries apply to Latin names, not the Chinese end
    // of a mixed alias such as "Livermore 奥特莱斯".
    if (!/^[a-z0-9_]/i.test(alias)) pattern = pattern.replace(/^\\b/, '');
    if (!/[a-z0-9_]$/i.test(alias)) pattern = pattern.replace(/\\b$/, '');
    remaining = remaining.replace(new RegExp(pattern, 'gi'), () => {
      requestedShops.add(name); return ' ';
    });
  }
  const scopedCity = requestedCities.size > 0;
  const scopedShopping = requestedShops.size > 0;
  const eligible = index => (!scopedCity || !cityParagraphs.has(index) || requestedCities.has(cityParagraphs.get(index))) &&
    (!scopedShopping || !shoppingParagraphs.has(index) || requestedShops.has(shoppingParagraphs.get(index)));
  const ranked = paragraphs.map((text, index) => ({ text, index,
    score: terms.filter(term => normal(text).includes(term)).length +
      (scopedCity && requestedCities.has(cityParagraphs.get(index)) ? 100 : 0) +
      (scopedShopping && requestedShops.has(shoppingParagraphs.get(index)) ? 100 : 0),
  })).filter(item => eligible(item.index))
    .filter(item => item.score > 0).sort((a, b) => b.score - a.score);
  const selected = new Set();
  // The first 1,000 characters can already contain an unrelated directory
  // record. A scoped excerpt keeps only the prose before those records.
  const firstRecord = Math.min(scopedCity ? cityParagraphs.keys().next().value : Infinity,
    scopedShopping ? shoppingParagraphs.keys().next().value : Infinity);
  const introduction = scopedCity || scopedShopping
    ? paragraphs.slice(0, firstRecord).join('\n\n').slice(0, 1000)
    : content.slice(0, 1000);
  let length = introduction.length;
  for (const item of ranked) {
    // Shopping records are complete independent entries. Select all named
    // entries before general advice; neighboring venues are not context.
    const context = scopedShopping ? [item.index] : scopedCity ? [item.index, item.index - 1, item.index + 1] : [item.index - 1, item.index, item.index + 1];
    for (const index of context) {
      if (index < 0 || index >= paragraphs.length || selected.has(index) || !eligible(index)) continue;
      if (length + paragraphs[index].length > 8500) continue;
      selected.add(index); length += paragraphs[index].length;
    }
  }
  return `${introduction}\n[以下为相关段落摘录，未包含的条件请查原文]\n${[...selected].sort((a, b) => a - b).map(index => paragraphs[index]).join('\n')}`.slice(0, 9000);
}

module.exports = { normalizeGuideHistory, selectConversationGuides, groundedGuideFallback, guideSourceExcerpt, guideEditionMonth, resolveConversationRequest, isSchoolRequest };
