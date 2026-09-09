const MAX_HISTORY_MESSAGES = 8;
const { REGIONS, detectLocation, literalPattern } = require('./postSearch');
const segmenter = new Intl.Segmenter('zh', { granularity: 'word' });
const normal = value => String(value || '').normalize('NFKC').toLowerCase();
const guideEditionMonth = guide => guide.editionMonth || String(guide.slug || '').match(/(20\d{2}-(?:0[1-9]|1[0-2]))(?:$|-)/)?.[1] || '';

function conversationTopic(message) {
  const topics = [
    ['library', /图书馆|library/i], ['museum', /博物馆|museum/i],
    ['translation', /翻译|口译|translation/i], ['work', /兼职|招聘|求职|找工作|hiring|job/i],
    ['roommate', /室友|合租|roommate/i], ['repair', /维修|修理|水管|电工|repair/i],
    ['moving', /搬家|搬运|moving/i], ['cleaning', /清洁|打扫|保洁|cleaning/i],
    ['ride', /接送|接机|送机|机场|airport|pickup/i], ['used', /二手|闲置|卖东西|出售|secondhand/i],
    ['rent', /租房|租屋|出租|月租|房源|找房|求租|押金|租约|studio|housing|apartment/i],
    ['leisure', /周末|亲子|带娃|儿童|孩子|手工|优惠|福利|免费|领取|weekend|freebie/i],
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
  const ignored = new Set(['湾区', '我想', '想要', '帮我', '请问', '一下', '什么', '哪些', '根据', '站内', '攻略', '指南', '可以', '需要', '一个', '一些', '最新', '提醒', '方向', '比较', '几个', '先看', '区分', '不要', '内容', '问题', '补充', '给我']);
  for (const word of ['the', 'and', 'for', 'with', 'from', 'into', 'about', 'this', 'that', 'these', 'those', 'what', 'which', 'where', 'when', 'how', 'why', 'who', 'can', 'could', 'would', 'should', 'will', 'do', 'does', 'did', 'is', 'are', 'am', 'be', 'to', 'of', 'in', 'on', 'at', 'an', 'it', 'my', 'our', 'your', 'you', 'we', 'me', 'us', 'please', 'help', 'want', 'need', 'find', 'show', 'some', 'any', 'get', 'try', 'start']) ignored.add(word);
  const terms = [...segmenter.segment(text)].filter(part => part.isWordLike).map(part => part.segment).filter(term => term.length >= 2 && !ignored.has(term));
  if (/周末|去哪里|去处|玩一天|路线|weekend/.test(text)) terms.push('周末', '路线', '半天');
  if (/亲子|带娃|儿童|孩子|手工/.test(text)) terms.push('亲子', '儿童', '免费', '手工');
  if (/省钱|优惠|福利|freebie|领取/.test(text)) terms.push('优惠', '免费', '福利');
  if (/刚来|第一个月|新移民/.test(text)) terms.push('刚来', '第一个月', '落地');
  return [...new Set(terms)].slice(0, 35);
}

function selectConversationGuides(catalog, message, category, currentPath = '/', history = [], today = '') {
  const terms = guideTerms(message);
  const previous = resolveConversationRequest('', history);
  const priorTerms = followsPreviousRequest(message, previous) ? guideTerms(resolveConversationRequest(message, history)) : [];
  const article = catalog.find(guide => guide.url === currentPath);
  const effectiveTopic = conversationTopic(resolveConversationRequest(message, history));
  const articleTopic = article ? conversationTopic(`${article.title} ${article.summary || ''}`) : '';
  const referenceArticle = !!article && (/这篇|本文|这份|当前(?:文章|攻略)|正在读/.test(message) ||
    !effectiveTopic || (!!articleTopic && articleTopic === effectiveTopic));
  const currentMonth = today.slice(0, 7);
  const ranked = catalog.filter(guide => {
    const editionMonth = guideEditionMonth(guide);
    // An explicitly opened archived article stays readable; general discovery excludes old editions.
    return !currentMonth || !editionMonth || editionMonth >= currentMonth || (referenceArticle && guide.url === currentPath);
  }).map(guide => {
    const title = normal(guide.title);
    const summary = normal(guide.summary);
    const keywords = normal((guide.keywords || []).join(' '));
    const content = normal(guide.content).slice(0, 24000);
    const scoreTerms = words => words.reduce((score, term) => score + (title.includes(term) ? 9 : keywords.includes(term) ? 5 : summary.includes(term) ? 4 : content.includes(term) ? 1 : 0), 0);
    let score = scoreTerms(terms);
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
  return `暂时无法生成个性化方案，先给你这些已发布攻略的摘要：\n\n${summaries.join('\n\n')}\n\n下方可打开原文。活动日期、免费领取门槛、名额和价格请按文中的官方来源确认；这些摘要不代表实时查询结果。`.slice(0, 1200);
}

function guideSourceExcerpt(guide, message) {
  const content = String(guide.content || '');
  if (content.length <= 9000) return content;
  const terms = guideTerms(message);
  // Exported offer blocks keep title, date, conditions and source together between blank lines.
  const blocks = content.split(/\n\s*\n/);
  const paragraphs = blocks.length > 1 ? blocks : content.split(/\n+/);
  const ranked = paragraphs.map((text, index) => ({ text, index, score: terms.filter(term => normal(text).includes(term)).length }))
    .filter(item => item.score > 0).sort((a, b) => b.score - a.score);
  const selected = new Set();
  const introduction = content.slice(0, 1000);
  let length = introduction.length;
  for (const item of ranked) {
    for (const index of [item.index - 1, item.index, item.index + 1]) {
      if (index < 0 || index >= paragraphs.length || selected.has(index)) continue;
      if (length + paragraphs[index].length > 8500) continue;
      selected.add(index); length += paragraphs[index].length;
    }
  }
  return `${introduction}\n[以下为相关段落摘录，未包含的条件请查原文]\n${[...selected].sort((a, b) => a - b).map(index => paragraphs[index]).join('\n')}`.slice(0, 9000);
}

module.exports = { normalizeGuideHistory, selectConversationGuides, groundedGuideFallback, guideSourceExcerpt, guideEditionMonth, resolveConversationRequest };
