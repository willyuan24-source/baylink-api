// A guide search or web lookup is not a query of community posts or outings.
// Only the caller's actual retrieval state can support a negative match result.
const RENTAL = '房源|(?:租房|出租|合租|室友).{0,10}(?:帖子|信息|資訊|记录|記錄)|(?:rental|housing|roommate|apartment)[ -]+(?:posts?|listings?|records?|offers?|properties)';
const OUTING = '小队|小隊|出游队伍|出遊隊伍|\\b(?:outings?|(?:outing|hiking|travel)[ -]+(?:teams?|groups?))\\b';
const SERVICE = '服务(?:帖子|信息|資訊|记录|記錄)|服務(?:帖子|信息|資訊|记录|記錄)|(?:维修|維修|水管|清洁|清潔|搬家|翻译|翻譯|接送).{0,10}(?:服务|服務|师傅|師傅|商家)|(?:service|repair|cleaning|moving|translation|ride|plumb(?:er|ing))[ -]+(?:providers?|posts?|listings?|records?|services?)|\\b(?:plumbers?|cleaners?|handymen)\\b';
const SITE = /站内|站內|本站|平台|BAYLINK|on (?:the |this )?site|site (?:has|records|posts)|published|listed/i;
const COMMUNITY_POST = /(?:房源|租房|出租|合租|室友|服务|服務|清洁|清潔|维修|維修).{0,10}(?:帖子|信息|資訊|记录|記錄)|(?:rental|housing|roommate|apartment|service|repair|cleaning|moving|translation|ride)[ -]+(?:posts?|listings?|records?|offers?)/i;
const PUBLIC_OUTING = /(?:公开|公開|已发布|已發布).{0,15}(?:小队|小隊|出游队伍|出遊隊伍)|\b(?:public|published|listed|site)\s+(?:outings?|outing (?:teams?|groups?))\b/i;
const NEGATIVE = '(?:没有|沒有|不存在|暂无|暫無|未收录|未收錄|未找到|找不到|未能找到|无|無)';
function denies(clause, noun) {
  // Explicit uncertainty and "does not mean none exist" are useful boundaries,
  // not assertions that the public collection is empty.
  if (/[?？]\s*$/.test(clause) || /^\s*(?:如果|若|假如|倘若|假设|假設|if\b)/i.test(clause)
    || /(?:不代表|不能(?:判断|判斷|证明|證明|断言|斷言)|无法(?:判断|判斷|确定|確定|确认|確認)|不要(?:说|說|声称|聲稱)).{0,35}(?:没有|沒有|无|無)|(?:does not|doesn't|cannot|can't) (?:mean|confirm|determine|say|conclude).{0,45}\bno\b/i.test(clause)) return false;
  return new RegExp(`${NEGATIVE}.{0,35}(?:${noun})|(?:${noun}).{0,25}(?:不存在|没有|沒有|暂无|暫無|未收录|未收錄|未找到)|\\b(?:no|zero)\\s+(?:(?:currently|public|published|matching|available|relevant|active|any|new|other|local|Chinese[- ]speaking|Chinese[- ]language)\\s+){0,5}(?:${noun})|(?:${noun}).{0,35}\\b(?:are not available|aren't available|do not exist|don't exist|not (?:listed|recorded|available)|none available)\\b`, 'i').test(clause);
}
const say = (locale, en, hans, hant) => locale === 'en' ? en : locale === 'zh-Hant' ? hant : hans;
function categoryFor(text, hint) {
  if (['moving', 'cleaning', 'repair', 'translation', 'ride'].includes(hint)) return hint;
  if (/清洁|清潔|clean/i.test(text)) return 'cleaning';
  if (/搬家|moving/i.test(text)) return 'moving';
  if (/翻译|翻譯|translat|interpret/i.test(text)) return 'translation';
  if (/接送|rides?|pickup/i.test(text)) return 'ride';
  if (/维修|維修|水管|repair|plumb|handyman/i.test(text)) return 'repair';
  return 'other';
}
const REFERENCES = /\[\[[^\]\r\n]+\]\]|\[[^\]\r\n]*\]\([^\r\n)]*\)|https?:\/\/[^\s<>。！？；，]+/g;
function answerFragments(answer) {
  const references = [...answer.matchAll(REFERENCES)].map(match => {
    // Terminal sentence punctuation can follow a bare URL. It stays in the
    // original fragment; only its boundary is outside the protected token.
    const token = /^https?:\/\//.test(match[0]) ? match[0].replace(/[.!?;:,]+$/, '') : match[0];
    return { start: match.index, end: match.index + token.length };
  });
  const fragments = []; let start = 0;
  for (const boundary of answer.matchAll(/[。！？；，][ \t]*|[.!?;,](?:[ \t]+|(?=\r?$))|\r?\n+/gm)) {
    if (boundary.index < start) continue;
    if (references.some(range => boundary.index >= range.start && boundary.index < range.end)) continue;
    let end = boundary.index + boundary[0].length;
    if (/^[。！？；，.!?;,]/.test(boundary[0])) {
      // A citation immediately after sentence punctuation belongs to that
      // preceding statement, not an adjacent claim in the next sentence.
      let citation;
      while ((citation = answer.slice(end).match(/^\[\[[^\]\r\n]+\]\][ \t]*/))) end += citation[0].length;
    }
    fragments.push(answer.slice(start, end)); start = end;
  }
  if (start < answer.length) fragments.push(answer.slice(start));
  return fragments;
}
function guardCommunityAbsence({ answer, locale = 'zh-Hans', category, searches = {} }) {
  if (typeof answer !== 'string') return { answer, changed: false, suggestedActions: [] };
  const actions = new Map(), repaired = new Set();
  const repair = clause => {
    const prose = clause.replace(REFERENCES, '');
    const siteCollection = SITE.test(prose) || COMMUNITY_POST.test(prose);
    const kind = siteCollection && denies(prose, RENTAL) ? 'posts'
      : (SITE.test(prose) || PUBLIC_OUTING.test(prose)) && denies(prose, OUTING) ? 'outings'
        : siteCollection && (denies(prose, SERVICE) || denies(prose, '服务|服務|师傅|師傅|services?|providers?')) ? 'services' : null;
    if (!kind) return clause;
    const state = searches[kind === 'services' ? 'posts' : kind];
    const cat = kind === 'posts' ? 'rent' : categoryFor(prose, category);
    const url = kind === 'outings' ? '/together' : `/category/${cat}`;
    actions.set(url, { label: kind === 'outings' ? say(locale, 'Browse public outings', '查看公开小队', '查看公開小隊')
      : say(locale, kind === 'posts' ? 'Housing posts' : 'Browse service posts', kind === 'posts' ? '查看租房分类' : '查看服务分类', kind === 'posts' ? '查看租房分類' : '查看服務分類'), type: kind === 'outings' ? 'guide' : 'category', url, ...(kind === 'outings' ? {} : { category: cat }) });
    if (kind !== 'outings') actions.set(`help-${cat}`, { label: say(locale, 'Post a request', '发布求助', '發布求助'), type: 'post', url: `/?type=client&category=${cat}`, postType: 'client', category: cat });
    if (repaired.has(kind)) return '';
    repaired.add(kind);
    const collection = kind === 'outings' ? say(locale, 'public outings', '公开小队', '公開小隊')
      : kind === 'posts' ? say(locale, 'public housing posts', '公开房源帖子', '公開房源帖子') : say(locale, 'public service posts', '公开服务帖子', '公開服務帖子');
    const next = kind === 'outings' ? say(locale, 'Open public outings and narrow the city and date.', '请打开公开小队，按城市和日期继续查看。', '請打開公開小隊，按城市和日期繼續查看。')
      : say(locale, 'Open the public category, or post a request with your city and requirements.', '请打开公开分类继续查看，也可发布求助帖，说明城市和需求。', '請打開公開分類繼續查看，也可發布求助帖，說明城市和需求。');
    if (state?.status === 'completed' && Number.isInteger(state.matchingCount) && state.matchingCount >= 0) {
      return state.matchingCount > 0
        ? say(locale, `This query returned ${state.matchingCount} matching records. Their current availability still needs confirmation. ${next}`, `本次查询返回 ${state.matchingCount} 条匹配记录，是否仍可用还需确认。${next}`, `本次查詢返回 ${state.matchingCount} 條匹配記錄，是否仍可用還需確認。${next}`)
        : say(locale, `This ${collection} query returned no matches for the applied filters. This does not establish that the whole site or local area has none. ${next}`, `本次${collection}查询没有匹配已应用条件的记录，不代表全站或当地没有相关信息。${next}`, `本次${collection}查詢沒有匹配已套用條件的記錄，不代表全站或當地沒有相關資訊。${next}`);
    }
    return state?.status === 'unavailable'
      ? say(locale, `The ${collection} query could not be completed, so I cannot determine whether matching records exist. ${next}`, `本次${collection}查询未能完成，无法判断是否有匹配记录。${next}`, `本次${collection}查詢未能完成，無法判斷是否有匹配記錄。${next}`)
      : say(locale, `I have not queried the site's ${collection} in this turn, so I cannot determine whether matching records exist. ${next}`, `本轮尚未检索站内${collection}，不能判断是否有符合条件的记录。${next}`, `本輪尚未檢索站內${collection}，不能判斷是否有符合條件的記錄。${next}`);
  };
  const output = answerFragments(answer).map(fragment => {
    const [, leading, clause, trailing] = fragment.match(/^(\s*)([\s\S]*?)(\s*)$/);
    return leading + repair(clause) + trailing;
  });
  return { answer: repaired.size ? output.join('') : answer, changed: repaired.size > 0,
    warning: repaired.size ? 'community_absence_unverified' : undefined, suggestedActions: [...actions.values()].slice(0, 3) };
}

module.exports = { guardCommunityAbsence };
