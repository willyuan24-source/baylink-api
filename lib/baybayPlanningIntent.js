// Recognize a planning speech act, not a keyword alone. An arrangement verb
// must govern an outing/itinerary or a bounded leisure day. This supplements
// deterministic task extraction without guessing places, clocks or prices.
const PLAN_OBJECT = /行程|[游遊]程|玩法|一日[游遊]|半日[游遊]|\b(?:itinerar(?:y|ies)|outing|day[- ]trip|day[- ]plan|tour)\b/i;
const ROUTE_OBJECT = /路[线線]|走法|\broute\b/i;
const DURATION = /半[天日]|(?:一|整)[天日]|[两兩三四五六七八九\d]+(?:个|個)?小[时時]|\b(?:half[- ](?:a[- ])?day|full[- ]day|whole day|one day|a day|\d+ hours?)\b/i;
const LEISURE = /逛|出[游遊門门]|走走|玩|散步|景[点點]|公[园園]|带娃|帶娃|带小孩|帶小孩|\b(?:outing|trip|visit|tour|family|sightseeing|stroll|walk|park)\b/i;
const ARRANGE = /安排|规[划劃]|規劃|排(?:[个個成一]|一下|出|好)|[设設][计計]|串(?:成|起[来來]?|一下)|改(?:成|[为為])|\b(?:put together|map out|work out|sketch(?: out)?|plan|arrange|organi[sz]e|build|schedule|make)\b/gi;
const NEGATIVE = /(?:不要|不想|不需要|不用|不必|别|別|无需|無需|不是|不|取消|停止)(?:再|先|帮我|幫我|帮我们|幫我們|给我|給我|[做排]|\s)*$|\b(?:do not|don['’]t|not|never|no need to|stop|cancel)(?:\s+(?:want|need|to|please|help|me|us|you|recommend|suggest|attractions?|events?|routes?|itineraries|and|or))*\s*$/i;
const HISTORICAL = /(?:上次|昨天|昨日|曾经|曾經|以前|之前)(?:我|我们|我們)?|(?:官网|官網|网页|網頁|文章|指南)(?:上)?(?:写|寫|说|說|提到)|\b(?:yesterday|last (?:time|week|month)|previously|used to|(?:website|page|article|guide) (?:says|said|mentions))\b/i;

function planningClauses(message) {
  // A quoted label or reported past outing is not a new instruction. Split
  // corrections first so “yesterday ..., but now arrange ...” keeps the request.
  const text = String(message || '').replace(/“[^”]*”|「[^」]*」|『[^』]*』|"[^"\n]*"/g, ' ');
  return text.split(/[，,。.!！？?；;\n]|\b(?:but|instead|actually)\b|不过|不過|而是|改口说|改口說/gi)
    .map(value => value.trim()).filter(value => value && !(HISTORICAL.test(value)
      && (PLAN_OBJECT.test(value) || /安排|规[划劃]|規劃|\b(?:plan(?:ned)?|arranged|put together)\b/i.test(value))));
}

function planningDirective(message) {
  const clauses = planningClauses(message);
  const boundedOuting = DURATION.test(clauses.join(' ')) && LEISURE.test(clauses.join(' '));
  let found = null;
  const handled = new Set();
  clauses.forEach((clause, index) => {
    if (/^(?:(?:那就|现在|現在|请|請|帮我|幫我)\s*)?(?:继续|繼續|重新)(?:规划|規劃|安排|排)(?:行程|一下|吧)?$|^\s*(?:please\s+)?(?:resume|continue)\s+(?:planning|(?:the\s+)?itinerary)\s*$/i.test(clause)) {
      found = { kind: 'plan' }; handled.add(index); return;
    }
    // Preservation and pace constraints are not instructions to stop planning.
    const preserved = /(?:不|别|別|不要|不用)(?:再)?(?:改|修改|更改|变更|變更|调整|調整|替[换換]).{0,18}(?:行程|[游遊]程|路[线線])|\b(?:don['’]t|do not|no need to)\s+(?:change|alter|modify|replan|rearrange)\b/i.test(clause);
    const pause = !preserved && /(?:先|暂时|暫時)?(?:不要|不用|不必|别|別)(?:再)?(?:帮我|幫我)?(?:排(?:行程)?|安排(?:行程)?|规[划劃]|規劃)(?:了|啦)?$|(?:取消|停止|暂停|暫停).{0,16}(?:行程|[游遊]程|一日[游遊]|半日[游遊]|规[划劃]|規劃)|\b(?:pause|stop|cancel)\s+(?:(?:planning|arranging)(?:\s+(?:the|my|our))?|(?:the|my|our)\s+)?(?:itinerary|outing|day[- ](?:trip|plan)|planning)\b/i.test(clause);
    if (pause) { found = { kind: 'pause' }; handled.add(index); return; }
    if (preserved) return;
    for (const match of clause.matchAll(ARRANGE)) {
      const before = clause.slice(0, match.index), after = clause.slice(match.index + match[0].length);
      const relevant = PLAN_OBJECT.test(after) || ROUTE_OBJECT.test(after) && boundedOuting
        || DURATION.test(after) && (LEISURE.test(clause) || boundedOuting || /安排|规[划劃]|規劃|\bplan\b/i.test(match[0]))
        || boundedOuting && /^[吗嗎吧呢\s]*$/.test(after);
      if (!relevant) continue;
      if (NEGATIVE.test(before)) { found = { kind: 'pause' }; handled.add(index); continue; }
      // “What does plan a day mean?” asks about wording, not an outing.
      if (/翻译|翻譯|什么意思|什麼意思|怎么翻|怎麼翻|\b(?:translate|meaning|what does|definition)\b/i.test(clause)) continue;
      found = { kind: 'plan' }; handled.add(index);
    }
  });
  return found ? { ...found, tail: clauses.filter((_, index) => !handled.has(index)).join('，') } : null;
}

module.exports = { planningDirective, planningClauses };
