const emergency = /胸(?:口)?(?:很|非常|剧烈|劇烈)?(?:痛|疼)|呼吸(?:很|非常|十分)?(?:困难|困難)|(?:喘|透)不(?:过|過|上)(?:气|氣)|不能呼吸|中毒|(?:误吞|誤吞|误食|誤食|吞(?:了|下)?|(?:不小心)?喝(?:了|下)).{0,12}(?:清洁剂|清潔劑|洗涤剂|洗滌劑|漂白水|药|藥)|不想(?:再)?活(?:了|下去)?|活不下去|想(?:自杀|自殺|自伤|自傷|死)|(?:想|打算|准备|準備)(?:要)?(?:结束|結束)(?:自己|我)?的?生命|(?:chest pain|\bchest hurts\b|\bpain in (?:my|his|her|their) chest\b|can(?:not|['’]t) breathe|(?:unable|struggling) to breathe|(?:hav(?:e|ing)|has) trouble breathing|difficulty breathing|poison(?:ing|ed)?|(?:swallowed|drank|ingested).{0,30}(?:cleaner|detergent|bleach|medicine|pills)|(?:do not|don['’]t) want to (?:live|be alive)(?: anymore| any more)?|\b(?:want|plan|intend) to end my life\b|suicid(?:e|al)|kill myself|hurt myself)/gi;

function hasCurrentEmergency(message) {
  const clauses = message.split(/[。.!！？?;；，,\n]|(?:但是|但现在|但現在|\bbut\b)/i);
  for (const [clauseIndex, clause] of clauses.entries()) {
    // A requested translation/definition is quoted language, even when its
    // wording contains "now". A later disclosure after "but" is a new clause.
    if (/^\s*(?:(?:(?:请|請)(?:帮我|幫我)?)?(?:翻译|翻譯|定义|定義)|(?:please\s+)?(?:translate|define)\b|(?:what does|什[么麼]意思|什[么麼]是).{0,35}["'“‘「『])/i.test(clause)) continue;
    for (const match of clause.matchAll(emergency)) {
      const prefix = clause.slice(0, match.index);
      const last = (pattern, value = prefix) => [...value.matchAll(pattern)].at(-1)?.index ?? -1;
      const quotedFrame = /(?:(?:新闻|新聞|报道|報導|文章|小说|小說|电影|電影|\b(?:news|article|report|novel|movie|fictional)\b)[^：:"'“‘「『]{0,80}(?:quotes?|quoted|says?|said|states?|他[说說]|她[说說])|(?:翻译|翻譯|\b(?:translate|translation)\b))[^：:"'“‘「『]{0,60}([：:"'“‘「『])/i.exec(prefix);
      let currentPrefix = prefix;
      if (quotedFrame) {
        let quote = quotedFrame[1], start = quotedFrame.index + quotedFrame[0].length;
        const opening = /^(\s*)(["'“‘「『])/.exec(prefix.slice(start));
        if (/[：:]/.test(quote) && opening) { quote = opening[2]; start += opening[0].length; }
        const close = ({ '"': '"', "'": "'", '“': '”', '‘': '’', '「': '」', '『': '』' })[quote];
        const end = close ? prefix.indexOf(close, start) : -1;
        const after = end < 0 ? prefix.length : end;
        currentPrefix = prefix.slice(0, start) + ' '.repeat(after - start) + prefix.slice(after);
      }
      const current = last(/现在|現在|目前|刚刚|剛剛|刚才|剛才|\b(?:now|today|just)\b/gi, currentPrefix);
      // A news report, translation exercise or past account is not evidence
      // that the speaker is currently in danger. A later present-tense cue
      // keeps a real current disclosure from being hidden by an earlier frame.
      const noncurrent = last(/以前|过去|過去|曾经|曾經|昨天|昨日|前天|上[个個](?:月|星期)|上[周週]|历史|歷史|新闻|新聞|报道|報導|文章|小说|小說|电影|電影|翻译|翻譯|例句|\b(?:history of|in the past|used to|previously|yesterday|last (?:night|week|month|year)|news|article|report|novel|movie|fictional|translate|translation|example sentence)\b/gi);
      // Starting yesterday is not a past-only episode when the same symptom
      // explicitly continues now. Inspect only its suffix and next clause;
      // general "now", recovery statements and reported/quoted text do not
      // revive a historical disclosure.
      const continuation = `${clause.slice(match.index + match[0].length)} ${clauses[clauseIndex + 1] || ''}`.slice(0, 240);
      const reported = /新闻|新聞|报道|報導|文章|小说|小說|电影|電影|翻译|翻譯|例句|\b(?:news|article|report|novel|movie|fictional|translate|translation|example sentence)\b/i.test(prefix);
      const stillCurrent = !reported && /(?:现在|現在|目前)(?:仍然|仍|还是|還是)(?:这样|這樣)|\bit\s+(?:is|'s)\s+still\s+happening\s+(?:right\s+)?now\b/i.test(continuation);
      if (noncurrent >= 0 && current <= noncurrent && !stillCurrent) continue;
      const nearby = prefix.slice(-40).replace(/["'“”‘’]\s*$/, '').trim();
      if (/(?:不是|没有|沒有|并非|並非|否认|否認|从未|從未|未|无|無|不)\s*(?:真的|再|已经|已經|发生|發生|觉得|覺得|表示|说|說)?\s*$|\b(?:no(?:\s+longer)?|not|never|(?:did|do|does|have|has) not|(?:didn['’]t|don['’]t|doesn['’]t|haven['’]t|hasn['’]t))\s*(?:(?:currently|now|really)\s*)?(?:have|feel|feeling|experience|experienced|say|saying)?\s*(?:(?:any|very|severe|sharp|intense|bad)\s*){0,3}$/i.test(nearby)) continue;
      return true;
    }
  }
  return false;
}
const professionalGuideSlugs = {
  medicare: 'bay-area-medicare-hicap-medi-cal-guide',
  insurance: 'bay-area-medicare-hicap-medi-cal-guide',
  tax: 'bay-area-free-tax-help-vita-calfile-guide',
};
const guideLabels = {
  'bay-area-medicare-hicap-medi-cal-guide': {
    en: 'Medicare, Medi-Cal and HICAP counseling preparation',
    'zh-Hant': 'Medicare、Medi-Cal 與 HICAP 諮詢準備',
  },
  'bay-area-free-tax-help-vita-calfile-guide': {
    en: 'VITA, TCE and CalFile tax-help preparation',
    'zh-Hant': 'VITA、TCE 與 CalFile 報稅求助準備',
  },
};

function relatedSafetyGuides(kinds, locale, context) {
  // Resolve only known published IDs from this application's current catalog.
  // A missing guide must not produce an invented route; translated catalogs
  // supply presentation only and never override the canonical guide URL.
  const catalog = context.guideCatalog === undefined ? require('../data/guide-catalog.json') : context.guideCatalog;
  const english = context.englishGuideCatalog === undefined ? require('../data/guide-catalog.en.json') : context.englishGuideCatalog;
  const slugs = [...new Set(kinds.map(kind => professionalGuideSlugs[kind]).filter(Boolean))];
  return slugs.flatMap(slug => {
    const canonical = Array.isArray(catalog) && catalog.find(row => row.slug === slug && row.url === `/guides/${slug}` && typeof row.title === 'string');
    if (!canonical) return [];
    const translated = english instanceof Map ? english.get(slug) : Array.isArray(english) ? english.find(row => row.slug === slug) : undefined;
    const title = locale === 'en'
      ? (typeof translated?.title === 'string' && translated.title.trim() && !/[\u3400-\u9fff]/u.test(translated.title) ? translated.title : guideLabels[slug].en)
      : locale === 'zh-Hant' ? guideLabels[slug]['zh-Hant'] : canonical.title;
    return [{ slug, title, url: canonical.url }];
  });
}

function professionalPreparation(kinds, locale) {
  const en = locale === 'en', hant = locale === 'zh-Hant';
  const answer = [], sources = [];
  if (kinds.includes('medicare') || kinds.includes('insurance')) {
    answer.push(en
      ? 'For Medicare questions, find your county HICAP office through the California Department of Aging or call 1-800-434-0222. HICAP offers free, confidential counseling; confirm appointment and Chinese/interpreter availability with the office. Prepare your birthday month, current coverage and its end date, insurance notices, doctors and medication list for the verified counselor. For Medi-Cal applications or renewals, use DHCS; Medicare and Medi-Cal are different programs. This does not determine your eligibility or recommend an insurance product.'
      : hant
        ? 'Medicare 問題可從加州老齡部官方頁面找所在縣的 HICAP，或撥打 1-800-434-0222。HICAP 提供免費、保密諮詢；預約與中文／口譯安排需向辦公室確認。為已核實的諮詢員準備生日月份、目前保險與結束日期、通知、醫生及藥物清單。Medi-Cal 申請或續保從 DHCS 開始；兩者是不同項目。這不是對你個人資格的判定或保險產品推薦。'
        : 'Medicare 问题可从加州老龄部官方页面找所在县的 HICAP，或拨打 1-800-434-0222。HICAP 提供免费、保密咨询；预约与中文／口译安排需向办公室确认。为已核实的咨询员准备生日月份、目前保险与结束日期、通知、医生及药物清单。Medi-Cal 申请或续保从 DHCS 开始；两者是不同项目。这不是对你个人资格的判定或保险产品推荐。');
    sources.push(
      { id: 'safety-hicap', title: 'California Department of Aging: HICAP', url: 'https://www.aging.ca.gov/Programs_and_Services/Medicare_Counseling/' },
      { id: 'safety-medi-cal', title: 'DHCS: Medi-Cal', url: 'https://www.dhcs.ca.gov/medi-cal/' },
    );
  }
  if (kinds.includes('tax')) {
    answer.push(en
      ? 'Use the IRS VITA/TCE locator or call 800-906-9887 to find tax-help sites. Confirm the tax year, income types and forms, opening dates, appointment and language arrangements, and the site\'s eligibility rules; a listing does not guarantee that a site is open or that your return qualifies. Follow the official document checklist, including identity documents, tax forms and the prior return, and share them only with the verified organization. Check California CalFile eligibility separately through FTB; free federal filing does not guarantee free state filing.'
      : hant
        ? '從 IRS 的 VITA／TCE 查詢入口，或撥打 800-906-9887 找報稅點。先確認稅務年份、收入類型與表格、開放日期、預約、語言安排及站點資格；有服務入口不代表現在開門或你的申報一定符合條件。按官方清單準備身分證明、稅務表格和上年申報資料，只交給已核實的機構。加州 CalFile 資格另從 FTB 核對；聯邦免費不代表州申報也免費。'
        : '从 IRS 的 VITA／TCE 查询入口，或拨打 800-906-9887 找报税点。先确认税务年份、收入类型与表格、开放日期、预约、语言安排及站点资格；有服务入口不代表现在开门或你的申报一定符合条件。按官方清单准备身份证明、税务表格和上年申报资料，只交给已核实的机构。加州 CalFile 资格另从 FTB 核对；联邦免费不代表州申报也免费。');
    sources.push(
      { id: 'safety-vita', title: 'IRS: VITA/TCE tax help', url: 'https://www.irs.gov/individuals/free-tax-return-preparation-for-qualifying-taxpayers' },
      { id: 'safety-calfile', title: 'California FTB: online filing options', url: 'https://www.ftb.ca.gov/file/ways-to-file/online/index.html' },
    );
  }
  if (answer.length) answer.push(en ? 'These are official reference links and preparation steps, not a live source check. Do not send the documents or full identifiers to BayBay.'
    : hant ? '以上是官方參考入口與準備事項，不是本次即時網頁核驗。請勿把材料或完整識別號碼傳給 BayBay。'
      : '以上是官方参考入口与准备事项，不是本次即时网页核验。请勿把材料或完整识别号码传给 BayBay。');
  return { answer: answer.join('\n\n'), sources };
}

function safetyResponse(message, locale = 'zh-Hans', context = {}) {
  if (typeof message !== 'string' || message.length > 5000) return null;
  const en = locale === 'en', traditional = locale === 'zh-Hant';
  if (hasCurrentEmergency(message)) {
    const answer = en ? 'If this is happening now, call 911 for severe chest pain, trouble breathing or immediate danger. For a possible poisoning, call Poison Control at 1-800-222-1222; for suicide or emotional crisis, call or text 988. Do not wait for BayBay or rely on a generated diagnosis.' : traditional ? '若正在發生嚴重胸痛、呼吸困難或有立即危險，請立即撥打 911。疑似中毒可聯絡 Poison Control：1-800-222-1222；自殺或情緒危機可撥打或傳簡訊至 988。不要等待 BayBay 回覆，也不要依賴生成的診斷。' : '若正在发生严重胸痛、呼吸困难或有立即危险，请立即拨打 911。疑似中毒可联系 Poison Control：1-800-222-1222；自杀或情绪危机可拨打或发短信至 988。不要等待 BayBay 回复，也不要依赖生成的诊断。';
    return { ok: true, answer, safetyRoute: 'emergency', responseMode: 'safety', degraded: false, sources: [{ id: 'safety-911', title: '911', url: 'https://www.911.gov/' }, { id: 'safety-poison', title: 'Poison Control', url: 'https://www.poisonhelp.org/' }, { id: 'safety-988', title: '988 Lifeline', url: 'https://988lifeline.org/' }], suggestedGuides: [], suggestedActions: [], matchingPosts: [], interactiveCards: [], followups: [] };
  }
  const topics = [
    ['immigration', /绿卡|綠卡|移民|庇护|庇護|\b(?:green card|immigration|asylum)\b/i, 'USCIS', 'https://www.uscis.gov/'],
    ['medicare', /\b(?:medicare|hicap)\b/i, 'Medicare', 'https://www.medicare.gov/'],
    ['insurance', /医保|醫保|\b(?:health insurance|medi[- ]cal)\b/i, 'Covered California', 'https://www.coveredca.com/coverage-basics/'],
    ['medical', /医疗|醫療|诊断|診斷|处方|處方|\b(?:medical diagnosis|prescription)\b/i, 'MedlinePlus', 'https://medlineplus.gov/'],
    ['tax', /报税|報稅|税务|稅務|\b(?:vita|tce|calfile|tax return|tax advice|tax filing|tax help|tax preparation|file (?:my )?taxes)\b/i, 'IRS', 'https://www.irs.gov/'],
    ['legal', /法律意见|法律意見|法律咨询|法律諮詢|驱逐|驅逐|\b(?:legal advice|eviction)\b/i, 'California Courts Self-Help', 'https://selfhelp.courts.ca.gov/'],
  ];
  const topic = topics.find(([, pattern]) => pattern.test(message));
  if (topic) {
    const [kind, , title, url] = topic;
    const kinds = topics.filter(([, pattern]) => pattern.test(message)).map(([value]) => value);
    const preparation = professionalPreparation(kinds, locale);
    const boundary = en ? `Start with ${title}'s official resource. Rules depend on your circumstances and the current published requirements. Avoid sharing full IDs, case numbers, home addresses or medical records here. For a personal determination, contact the appropriate qualified professional or the official service.` : traditional ? `先從 ${title} 的官方入口核對。適用規則取決於你的具體情況和最新公布要求。請勿在此提供完整證件、案件號、住址或病歷；個人判定應由合資格專業人士或官方服務確認。` : `先从 ${title} 的官方入口核对。适用规则取决于你的具体情况和最新公布要求。请勿在此提供完整证件、案件号、住址或病历；个人判定应由合资格专业人士或官方服务确认。`;
    return { ok: true, answer: [preparation.answer, boundary].filter(Boolean).join('\n\n'), safetyRoute: 'professional', safetyTopic: kind, responseMode: 'safety', degraded: false, sources: [{ id: `safety-${kind}`, title, url }, ...preparation.sources], suggestedGuides: relatedSafetyGuides(kinds, locale, context), suggestedActions: [], matchingPosts: [], interactiveCards: [], followups: [] };
  }
  return null;
}
module.exports = { safetyResponse };
