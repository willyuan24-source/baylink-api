// Deterministic safety routing for BayBay and the AI helpers.
//
// 1. A possible CURRENT emergency always returns a fixed 911-first card before
//    any quota, provider or retrieval work. Each entry is [topic, pattern]; the
//    union is evaluated clause by clause so denials, history, news reports and
//    translation requests do not trigger it.
// 2. A professional topic (immigration, Medicare/insurance, medical decisions,
//    tax, legal) is no longer a template that replaces the answer. BayBay gives
//    a guarded model answer plus a deterministic resource card; the template is
//    kept for legacy clients, the planner route and BayBay's degraded floor.
const EMERGENCY_PATTERNS = [
  ['stroke', /嘴歪|口角歪斜|口眼歪斜|[脸臉](?:突然)?歪|(?:突然|忽然)[^。！？!?]{0,10}(?:说话不清|說話不清|口齿不清|口齒不清|讲话不清|講話不清|说不出话|說不出話|讲不出话|講不出話|说话含糊|說話含糊)|半[边邊](?:身子|身体|身體|[脸臉])?(?:突然)?(?:无力|無力|[没沒](?:有)?力[气氣]|[发發]麻|麻木|不能[动動]|[动動]不了)|一[侧側](?:身体|身體|手脚|手腳)?(?:无力|無力|麻木|[没沒]力[气氣])|(?:突然|好像|可能|疑似|是不是)(?:是)?中[风風]|中[风風]了|\b(?:face|mouth|smile)\s+(?:is\s+|was\s+)?(?:suddenly\s+)?droop(?:ing|y|s|ed)?\b|\bfacial droop|\bslurred speech\b|\bspeech\s+(?:is\s+|was\s+)?(?:suddenly\s+)?slurred\b|\bslurring\b|\bsuddenly\s+(?:can(?:not|['’]t)|could(?:n['’]t| not))\s+(?:speak|talk|move)\b|\bone side of (?:his|her|my|their) (?:body|face)\b[^.!?]{0,20}\b(?:weak|numb|droop)|\b(?:having|had|is having|just had)\s+a\s+stroke\b/],
  ['cardiac', /胸(?:口)?(?:很|非常|剧烈|劇烈)?(?:痛|疼)|心[脏臟]病(?:发作|發作|犯了)|心梗|心肌梗(?:塞|死)|心[脏臟](?:骤停|驟停)|chest pain|\bchest hurts\b|\bpain in (?:my|his|her|their) chest\b|\bheart attack\b|\bcardiac arrest\b/],
  ['breathing', /呼吸(?:很|非常|十分)?(?:困难|困難)|(?:喘|透)不(?:过|過|上)(?:气|氣)|不能呼吸|(?:[没沒]有|[没沒]了|停止)(?:了)?呼吸(?:了)?(?!困|道|急|[问問]|系|[练練]|[声聲]|[机機]|器|科|[内內])|can(?:not|['’]t) breathe|(?:unable|struggling) to breathe|(?:hav(?:e|ing)|has) trouble breathing|difficulty breathing|\b(?:isn['’]t|is not|aren['’]t|are not|wasn['’]t|stopped|has stopped|not)\s+breathing\b/],
  ['unconscious', /[晕暈昏]倒|昏迷|[晕暈昏](?:过|過)去|[晕暈]厥|不省人事|失去意[识識]|意[识識]不清|[叫喊]不醒|[叫喊](?:了|他|她|也|都|半天|几[声下]|幾[聲下]){0,3}[没沒](?:有)?反[应應]|(?:老人|孩子|小孩|宝宝|寶寶|爸|[妈媽]|[爷爺]爷|[爷爺]爺|奶奶|外公|外婆|老公|老婆|老伴|他|她)(?:突然)?[没沒](?:有)?(?:反[应應]|意[识識])(?!过来|過來)|\b(?:is|was|are|were|went|fell|became|lying|found)\s+(?:\w+\s+)?unconscious\b(?!\s+(?:bias|mind|level|thoughts?|process(?:es)?|memor))|\bunconscious\s+(?:and|now|on)\b|\bunresponsive\b|\bpassed out\b(?!\s+(?:the\s+)?(?:flyers?|cand(?:y|ies)|copies|food|samples|leaflets|papers|cards|tickets|gifts|water|snacks))|\b(?:won['’]t|will not|can['’]t|cannot|doesn['’]t|does not|didn['’]t|did not)\s+wake\s+(?:up|him|her|them)\b|\bfainted\b/],
  // “大出血” is also shopping slang for deep discounts; require a person or injury.
  ['bleeding', /(?:[伤傷]口|[产產]后|產後|生完|手[术術]后|手術後|[车車][祸禍]|摔|撞|割|我|他(?![们們])|她(?![们們])|孩子|小孩|宝宝|寶寶|老人|爸|[妈媽]|病人)[^，。！？!?,]{0,6}大出血(?!价|價|促|甩|特|[优優]|折|[减減]|清[仓倉]|放送)|大出血(?:怎[么麼]办|怎麼辦|不止|休克|昏迷)|血止不住|止不住血|血流不止|出血不止|流了(?:很多|好多|一大堆|一地)(?:的)?血|流很多血|\bsevere bleeding\b|\bbleeding\s+(?:heavily|badly|a lot|profusely|everywhere)\b|\b(?:won['’]t|will not|can['’]t|cannot|doesn['’]t|does not)\s+stop\s+(?:the\s+)?bleeding\b|\bbleeding\s+(?:won['’]t|will not|doesn['’]t|does not)\s+stop\b/],
  ['anaphylaxis', /(?:过敏|過敏)[^。！？!?]{0,8}(?:喉[咙嚨]|嗓子|嘴唇|舌[头頭]|[脸臉]|眼睛)(?:都|也|有点|有點|开始|開始)?(?:肿|腫|[发發]紧|[发發]緊)|(?:严重|嚴重)(?:过敏|過敏)反[应應]|(?:过敏|過敏)性休克|\b(?:having|in|going into|went into)\s+anaphyla|\banaphylactic\s+(?:shock|reaction)\b|\bthroat\s+(?:is\s+)?(?:swelling|closing|tight(?:ening)?)\b|\b(?:lips?|tongue|face)\s+(?:is\s+|are\s+)?(?:swelling|swollen)\b[^.!?]{0,40}\ballerg|\ballergic reaction\b[^.!?]{0,40}\b(?:throat|breath|swell)/],
  ['seizure', /(?<!(?:眼皮|眼睛|嘴角|眼角|肌肉|[脸臉]部|小?腿|手指).{0,3})抽搐|[癫癲][痫癇](?:发作|發作)|羊[癫癲][疯瘋]|口吐白沫|\b(?:having|had|has|is having)\s+(?:a\s+)?seizures?\b|\bseizing\b|\bconvuls(?:ing|ions?)\b/],
  ['ingestion', /(?:误吞|誤吞|误食|誤食|吞(?:了|下|进|進)?|吃(?:了|下|进|進))[^。！？!?]{0,8}(?:[纽鈕]扣[电電]池|[电電]池|磁[铁鐵]|磁珠|吸[铁鐵]石)|\bswallow(?:ed|s)?\b[^.!?]{0,20}\b(?:batter(?:y|ies)|magnets?)\b|\bate\s+(?:a\s+)?(?:button\s+|coin\s+)?(?:batter(?:y|ies)|magnets?)\b/],
  ['poisoning', /中毒|(?:误吞|誤吞|误食|誤食|吞(?:了|下)?|(?:不小心)?喝(?:了|下)).{0,12}(?:清洁剂|清潔劑|洗涤剂|洗滌劑|漂白水|药|藥)|poison(?:ing|ed)?|(?:swallowed|drank|ingested).{0,30}(?:cleaner|detergent|bleach|medicine|pills)/],
  ['self-harm', /不想(?:再)?活(?:了|下去)?|活不下去|想(?:自杀|自殺|自伤|自傷|死)|(?:想|打算|准备|準備)(?:要)?(?:结束|結束)(?:自己|我)?的?生命|(?:do not|don['’]t) want to (?:live|be alive)(?: anymore| any more)?|\b(?:want|plan|intend) to end my life\b|suicid(?:e|al)|kill myself|hurt myself/],
];
const emergency = new RegExp(EMERGENCY_PATTERNS.map(([, pattern]) => `(?:${pattern.source})`).join('|'), 'gi');
const topicPatterns = EMERGENCY_PATTERNS.map(([topic, pattern]) => [topic, new RegExp(pattern.source, 'i')]);

/** The emergency topic of a current disclosure, or null. */
function currentEmergencyTopic(message) {
  if (typeof message !== 'string') return null;
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
      // A general-knowledge question about warning signs ("心脏病发作前有什么征兆",
      // "what are the signs of a heart attack") names a condition, not a person
      // in it. Only that exact question shape is skipped; a disclosure such as
      // "我爸有心脏病发作的症状" still routes.
      const suffix = clause.slice(match.index + match[0].length);
      if (/^\s*(?:之?前)?(?:会|會)?(?:有)?(?:什[么麼]|哪些)(?:样的?|樣的?)?(?:征兆|徵兆|前兆|症状|症狀|迹象|跡象|表现|表現)/.test(suffix)
        || /\bwhat\s+(?:are|is)\s+(?:the\s+)?(?:(?:early|warning|common)\s+)*(?:signs?|symptoms?)\s+of\s+(?:an?\s+)?$/i.test(prefix)) continue;
      const nearby = prefix.slice(-40).replace(/["'“”‘’]\s*$/, '').trim();
      if (/(?:不是|没有|沒有|并非|並非|否认|否認|从未|從未|未|无|無|不)\s*(?:真的|再|已经|已經|发生|發生|觉得|覺得|表示|说|說)?\s*$|\b(?:no(?:\s+longer)?|not|never|(?:did|do|does|have|has) not|(?:didn['’]t|don['’]t|doesn['’]t|haven['’]t|hasn['’]t))\s*(?:(?:currently|now|really)\s*)?(?:have|feel|feeling|experience|experienced|say|saying)?\s*(?:(?:any|very|severe|sharp|intense|bad)\s*){0,3}$/i.test(nearby)) continue;
      return topicPatterns.find(([, pattern]) => pattern.test(match[0]))?.[0] || 'general';
    }
  }
  return null;
}

// One short, widely published first-aid line per topic. The 911 instruction
// always comes first and the dispatcher's instructions take precedence.
const EMERGENCY_LINES = {
  stroke: ['嘴歪、说话不清或半边无力可能是中风：记下症状开始的时间告诉接线员，不要自己开车去医院。', '嘴歪、說話不清或半邊無力可能是中風：記下症狀開始的時間告訴接線員，不要自己開車去醫院。', 'A drooping face, slurred speech or weakness on one side can be a stroke: note when the symptoms started and tell the dispatcher. Do not drive to the hospital yourself.'],
  cardiac: ['胸痛或疑似心脏病发作时不要自己开车去医院，按接线员的指示做。', '胸痛或疑似心臟病發作時不要自己開車去醫院，按接線員的指示做。', 'For chest pain or a possible heart attack, do not drive yourself to the hospital; follow the dispatcher’s instructions.'],
  breathing: ['按接线员的指示做，并打开门锁方便救护人员进入。', '按接線員的指示做，並打開門鎖方便救護人員進入。', 'Follow the dispatcher’s instructions and unlock the door for responders.'],
  unconscious: ['叫不醒或没有正常呼吸时，按接线员的指示做，不要离开他。', '叫不醒或沒有正常呼吸時，按接線員的指示做，不要離開他。', 'If the person cannot be woken or is not breathing normally, follow the dispatcher’s instructions and stay with them.'],
  bleeding: ['用干净的布用力按住伤口，等待救护车。', '用乾淨的布用力按住傷口，等待救護車。', 'Press firmly on the wound with a clean cloth while you wait for the ambulance.'],
  anaphylaxis: ['如有医生开的肾上腺素笔（EpiPen），按说明使用。', '如有醫生開的腎上腺素筆（EpiPen），按說明使用。', 'If a prescribed epinephrine auto-injector (EpiPen) is available, use it as directed.'],
  seizure: ['让他侧躺，移开周围硬物，不要往嘴里塞东西。', '讓他側躺，移開周圍硬物，不要往嘴裡塞東西。', 'Turn the person on their side, move hard objects away and do not put anything in their mouth.'],
  ingestion: ['吞下纽扣电池或磁铁可能很快造成严重伤害，不要催吐。', '吞下鈕扣電池或磁鐵可能很快造成嚴重傷害，不要催吐。', 'A swallowed button battery or magnet can cause serious injury quickly; do not induce vomiting.'],
};

function emergencyResponse(message, locale = 'zh-Hans') {
  if (typeof message !== 'string' || message.length > 5000) return null;
  const topic = currentEmergencyTopic(message);
  if (!topic) return null;
  const index = locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;
  const pick = (...values) => values[index];
  // The first sentence is always the 911 instruction, on the normal and the
  // degraded path alike. Poison Control and 988 stay on every card.
  const answer = [
    pick('请立即拨打 911。', '請立即撥打 911。', 'Call 911 now.'),
    EMERGENCY_LINES[topic]?.[index],
    pick('疑似中毒可联系 Poison Control：1-800-222-1222；自杀或情绪危机可拨打或发短信至 988。不要等待 BayBay 回复，也不要依赖生成的诊断。',
      '疑似中毒可聯絡 Poison Control：1-800-222-1222；自殺或情緒危機可撥打或傳簡訊至 988。不要等待 BayBay 回覆，也不要依賴生成的診斷。',
      'For a possible poisoning, call Poison Control at 1-800-222-1222; for suicide or emotional crisis, call or text 988. Do not wait for BayBay or rely on a generated diagnosis.'),
  ].filter(Boolean).join(locale === 'en' ? ' ' : '');
  const safety = {
    kind: 'emergency', topic,
    title: pick('现在就打 911', '現在就打 911', 'Call 911 now'),
    actions: [
      { id: 'call-911', label: pick('拨打 911', '撥打 911', 'Call 911'), href: 'tel:911', primary: true },
      { id: 'call-poison-control', label: 'Poison Control 1-800-222-1222', href: 'tel:+18002221222' },
      { id: 'call-988', label: pick('988 危机热线', '988 危機熱線', '988 crisis line'), href: 'tel:988' },
    ],
    // A frightened family member needs the call button, not feedback or
    // generic follow-up chips. Clients that understand these flags hide them.
    hideFollowups: true, hideFeedback: true,
  };
  return { ok: true, answer, safetyRoute: 'emergency', emergencyTopic: topic, responseMode: 'safety', degraded: false, safety,
    sources: [{ id: 'safety-911', title: '911', url: 'https://www.911.gov/' }, { id: 'safety-poison', title: 'Poison Control', url: 'https://www.poisonhelp.org/' }, { id: 'safety-988', title: '988 Lifeline', url: 'https://988lifeline.org/' }],
    suggestedGuides: [], suggestedActions: [], matchingPosts: [], interactiveCards: [], followups: [] };
}

const MEDICARE_GUIDE = 'bay-area-medicare-hicap-medi-cal-guide';
const TAX_GUIDE = 'bay-area-free-tax-help-vita-calfile-guide';
const professionalGuideSlugs = { medicare: MEDICARE_GUIDE, insurance: MEDICARE_GUIDE, tax: TAX_GUIDE };
// The guarded model path boosts and cites the published pillar guide of each
// topic. A slug missing from the application catalog is skipped, never invented.
const PILLAR_GUIDES = { ...professionalGuideSlugs,
  immigration: 'bay-area-naturalization-official-path-guide',
  medical: 'bay-area-first-doctor-insurance-network-guide',
  legal: 'california-tenant-deposit-rights-help-guide' };
const guideLabels = {
  [MEDICARE_GUIDE]: { en: 'Medicare, Medi-Cal and HICAP counseling preparation', 'zh-Hant': 'Medicare、Medi-Cal 與 HICAP 諮詢準備' },
  [TAX_GUIDE]: { en: 'VITA, TCE and CalFile tax-help preparation', 'zh-Hant': 'VITA、TCE 與 CalFile 報稅求助準備' },
};
const HICAP_URL = 'https://www.aging.ca.gov/Programs_and_Services/Medicare_Counseling/';
const VITA_URL = 'https://www.irs.gov/individuals/free-tax-return-preparation-for-qualifying-taxpayers';
// Official contacts on the resource card. Every phone number and URL here is
// already published in a BAYLINK pillar guide's verified source list.
const RESOURCES = {
  hicap: { title: ['HICAP 免费 Medicare 咨询', 'HICAP 免費 Medicare 諮詢', 'HICAP free Medicare counseling'], phone: '1-800-434-0222', url: HICAP_URL },
  'medi-cal': { title: ['DHCS：Medi-Cal 申请与续保', 'DHCS：Medi-Cal 申請與續保', 'DHCS: Medi-Cal applications and renewals'], url: 'https://www.dhcs.ca.gov/medi-cal/' },
  vita: { title: ['IRS VITA／TCE 免费报税点查询', 'IRS VITA／TCE 免費報稅點查詢', 'IRS VITA/TCE free tax help'], phone: '800-906-9887', url: VITA_URL },
  calfile: { title: ['加州 FTB：CalFile 等网上申报方式', '加州 FTB：CalFile 等網上申報方式', 'California FTB: CalFile and online filing'], url: 'https://www.ftb.ca.gov/file/ways-to-file/online/index.html' },
  uscis: { title: ['USCIS 官方网站', 'USCIS 官方網站', 'USCIS official website'], url: 'https://www.uscis.gov/' },
  'uscis-legal-help': { title: ['USCIS：如何找合规的移民法律服务', 'USCIS：如何找合規的移民法律服務', 'USCIS: find legitimate immigration legal services'], url: 'https://www.uscis.gov/scams-fraud-and-misconduct/avoid-scams/find-legal-services' },
  'health-center': { title: ['HRSA 社区医疗中心查询', 'HRSA 社區醫療中心查詢', 'HRSA: find a health center'], url: 'https://findahealthcenter.hrsa.gov/' },
  'courts-self-help': { title: ['加州法院自助中心', '加州法院自助中心', 'California Courts Self-Help'], url: 'https://selfhelp.courts.ca.gov/' },
  'calbar-legal-help': { title: ['加州律师协会：免费法律援助', '加州律師協會：免費法律援助', 'State Bar of California: free legal help'], url: 'https://www.calbar.ca.gov/public/legal-resources/free-legal-help' },
};
const TOPIC_RESOURCES = { medicare: ['hicap', 'medi-cal'], insurance: ['hicap', 'medi-cal'], tax: ['vita', 'calfile'], immigration: ['uscis', 'uscis-legal-help'], medical: ['health-center'], legal: ['courts-self-help', 'calbar-legal-help'] };

// “移民” alone is a life stage (新移民, 刚移民来的爸妈, 移民家庭), not a legal
// question. It counts only together with a status or filing word. Green card,
// naturalization and asylum questions are professional on their own.
function immigrationTopic(message) {
  if (/绿卡|綠卡|入籍|庇护|庇護|\b(?:green cards?|asylum|naturali[sz](?:ation|e)|uscis)\b/i.test(message)) return true;
  const residual = message.replace(/新移民|[刚剛]移民|移民[来來]|移民家庭/g, ' ');
  if (/移民/.test(residual) && /[签簽][证證]|律[师師]|身份|[递遞]件/.test(message)) return true;
  const english = message.replace(/\b(?:new|recent|newly arrived)\s+immigrants?\b|\bimmigrant\s+famil(?:y|ies)\b/gi, ' ');
  return /\bimmigra(?:tion|nts?)\b/i.test(english) && /\b(?:green card|visas?|citizenship|naturali[sz]|asylum|lawyers?|attorneys?|status|petitions?|filing)\b/i.test(message);
}
// “医疗” alone (医疗中心, 中文医疗服务, 医疗翻译志愿者) is not a medical decision.
function medicalTopic(message) {
  if (/医疗|醫療/.test(message) && /诊断|診斷|处方|處方|症状|症狀|用药|用藥|[该該]不[该該]吃/.test(message)) return true;
  if (/诊断|診斷|处方|處方|[药藥][^。？?！!]{0,8}(?:[该該]不[该該]吃|能不能吃|要不要吃)|(?:[该該]不[该該]吃|能不能吃|要不要吃)[^。？?！!]{0,4}[药藥]/.test(message)) return true;
  return /\b(?:medical diagnosis|prescriptions?|diagnose (?:me|my|him|her|them))\b|\bshould (?:i|he|she|we|they) (?:take|stop taking)\b[^.?!]{0,30}\b(?:medication|medicine|pills?|drugs?)\b/i.test(message);
}
const PROFESSIONAL_TOPICS = [
  ['immigration', immigrationTopic, 'USCIS', 'https://www.uscis.gov/'],
  ['medicare', message => /\b(?:medicare|hicap)\b/i.test(message), 'Medicare', 'https://www.medicare.gov/'],
  ['insurance', message => /医保|醫保|\b(?:health insurance|medi[- ]cal)\b/i.test(message), 'Covered California', 'https://www.coveredca.com/coverage-basics/'],
  ['medical', medicalTopic, 'MedlinePlus', 'https://medlineplus.gov/'],
  ['tax', message => /报税|報稅|税务|稅務|\b(?:vita|tce|calfile|tax return|tax advice|tax filing|tax help|tax preparation|file (?:my )?taxes)\b/i.test(message), 'IRS', 'https://www.irs.gov/'],
  ['legal', message => /法律意见|法律意見|法律咨询|法律諮詢|驱逐|驅逐|\b(?:legal advice|eviction)\b/i.test(message), 'California Courts Self-Help', 'https://selfhelp.courts.ca.gov/'],
];

function professionalTopics(message) {
  if (typeof message !== 'string' || message.length > 5000) return [];
  return PROFESSIONAL_TOPICS.filter(([, matches]) => matches(message)).map(([kind]) => kind);
}

function catalogGuide(slug, locale, context) {
  // Resolve only known published IDs from this application's current catalog.
  // A missing guide must not produce an invented route; translated catalogs
  // supply presentation only and never override the canonical guide URL.
  const catalog = context.guideCatalog === undefined ? require('../data/guide-catalog.json') : context.guideCatalog;
  const english = context.englishGuideCatalog === undefined ? require('../data/guide-catalog.en.json') : context.englishGuideCatalog;
  const canonical = Array.isArray(catalog) && catalog.find(row => row.slug === slug && row.url === `/guides/${slug}` && typeof row.title === 'string');
  if (!canonical) return null;
  const translated = english instanceof Map ? english.get(slug) : Array.isArray(english) ? english.find(row => row.slug === slug) : undefined;
  const title = locale === 'en'
    ? (typeof translated?.title === 'string' && translated.title.trim() && !/[\u3400-\u9fff]/u.test(translated.title) ? translated.title : guideLabels[slug]?.en)
    : locale === 'zh-Hant' ? guideLabels[slug]?.['zh-Hant'] || canonical.title : canonical.title;
  return title ? { slug, title, url: canonical.url } : null;
}

function relatedSafetyGuides(kinds, locale, context) {
  return [...new Set(kinds.map(kind => professionalGuideSlugs[kind]).filter(Boolean))].map(slug => catalogGuide(slug, locale, context)).filter(Boolean);
}

/** Deterministic resource card for a professional topic. */
function professionalGuard(kinds, locale = 'zh-Hans', context = {}) {
  if (!kinds?.length) return null;
  const index = locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;
  const resources = [...new Set(kinds.flatMap(kind => TOPIC_RESOURCES[kind] || []))].map(id => {
    const row = RESOURCES[id];
    return { id, title: row.title[index], url: row.url, ...(row.phone ? { phone: row.phone, href: `tel:+1${row.phone.replace(/\D/g, '').slice(-10)}` } : {}) };
  });
  const guides = [...new Set(kinds.map(kind => PILLAR_GUIDES[kind]).filter(Boolean))].map(slug => catalogGuide(slug, locale, context)).filter(Boolean);
  return { kind: 'professional', topic: kinds[0], topics: kinds, resources, guides };
}

/** Rules appended to BayBay's model instructions for a professional topic. */
function professionalInstructions(guard) {
  const contacts = guard.resources.map(row => `${row.title}${row.phone ? ` ${row.phone}` : ''} (${row.url})`).join('; ');
  return `\nProfessional-topic guard (${guard.topics.join(', ')}). Give a useful general answer, never a refusal or a one-line redirect: explain the general process, what to prepare and the official entry points from the evidence, and cite the matching BAYLINK guide with [[source-id]] when it is in evidence. Do not decide this person's individual eligibility, case outcome, diagnosis, medication or dosage, tax liability or legal position; say which official office, free counselor or licensed professional can decide it. Name the relevant official contact in the answer: ${contacts}. Never ask for and never repeat full ID, Social Security, A-number, receipt or case numbers, medical records or a home address, and tell the user not to send them. Do not invent fees, processing times, deadlines or eligibility rules that are not in the evidence.`;
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
      { id: 'safety-hicap', title: 'California Department of Aging: HICAP', url: HICAP_URL },
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
      { id: 'safety-vita', title: 'IRS: VITA/TCE tax help', url: VITA_URL },
      { id: 'safety-calfile', title: 'California FTB: online filing options', url: 'https://www.ftb.ca.gov/file/ways-to-file/online/index.html' },
    );
  }
  if (answer.length) answer.push(en ? 'These are official reference links and preparation steps, not a live source check. Do not send the documents or full identifiers to BayBay.'
    : hant ? '以上是官方參考入口與準備事項，不是本次即時網頁核驗。請勿把材料或完整識別號碼傳給 BayBay。'
      : '以上是官方参考入口与准备事项，不是本次即时网页核验。请勿把材料或完整识别号码传给 BayBay。');
  return { answer: answer.join('\n\n'), sources };
}

/** Deterministic professional template: legacy clients, the planner route and
 * BayBay's degraded floor. BayBay v2 answers with a guarded model call. */
function professionalResponse(message, locale = 'zh-Hans', context = {}) {
  const kinds = professionalTopics(message);
  if (!kinds.length) return null;
  const en = locale === 'en', traditional = locale === 'zh-Hant';
  const [kind, , title, url] = PROFESSIONAL_TOPICS.find(([value]) => value === kinds[0]);
  const preparation = professionalPreparation(kinds, locale);
  const boundary = en ? `Start with ${title}'s official resource. Rules depend on your circumstances and the current published requirements. Avoid sharing full IDs, case numbers, home addresses or medical records here. For a personal determination, contact the appropriate qualified professional or the official service.` : traditional ? `先從 ${title} 的官方入口核對。適用規則取決於你的具體情況和最新公布要求。請勿在此提供完整證件、案件號、住址或病歷；個人判定應由合資格專業人士或官方服務確認。` : `先从 ${title} 的官方入口核对。适用规则取决于你的具体情况和最新公布要求。请勿在此提供完整证件、案件号、住址或病历；个人判定应由合资格专业人士或官方服务确认。`;
  return { ok: true, answer: [preparation.answer, boundary].filter(Boolean).join('\n\n'), safetyRoute: 'professional', safetyTopic: kind, responseMode: 'safety', degraded: false,
    safety: professionalGuard(kinds, locale, context),
    sources: [{ id: `safety-${kind}`, title, url }, ...preparation.sources], suggestedGuides: relatedSafetyGuides(kinds, locale, context), suggestedActions: [], matchingPosts: [], interactiveCards: [], followups: [] };
}

/** Full deterministic routing: a current emergency first, then the professional template. */
function safetyResponse(message, locale = 'zh-Hans', context = {}) {
  if (typeof message !== 'string' || message.length > 5000) return null;
  return emergencyResponse(message, locale) || professionalResponse(message, locale, context);
}

module.exports = { safetyResponse, emergencyResponse, professionalResponse, professionalTopics, professionalGuard, professionalInstructions, currentEmergencyTopic, EMERGENCY_PATTERNS, PILLAR_GUIDES };
