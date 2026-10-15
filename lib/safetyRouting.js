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
// FAST stroke wording shared by the strong patterns below and the weaker signs
// in weakStrokeSigns(). One-sided words: 半边/一侧/单侧/左右侧 may stand alone
// before a symptom; 一边 and 左边/右边 need a body part (一边…一边 means "while").
const ONE_SIDE = String.raw`(?:半[边邊]|一[侧側]|(?:单|單)[侧側]|[左右]半[边邊]|[左右][侧側])`;
const ONE_SIDE_WITH_PART = String.raw`(?:一[边邊]|[左右][边邊])`;
// One side of the body numb or weak is a strong sign. A single limb is strong
// only for weakness: one numb hand (一边手麻了 after sleeping on it, 一边腿麻了
// after sitting) is a weak sign in weakStrokeSigns().
const BODY_PART = String.raw`(?:身子|身体|身體|手脚|手腳|肢体|肢體)`;
const LIMB_PART = String.raw`(?:手臂|胳膊|胳臂|手)`;
const LOWER_PART = String.raw`(?:腿|脚|腳)`;
const FACE_PART = String.raw`(?:[脸臉]部|[脸臉]|面部|嘴角|嘴巴|嘴)`;
const LEAD = String.raw`(?:突然|忽然)?(?:也|都|又)?(?:变得|變得|开始|開始|有点|有點)?`;
const WEAKNESS = String.raw`(?:无力|無力|[没沒](?:有)?力(?:[气氣])?|使不上劲|使不上勁|不能[动動]|[动動]不了|抬不起来|抬不起來|抬不起|举不起来|舉不起來|不听使唤|不聽使喚|[瘫癱])`;
const NUMB = String.raw`(?:[发發]麻|麻木|麻了)`;
// 麻 alone counts on the face (他一侧脸麻), never 麻辣, 麻婆, 麻将 or 麻烦.
const FACE_NUMB = String.raw`[发發]?麻(?:木|了)?(?![辣婆将將酱醬烦煩雀油花])`;
// 歪着笑 / 歪了一下笑 is a smirk, not a droop.
const NOT_SMIRK = String.raw`(?![着著了]?(?:一下)?(?:笑|一笑))`;
const FACE_SIGN = String.raw`(?:突然|忽然)?(?:也|都)?(?:往下|向下|有点|有點|开始|開始)?(?:下垂|垂|耷拉|歪${NOT_SMIRK}|塌|${FACE_NUMB}|僵)`;
// Speech words: 含糊其辞 (evasive) and 不清不楚 (murky dealings) are idioms, never
// symptoms; 感动得说不出话 (speechless) is not either.
const UNCLEAR = String.raw`(?:不清(?!不楚)|含糊(?!其)|含混)`;
const SPEECH = String.raw`(?:说话|說話|讲话|講話)${UNCLEAR}|口齿不清|口齒不清|口齿含糊|口齒含糊|说不清(?:楚)?话|說不清(?:楚)?話|讲不清(?:楚)?话|講不清(?:楚)?話|吐字不清|(?<![得到])(?:说不出话|說不出話|讲不出话|講不出話)`;
// English stroke signs. Numbness and paralysis are body words; weakness and a
// droop also describe wifi, tents, paint or a team's defense, so they need the
// body named ("the left side of his body is weak", "his face droops on one side",
// "weakness in her left arm"). "His left side is weak" alone is a weak sign.
const EN_SIDE = String.raw`(?:one|the\s+left|the\s+right|(?:his|her|my|their)\s+(?:left|right))\s+side`;
const EN_BODY = String.raw`(?:his|her|my|their|the)\s+(?:body|face)`;
const EN_DROOP = String.raw`(?:weak(?:ness)?|droop(?:ing|y|s|ed)?|sagging|limp)`;
// A twisted mouth or face with a degree word between: 嘴有点歪, 脸有点歪, 嘴巴好像歪了.
const FACE_DEGREE = String.raw`(?:突然|忽然|好像)?(?:也|都|又)?(?:往下|向下|往一[边邊]|有点|有點|有些|稍微|稍稍|一点|一點|明显|明顯)?`;
// FAST signs (face, arm, speech). strokeSignMentioned() reuses these without the
// named-stroke patterns below, so a past stroke is not by itself a symptom.
const STROKE_SIGNS = [
  String.raw`嘴(?:巴|角)?${FACE_DEGREE}歪${NOT_SMIRK}|口角歪斜|口眼歪斜|[脸臉]${FACE_DEGREE}歪${NOT_SMIRK}`,
  // 突然…说话含糊 and 说话突然含糊 (either order of the sudden onset).
  String.raw`(?:突然|忽然)[^。！？!?]{0,10}(?:${SPEECH})`,
  String.raw`(?:说话|說話|讲话|講話|口齿|口齒|吐字)(?:突然|忽然)(?:就|变得|變得|有点|有點|开始|開始)?(?:${UNCLEAR}|说不清|說不清|讲不清|講不清)`,
  // A drooping or numb face on one side: 一边脸往下垂, 半边脸麻木, 一侧嘴角下垂,
  // 他一侧脸麻, 脸有一边垂下来了.
  String.raw`(?:${ONE_SIDE}|${ONE_SIDE_WITH_PART})(?:的)?${FACE_PART}${FACE_SIGN}`,
  String.raw`[脸臉](?:部)?(?:有)?(?:${ONE_SIDE}|${ONE_SIDE_WITH_PART})${FACE_SIGN}`,
  String.raw`(?:嘴角|嘴巴)(?:突然|忽然)?(?:也|都)?(?:往下|向下|有点|有點)?歪${NOT_SMIRK}`,
  // One side of the body weak or numb: 一边手脚无力, 半边身体麻木, 右边身子没力气.
  String.raw`半[边邊](?:身子|身体|身體|[脸臉])?(?:突然)?(?:无力|無力|[没沒](?:有)?力[气氣]|${FACE_NUMB}|不能[动動]|[动動]不了)`,
  String.raw`(?:${ONE_SIDE}|${ONE_SIDE_WITH_PART})(?:的)?${BODY_PART}${LEAD}(?:${WEAKNESS}|${NUMB})|${ONE_SIDE}(?:的)?${LEAD}(?:${WEAKNESS}|${NUMB})`,
  // One limb weak on one side: 一侧手抬不起来, 左边胳膊没力气, 我爸左手抬不起来了
  // (not 左右手, both hands). Benign and long-standing causes are in explainedSign().
  String.raw`(?:${ONE_SIDE}|${ONE_SIDE_WITH_PART})(?:的)?(?:${LIMB_PART}|${LOWER_PART})${LEAD}${WEAKNESS}|(?<![左右])[左右](?:手臂|胳膊|胳臂|手|臂|腿)${LEAD}${WEAKNESS}`,
  String.raw`\b(?:face|mouth|smile)\s+(?:is\s+|was\s+)?(?:suddenly\s+)?droop(?:ing|y|s|ed)?\b|\bfacial droop|\bdroop(?:ing|y)\s+(?:(?:his|her|my|their|the)\s+)?(?:face|mouth|smile)\b`,
  String.raw`\bslurred speech\b|\bspeech\s+(?:is\s+|was\s+)?(?:suddenly\s+)?slurred\b|\bslurring\b|\bsuddenly\s+(?:can(?:not|['’]t)|could(?:n['’]t| not))\s+(?:speak|talk|move)\b`,
  String.raw`\bone side of (?:his|her|my|their) (?:body|face)\b[^.!?]{0,20}\b(?:weak|numb|droop)`,
  // Numbness or paralysis on one side: "his left side went numb", "numbness on one side".
  String.raw`\b(?:one|left|right)\s+side\s+(?:of\s+${EN_BODY}\s+)?(?:(?:is|went|has\s+gone|feels|felt|suddenly|now)\s+){0,3}(?:numb|paraly[sz]ed)\b`,
  String.raw`\b(?:numb(?:ness)?|paraly(?:sis|[sz]ed))\s+(?:\w+\s+){0,2}(?:on|in)\s+${EN_SIDE}\b`,
  // Weakness or a droop with the body named.
  String.raw`\b(?:one|left|right)\s+side\s+of\s+${EN_BODY}\s+(?:(?:is|went|has\s+gone|feels|felt|suddenly|now|looks)\s+){0,3}${EN_DROOP}\b`,
  String.raw`\b${EN_DROOP}\s+(?:\w+\s+){0,2}(?:on|in)\s+${EN_SIDE}\s+of\s+${EN_BODY}\b`,
  String.raw`\b(?:face|mouth|smile|body)\s+(?:is\s+|was\s+|looks\s+|feels\s+)?(?:suddenly\s+)?${EN_DROOP}\s+(?:on|in)\s+(?:one|the\s+left|the\s+right)\s+side\b`,
  // One limb weak on one side: "his left arm is numb and weak", "weakness in her
  // right leg", "can't lift his left arm".
  String.raw`\b(?:left|right)\s+(?:arm|leg|hand)\s+(?:(?:is|was|went|has\s+gone|feels|felt|got|suddenly|now|so|very|really)\s+){1,3}(?:\w+\s+and\s+)?(?:weak|limp|paraly[sz]ed)\b|\bweak(?:ness)?\s+in\s+(?:his|her|my|their|the|one)\s+(?:left|right)\s+(?:arm|leg|hand)\b|\b(?:can(?:not|['’]t)|could(?:n['’]t| not)|unable to)\s+(?:lift|raise|move)\s+(?:(?:his|her|my|their|the)\s+)?(?:left|right)\s+(?:arm|leg|hand)\b`,
];
const STROKE = new RegExp([
  ...STROKE_SIGNS,
  String.raw`(?:突然|好像|可能|疑似|是不是)(?:是)?中[风風]|中[风風]了`,
  String.raw`\b(?:having|had|is having|just had)\s+a\s+stroke\b`,
].join('|'));
const STROKE_SIGN_ANY = new RegExp(STROKE_SIGNS.join('|'), 'gi');
// SAFETY-1 (re-audit 10-11: 19/25 recall). Someone else's words, wider wording for
// seizures, swallowed medicines and household chemicals, collapse, gas, and a head
// injury with a red flag (headInjury() below). The everyday readings stay out: a
// cramp after exercise, a film's plot, a pill taken as prescribed, a gas bill.
const EN_SUBJECT = String.raw`(?:he|she|they|him|her|them|dad|daddy|mom|mommy|mum|mother|father|grandma|grandpa|grandmother|grandfather|granny|baby|infant|toddler|child|kid|boy|girl|son|daughter|husband|wife|partner|brother|sister|patient|person|man|woman|friend|someone|somebody|neighbou?r|roommate)`;
const UNCONSCIOUS = new RegExp([
  String.raw`[晕暈昏]倒|昏迷|昏厥|[晕暈昏](?:过|過)去|[晕暈]厥|不省人事|失去意[识識]|意[识識]不清|倒地不起|[叫喊]不醒|[叫喊](?:了|他|她|也|都|半天|几[声下]|幾[聲下]){0,3}[没沒](?:有)?反[应應]`,
  String.raw`(?:老人|孩子|小孩|宝宝|寶寶|爸|[妈媽]|[爷爺]爷|[爷爺]爺|奶奶|外公|外婆|老公|老婆|老伴|他|她)(?:突然)?[没沒](?:有)?(?:反[应應]|意[识識])(?!到|过来|過來)`,
  String.raw`\b(?:is|was|are|were|went|fell|became|lying|found)\s+(?:\w+\s+)?unconscious\b(?!\s+(?:bias|mind|level|thoughts?|process(?:es)?|memor))|\bunconscious\s+(?:and|now|on)\b`,
  String.raw`\b${EN_SUBJECT}\b(?:\s+\w+){0,2}\s+unresponsive\b`,
  // "I almost passed out when I saw the price" is a figure of speech.
  String.raw`(?<!\b(?:almost|nearly)\s)\bpassed out\b(?!\s+(?:the\s+)?(?:flyers?|cand(?:y|ies)|copies|food|samples|leaflets|papers|cards|tickets|gifts|water|snacks))`,
  String.raw`\b(?:won['’]t|will not|can['’]t|cannot|doesn['’]t|does not|didn['’]t|did not)\s+wake\s+(?:up|him|her|them)\b`,
  String.raw`\b${EN_SUBJECT}\b(?:\s+(?!almost\b|nearly\b)\w+){0,2}\s+(?:fainted|blacked out)\b`,
].join('|'));
// A person collapsed; a tent, a market or a bridge did not ("her tent collapsed"). Read
// after the lexicon, so "he collapsed and isn't breathing" keeps the breathing card.
const COLLAPSED = new RegExp(String.raw`\b${EN_SUBJECT}\s+(?:(?:just|suddenly|has|had|then)\s+){0,2}collapsed\b`, 'i');
const SEIZURE = new RegExp([
  String.raw`(?<!(?:眼皮|眼睛|嘴角|眼角|肌肉|[脸臉]部|小?腿|手指).{0,3})抽搐|[癫癲][痫癇](?:发作|發作)|羊[癫癲][疯瘋]|口吐白沫|[惊驚]厥`,
  // 抽筋 is also a cramp: it counts with a fever, over the whole body, or as a small
  // child's sudden fit; a cramp after exercise is excluded in currentEmergencyTopic().
  String.raw`(?:[发發](?:高)?[烧燒]|高[烧燒]|[烧燒]到[^。！？!?，,]{0,4}度)[^。！？!?，,]{0,6}抽筋|(?:全身|浑身|渾身)(?:都|在|一直)?抽筋|(?:孩子|小孩|宝宝|寶寶|婴儿|嬰兒|幼儿|幼兒|儿子|兒子|女儿|女兒)(?:突然|忽然)?抽筋(?:了|起来|起來)`,
  String.raw`\b(?:having|had|has|is having)\s+(?:a\s+)?(?:febrile\s+|grand mal\s+)?seizures?\b|\b(?:is|are|was|were|started|starts|keeps|kept|been|began|now)\s+seizing\b|\bconvuls(?:ing|ions?)\b`,
].join('|'));
const CHEMICAL = String.raw`(?:洗衣凝珠|洗衣球|洗衣[液粉]|洗洁精|洗潔精|清洁剂|清潔劑|洗涤剂|洗滌劑|漂白[水剂劑粉]?|消毒[水液]|84消毒液|农药|農藥|老鼠药|老鼠藥|鼠药|鼠藥|杀虫剂|殺蟲劑|除草剂|除草劑|防冻液|防凍液|电子烟油|電子煙油|烟油|煙油|尼古丁|干燥剂|乾燥劑|樟脑丸|樟腦丸|洗甲水|管道疏通剂|管道疏通劑|通渠剂|通渠劑)`;
const PILLS = String.raw`(?:药片|藥片|药丸|藥丸|胶囊|膠囊|安眠药|安眠藥|止痛药|止痛藥|降压药|降壓藥|降糖药|降糖藥|维生素|維生素|铁剂|鐵劑)`;
const YOUNG = String.raw`(?:孩子|小孩|宝宝|寶寶|婴儿|嬰兒|幼儿|幼兒|儿子|兒子|女儿|女兒|狗|猫|貓)`;
const POISONING = new RegExp([
  String.raw`中毒`,
  String.raw`(?:误|誤)(?:吞|食|吃|服|喝)[^。！？!?，,]{0,12}(?:${CHEMICAL}|${PILLS}|药|藥)`,
  // Only an owner or a measure word between the verb and the chemical: 吃了一颗洗衣凝珠,
  // 喝了奶奶的消毒水; "吃了饭用洗洁精洗碗" is washing up.
  String.raw`(?:吞|吃|喝|舔)(?:了|下|进|進|下去|进去|進去)?(?:[^。！？!?，,]{1,4}的)?(?:一|两|兩|几|幾|半)?(?:颗|顆|个|個|口|粒|块|塊|点|點|些|瓶|包|片|袋)?${CHEMICAL}`,
  String.raw`(?:吞(?:了|下)?|(?:不小心)?喝(?:了|下)).{0,12}(?:清洁剂|清潔劑|洗涤剂|洗滌劑|漂白水|药|藥)`,
  // Object first: 把洗衣凝珠吃进去了 (anyone), 孩子把奶奶的药片吃了 (a child or a pet:
  // 提醒爸爸把药吃了 is a reminder, not an accident).
  String.raw`把[^。！？!?，,]{0,10}${CHEMICAL}[^。！？!?，,]{0,4}(?:吃|吞|喝|咽|舔)(?:了|下去|下|进去|進去|掉)`,
  String.raw`${YOUNG}[^。！？!?，,]{0,6}把[^。！？!?，,]{0,10}(?:${PILLS}|药|藥)[^。！？!?，,]{0,4}(?:吃|吞|喝|咽)(?:了|下去|下|进去|進去|掉)`,
  String.raw`(?:吃|吞|服)(?:了|下)?(?:一整瓶|整瓶|一瓶|一大把|一把|大量|过量|過量)[^。！？!?，,]{0,6}(?:${PILLS}|${CHEMICAL}|药|藥)|(?:药|藥)(?:物)?(?:过量|過量)|偷吃(?:了)?[^。！？!?，,]{0,6}(?:${PILLS}|${CHEMICAL}|药|藥)`,
  // Poison oak and poison ivy are rashes on a hike, not a poisoning.
  String.raw`poison(?:ing|ed)?(?!\s+(?:oak|ivy|sumac))|(?:swallowed|drank|ingested).{0,30}(?:cleaner|detergent|bleach|medicine|pills)`,
  String.raw`\b(?:accidentally|mistakenly)\s+(?:swallowed|ate|drank|ingested|took)\b|\boverdos(?:e|ed|ing)\b`,
  String.raw`\bgot into\b[^.!?]{0,30}\b(?:pills?|medicines?|medications?|meds|vitamins|cleaning|chemicals?|bleach|detergent|pods?|edibles?)\b`,
  String.raw`\b(?:swallowed|ate|drank|ingested|chewed|licked|bit into)\b[^.!?]{0,30}\b(?:bleach|detergent|laundry\s+(?:pods?|packets?)|tide\s+pods?|dishwasher\s+(?:pods?|tablets?)|cleaner|cleaning\s+(?:fluid|products?|solution)|antifreeze|pesticide|insecticide|rat\s+poison|weed\s+killer|lighter\s+fluid|lamp\s+oil|vape\s+(?:juice|liquid)|e-?liquid|nicotine)\b`,
  String.raw`\b(?:a\s+(?:whole|full)\s+bottle|an\s+entire\s+bottle|a\s+handful)\s+of\s+(?:\w+\s+){0,2}(?:pills?|tablets?|medicines?|meds|vitamins|gummies|tylenol|advil|ibuprofen|acetaminophen)\b`,
].join('|'));
const SELF_HARM = new RegExp([
  String.raw`不想(?:再)?活(?:了|下去)?|活不下去|想(?:自杀|自殺|自伤|自傷|死(?![你您妳]))|(?:想|打算|准备|準備)(?:要)?(?:结束|結束)(?:自己|我)?的?生命`,
  // Someone else's words: 朋友说要自杀, 他闹着要跳楼, 同学扬言轻生.
  String.raw`(?:要|想要|想|打算|准备|準備|计划|計劃|闹着要|鬧著要|吵着要|吵著要|威胁要|威脅要|扬言要?|揚言要?)(?:去)?(?:自杀|自殺|轻生|輕生|寻死|尋死|跳楼|跳樓|割腕|上吊|服毒)`,
  String.raw`(?:自杀|自殺|轻生|輕生|寻死|尋死|自残|自殘|割腕)(?!率|案|新[闻聞]|[题題]材|[话話]题|[话話]題)|活[着著](?:[没沒])(?:有)?(?:意思|意义|意義)`,
  String.raw`(?:do not|don['’]t) want to (?:live|be alive)(?: anymore| any more)?|\b(?:want|plan|intend) to end my life\b|suicid(?:e|al)|kill myself|hurt myself|\bself[- ]harm(?:ing)?\b`,
  String.raw`\bkill(?:s|ing|ed)?\s+(?:him|her|them|my|your)sel(?:f|ves)\b|\b(?:wants?|wanted|trying|tried|going|plans?|planning|threaten(?:s|ed|ing)?|talk(?:s|ing|ed)?\s+about)\s+(?:to\s+)?(?:hurt(?:ing)?|harm(?:ing)?)\s+(?:him|her|them)sel(?:f|ves)\b`,
  // "She wants to end it with her boyfriend" is a breakup.
  String.raw`\bend(?:ing)?\s+(?:it\s+all|(?:his|her|their|my)\s+(?:own\s+)?life)\b|\b(?:wants?|wanted|going|plans?|planning|threaten(?:s|ed|ing)?)\s+to\s+end\s+it\b(?!\s+(?:with|between)\b)|\b(?:wants?|wanted)\s+to\s+die\b`,
].join('|'));
// Someone hit by a vehicle (有人被车撞了躺在地上); "小心被车撞" is a warning.
const TRAUMA = new RegExp(String.raw`(?<!防止|避免|以免|小心|当心|當心|怕|担心|擔心|别|別|不要|不会|不會)被(?:车|車|汽车|汽車|卡车|卡車|公交车|公車|巴士)(?:子)?撞(?:了|倒|伤|傷|到|飞|飛)?|\b(?:was|got|been|is|just)\s+(?:just\s+)?(?:hit|run over|struck)\s+by\s+a\s+(?:car|truck|bus|van|vehicle|motorcycle)\b`, 'i');
// A gas smell or a carbon-monoxide alarm: leave first, then call. A gas bill is not one.
const GAS = new RegExp([
  String.raw`(?:煤气|煤氣|燃气|燃氣|天然气|天然氣|瓦斯)(?:的)?(?:味|味道|泄漏|洩漏|泄露|洩露|漏了|漏气|漏氣|外泄|外洩)|(?:闻到|聞到)(?:了)?(?:一股)?(?:煤气|煤氣|燃气|燃氣|天然气|天然氣|瓦斯)`,
  String.raw`一氧化碳(?:报警器|報警器|警报器|警報器|探测器|探測器|报警|報警|警报|警報)(?:一直|在|突然|又){0,2}(?:响|響|叫|鸣|鳴)`,
  String.raw`\b(?:smell(?:s|ed|ing)?|smells like)\s+(?:of\s+)?(?:natural\s+)?gas\b|\bgas\s+(?:leak(?:s|ing)?|smell)\b|\b(?:carbon monoxide|co)\s+(?:alarm|detector)\b[^.!?]{0,20}\b(?:going off|beeping|sounding|went off|keeps)\b`,
].join('|'));
const EMERGENCY_PATTERNS = [
  ['stroke', STROKE],
  ['cardiac', /胸(?:口)?(?:很|非常|剧烈|劇烈)?(?:痛|疼)|心[脏臟]病(?:发作|發作|犯了)|心梗|心肌梗(?:塞|死)|心[脏臟](?:骤停|驟停)|chest pain|\bchest hurts\b|\bpain in (?:my|his|her|their) chest\b|\bheart attack\b|\bcardiac arrest\b/],
  ['breathing', /呼吸(?:很|非常|十分)?(?:困难|困難)|(?:喘|透)不(?:过|過|上)(?:气|氣)|不能呼吸|(?:[没沒]有|[没沒]了|停止)(?:了)?呼吸(?:了)?(?!困|道|急|[问問]|系|[练練]|[声聲]|[机機]|器|科|[内內]|到|新|一口)|can(?:not|['’]t) breathe|(?:unable|struggling) to breathe|(?:hav(?:e|ing)|has) trouble breathing|difficulty breathing|\b(?:isn['’]t|is not|aren['’]t|are not|wasn['’]t|stopped|has stopped|not)\s+breathing\b/],
  ['unconscious', UNCONSCIOUS],
  ['trauma', TRAUMA],
  // “大出血” is also shopping slang for deep discounts; require a person or injury.
  ['bleeding', /(?:[伤傷]口|[产產]后|產後|生完|手[术術]后|手術後|[车車][祸禍]|摔|撞|割|我|他(?![们們])|她(?![们們])|孩子|小孩|宝宝|寶寶|老人|爸|[妈媽]|病人)[^，。！？!?,]{0,6}大出血(?!价|價|促|甩|特|[优優]|折|[减減]|清[仓倉]|放送|了?[买買购購]|一把|剁手|消[费費])|大出血(?:怎[么麼]办|怎麼辦|不止|休克|昏迷)|血止不住|止不住血|血流不止|出血不止|流了(?:很多|好多|一大堆|一地)(?:的)?血|流很多血|\bsevere bleeding\b|\bbleeding\s+(?:heavily|badly|a lot|profusely|everywhere)\b|\b(?:won['’]t|will not|can['’]t|cannot|doesn['’]t|does not)\s+stop\s+(?:the\s+)?bleeding\b|\bbleeding\s+(?:won['’]t|will not|doesn['’]t|does not)\s+stop\b/],
  ['anaphylaxis', /(?:过敏|過敏)[^。！？!?]{0,8}(?:喉[咙嚨]|嗓子|嘴唇|舌[头頭]|[脸臉]|眼睛)(?:都|也|有点|有點|开始|開始)?(?:肿|腫|[发發]紧|[发發]緊)|(?:严重|嚴重)(?:过敏|過敏)反[应應]|(?:过敏|過敏)性休克|\b(?:having|in|going into|went into)\s+anaphyla|\banaphylactic\s+(?:shock|reaction)\b|\bthroat\s+(?:is\s+)?(?:swelling|closing|tight(?:ening)?)\b|\b(?:lips?|tongue|face)\s+(?:is\s+|are\s+)?(?:swelling|swollen)\b[^.!?]{0,40}\ballerg|\ballergic reaction\b[^.!?]{0,40}\b(?:throat|breath|swell)/],
  ['seizure', SEIZURE],
  // Object first as well: 把纽扣电池吞下去了 (completed swallowing only; 吞下去会怎样 is a question).
  ['ingestion', /(?:误吞|誤吞|误食|誤食|吞(?:了|下|进|進)?|吃(?:了|下|进|進))[^。！？!?]{0,8}(?:[纽鈕]扣[电電]池|[电電]池|磁[铁鐵]|磁珠|吸[铁鐵]石)|(?:[纽鈕]扣[电電]池|[电電]池|磁[铁鐵]|磁珠|吸[铁鐵]石)[^。！？!?，,]{0,6}(?:吞|吃|咽)(?:了|下去了|下了|进去了|進去了|进肚|進肚)|\bswallow(?:ed|s)?\b[^.!?]{0,20}\b(?:batter(?:y|ies)|magnets?)\b|\bate\s+(?:a\s+)?(?:button\s+|coin\s+)?(?:batter(?:y|ies)|magnets?)\b/],
  ['gas', GAS],
  ['poisoning', POISONING],
  ['self-harm', SELF_HARM],
];
const emergency = new RegExp(EMERGENCY_PATTERNS.map(([, pattern]) => `(?:${pattern.source})`).join('|'), 'gi');
const topicPatterns = EMERGENCY_PATTERNS.map(([topic, pattern]) => [topic, new RegExp(pattern.source, 'i')]);

// A requested translation/definition is quoted language, even when its wording
// contains "now". A later disclosure after "but" is a new clause.
const TRANSLATION_CLAUSE = /^\s*(?:(?:(?:请|請)(?:帮我|幫我)?)?(?:翻译|翻譯|定义|定義)|(?:please\s+)?(?:translate|define)\b|(?:what does|什[么麼]意思|什[么麼]是).{0,35}["'“‘「『])/i;
const splitClauses = message => message.split(/[。.!！？?;；，,\n]|(?:但是|但现在|但現在|\bbut\b)/i);
// Numbness after a dental visit (拔完牙半边脸还是麻的) is the anaesthetic, not a stroke.
const DENTAL = /牙医|牙醫|拔牙|拔完牙|补牙|補牙|麻药|麻藥|打麻|\b(?:dentist|dental|novocaine|lidocaine|numbing (?:shot|injection))\b/i;

/** The emergency topic of a current disclosure, or null. */
function currentEmergencyTopic(message) {
  if (typeof message !== 'string') return null;
  const clauses = splitClauses(message);
  for (const [clauseIndex, clause] of clauses.entries()) {
    if (TRANSLATION_CLAUSE.test(clause)) continue;
    for (const match of clause.matchAll(emergency)) {
      if (!currentDisclosure(clauses, clauseIndex, match)) continue;
      const topic = topicPatterns.find(([, pattern]) => pattern.test(match[0]))?.[0] || 'general';
      if (topic === 'stroke' && (notASymptom(message, clause, match) || explainedSign(message, clause, match))) continue;
      if (topic === 'seizure' && /抽筋/.test(match[0]) && CRAMP_CONTEXT.test(clause)) continue;
      return topic;
    }
  }
  return headInjury(message, clauses) || collapsed(clauses) || fallTrauma(clauses) || allergyAirway(message, clauses)
    || cardiacSigns(message, clauses) || suddenVisionStroke(message, clauses) || lowSugarConfusion(message, clauses) || weakStrokeSigns(message, clauses);
}
/** Whether some clause (not a translation request) has a current disclosure matching `pattern`. */
function currentMatch(clauses, pattern) {
  const global = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
  for (const [clauseIndex, clause] of clauses.entries()) {
    if (TRANSLATION_CLAUSE.test(clause)) continue;
    for (const match of clause.matchAll(global)) if (currentDisclosure(clauses, clauseIndex, match)) return true;
  }
  return false;
}

// H11 (audit 10-13, BB-1013-04): four phrasings the lexicon missed, each a combination
// of two signs. All of them still pass currentDisclosure() (no past, reported, class or
// denied wording) and stay linear-time (bounded gaps only).
// A fall from a height (balcony, roof, window, a numbered floor, a cliff) is trauma by itself;
// any fall (stairs, a ladder, a tree, a bed) is trauma when the person is not moving.
const PERSON_ZH = String.raw`(?:孩子|小孩|宝宝|寶寶|婴儿|嬰兒|幼儿|幼兒|儿子|兒子|女儿|女兒|老人|爸爸|爸|[妈媽]|[爷爺]爷|[爷爺]爺|奶奶|外公|外婆|老公|老婆|老伴|他|她|朋友|同学|同學|室友|邻居|鄰居|工人|有人)`;
const HIGH_PLACE_ZH = String.raw`(?:阳台|陽台|楼顶|樓頂|屋顶|屋頂|房顶|房頂|天台|窗户|窗戶|窗口|窗台|窗檯|高处|高處|悬崖|懸崖|[二三四五六七八九十0-9]+(?:楼|樓|层|層))`;
const LOW_PLACE_ZH = String.raw`(?:楼梯|樓梯|梯子|台阶|台階|树上|樹上|树|樹|床上|床|上铺|上鋪|椅子|桌子)`;
// The words between the person and 从 never hold 的 or an object (他的手机从阳台掉下去了 is a phone).
const PERSON_GAP_ZH = String.raw`(?:(?!的|手机|手機|玩具|球|钥匙|鑰匙|东西|東西|衣服|鞋|帽子|杯子|包)[^。！？!?，,]){0,8}`;
const FALL_VERB_ZH = String.raw`(?:摔|掉|跌|坠|墜|滚|滾)(?:了)?(?:下来|下來|下去|落|地)`;
const EN_HIGH_PLACE = String.raw`(?:balcony|roof|rooftop|window|building|cliff|deck|(?:second|third|fourth|2nd|3rd|4th)[- ]?(?:floor|stor(?:e)?y))`;
const EN_LOW_PLACE = String.raw`(?:stairs|staircase|ladder|tree|bunk bed|bed|chair|horse|bike|bicycle|scooter|skateboard|playground|monkey bars|slide)`;
const EN_FELL = String.raw`(?:fell|has fallen|had fallen|tumbled|plunged)\s+(?:off|from|out of|down)\s+(?:(?:a|an|the|his|her|their|our|my)\s+)?(?:\w+\s+)?`;
const FALL_FROM_HEIGHT = new RegExp([
  String.raw`${PERSON_ZH}${PERSON_GAP_ZH}(?:从|從)${HIGH_PLACE_ZH}[^。！？!?，,]{0,4}${FALL_VERB_ZH}`,
  String.raw`(?:坠楼|墜樓)`,
  String.raw`\b${EN_SUBJECT}\b(?:\s+\w+){0,2}\s+${EN_FELL}${EN_HIGH_PLACE}\b`,
].join('|'), 'i');
const ANY_FALL = new RegExp([
  String.raw`${PERSON_ZH}${PERSON_GAP_ZH}(?:从|從)(?:${HIGH_PLACE_ZH}|${LOW_PLACE_ZH})[^。！？!?，,]{0,4}${FALL_VERB_ZH}`,
  String.raw`(?:摔|跌|滑)(?:倒|了一跤|跤|下来|下來|下去|在地上)`,
  String.raw`\b${EN_SUBJECT}\b(?:\s+\w+){0,2}\s+(?:${EN_FELL}(?:${EN_HIGH_PLACE}|${EN_LOW_PLACE})|(?:fell|has fallen|had a fall|took a (?:bad )?fall)(?!\s+(?:asleep|in love|behind|apart|for|through|short|silent|ill|sick)))\b`,
].join('|'), 'i');
const NOT_MOVING = /一[动動]不[动動]|不[动動]了|[动動]不了|不能[动動]|[没沒](?:有)?[动動][静靜]|\b(?:is not|isn['’]t|not|is no longer|stopped|has stopped)\s+moving\b|\b(?:won['’]t|can['’]t|cannot|is unable to)\s+move\b(?!\s+(?:his|her|their|my|your|its|the|a|an|one|both|either|left|right)\b)/i;
function fallTrauma(clauses) {
  if (currentMatch(clauses, FALL_FROM_HEIGHT)) return 'trauma';
  return currentMatch(clauses, ANY_FALL) && currentMatch(clauses, NOT_MOVING) ? 'trauma' : null;
}
// A sting, a bite or a food, then a tight or swelling throat, tongue or lips: anaphylaxis
// (宝宝被蜜蜂蛰了以后全身起疹子，嗓子发紧; "stung by a wasp and his throat feels tight").
const ALLERGY_TRIGGER = /[蛰蜇螫]|叮|蜂|[过過]敏|花生|[坚堅]果|海[鲜鮮]|[虾蝦]|蟹|[鸡雞]蛋|牛奶|\b(?:stung|stings?|bee|wasp|hornet|yellow ?jacket|peanuts?|tree nuts?|nuts|shellfish|shrimp|allerg\w*)\b/i;
// Something just eaten counts too, unless the message is about a cold or a sore throat
// (感冒了嗓子有点肿，吃了药 is not anaphylaxis), or about spicy food (吃了辣的嗓子有点肿).
const ATE_SOMETHING = /(?:吃|喝)(?:了|完|[过過])|\b(?:ate|eating|eaten)\b/i;
const THROAT_ILLNESS = /感冒|着凉|著涼|咳嗽|扁桃|嗓子(?:疼|痛)|喉[咙嚨](?:疼|痛)|[发發]炎|上火|辣|火锅|火鍋|\b(?:cold|flu|strep|cough\w*|sore throat|tonsil\w*|spicy|hot ?pot)\b/i;
const AIRWAY_SWELLING = /(?:嗓子|喉[咙嚨]|[气氣]管)(?:眼)?(?:有点|有點|开始|開始|都|也|好像|突然|一直)?(?:[发發]紧|[发發]緊|紧|緊|肿|腫|堵|卡住)|舌[头頭](?:有点|有點|开始|開始|都|也)?(?:肿|腫|大了)|嘴唇(?:有点|有點|开始|開始|都|也)?(?:肿|腫)|\bthroat\s+(?:(?:feels?|is|was|getting|got|going|seems?|keeps)\s+){1,2}(?:\w+\s+)?(?:tight|swollen|swelling|closing(?:\s+up)?)\b|\b(?:tongue|lips?)\s+(?:is\s+|are\s+)?(?:swelling|swollen)\b/i;
function allergyAirway(message, clauses) {
  const trigger = ALLERGY_TRIGGER.test(message) || (ATE_SOMETHING.test(message) && !THROAT_ILLNESS.test(message));
  return trigger && currentMatch(clauses, AIRWAY_SWELLING) ? 'anaphylaxis' : null;
}
// Chest tightness with a left arm that is numb or hurts, a cold sweat or a pale face
// (我老婆说胸闷，左手发麻，脸色很白) is a possible heart attack. 胸闷 alone stays the floor's.
const CHEST_TIGHT = /胸(?:口)?(?:很|有点|有點|特别|特別|突然|一直)?(?:[闷悶]|[发發]紧|[发發]緊|紧|緊|[压壓]|堵)|\bchest\s+(?:tightness|pressure|heaviness)\b|\bchest\s+(?:feels?|is|was|got)\s+(?:\w+\s+)?(?:tight|heavy)\b|\b(?:tight|heavy)\s+chest\b/i;
const CARDIAC_COMPANION = /左(?:手|臂|胳膊|胳臂|肩)(?:臂)?(?:也|都|有点|有點|开始|開始|突然)?(?:[发發]麻|麻|痛|疼|酸|[没沒]力)|(?:手臂|胳膊)(?:[发發]麻|麻木|痛|疼)|(?:冒|出)冷汗|[脸臉]色(?:很|[发發]|有点|有點|特别|特別)?(?:白|苍白|蒼白|[发發]青|[发發]灰)|下巴(?:痛|疼)|\bleft\s+arm\b|\barm\s+(?:is\s+|feels?\s+)?(?:numb|tingling|hurts)\b|\bjaw\s+(?:pain|hurts)\b|\bcold sweat|\bsweating\b|\b(?:very\s+)?(?:pale|gr[ae]y|clammy)\b/i;
const CHEST_EXERCISE = /健身|练胸|練胸|胸肌|卧推|臥推|俯卧撑|俯臥撐|\b(?:workout|gym|bench press|push-?ups?)\b/i;
function cardiacSigns(message, clauses) {
  return !CHEST_EXERCISE.test(message) && CARDIAC_COMPANION.test(message) && currentMatch(clauses, CHEST_TIGHT) ? 'cardiac' : null;
}
// BE-FAST: a sudden loss of vision with unsteady walking or odd speech
// (外公突然看不清东西，走路也不稳，说话怪怪的).
const SUDDEN_VISION = /(?:突然|忽然)[^。！？!?，,]{0,4}(?:看不清|看不见|看不見|眼前[发發]黑|[视視]力模糊|[视視][线線]模糊)|\bsudden(?:ly)?\s+(?:can(?:not|['’]t)\s+see|blurr?ed vision|vision loss|lost (?:his|her|their) (?:vision|sight))\b/i;
const BALANCE_OR_SPEECH = /走路(?:也|都|有点|有點)?不[稳穩]|站不[稳穩]|走不[稳穩]|[说說](?:话|話)(?:也|都)?(?:怪怪的|怪|奇怪|不清)|\b(?:can(?:not|['’]t) walk straight|losing (?:his|her|their) balance|off balance|unsteady|slurr\w*)\b/i;
// Very low blood sugar and barely responding (我妈血糖很低，人有点迷糊，叫她不太答应). Confusion alone
// (人有点迷糊) stays the floor's, so a model answer can say what to do first.
const LOW_SUGAR = /血糖(?:很|太|特别|特別|突然)?低|低血糖|\blow blood sugar\b|\bhypoglyc\w*/i;
const ALTERED = /[叫喊](?:她|他)?(?:也|都)?不(?:太)?(?:答应|答應|醒)|[没沒](?:有)?反[应應]|\b(?:barely respond\w*|not responding|unresponsive|won['’]t wake)\b/i;
function lowSugarConfusion(message, clauses) {
  return ALTERED.test(message) && currentMatch(clauses, LOW_SUGAR) ? 'unconscious' : null;
}
function suddenVisionStroke(message, clauses) {
  return BALANCE_OR_SPEECH.test(message) && currentMatch(clauses, SUDDEN_VISION) ? 'stroke' : null;
}
function collapsed(clauses) {
  for (const [clauseIndex, clause] of clauses.entries()) {
    const match = TRANSLATION_CLAUSE.test(clause) ? null : COLLAPSED.exec(clause);
    if (match && currentDisclosure(clauses, clauseIndex, match)) return 'unconscious';
  }
  return null;
}

// A cramp after a run, a swim or a stretch is not a fit, even with 全身.
const CRAMP_CONTEXT = /跑步|跑完|游泳|运动|運動|健身|锻炼|鍛煉|拉伸|伸展|球|爬山|骑车|騎車|马拉松|馬拉松|练习|練習|睡觉|睡覺|半夜|缺钙|缺鈣/;
// A blow to the head is an emergency when the same message reports a red flag:
// bleeding, confusion, vomiting, drowsiness, a seizure. "撞到头起了个包" or "没有流血"
// is not one; past, reported and class-lookup wording is excluded by currentDisclosure().
const HEAD_HIT = /(?:摔|跌|撞|磕|碰|砸)(?:倒|伤|傷|到|了|在|破)?[^。！？!?，,]{0,6}(?:头|頭|脑袋|腦袋|后脑|後腦|额头|額頭)|(?:头|頭|脑袋|腦袋|后脑勺|後腦勺)(?:被)?[^。！？!?，,]{0,3}(?:撞|磕|摔|砸|碰)(?:到|伤|傷|破|了)|\b(?:hit|bumped|banged|struck|smacked)\s+(?:his|her|my|their|the|its)\s+head\b|\bhead\s+(?:injury|trauma)\b|\bfell\b[^.!?]{0,30}\bhead\b/i;
const HEAD_RED_FLAG = /(?<!没|沒|没有|沒有|不|无|無|未)(?:流血|出血|流了(?:很多|好多|一些|一点|一點)?血|在流血)|(?<!不)(?:迷糊|糊涂|糊塗|意[识識]不清|神志不清|叫不醒|昏迷|[昏晕暈](?:过|過)去|一直吐|吐了|呕吐|嘔吐|抽搐|[说說]话不清|說話不清|想睡|嗜睡)|(?<!\bnot\s)(?<!n['’]t\s)(?<!\bno\s)\b(?:bleeding|confused|confusion|disoriented|vomit(?:s|ed|ing)?|throwing up|threw up|drowsy|unconscious|passed out|seizure|slurring)\b/i;
// H11: a fall, then the head bleeding in a later clause (奶奶在浴室摔倒起不来，头一直在流血).
// The head word and the red flag share a clause, so a scraped knee beside "头没事" is not one.
const FALL_ONLY = /(?:摔|跌|滑)(?:倒|了一跤|跤|下来|下來|下去|在地上)|\b(?:fell|has fallen|had a fall|took a (?:bad )?fall|slipped|tripped)\b(?!\s+(?:asleep|in love|behind|apart|for|through|short|silent|ill|sick))/i;
const HEAD_WORD = /[头頭]|[脑腦]袋|后[脑腦]|後[脑腦]|[额額][头頭]|\bhead\b/i;
function headInjury(message, clauses) {
  for (const [clauseIndex, clause] of clauses.entries()) {
    if (TRANSLATION_CLAUSE.test(clause)) continue;
    const hit = HEAD_HIT.exec(clause);
    if (hit && currentDisclosure(clauses, clauseIndex, hit)) {
      if (clauses.some(other => !TRANSLATION_CLAUSE.test(other) && HEAD_RED_FLAG.test(other))) return 'head-injury';
      continue;
    }
    const fall = FALL_ONLY.exec(clause);
    if (fall && currentDisclosure(clauses, clauseIndex, fall)
      && clauses.some(other => !TRANSLATION_CLAUSE.test(other) && HEAD_WORD.test(other) && HEAD_RED_FLAG.test(other))) return 'head-injury';
  }
  return null;
}

// Which FAST sign a stroke match describes; the guards below depend on it.
function signKind(text) {
  if (/[说說讲講话話]|口齿|口齒|吐字|舌|speech|speak|talk|slurr|garbl/i.test(text)) return 'speech';
  if (/[脸臉嘴]|面部|口角|口眼|\b(?:face|facial|mouth|smile)\b/i.test(text)) return 'face';
  if (/[手臂胳腿脚腳]|\b(?:arms?|hands?|legs?)\b/i.test(text)) return 'limb';
  if (/[身肢边邊侧側]|\b(?:side|body)\b/i.test(text)) return 'body';
  return 'other';
}

// Not a symptom at all, so neither the 911 card nor BayBay's degraded health floor
// applies: evasive or business talk (房东说话突然含糊起来，押金…; 他说话含糊，是不是在骗我),
// a dental anaesthetic (拔完牙半边脸麻), or a team's side ("his left side is weak in
// basketball"). Idioms (含糊其辞, 不清不楚) and smirks (歪着笑) are excluded in the patterns.
const EVASIVE = /骗|騙|撒谎|撒謊|说谎|說謊|隐瞒|隱瞞|心虚|心虛|敷衍|搪塞|推脱|推脫|\b(?:lying|lied|evasive|hiding something|dodg(?:e|ed|ing))\b/i;
const SERVICE_ROLE = /房东|房東|中介|经纪|經紀|客服|老板|老闆|店家|商家|卖家|賣家|销售|銷售|业务员|業務員|物业|物業|\b(?:landlord|realtor|agent|seller|vendor|customer service|sales(?:person|man|woman))\b/i;
const DEALING = /押金|定金|订金|訂金|退款|退钱|退錢|租金|房租|合同|合约|合約|价格|價格|报价|報價|费用|費用|收费|收費|赔偿|賠償|维修|維修|订单|訂單|发票|發票|\b(?:deposit|refund|price|contract|lease|rent|fee|charge|invoice|order|repair)s?\b/i;
// 感动得说不出话 / 紧张得突然说不出话: speechless, not aphasia.
const SPEECHLESS = /感动|感動|激动|激動|气得|氣得|吓得|嚇得|惊讶|驚訝|震惊|震驚|高兴得|高興得|哭得|笑得|紧张得|緊張得|害羞|尴尬|尷尬|无语|無語/;
const SPORT = /篮球|籃球|足球|网球|網球|排球|棒球|打球|比赛|比賽|球队|球隊|防守|进攻|進攻|\b(?:basketball|soccer|football|tennis|volleyball|baseball|hockey|golf|games?|match|team|defen[cs]e|offen[cs]e|drills?|court|player)\b/i;
function notASymptom(message, clause, match) {
  const kind = signKind(match[0]);
  if (/麻|numb/i.test(match[0]) && DENTAL.test(message)) return true;
  if (kind === 'speech' && /[说說讲講]不出/.test(match[0]) && SPEECHLESS.test(clause)) return true;
  if (kind === 'speech') return EVASIVE.test(message) || (SERVICE_ROLE.test(clause.slice(0, match.index)) && DEALING.test(message));
  if (kind === 'body' && /\bside\b/i.test(match[0])) return SPORT.test(clause);
  // 笑得嘴都歪了 / 气得脸都歪了 are figures of speech; a crooked photo or a brace is not a face.
  if (kind === 'face') return FACE_FIGURATIVE.test(clause);
  return false;
}
const FACE_FIGURATIVE = /笑得|笑到|笑歪|乐得|樂得|气得|氣得|照片|相片|图片|圖片|拍照|自拍|镜头|鏡頭|美颜|美顏|整容|牙套|正畸|\b(?:photo|picture|selfie|camera|braces)\b/i;

// A limb or one side of the body with a non-emergency explanation in the same
// message: slept on it, a frozen shoulder, a workout or vaccine, a lifelong or
// post-stroke condition (右手肩周炎抬不起来, 我爸中风后左手抬不起来). A clause that says the
// onset is new (突然, 刚才, 又, suddenly) still routes. Used for the 911 card
// only; the degraded floor still treats these as health worries.
const NEW_ONSET = /突然|忽然|一下子|刚才|剛才|刚刚|剛剛|又|\b(?:sudden(?:ly)?|all of a sudden|out of nowhere|just now|again)\b/i;
const PRESSURE = /睡觉压|睡覺壓|压到|壓到|压着|壓著|压麻|壓麻|枕着|枕著|\b(?:slept on|sleeping on|sleep on|lying on|lay on)\b/i;
const LIMB_CAUSE = /颈椎|頸椎|腕管|肩周炎|五十肩|肩膀|网球肘|網球肘|拉伤|拉傷|扭伤|扭傷|扭到|骨折|石膏|健身|举铁|舉鐵|运动后|運動後|跑步|爬山|打针|打針|疫苗|抽血|手术|手術|开刀|開刀|腱鞘炎|关节炎|關節炎|\b(?:pinched nerve|carpal tunnel|frozen shoulder|rotator cuff|tennis elbow|sprain\w*|fractur\w*|broken|cast|workout|gym|lifting|exercis\w*|vaccine|flu shot|booster|blood draw|surgery|operation|arthritis|tendinitis)\b/i;
const LONGSTANDING = /从小|從小|天生|一直(?:都|是|这样|這樣)|老毛病|后遗症|後遺症|康复|康復|复健|復健|中[风風](?:后|後|过|過|之后|之後|以后|以後)|\b(?:always|since (?:birth|childhood)|for years|chronic|after (?:a|his|her|the|my) stroke|stroke survivor|rehab)\b/i;
// "For years" next to the sign itself (右手瘫痪多年); elsewhere in the message it may
// describe another condition (糖尿病很多年了，今天一边手脚无力), so only the clause counts.
// Words that make a face sign current even after an old stroke (see explainedSign).
const FACE_NOW = /今天|今日|今早|今晚|早上|起床|起来|起來|现在|現在|刚|剛|怎么办|怎麼辦|急|救命|\b(?:today|this morning|tonight|now|right now|what (?:should|do) (?:i|we) do|help)\b/i;
const YEARS_IN_CLAUSE = /多年|好几年|好幾年|很多年|好多年|几十年|幾十年|长期|長期|\bfor (?:many )?years\b/i;
function explainedSign(message, clause, match) {
  const kind = signKind(match[0]);
  // A face that has drooped since a stroke last year (我爸去年中风，嘴有点歪，有适合他的
  // 活动吗) is the after-effect. Any sign of a new or worrying onset keeps the card:
  // 又歪了, 今天早上起来嘴歪了, 嘴歪了怎么办, "suddenly", "this morning".
  if (kind === 'face' && !NEW_ONSET.test(clause) && !FACE_NOW.test(message)) return CHRONIC_OR_AFTER_STROKE.test(message);
  if (!['limb', 'body'].includes(kind) || NEW_ONSET.test(clause)) return false;
  return PRESSURE.test(message) || LONGSTANDING.test(message) || YEARS_IN_CLAUSE.test(clause) || (kind === 'limb' && LIMB_CAUSE.test(message));
}

// Weaker FAST signs: alone each has an everyday reading (孩子口齿不清 and speech
// therapy, 肩周炎手抬不起来, 嘴角下垂 as a cosmetic worry, slurring after a party).
// They route as a stroke when the same clause says the onset was sudden (a speech
// change also when it happened 刚才 / 刚刚), or when two different signs (speech,
// face, arm) are described together, e.g. 我爸说话不清楚，手也抬不起来.
const EN_PERSON = String.raw`(?:his|her|my|their|(?:mom|mum|mother|dad|father|grandma|grandpa|grandmother|grandfather|granny|husband|wife|partner|son|daughter|brother|sister|friend|neighbou?r|aunt|uncle)['’]s)`;
const WEAK_STROKE_SIGNS = [
  ['speech', new RegExp(String.raw`(?:说话|說話|讲话|講話)(?:有点|有點|有些|变得|變得|开始|開始|也|都|又)?(?:${UNCLEAR}|不利索|不太清楚)|口齿不清|口齒不清|口齿含糊|口齒含糊|说不清(?:楚)?话|說不清(?:楚)?話|讲不清(?:楚)?话|講不清(?:楚)?話|吐字不清|(?<![得到])(?:说不出话|說不出話|讲不出话|講不出話)|(?<!一句|几句|幾句|两句|兩句|[电電])(?:话(?:都)?说不清|話(?:都)?說不清)|大舌[头頭]|\bslurr(?:ed|ing)\b|\b(?:can(?:not|['’]t)|could(?:n['’]t| not)|unable to)\s+(?:speak|talk)\s+(?:clearly|properly|normally|right)\b|\b(?:trouble|difficulty)\s+(?:speaking|talking)\b|\bgarbled\s+(?:speech|words)\b|\b(?:speech|words)\s+(?:is|are|was|were|sounds?|seems?)\s+(?:\w+\s+){0,2}(?:slurred|garbled|unclear(?!\s+(?:about|on|regarding|why|how|what|whether|if)\b)|off(?![-\w]))`, 'gi')],
  ['face', new RegExp(String.raw`嘴角(?:往下|向下)?(?:下垂|垂|耷拉)|[脸臉](?:往下|向下)(?:垂|耷拉)|嘴(?:巴)?歪${NOT_SMIRK}|\b(?:face|mouth|smile)\s+(?:is\s+|looks\s+|seems\s+)?(?:\w+\s+)?(?:lopsided|crooked|uneven|droop\w*|sag\w*)\b`, 'gi')],
  ['arm', new RegExp(String.raw`(?:手|胳膊|胳臂|手臂|[左右]手|[左右]臂)(?:也|都|又|突然|忽然|一下子)?(?:抬不起来|抬不起來|抬不起|举不起来|舉不起來|[没沒](?:有)?力[气氣]|使不上劲|使不上勁|无力|無力|[发發]麻|麻了|麻木|不听使唤|不聽使喚)|\b(?:can(?:not|['’]t)|could(?:n['’]t| not)|unable to)\s+(?:lift|raise|move)\s+(?:(?:his|her|my|their|the|one|either)\s+)?(?:(?:left|right)\s+)?(?:arm|hand|leg)s?\b|\b(?:arm|hand|leg)s?\s+(?:is|are|was|went|feels?|felt|got)\s+(?:suddenly\s+)?(?:weak|numb|limp)\b|\barm weakness\b|\bweak(?:ness)?\s+in\s+(?:his|her|my|their|one)\s+(?:left\s+|right\s+)?(?:arm|leg)\b|\b${EN_PERSON}\s+(?:left|right)\s+side\s+(?:is|was|went|feels?|felt|got|seems?|has\s+gone)\s+(?:\w+\s+)?(?:weak|limp|droopy)\b|\bweak(?:ness)?\s+(?:on|in)\s+(?:his|her|my|their)\s+(?:left|right)\s+side\b`, 'gi')],
];
const SUDDEN = /突然|忽然|一下子|\bsudden(?:ly)?\b|all of a sudden|out of nowhere/i;
const RECENT_ONSET = /刚才|剛才|刚刚|剛剛|\bjust\s+(?:now|started|began)\b/i;
// A long-standing or post-stroke condition (从小口齿不清, 中风后说话含糊、手抬不起来)
// is context for an outing, not a new emergency. A strong sign still routes.
const CHRONIC_OR_AFTER_STROKE = /从小|從小|天生|一直(?:都|是|这样|這樣)|多年|好几年|好幾年|长期|長期|老毛病|中[风風](?:后|後|过|過|之后|之後|以后|以後)|(?<![0-9一二两兩三四五六七八九十几幾半])[0-9一二两兩三四五六七八九十几幾半]+(?:多)?(?:年|个月|個月)(?:多)?前|去年|前年|后遗症|後遺症|康复|康復|复健|復健|\b(?:always|since (?:birth|childhood)|for years|chronic|after (?:a|his|her|the|my) stroke|stroke survivor|had a stroke|recover(?:ing|ed)|rehab)/i;
// "说话含糊、手抬不起来是中风的症状吗" asks about signs; it does not report them.
const SIGNS_QUESTION = /(?:什[么麼]|哪些|是不是|算不算|是否)[^。！？!?]{0,12}(?:征兆|徵兆|前兆|症状|症狀|迹象|跡象|表现|表現)|(?:征兆|徵兆|前兆|症状|症狀|迹象|跡象|表现|表現)[^。！？!?]{0,4}(?:吗|嗎|有哪些|是什[么麼])|\b(?:what|which)\s+(?:are|is)\s+(?:the\s+)?(?:(?:early|warning|common)\s+)*(?:signs?|symptoms?)\b|\b(?:are|is)\s+(?:these|those|this|that|they|it)\s+(?:the\s+)?(?:(?:early|warning|common)\s+)*(?:signs?|symptoms?)\b/i;

function weakStrokeSigns(message, clauses) {
  if (CHRONIC_OR_AFTER_STROKE.test(message) || SIGNS_QUESTION.test(message)) return null;
  const kinds = new Set();
  for (const [clauseIndex, clause] of clauses.entries()) {
    if (TRANSLATION_CLAUSE.test(clause)) continue;
    for (const [kind, pattern] of WEAK_STROKE_SIGNS) for (const match of clause.matchAll(pattern)) {
      if (!currentDisclosure(clauses, clauseIndex, match)) continue;
      if (notASymptom(message, clause, match) || explainedSign(message, clause, match)) continue;
      if (SUDDEN.test(clause) || (kind === 'speech' && RECENT_ONSET.test(clause))) return 'stroke';
      kinds.add(kind);
    }
  }
  return kinds.size >= 2 ? 'stroke' : null;
}

/** Whether the message describes any FAST stroke sign, strong or weak, whether or
 * not it routes to the 911 card: no sudden-onset or two-sign requirement and no
 * past, chronic or benign-cause exclusion. BayBay's degraded health floor uses it,
 * so the floor is a superset of the lexicon (我爸话都说不清了, "my mom has arm
 * weakness" still get 911/211 when the model is down). Translation requests,
 * idioms (含糊其辞, 不清不楚), business talk and dental numbness are not signs. */
function strokeSignMentioned(message) {
  if (typeof message !== 'string' || message.length > 5000) return false;
  for (const clause of splitClauses(message)) {
    if (TRANSLATION_CLAUSE.test(clause)) continue;
    for (const pattern of [STROKE_SIGN_ANY, ...WEAK_STROKE_SIGNS.map(([, weak]) => weak)]) {
      for (const match of clause.matchAll(pattern)) if (!notASymptom(message, clause, match)) return true;
    }
  }
  return false;
}

/** Whether a lexicon match reads as something happening to someone now: not a
 * report, translation, past or recovered episode, class lookup, warning-signs
 * question, unanswered message or denial. */
function currentDisclosure(clauses, clauseIndex, match) {
  const clause = clauses[clauseIndex];
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
  const current = last(/现在|現在|目前|刚刚|剛剛|刚才|剛才|今天|今日|今早|今晚|\b(?:now|today|just)\b/gi, currentPrefix);
  // A news report, translation exercise or past account is not evidence
  // that the speaker is currently in danger. A later present-tense cue
  // keeps a real current disclosure from being hidden by an earlier frame.
  const noncurrent = last(/以前|过去|過去|曾经|曾經|昨天|昨日|前天|去年|前年|之前|(?<![0-9一二两兩三四五六七八九十几幾半])[0-9一二两兩三四五六七八九十几幾半]+(?:多)?(?:年|个月|個月|周|週|[个個]?星期|天)(?:多)?前|上[个個](?:月|星期)|上[周週]|历史|歷史|新闻|新聞|报道|報導|文章|小说|小說|电影|電影|翻译|翻譯|例句|\b(?:history of|in the past|used to|previously|yesterday|last (?:night|week|month|year)|\w+ (?:years?|months?|weeks?|days?) ago|news|article|report|novel|movie|fictional|translate|translation|example sentence)\b/gi);
  // Starting yesterday is not a past-only episode when the same symptom
  // explicitly continues now. Inspect only its suffix and next clause;
  // general "now", recovery statements and reported/quoted text do not
  // revive a historical disclosure.
  const continuation = `${clause.slice(match.index + match[0].length)} ${clauses[clauseIndex + 1] || ''}`.slice(0, 240);
  const reported = /新闻|新聞|报道|報導|文章|小说|小說|电影|電影|翻译|翻譯|例句|\b(?:news|article|report|novel|movie|fictional|translate|translation|example sentence)\b/i.test(prefix);
  const stillCurrent = !reported && /(?:现在|現在|目前)(?:仍然|仍|还是|還是)(?:这样|這樣)|\bit\s+(?:is|'s)\s+still\s+happening\s+(?:right\s+)?now\b/i.test(continuation);
  if (noncurrent >= 0 && current <= noncurrent && !stillCurrent) return false;
  // A past or recovered episode can also be marked right after the
  // symptom: 晕倒过一次, 癫痫发作史, 心梗出院后, "had a stroke last year",
  // "two years ago". Only year/month/week scales count as past in English
  // ("started two hours ago" is still an emergency).
  const after = clause.slice(match.index + match[0].length);
  if (!stillCurrent && (/^[过過](?![去来來敏])|^\s*(?:的)?(?:病)?史/.test(after)
    || /出院|康复|康復|恢复|恢復|痊愈|痊癒|后遗症|後遺症|好转|好轉|去年|前年|(?<![0-9一二两兩三四五六七八九十几幾半])[0-9一二两兩三四五六七八九十几幾半]+(?:多)?(?:年|个月|個月)(?:多)?前|\blast (?:year|month|spring|summer|fall|autumn|winter)\b|\b(?:years?|months?|weeks?) ago\b|\bin (?:19|20)\d\d\b|(?<!(?:\bnot|n['’]t)\s+)\brecover(?:ed|ing|y)\b|\brehab/i.test(after.slice(0, 24)))) return false;
  // A class, course or talk about the topic (CPR 和心脏骤停急救课程, "a CPR
  // class for cardiac arrest") is an event lookup. Being in class or at
  // training when it happens is not: those location uses still route.
  if (/(?<![在上])(?:课程|課程|讲座|講座|培[训訓]|急救[课課]|工作坊)(?!班?(?:[上中时時里裡]|的时候|的時候|期[间間]))|(?<!\b(?:in|during|at|after|before|from|of|on)\s+(?:\S+\s+){0,2})\b(?:class(?:es)?|courses?|training|workshops?|seminars?|certification)\b/i.test(clause)) return false;
  // A general-knowledge question about warning signs ("心脏病发作前有什么征兆",
  // "what are the signs of a heart attack") names a condition, not a person
  // in it. Only that exact question shape is skipped; a disclosure such as
  // "我爸有心脏病发作的症状" still routes.
  const suffix = clause.slice(match.index + match[0].length);
  if (/^\s*(?:之?前)?(?:会|會)?(?:有|是)?(?:什[么麼]|哪些)(?:样的?|樣的?)?(?:征兆|徵兆|前兆|症状|症狀|迹象|跡象|表现|表現)|^\s*的(?:征兆|徵兆|前兆|症状|症狀|迹象|跡象|表现|表現)(?:是|有)(?:什[么麼]|哪些)/.test(suffix)
    || /\bwhat\s+(?:are|is)\s+(?:the\s+)?(?:(?:early|warning|common)\s+)*(?:signs?|symptoms?)\s+of\s+(?:an?\s+)?$/i.test(prefix)) return false;
  // "他没反应" after a message, call or post is an unanswered message,
  // not an unresponsive person (叫他没反应 / 叫不醒 still route).
  if (/^[^叫喊]*[没沒](?:有)?反[应應]$/.test(match[0]) && /消息|訊息|信息|微信|短信|简讯|簡訊|邮件|郵件|留言|回复|回覆|已读|已讀|电话|電話|群里|群裡|\b(?:texts?|messages?|emails?|app)\b/i.test(`${clauses[clauseIndex - 1] || ''} ${clause}`)) return false;
  const nearby = prefix.slice(-40).replace(/["'“”‘’]\s*$/, '').trim();
  if (/(?:不是|没有|沒有|并非|並非|否认|否認|从未|從未|未|无|無|不)\s*(?:真的|再|已经|已經|发生|發生|觉得|覺得|表示|说|說)?\s*$|\b(?:no(?:\s+longer)?|not|never|(?:did|do|does|have|has) not|(?:didn['’]t|don['’]t|doesn['’]t|haven['’]t|hasn['’]t))\s*(?:(?:currently|now|really)\s*)?(?:have|feel|feeling|experience|experienced|say|saying)?\s*(?:(?:any|very|severe|sharp|intense|bad)\s*){0,3}$/i.test(nearby)) return false;
  return true;
}

// One short, widely published first-aid line per topic. The 911 instruction
// always comes first and the dispatcher's instructions take precedence.
const EMERGENCY_LINES = {
  stroke: ['嘴歪、说话不清或半边无力可能是中风：记下症状开始的时间告诉接线员，不要自己开车去医院。', '嘴歪、說話不清或半邊無力可能是中風：記下症狀開始的時間告訴接線員，不要自己開車去醫院。', 'A drooping face, slurred speech or weakness on one side can be a stroke: note when the symptoms started and tell the dispatcher. Do not drive to the hospital yourself.'],
  cardiac: ['胸痛或疑似心脏病发作时不要自己开车去医院，按接线员的指示做。', '胸痛或疑似心臟病發作時不要自己開車去醫院，按接線員的指示做。', 'For chest pain or a possible heart attack, do not drive yourself to the hospital; follow the dispatcher’s instructions.'],
  breathing: ['按接线员的指示做，并打开门锁方便救护人员进入。', '按接線員的指示做，並打開門鎖方便救護人員進入。', 'Follow the dispatcher’s instructions and unlock the door for responders.'],
  unconscious: ['叫不醒或没有正常呼吸时，按接线员的指示做，不要离开他。', '叫不醒或沒有正常呼吸時，按接線員的指示做，不要離開他。', 'If the person cannot be woken or is not breathing normally, follow the dispatcher’s instructions and stay with them.'],
  bleeding: ['用干净的布用力按住伤口，等待救护车。', '用乾淨的布用力按住傷口，等待救護車。', 'Press firmly on the wound with a clean cloth while you wait for the ambulance.'],
  trauma: ['除非有危险，不要移动伤者；用干净的布按住出血处，按接线员的指示做。', '除非有危險，不要移動傷者；用乾淨的布按住出血處，按接線員的指示做。', 'Do not move the injured person unless they are in danger; press a clean cloth on any bleeding and follow the dispatcher’s instructions.'],
  anaphylaxis: ['如有医生开的肾上腺素笔（EpiPen），按说明使用。', '如有醫生開的腎上腺素筆（EpiPen），按說明使用。', 'If a prescribed epinephrine auto-injector (EpiPen) is available, use it as directed.'],
  seizure: ['让他侧躺，移开周围硬物，不要往嘴里塞东西。', '讓他側躺，移開周圍硬物，不要往嘴裡塞東西。', 'Turn the person on their side, move hard objects away and do not put anything in their mouth.'],
  ingestion: ['吞下纽扣电池或磁铁可能很快造成严重伤害，不要催吐。', '吞下鈕扣電池或磁鐵可能很快造成嚴重傷害，不要催吐。', 'A swallowed button battery or magnet can cause serious injury quickly; do not induce vomiting.'],
  poisoning: ['不要催吐。人清醒、呼吸正常时，也可以打 Poison Control 1-800-222-1222 问怎么处理，打电话时把药瓶或包装放在手边。', '不要催吐。人清醒、呼吸正常時，也可以打 Poison Control 1-800-222-1222 詢問處理方式，打電話時把藥瓶或包裝放在手邊。', 'Do not induce vomiting. If the person is awake and breathing normally, Poison Control at 1-800-222-1222 can also tell you what to do; keep the bottle or package with you when you call.'],
  'self-harm': ['如果有人可能伤害自己，不要让他独处，把刀具、药物等危险物品拿开；也可以拨打或发短信至 988 自杀与危机热线。', '如果有人可能傷害自己，不要讓他獨處，把刀具、藥物等危險物品拿開；也可以撥打或傳簡訊至 988 自殺與危機熱線。', 'If someone may hurt themselves, do not leave them alone and move knives, medicines and other dangerous items away; you can also call or text 988, the Suicide & Crisis Lifeline.'],
  gas: ['先离开屋子，到外面安全的地方再打电话；不要开关电灯电器，不要点火。', '先離開屋子，到外面安全的地方再打電話；不要開關電燈電器，不要點火。', 'Leave the building first and call from outside; do not switch lights or appliances on or off, and do not light anything.'],
  'head-injury': ['头部受伤后出血、迷糊或呕吐时，让他躺着别动，用干净的布按住出血处，按接线员的指示做。', '頭部受傷後出血、迷糊或嘔吐時，讓他躺著別動，用乾淨的布按住出血處，按接線員的指示做。', 'After a head injury with bleeding, confusion or vomiting, keep the person still, press a clean cloth on any bleeding and follow the dispatcher’s instructions.'],
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

// SAFETY-2: BayBay's no-model floor (paused, past the daily limit, provider down, or a
// template that replaced the answer). A question that may be an emergency but does not
// meet the card's bar (a weak stroke sign, 人有点迷糊, 突然看不清, choking, low blood
// sugar, or a card topic in the previous user turn) gets a 911-first answer and no site
// cards, instead of excerpts or listings that read as an answer.
const URGENT_SIGNS = /人(?:有点|有點|有些)?迷糊|(?:摔|跌|滑)倒[^。！？!?]{0,8}(?:起不来|起不來|爬不起来|爬不起來|站不起来|站不起來)|(?:全身|浑身|渾身)(?:都)?(?:起|长|長|出)(?:了)?(?:疹子|红疹|紅疹|风团|風團|荨麻疹|蕁麻疹)|[叫喊](?:她|他)?(?:也|都)?不太?(?:答应|答應)|\b(?:fell|has fallen)\b[^.!?]{0,30}\b(?:can(?:not|['’]t)|unable to)\s+get\s+up\b|\bhives\s+all\s+over\b|意[识識](?:有点|有點)?(?:模糊|迷糊)|神志不清|(?:突然|忽然)(?:看不清|看不见|看不見|眼前[发發]黑)|(?:剧烈|劇烈)(?:的)?[头頭](?:痛|疼)|[头頭]痛欲裂|胸[闷悶]|呼吸急促|嘴唇[发發]紫|(?:冒|出)冷汗|血糖(?:很|太|特别|特別)?低|舌[头頭][发發]硬|触电|觸電|溺水|窒息|噎住|卡住(?:了)?喉[咙嚨]|喉[咙嚨]被?卡住|\bchok(?:e|es|ed|ing)\b|\bdrown(?:ed|ing)?\b|\belectrocut\w*|\bblue lips\b|\bcold sweats?\b|\b(?:severe|worst|sudden)\s+headache\b|\bsudden(?:ly)?\s+(?:can(?:not|['’]t)\s+see|blurr?ed vision|vision loss)\b|\b(?:is|seems|became|got)\s+(?:very\s+|really\s+|suddenly\s+)?(?:confused|disoriented)\b|\blow blood sugar\b|\bhypoglyc\w*/gi;
/** The emergency topic for the no-model floor: the card's own topic, a FAST sign, an
 * urgent sign ('general'), or a card topic in the last user turn; else null. */
function possibleEmergencyTopic(message, history = []) {
  if (typeof message !== 'string' || message.length > 5000) return null;
  const topic = currentEmergencyTopic(message);
  if (topic) return topic;
  if (strokeSignMentioned(message)) return 'stroke';
  const clauses = splitClauses(message);
  for (const [clauseIndex, clause] of clauses.entries()) {
    if (TRANSLATION_CLAUSE.test(clause)) continue;
    for (const match of clause.matchAll(URGENT_SIGNS)) if (currentDisclosure(clauses, clauseIndex, match)) return 'general';
  }
  const lastUser = (Array.isArray(history) ? history : []).filter(turn => turn?.role === 'user' && typeof turn.content === 'string').at(-1);
  return lastUser && lastUser.content.length <= 5000 ? currentEmergencyTopic(lastUser.content) : null;
}
/** The floor itself: 911 (with 988 or Poison Control for those topics) in the first
 * sentence, then that BayBay cannot answer now and 211 for local services. */
function emergencyFloor(topic, locale = 'zh-Hans') {
  const index = locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;
  const pick = (...values) => values[index];
  const first = topic === 'self-harm'
    ? pick('如果有人可能伤害自己，请立即拨打 911，或拨打、发短信至 988 自杀与危机热线。', '如果有人可能傷害自己，請立即撥打 911，或撥打、傳簡訊至 988 自殺與危機熱線。', 'If someone may hurt themselves, call 911 now, or call or text 988, the Suicide & Crisis Lifeline.')
    : ['poisoning', 'ingestion'].includes(topic)
      ? pick('如果有人误吞了东西或可能中毒，请立即拨打 911；人清醒、呼吸正常时也可以打 Poison Control：1-800-222-1222。', '如果有人誤吞了東西或可能中毒，請立即撥打 911；人清醒、呼吸正常時也可以打 Poison Control：1-800-222-1222。', 'If someone swallowed something or may be poisoned, call 911 now; if they are awake and breathing normally, Poison Control at 1-800-222-1222 can also help.')
      : topic === 'gas'
        ? pick('如果闻到燃气味，先离开屋子，到外面立即拨打 911。', '如果聞到燃氣味，先離開屋子，到外面立即撥打 911。', 'If you smell gas, leave the building and call 911 from outside now.')
        : pick('如果情况紧急或有人突然身体不适，请立即拨打 911。', '如果情況緊急或有人突然身體不適，請立即撥打 911。', 'If this is an emergency or someone is suddenly unwell, call 911 now.');
  const rest = pick('BayBay 暂时无法回答这个问题，请不要等待回复。需要食物、住房等本地服务转介，可拨打 211。', 'BayBay 暫時無法回答這個問題，請不要等待回覆。需要食物、住房等本地服務轉介，可撥打 211。', 'BayBay cannot answer this right now; do not wait for a reply. For food, housing or other local services, call 211.');
  const actions = [{ id: 'call-911', label: '911', href: 'tel:911' },
    ...(topic === 'self-harm' ? [{ id: 'call-988', label: '988', href: 'tel:988' }] : []),
    ...(['poisoning', 'ingestion'].includes(topic) ? [{ id: 'call-poison-control', label: 'Poison Control', href: 'tel:+18002221222' }] : []),
    { id: 'call-211', label: '211', href: 'tel:211' }];
  return { answer: `${first}${locale === 'en' ? ' ' : ''}${rest}`, actions, topic };
}

const MEDICARE_GUIDE = 'bay-area-medicare-hicap-medi-cal-guide';
const TAX_GUIDE = 'bay-area-free-tax-help-vita-calfile-guide';
const professionalGuideSlugs = { medicare: MEDICARE_GUIDE, insurance: MEDICARE_GUIDE, tax: TAX_GUIDE };
// The guarded model path boosts and cites the published pillar guide of each
// topic. A slug missing from the application catalog is skipped, never invented.
const PILLAR_GUIDES = { ...professionalGuideSlugs,
  immigration: 'bay-area-naturalization-official-path-guide',
  medical: 'bay-area-first-doctor-insurance-network-guide',
  legal: 'california-tenant-deposit-rights-help-guide',
  // An SSN question usually comes from a newcomer (BBL-04): the first-month checklist.
  ssa: 'bay-area-newcomer-first-month-checklist' };
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
  // SSA's phone line is in the BAYLINK Social Security guide; the number-and-card
  // page is SSA's own entry for applying (BBL-04).
  ssa: { title: ['SSA：社会安全号码与社安卡', 'SSA：社會安全號碼與社安卡', 'SSA: Social Security number and card'], phone: '1-800-772-1213', url: 'https://www.ssa.gov/number-card' },
};
const TOPIC_RESOURCES = { medicare: ['hicap', 'medi-cal'], insurance: ['hicap', 'medi-cal'], tax: ['vita', 'calfile'], immigration: ['uscis', 'uscis-legal-help'], medical: ['health-center'], legal: ['courts-self-help', 'calbar-legal-help'], ssa: ['ssa'] };

// Routing reads the task first and status words second (BBL-04, BBENG-02): "刚拿绿卡，
// 怎么申请 Medi-Cal / 社安号" asks about Medi-Cal or an SSN; the green card or immigrant
// visa only says who is asking. Such a status clause does not make the question an
// immigration one when another task is named; a question about the status itself
// (申请绿卡, 绿卡面试, H-1B 宽限期, OPT, 签证过期) still is.
const SSA_TASK = /社安[号號卡]|社会安全(?:号|号码|卡)|社會安全(?:號|號碼|卡)|社会保障(?:号|号码|卡)|社會保障(?:號|號碼|卡)|\bSSN\b|\bsocial security (?:number|card)s?\b/i;
const OTHER_TASK = /医保|醫保|\b(?:medi[- ]?cal|medicare|hicap|health insurance)\b|报税|報稅|驾照|駕照|驾驶执照|駕駛執照|州\s*ID|身份证明卡|\b(?:DMV|driver'?s licen[cs]e|state ID)\b|银行|銀行|开户|開戶|\bbank account\b/i;
const STATUS_CLAUSE = /(?:[刚剛才已]|已经|已經)?(?:拿到?|持有?|有)(?:了)?(?:绿卡|綠卡|移民[签簽][证證])(?:[来來](?:美国|美國|湾区|灣區)?)?|(?:绿卡|綠卡)持有人|移民[签簽][证證](?:入境|[来來](?:美国|美國|湾区|灣區)?)|\b(?:just got|have|with|holding|on|got|getting|received|after (?:getting|receiving)) (?:a |an |my |our |their |his |her |the )?(?:green cards?|immigrant visas?)\b|\bgreen[- ]card holders?\b/gi;
// Visa and status words that are immigration questions on their own. OPT, CPT and
// EAD are matched in capitals only ("opt out" is not a visa).
// H74 (audit 10-13, BB-1013-11): visa extensions and USCIS form numbers (I-485 pending, advance
// parole) are immigration questions too.
const VISA_STATUS = /\bH-?1B\b|\bH-?4\b|\bF-?1\s*(?:签证|簽證|学生|學生|visa|status|student)|\bL-1\b|\bI-20\b|宽限期|寬限期|身份(?:过期|過期|失效|转换|轉換|维持|維持|有问题|有問題)|(?:签证|簽證)(?:过期|過期|续签|續簽|面签|面簽|被拒|拒签|拒簽|状态|狀態)|移民律[师師]|\b(?:grace period|visa status|out of status|maintain(?:ing)? status|immigration (?:lawyer|attorney)s?)\b|(?:签证|簽證)[^。？?！!]{0,8}(?:延期|延长|延長)|\bI-?(?:90|94|129|130|131|140|485|539|751|765)\b|\badvance parole\b|回美证|回美證|返美证|返美證/i;
const VISA_ACRONYM = /\b(?:OPT|CPT|EAD)\b/;
// A visitor visa is context, as a green card is in STATUS_CLAUSE: parents visiting on a B2 visa
// who ask about museums or day trips are an outing question (H74 review). Only a question about
// the visa itself (extend, stay longer, overstay, an expired visa, a change of status) is
// immigration: 旅游签证 B2 可以延期吗, 我爸妈拿 B1/B2 签证来探亲，可以多待几个月吗.
// A coming expiry (review round 3) is the question only when it is not a deadline for something
// else (签证到期前想带他们去优胜美地玩, before my parents' tourist visa expires) and the ask is not an
// outing with no question about the visa (还有两个月过期，周末带他们去哪玩, expires soon so we want
// one last weekend trip — ideas?). 爸妈的旅游签证快到期了怎么办 and 过期了会怎样 stay immigration.
const VISITOR_VISA = /旅游签证|旅遊簽證|探亲签证|探親簽證|\bB-?1\s*\/\s*B-?2\b|\bB-?[12]\s*(?:签证|簽證|visas?|status)|(?:签证|簽證)\s*B-?[12]\b|\b(?:tourist|visitor|visiting) visas?\b/gi;
const VISITOR_VISA_ASK = /延期|延长|延長|多待|多留|多住|久留|待多久|能待|可以待|逾期|续签|續簽|转身份|轉身份|已(?:经|經)?(?:过期|過期|到期)|(?<![快要将將就上])(?:过期|過期|到期)了|\bextend(?:ed|ing|s)?\b|\bextension\b|\boverstay(?:ed|ing|s)?\b|\bexpired\b|\bchange (?:of |their |my |his |her |our )?(?:status|visa)\b|\bstay longer\b|\bhow long can\b|\bmaximum stay\b|\bI-?539\b/i;
const VISITOR_VISA_EXPIRY = /过期|過期|到期|\bexpir(?:e|es|ing|ation)\b/i;
const VISITOR_VISA_DEADLINE = /(?:过期|過期|到期)(?:之|以)?前|\b(?:before|until|till|by the time)\b[^.?!,;，。？！；]{0,40}\bexpir(?:e|es)\b/gi;
const VISITOR_VISA_WORRY = /怎么办|怎麼辦|会怎样|會怎樣|怎么处理|怎麼處理|后果|後果|还能留|還能留|能不能留|可以留|\bwhat happens\b|\bconsequences?\b|\bcan (?:they|we|he|she|i) (?:stay|remain)\b|\bwhat (?:do|should|can) (?:we|i|they) do\s*(?:about|if|when|now|[?？]|$)/i;
const VISITOR_OUTING = /去哪|玩|怎么去|怎麼去|景点|景點|博物馆|博物館|公园|公園|\b(?:trips?|ideas?|where (?:should|can|could) (?:we|i) (?:take|go)|what (?:should|can|could) (?:we|i) do with|things to do|sightseeing|outings?|visit)\b/i;
function visitorVisaQuestion(message) {
  const text = String(message);
  for (const match of text.matchAll(VISITOR_VISA)) {
    const before = text.slice(Math.max(0, match.index - 40), match.index).split(/[。？?！!]/).pop();
    const after = text.slice(match.index + match[0].length, match.index + match[0].length + 40).split(/[。？?！!]/)[0];
    const around = `${before}${match[0]}${after}`;
    if (VISITOR_VISA_ASK.test(around)) return true;
    if (VISITOR_VISA_EXPIRY.test(around.replace(VISITOR_VISA_DEADLINE, ' ')) && (VISITOR_VISA_WORRY.test(text) || !VISITOR_OUTING.test(text))) return true;
  }
  return false;
}
function immigrationTopic(message) {
  if (VISA_STATUS.test(message) || VISA_ACRONYM.test(message) || visitorVisaQuestion(message)) return true;
  // Another named task (SSN, Medi-Cal, DMV, bank, taxes): drop the asker's status clause first.
  const text = SSA_TASK.test(message) || OTHER_TASK.test(message) ? message.replace(STATUS_CLAUSE, ' ') : message;
  if (/绿卡|綠卡|入籍|庇护|庇護|\b(?:green cards?|asylum|naturali[sz](?:ation|e)|uscis)\b/i.test(text)) return true;
  const residual = text.replace(/新移民|[刚剛]移民|移民[来來]|移民家庭/g, ' ');
  if (/移民/.test(residual) && /[签簽][证證]|律[师師]|身份|[递遞]件/.test(residual)) return true;
  const english = text.replace(/\b(?:new|recent|newly arrived)\s+immigrants?\b|\bimmigrant\s+famil(?:y|ies)\b/gi, ' ');
  return /\bimmigra(?:tion|nts?)\b/i.test(english) && /\b(?:green card|visas?|citizenship|naturali[sz]|asylum|lawyers?|attorneys?|status|petitions?|filing)\b/i.test(english);
}
// “医疗” alone (医疗中心, 中文医疗服务, 医疗翻译志愿者) is not a medical decision.
// Medication and dosing questions are (BBENG-02): 要不要给他吃抗生素, 泰诺吃几片.
const MEDICATION = /抗生素|消炎药|消炎藥|退烧药|退燒藥|泰诺|泰諾|布洛芬|对乙酰氨基酚|對乙醯胺基酚|阿司匹林|[剂劑]量|吃[几幾](?:片|粒|颗|顆|毫升)|\b(?:antibiotics?|dosage|dosing|Tylenol|ibuprofen|acetaminophen|Motrin|Advil|aspirin)\b/i;
// H74: changing a dose is a medical decision (我妈血压 160，降压药要不要加量？), in every language.
const DOSE_CHANGE = /(?:[药藥]|降压|降壓|降糖|血压|血壓|血糖|胰岛素|胰島素)[^。？?！!]{0,10}(?:加量|减量|減量|加倍|减半|減半|停(?:掉|用|吃|药|藥)|换(?:药|成)|換(?:藥|成)|多吃|少吃|加一[片粒颗顆]|减一[片粒颗顆]|減一[片粒顆])|停药|停藥|换药|換藥|\b(?:increase|decrease|raise|lower|double|halve|skip|stop|change|adjust)\s+(?:my |his |her |their |the |our )?(?:mom'?s |dad'?s |\w+'s )?(?:dose|dosage|medications?|meds|insulin|blood pressure (?:medicine|medication|meds|pills?))\b/i;
// "How many mg / ml / tablets" is a dose only with a drug, a dosing verb or a person in the same
// sentence (review round 3): not "How many ml in a cup?" or "how much mg of caffeine in a latte".
const DOSE_AMOUNT = /\bhow (?:much|many) (?:\w+\s+){0,2}(?:mg|milligrams?|ml|pills?|tablets?)\b/i;
const DOSE_CONTEXT = /\b(?:medicines?|medications?|meds|drugs?|syrup|doses?|dosage|give|giving|take|taking|toddlers?|bab(?:y|ies)|infants?|kids?|child(?:ren)?|son|daughter|lbs?|pounds?|kg|kilos?|(?:year|month|week)[- ]olds?|mom|dad|mother|father|grandma|grandpa)\b/i;
const doseAmount = message => String(message).split(/[.?!。？！]/).some(sentence => DOSE_AMOUNT.test(sentence) && DOSE_CONTEXT.test(sentence));
function medicalTopic(message) {
  if (MEDICATION.test(message) || DOSE_CHANGE.test(message) || doseAmount(message)) return true;
  if (/医疗|醫療/.test(message) && /诊断|診斷|处方|處方|症状|症狀|用药|用藥|[该該]不[该該]吃/.test(message)) return true;
  // A repair or computer "diagnosis" (免费维修诊断, Fixit Clinic) is not medical.
  if (/(?<!维修|維修|故障|电脑|電腦|系统|系統|[车車]辆|[车車]輛|[车車])(?:诊断|診斷)|处方|處方|[药藥][^。？?！!]{0,8}(?:[该該]不[该該]吃|能不能吃|要不要吃)|(?:[该該]不[该該]吃|能不能吃|要不要吃)[^。？?！!]{0,4}[药藥]/.test(message)) return true;
  return /\b(?:medical diagnosis|prescriptions?|diagnose (?:me|my|him|her|them))\b|\bshould (?:i|he|she|we|they) (?:take|stop taking)\b[^.?!]{0,30}\b(?:medication|medicine|pills?|drugs?)\b/i.test(message);
}
// Lawsuits, small claims and a withheld deposit are legal questions. A lawyer alone is
// one too, except in an immigration question, whose card already has legal help.
// H74: a withheld deposit or unpaid wages in English ("my landlord won't return my security deposit")
// and 拖欠工资 / 欠薪 are legal questions too.
const LEGAL_ACTION = /法律意见|法律意見|法律咨询|法律諮詢|(?:驱逐|驅逐)(?!舰|艦)|起诉|起訴|打官司|小[额額](?:法庭|诉讼|訴訟)|(?<![报報广廣警忠预預公通转轉宣布佈])告(?:他|她|房东|房東|老板|老闆|公司|对方|對方)|(?:不退|扣|没退|沒退)(?:还|還)?押金|押金[^。？?！!]{0,8}(?:不退|没退|沒退|被扣)|拖欠工[资資]|欠薪|\b(?:legal advice|eviction|lawsuit|small claims|sue (?:my|the|him|her|them)|unpaid wages|wage theft)\b|\b(?:won['’]?t|will not|wouldn['’]?t|didn['’]?t|did not|refus(?:es|ed|ing) to)\s+(?:return|give (?:me |us )?back|refund|pay back)\s+(?:my |our |the )?(?:security )?deposit\b|\b(?:kept|withheld|withholding|deducted from)\s+(?:my|our|the) (?:whole |entire |full )?(?:security )?deposit\b/i;
const LAWYER = /律[师師]|\b(?:lawyers?|attorneys?)\b/i;
const legalTopic = message => LEGAL_ACTION.test(message) || (LAWYER.test(message) && !/律[师師]事[务務]所.{0,6}(?:开业|開業|活动|活動)/.test(message) && !immigrationTopic(message));
// H74: tax amounts and credits (我今年 W-2 收入 8 万，要交多少州税？ / Child Tax Credit) are tax questions.
// A search for a tax talk, workshop or other event (这周末有免费的报税讲座吗？) is an event ask, not
// the tax guard: an event noun with a find frame (有…吗, 哪里, 这周, 周六, 免费, any, is there, this
// weekend), and no personal tax matter (要不要报税, 要交多少, 能不能抵, 退税什么时候, my W-2, can I
// deduct, do I need to file). A question that only mentions an event (我参加了一个活动赢了奖金，要报税吗？)
// stays a tax question (H74 review).
const TAX_QUESTION = /报税|報稅|税务|稅務|州税|州稅|联邦税|聯邦稅|所得税|所得稅|退税|退稅|抵税|抵稅|抵扣|税表|稅表|交多少[税稅]|要交[^。？?！!]{0,6}[税稅]|\bW-?2\b|\b1099(?:-[A-Z]+)?\b|\b(?:vita|tce|calfile|tax return|tax advice|tax filing|tax help|tax preparation|file (?:my |our )?taxes|child tax credit|tax credits?|EITC|CalEITC|tax refund|tax brackets?|tax rates?|income tax|state tax|federal tax)\b|\bhow much (?:state |federal |income )?tax(?:es)?\b/i;
const TAX_EVENT_NOUN = /讲座|講座|工作坊|说明会|說明會|课程|課程|活动|活動|\btax (?:talks?|clinics?)\b|\b(?:workshops?|seminars?|events?|classes|webinars?|info(?:rmation)? sessions?)\b/i;
const TAX_EVENT_FIND = /有没有|有沒有|有[^。？?！!，,]{0,20}(?:吗|嗎)|哪里|哪裡|哪儿|哪兒|这周|這週|这个周末|這個週末|下周|下週|(?:周|週)[一二三四五六日天末]|星期[一二三四五六日天]|今天|明天|免费|免費|\b(?:any|is there|are there|where|when is|when are|this (?:saturday|sunday|weekend|week|month)|next (?:saturday|sunday|weekend|week)|on (?:saturday|sunday)|upcoming|near me|free)\b/i;
// Review round 3: the asker's own how-to (怎么报税, 如何報稅, 学费能报税吗, 报税抵扣, 海外收入要申报吗)
// is personal too; "教怎么报税的讲座" (a talk that teaches it) is still an event search.
const PERSONAL_TAX = /(?:怎么|怎麼|如何)(?:报税|報稅)(?!的)|(?:能|可以)(?:报税|報稅)(?:吗|嗎)|(?:报税|報稅)抵(?:扣|税|稅)|收入[^。？?！!]{0,6}(?:怎么报|怎麼報|如何报|如何報|申报|申報)|要(?:申报|申報)(?:吗|嗎)|要不要(?:报税|報稅|交税|交稅)|(?:要|需要|用|得)(?:报税|報稅)(?:吗|嗎)|要交[^。？?！!]{0,6}[税稅]|交多少|(?:能不能|能|可以|可不可以)抵(?:税|稅|扣)|退[税稅][^。？?！!]{0,8}(?:什么时候|什麼時候|多久|没到|沒到|到账|到賬)|我[^。？?！!]{0,12}(?:W-?2|1099)|\b(?:do|does|did|can|could|should|will|would|am|are|must) (?:i|we)\b[^.?!]{0,50}\b(?:deduct|claim|file|pay|owe|report|eligible|qualify)\b|\bmy (?:tax(?:es| return| refund)?|w-?2|1099|refund|deductions?|income)\b|\bhow much (?:state |federal |income )?tax(?:es)?\b/i;
const taxTopic = message => TAX_QUESTION.test(message) && (PERSONAL_TAX.test(message) || !(TAX_EVENT_NOUN.test(message) && TAX_EVENT_FIND.test(message)));
const PROFESSIONAL_TOPICS = [
  ['immigration', immigrationTopic, 'USCIS', 'https://www.uscis.gov/'],
  ['ssa', message => SSA_TASK.test(message), 'SSA', 'https://www.ssa.gov/number-card'],
  // 红蓝卡 (Medicare) and 白卡 (Medi-Cal) are the everyday Chinese names (API-BB-4B).
  ['medicare', message => /\b(?:medicare|hicap)\b|[红紅][蓝藍]卡/i.test(message), 'Medicare', 'https://www.medicare.gov/'],
  ['insurance', message => /医保|醫保|白卡(?![纸紙])|加州[医醫][疗療]补助|加州醫療補助|\b(?:health insurance|medi[- ]cal)\b/i.test(message), 'Covered California', 'https://www.coveredca.com/coverage-basics/'],
  ['medical', medicalTopic, 'MedlinePlus', 'https://medlineplus.gov/'],
  ['tax', taxTopic, 'IRS', 'https://www.irs.gov/'],
  ['legal', legalTopic, 'California Courts Self-Help', 'https://selfhelp.courts.ca.gov/'],
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

// General, stable facts the guarded model may explain for a professional topic.
// They say how a program works for everyone, never whether this person
// qualifies, and deliberately carry no amounts, income limits, dates or
// processing times: those change and may only come from cited evidence.
const TOPIC_BACKGROUND = {
  medicare: 'Medicare is federal health insurance, mainly for people 65 or older and some younger people with disabilities. Part A (A 部分) is hospital insurance: inpatient hospital stays, skilled nursing facility care after a qualifying hospital stay, hospice and some home health care; most people pay no Part A premium because they or their spouse paid Medicare taxes long enough while working (enough work credits). Part B (B 部分) is medical insurance: doctors\' services, outpatient care, preventive services and medical equipment; it has a monthly premium, which is higher at higher incomes. A and B are not two options to choose between: most people have both, which together are called Original Medicare. Part C (Medicare Advantage) is a private plan that people can choose instead of Original Medicare, usually bundling A, B and often D; Part D is prescription drug coverage; Medigap is private supplemental insurance for Original Medicare. When to sign up for Part B (for example while still covered by an employer plan), Original Medicare versus Medicare Advantage, and which drug plan fits depend on the person\'s own coverage, doctors, medicines and income; HICAP counselors compare these free of charge.',
  insurance: 'Medi-Cal is California\'s Medicaid program: free or low-cost health coverage for people who meet its income and other rules, applied for online through BenefitsCal (the state benefits portal), with the county social services office in person, by phone or by mail, or through Covered California. Covered California is the state marketplace for private health plans, with financial help that depends on household income. Medicare is federal coverage mainly for people 65 or older; some people have both Medicare and Medi-Cal. Which program fits and what it costs depend on the household\'s income, age, immigration status and current coverage, and are decided by the program itself.',
  tax: 'VITA (Volunteer Income Tax Assistance) offers free basic tax-return preparation by IRS-certified volunteers, generally for people with low to moderate income, people with disabilities and people with limited English; TCE (Tax Counseling for the Elderly, including AARP Foundation Tax-Aide) focuses on people 60 and older. Sites have a scope: some returns (for example complex business or rental returns) are referred elsewhere. People usually bring photo ID; Social Security cards or ITIN letters for everyone on the return; all income forms such as W-2 and 1099; last year\'s return; and bank routing and account numbers for direct deposit; married couples filing jointly usually both attend. The federal return goes to the IRS and the California return to the Franchise Tax Board (CalFile is the state\'s free direct e-file for eligible returns). Whether a site can prepare a given return, and which credits, deductions or tax apply, depends on the person\'s documents and is decided with the preparer.',
  immigration: 'USCIS (U.S. Citizenship and Immigration Services) decides immigration benefit applications such as green cards (lawful permanent residence, often through Form I-485), naturalization (Form N-400), green-card replacement (Form I-90) and work permits (Form I-765); the Department of State issues visas abroad, and immigration courts handle removal cases. Forms, filing fees and processing times are published on uscis.gov and change, so the current form edition and fee there are what count. At a green-card (adjustment of status) interview an officer generally reviews the application under oath and the original documents: the interview notice, passport and other identity documents, original civil documents such as birth and marriage certificates, the evidence filed with the case, and anything the notice lists, such as the sealed medical exam (Form I-693) when it was not filed already; family-based cases usually also bring updated evidence of the relationship. A naturalization (Form N-400) interview is a separate step for green-card holders and adds English and civics tests unless an exemption applies. Only a licensed attorney or a DOJ-accredited representative at a recognized organization may give immigration legal advice; a "notario" or consultant may not. Eligibility, timelines and outcomes depend on the individual case and are decided by USCIS.',
  // BBL-04 / BBL-05: what SSA publishes for every newcomer, no processing time or amount.
  ssa: 'The Social Security Administration (SSA) issues Social Security numbers (SSN); the number and the card are free, so never pay a third party for them. Lawful permanent residents and other noncitizens with permission to work can get a number. An immigrant who asked for a Social Security number on the immigrant visa application (Form DS-260, the "Enumeration at Entry" option) generally does not need to visit an office: after entry SSA mails the card to the U.S. mailing address given; if it does not arrive, or the number was not requested, the person applies to SSA (the application can be started online at ssa.gov, then finished at a local office) with original documents that prove identity, age and immigration status, such as the foreign passport with the immigrant visa stamp or the green card. SSA offers free interpreters, including Chinese, at 1-800-772-1213. Which documents a given person needs, office hours and appointments are on ssa.gov.',
};

/** Rules appended to BayBay's model instructions for a professional topic:
 * explain the general program facts first, then the official channel, then
 * say the personal decision depends on the person's situation. */
function professionalInstructions(guard) {
  const contacts = guard.resources.map(row => `${row.title}${row.phone ? ` ${row.phone}` : ''} (${row.url})`).join('; ');
  const background = [...new Set(guard.topics)].filter(topic => TOPIC_BACKGROUND[topic]).map(topic => `- ${topic}: ${TOPIC_BACKGROUND[topic]}`);
  return `\nProfessional-topic guard (${guard.topics.join(', ')}). Give a useful general answer, never a refusal or a one-line redirect. Answer in this order:`
    + ' (1) explain the general, non-personal facts the user asked about (what each program, part, form or step is, who it is generally for, how it generally works and what to prepare), using the evidence and the stable background below (only the parts that match the question; do not add unrelated programs or steps), and cite the matching BAYLINK guide with [[source-id]] when it is in evidence;'
    // URLs are stripped from answers; the contacts are in evidence and cited by id.
    + ` (2) name the relevant official contact by name and phone number and cite its evidence entry with [[source-id]] instead of writing its URL: ${contacts};`
    + ' (3) say plainly that the personal choice or decision depends on their own situation (for example current coverage, income, work history, documents or case history) and that the official office, free counselor or licensed professional above can work it out with them.'
    + ' Do not decide this person\'s individual eligibility, which option, plan, part or filing choice they should pick, case outcome, diagnosis, medication or dosage, tax liability or legal position. Do not state or imply that this person qualifies or does not qualify (avoid wording such as 你符合 / 你不符合 / 你有资格 / 你应该选 / "you qualify"); describe rules in general terms ("一般来说…" / "generally…").'
    + ' Never ask for and never repeat full ID, Social Security, A-number, receipt or case numbers, medical records or a home address, and tell the user not to send them.'
    + ' Do not invent fees, premiums, income limits, processing times, deadlines, dates or eligibility rules that are not in the evidence; the background below deliberately contains none.'
    + (background.length ? `\nGeneral background (stable program facts, not about this person):\n${background.join('\n')}` : '');
}

// A question about Medicare's parts ("A 部分和 B 部分有什么区别", "Part A or B")
// gets the general explanation before the counseling steps, also without a model.
const MEDICARE_PARTS_QUESTION = /\bparts?\s*[a-d]?\b|[A-D]\s*(?:部分|部|和|与|與|跟|还是|還是|或)|部分|区别|區別|不同|\bdifference\b|\b[A-D]\s*(?:and|or|&|vs\.?)\s*[A-D]\b/i;
const MEDICARE_PARTS = [
  'Medicare 一般这样分：A 部分（Part A）是住院保险，包括住院、符合条件的住院后专业护理机构照护和临终关怀等；多数人因本人或配偶工作时缴够 Medicare 税，不用交 A 部分保费。B 部分（Part B）是医疗保险，包括看医生、门诊和预防服务，每月要交保费。A 和 B 通常不是二选一，多数人两部分都有（合称原始 Medicare）；C 部分（Medicare Advantage）是可替代原始 Medicare 的私营计划，D 部分是处方药保险。什么时候参加 B 部分、选哪种计划，取决于目前的保险、医生、用药和收入，可请 HICAP 免费比较。',
  'Medicare 一般這樣分：A 部分（Part A）是住院保險，包括住院、符合條件的住院後專業護理機構照護和臨終關懷等；多數人因本人或配偶工作時繳夠 Medicare 稅，不用交 A 部分保費。B 部分（Part B）是醫療保險，包括看醫生、門診和預防服務，每月要交保費。A 和 B 通常不是二選一，多數人兩部分都有（合稱原始 Medicare）；C 部分（Medicare Advantage）是可替代原始 Medicare 的私營計劃，D 部分是處方藥保險。什麼時候參加 B 部分、選哪種計劃，取決於目前的保險、醫生、用藥和收入，可請 HICAP 免費比較。',
  'How Medicare is generally organized: Part A is hospital insurance (inpatient stays, skilled nursing facility care after a qualifying hospital stay, hospice); most people pay no Part A premium because they or their spouse paid Medicare taxes long enough while working. Part B is medical insurance (doctors, outpatient care, preventive services) with a monthly premium. A and B are usually not a choice between two: most people have both (together called Original Medicare). Part C (Medicare Advantage) is a private alternative to Original Medicare, and Part D covers prescription drugs. When to start Part B and which plan fits depend on current coverage, doctors, medicines and income; HICAP compares these free.',
];

// H72 rest (API-BB-4B): a Medi-Cal question starts with the Medicare/Medi-Cal pillar guide's own
// sentence on DHCS's four ways to apply, read from the guide catalog (the paragraph under the
// guide's "DHCS：申请 Medi-Cal 的四种方式" source), so a guide edit carries over (review 10-14). The
// guide is written in zh-Hans and en; the zh-Hant rendering is used only while the zh-Hans
// sentence is still the one it was made from (tests/baybay-floor-4b.test.js pins it).
const MEDI_CAL_GUIDE = 'bay-area-medicare-hicap-medi-cal-guide';
const MEDI_CAL_WAYS = /^DHCS[^\n。.]{0,30}(?:四种|四種|four ways)/i;
const MEDI_CAL_WAYS_HANT = Object.freeze(['DHCS 列出四种申请 Medi-Cal 的方式：网上（BenefitsCal 或 Covered California）、打电话给县办公室、邮寄纸本申请、到县办公室当面办。',
  'DHCS 列出四種申請 Medi-Cal 的方式：網上（BenefitsCal 或 Covered California）、打電話給縣辦公室、郵寄紙本申請、到縣辦公室當面辦。']);
function mediCalWaysSentence(locale, context = {}) {
  const supplied = locale === 'en' ? context.englishGuideCatalog : context.guideCatalog;
  const catalog = supplied instanceof Map ? [...supplied.values()] : supplied;
  const guide = Array.isArray(catalog) ? catalog.find(row => row?.slug === MEDI_CAL_GUIDE && typeof row.content === 'string') : null;
  const paragraph = guide ? guide.content.split(/\n\s*\n/).map(part => part.trim()).find(part => MEDI_CAL_WAYS.test(part)) : null;
  if (!paragraph) return null;
  return locale === 'zh-Hant' && paragraph === MEDI_CAL_WAYS_HANT[0] ? MEDI_CAL_WAYS_HANT[1] : paragraph;
}
function professionalPreparation(kinds, locale, message = '', context = {}) {
  const en = locale === 'en', hant = locale === 'zh-Hant';
  const answer = [], sources = [];
  if (kinds.includes('medicare') && MEDICARE_PARTS_QUESTION.test(message)) answer.push(MEDICARE_PARTS[en ? 2 : hant ? 1 : 0]);
  // H72 rest (API-BB-4B, audit BB-1013-06): a Medi-Cal question (not Medicare) starts with how to
  // apply for Medi-Cal, as the Medicare/Medi-Cal pillar guide states it (DHCS's four ways), not with HICAP.
  const mediCalWays = !kinds.includes('medicare') && /\bmedi[- ]cal\b|白卡(?![纸紙])|[医醫][疗療]补助|醫療補助/i.test(message) && !/medicare|hicap|[红紅][蓝藍]卡/i.test(message) ? mediCalWaysSentence(locale, context) : null;
  if (mediCalWays) answer.push(mediCalWays);
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
  if (kinds.includes('ssa')) {
    answer.push(en
      ? 'Social Security numbers come from SSA and are free. If you asked for a number on your immigrant visa application (DS-260), SSA usually mails the card after you arrive; otherwise start the application on ssa.gov and bring your passport with the immigrant visa or your green card to a local SSA office. Call 1-800-772-1213 for a free Chinese interpreter. Office hours, appointments and the exact documents are on ssa.gov.'
      : hant
        ? '社會安全號碼（SSN）由 SSA 免費辦理。若申請移民簽證（DS-260）時勾選了申請社安號，入境後 SSA 一般會把卡寄到你填的美國地址；沒勾選或沒收到，可先在 ssa.gov 開始申請，再帶護照（含移民簽證）或綠卡到當地 SSA 辦公室辦理。撥 1-800-772-1213 可要求免費中文口譯。辦公時間、預約和所需材料以 ssa.gov 為準。'
        : '社会安全号码（SSN）由 SSA 免费办理。若申请移民签证（DS-260）时勾选了申请社安号，入境后 SSA 一般会把卡寄到你填的美国地址；没勾选或没收到，可先在 ssa.gov 开始申请，再带护照（含移民签证）或绿卡到当地 SSA 办公室办理。拨 1-800-772-1213 可要求免费中文口译。办公时间、预约和所需材料以 ssa.gov 为准。');
    sources.push({ id: 'safety-ssa', title: 'SSA: Social Security number and card', url: 'https://www.ssa.gov/number-card' });
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
  const preparation = professionalPreparation(kinds, locale, message, context);
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

module.exports = { safetyResponse, emergencyResponse, possibleEmergencyTopic, emergencyFloor, professionalResponse, professionalTopics, professionalGuard, professionalInstructions, currentEmergencyTopic, strokeSignMentioned, EMERGENCY_PATTERNS, PILLAR_GUIDES, MEDI_CAL_WAYS_HANT };
