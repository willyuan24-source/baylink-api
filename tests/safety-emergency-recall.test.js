// SAFETY-1 (re-audit 10-11, gaps G29; BBL-V1 / BBENG-V1: recall 19/25). Table tests for
// the emergency lexicon: every sentence below is a current emergency and must get the
// 911-first card with the right topic (100% recall); every near miss must not (0 false
// positives). Deterministic, $0: no model call.
const test = require('node:test');
const assert = require('node:assert/strict');
const { emergencyResponse, currentEmergencyTopic } = require('../lib/safetyRouting');

const FIRST_SENTENCE = { 'zh-Hans': '请立即拨打 911。', 'zh-Hant': '請立即撥打 911。', en: 'Call 911 now.' };

// [locale, message, topic]
const EMERGENCIES = [
  // Someone else's suicide or self-harm.
  ['zh-Hans', '我朋友想自杀', 'self-harm'], ['zh-Hans', '朋友说要自杀', 'self-harm'], ['zh-Hans', '我室友说她不想活了', 'self-harm'],
  ['zh-Hans', '我同学说要跳楼', 'self-harm'], ['zh-Hant', '我朋友說要自殺', 'self-harm'], ['zh-Hant', '我女兒割腕了', 'self-harm'],
  ['en', 'My dad says he wants to end it', 'self-harm'], ['en', 'My friend is talking about killing herself', 'self-harm'],
  ['en', 'My son keeps saying he wants to die', 'self-harm'],
  // Stroke signs with a degree word.
  ['zh-Hans', '我爸嘴有点歪，说话不清楚', 'stroke'], ['zh-Hans', '我爸说话含糊，脸有点歪', 'stroke'], ['zh-Hans', '我爸嘴巴有点歪', 'stroke'],
  ['zh-Hans', '我妈口眼歪斜', 'stroke'], ['zh-Hans', '奶奶一边脸歪了', 'stroke'], ['zh-Hant', '我爸的嘴巴有點歪', 'stroke'],
  ['zh-Hant', '爺爺突然說話不清楚，嘴角歪了', 'stroke'], ['en', "My mom's face is drooping", 'stroke'], ['en', 'Grandpa has face drooping and slurred speech', 'stroke'],
  // A new droop after an old stroke is still a stroke sign.
  ['zh-Hans', '我爸前年中风过，今天早上起来嘴歪了', 'stroke'], ['zh-Hans', '我爸去年中风过，嘴歪了怎么办', 'stroke'],
  // Seizures.
  ['zh-Hans', '孩子发烧抽筋了', 'seizure'], ['zh-Hans', '孩子高烧惊厥', 'seizure'], ['zh-Hans', '孩子突然全身抽筋', 'seizure'], ['zh-Hans', '我爸突然抽搐口吐白沫', 'seizure'],
  ['zh-Hant', '寶寶發燒抽筋了', 'seizure'], ['zh-Hant', '孩子驚厥了', 'seizure'], ['en', 'My daughter is having a seizure', 'seizure'], ['en', 'My son is convulsing', 'seizure'],
  ['en', 'My toddler is having a febrile seizure', 'seizure'],
  // Swallowed medicine or a household chemical.
  ['zh-Hans', '孩子把洗衣凝珠吃进去了', 'poisoning'], ['zh-Hans', '宝宝误吞了一颗药片', 'poisoning'], ['zh-Hans', '孩子把奶奶的药片吃了', 'poisoning'],
  ['zh-Hans', '孩子吃了一整瓶维生素', 'poisoning'], ['zh-Hans', '孩子偷吃了药', 'poisoning'], ['zh-Hans', '我妈一氧化碳中毒了', 'poisoning'],
  ['zh-Hant', '孩子誤喝了漂白水', 'poisoning'], ['zh-Hant', '寶寶把洗衣球咬破吃了', 'poisoning'], ['en', 'My toddler swallowed bleach', 'poisoning'],
  ['en', 'My son ate a laundry detergent pod', 'poisoning'], ['en', 'My kid got into my pills and ate some', 'poisoning'], ['en', 'I think my dad took an overdose', 'poisoning'],
  ['zh-Hans', '孩子吃了一颗洗衣凝珠', 'poisoning'], ['zh-Hans', '宝宝喝了奶奶的消毒水', 'poisoning'],
  // Fainting, unconscious, collapse.
  ['zh-Hans', '我妈突然昏倒了', 'unconscious'], ['zh-Hans', '我爸晕倒了', 'unconscious'], ['zh-Hans', '奶奶倒在地上叫不醒', 'unconscious'], ['zh-Hans', '爷爷突然昏厥', 'unconscious'],
  ['zh-Hant', '爺爺暈倒叫不醒', 'unconscious'], ['en', 'My mom collapsed and is unresponsive', 'unconscious'], ['en', "My husband passed out and won't wake up", 'unconscious'],
  ['en', 'My grandpa collapsed', 'unconscious'],
  // The re-audit's other misses: a head injury with a red flag, a gas smell, a road injury.
  ['zh-Hans', '奶奶摔倒后头流血，人有点迷糊', 'head-injury'], ['zh-Hans', '爸爸撞到头以后一直吐', 'head-injury'], ['en', 'My grandma fell and hit her head, she is confused', 'head-injury'],
  ['zh-Hans', '家里有煤气味，头很晕', 'gas'], ['zh-Hant', '家裡有瓦斯味', 'gas'], ['zh-Hans', '一氧化碳警报一直在响', 'gas'], ['en', 'I smell gas in my apartment', 'gas'],
  ['zh-Hans', '有人被车撞了躺在地上', 'trauma'], ['en', 'My neighbor was just hit by a car', 'trauma'],
];

// Everyday or reported wording around the same words: no 911 card. Decisions:
// a cramp after exercise or at night is a cramp; a film, novel or news plot is not a
// disclosure; a medicine taken as prescribed is not an ingestion; a training or a
// hotline lookup with 培训 is a class lookup; "almost passed out" is a figure of speech;
// a bump on the head without a red flag (no bleeding, confusion or vomiting) stays a
// question; a lasting droop after an old stroke is context, not a new sign.
const NEAR_MISSES = [
  '跑步后小腿抽筋怎么拉伸', '晚上睡觉腿抽筋是缺钙吗', '游泳的时候抽筋怎么办', '我腿抽筋了，怎么缓解', '跑完马拉松全身抽筋，怎么恢复',
  '电影里的中毒情节是真的吗', '这部电影讲的是一个人想自杀', '这本小说的主角最后自杀了', '食物中毒是什么症状',
  '孩子吃了退烧药，什么时候可以再吃', '我吃了药还是头痛', '提醒爸爸把降压药吃了', '洗衣凝珠哪里买便宜',
  '自杀预防热线志愿者培训在哪里报名', '我想死你了，这周末见面去哪', 'She wants to end it with her boyfriend',
  'I almost passed out from laughing', 'The tent collapsed in the wind last night', 'The stock market collapsed today', 'Her tent collapsed in the storm',
  '煤气费怎么交', 'How do I pay my PG&E gas bill?', 'Where can I see poison oak on the trail?', '吃完饭用洗洁精洗碗要冲几遍', 'Her phone has been totally unresponsive',
  '孩子撞到头起了个包，没有流血', '他笑得嘴都歪了', '这张照片里我的脸有点歪', '我爸去年中风，嘴有点歪，有适合他的活动吗', '小心别被车撞',
  'Where can I take a first aid class?', '心肺复苏 CPR 课程在哪里报名？', '孩子眼皮一直抽搐，要看哪个科？',
];

test('SAFETY-1: every current emergency in the table gets the 911-first card with its topic (100% recall)', () => {
  assert.ok(EMERGENCIES.length >= 30, `${EMERGENCIES.length} emergencies`);
  assert.deepEqual(new Set(EMERGENCIES.map(([locale]) => locale)), new Set(['zh-Hans', 'zh-Hant', 'en']));
  const missed = EMERGENCIES.filter(([locale, message, topic]) => emergencyResponse(message, locale)?.emergencyTopic !== topic);
  assert.deepEqual(missed.map(([, message, topic]) => `${message} -> ${topic} (got ${currentEmergencyTopic(message)})`), []);
  for (const [locale, message, topic] of EMERGENCIES) {
    const card = emergencyResponse(message, locale);
    assert.ok(card.answer.startsWith(FIRST_SENTENCE[locale]), `${message}: ${card.answer}`);
    assert.equal(card.safety.actions[0].href, 'tel:911');
    assert.match(card.answer, /988/); assert.match(card.answer, /1-800-222-1222/);
    if (topic === 'self-harm') assert.match(card.answer.split(/[。.]/).slice(1, 3).join(' '), /988|独处|獨處|alone/, `${message}: the self-harm line comes second`);
    if (topic === 'poisoning') assert.match(card.answer, /催吐|induce vomiting/, message);
  }
});

test('SAFETY-1: near misses around the same words get no emergency card (0 false positives)', () => {
  assert.ok(NEAR_MISSES.length >= 6);
  const flagged = NEAR_MISSES.filter(message => emergencyResponse(message, /[㐀-鿿]/u.test(message) ? 'zh-Hans' : 'en'));
  assert.deepEqual(flagged.map(message => `${message} -> ${currentEmergencyTopic(message)}`), []);
});

test('SAFETY-1: the re-audit probe set (BB-ENGINE verify, 25 emergencies, 6 lookups) is 25/25 with 0/6 false positives', () => {
  const positives = ['我爸胸口很痛，一直出冷汗，怎么办？', '孩子刚才误吞了一颗纽扣电池', '我妈突然倒地叫不醒了', '宝宝喘不过气，嘴唇发紫',
    '孩子吃了花生后脸肿了，呼吸困难', '我老公割到手，血止不住', '我不想活了', '朋友说要自杀', '奶奶摔倒后头流血，人有点迷糊',
    '孩子抽搐了怎么办', '我妈说话含糊，半边身体没力气', '孩子把洗衣凝珠吃进去了', '家里有煤气味，头很晕',
    '我爸胸口痛冒冷汗', '我媽突然昏倒叫不醒', '孩子誤吞電池', 'My dad has chest pain and is sweating a lot', 'My toddler swallowed a button battery',
    'My mom collapsed and is unresponsive', 'My kid is having a seizure', 'I want to kill myself', 'He is bleeding heavily and it will not stop',
    'My son ate peanuts and his throat is swelling', 'My grandma fell and hit her head, she is confused', 'my wife suddenly cannot speak and her face is drooping'];
  const lookups = ['周末带孩子去哪里看烟花？', '心肺复苏 CPR 课程在哪里报名？', '旧金山有什么急救培训课？', 'Where can I take a first aid class?', '电池回收点在哪里？', '老人防跌倒讲座'];
  const locale = message => /[a-z]/i.test(message[0]) ? 'en' : 'zh-Hans';
  assert.deepEqual(positives.filter(message => !emergencyResponse(message, locale(message))), []);
  assert.deepEqual(lookups.filter(message => emergencyResponse(message, locale(message))), []);
});

test('SAFETY-1: each new topic has its own first-aid line in all three languages', () => {
  for (const [message, topic, line] of [['朋友说要自杀', 'self-harm', /不要让他独处/], ['孩子误喝了漂白水', 'poisoning', /不要催吐/], ['家里有煤气味', 'gas', /先离开屋子/],
    ['奶奶摔倒后头流血，人有点迷糊', 'head-injury', /躺着别动/], ['有人被车撞了躺在地上', 'trauma', /不要移动伤者/]]) {
    const zh = emergencyResponse(message, 'zh-Hans'), hant = emergencyResponse(message, 'zh-Hant'), en = emergencyResponse(message, 'en');
    assert.equal(zh.emergencyTopic, topic);
    assert.match(zh.answer, line, message);
    assert.ok(hant.answer.startsWith(FIRST_SENTENCE['zh-Hant']) && hant.answer.length > FIRST_SENTENCE['zh-Hant'].length + 60, message);
    assert.doesNotMatch(en.answer, /[一-鿿]/, `${message}: the English card has no CJK`);
    assert.ok(en.answer.split('. ').length >= 3, `${message}: 911, the topic line, then Poison Control / 988`);
  }
});

// The unanswered-message guard had a literal backspace (U+0008) where \b was meant,
// so its English words never matched: "我给他发了 text，他没反应" got the unconscious card.
test('an unanswered text or app message is not an unresponsive person, in English words too', () => {
  for (const message of ['我给他发了 text，他没反应', '我发了 message 给我爸，他没反应', '我给她发了 email，她没反应', '我发消息给他，他没反应']) {
    assert.equal(emergencyResponse(message), null, message);
  }
  assert.equal(emergencyResponse('叫他没反应')?.emergencyTopic, 'unconscious');
  assert.equal(emergencyResponse('我爸倒在地上，他没反应')?.emergencyTopic, 'unconscious');
});

test('no source file in lib/ or server.js contains a control character (a backspace typed for a word boundary)', () => {
  const fs = require('node:fs'); const path = require('node:path');
  const root = path.join(__dirname, '..');
  // Recursive: the BayBay engine lives in lib/baybayEngine/ (H40), full of \b patterns.
  const files = ['server.js', ...fs.readdirSync(path.join(root, 'lib'), { recursive: true }).filter(file => file.endsWith('.js')).map(file => `lib/${file.replace(/\\/g, '/')}`)];
  assert.ok(files.includes('lib/baybayEngine/router.js') && files.includes('lib/baybayAgent.js'), 'the scan covers lib/ and its subfolders');
  const found = files.flatMap(file => fs.readFileSync(path.join(root, file), 'utf8').split('\n')
    .map((line, index) => /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(line) ? `${file}:${index + 1}` : null).filter(Boolean));
  assert.deepEqual(found, []);
});

// H11 (audit 10-13, BB-1013-04): the audit's 20 fresh phrasings (14 caught, 3 floor-only,
// 3 missed on 188d957) are all 911 cards now, with the four new combinations in all three
// languages. Near misses around the same words stay plain questions.
const AUDIT_1013_FRESH = [
  ['zh-Hans', '我朋友刚发消息说他不想活了，遗书都写好了，我该怎么办？', 'self-harm'], ['zh-Hans', '我爸吃饭的时候一边脸突然垂下来了，筷子也拿不住', 'stroke'],
  ['zh-Hans', '孩子吞了一块小磁铁，现在肚子疼', 'ingestion'], ['zh-Hans', '我同事说他刚吞了一整瓶安眠药', 'poisoning'],
  ['zh-Hans', '我老婆说胸闷，左手发麻，脸色很白', 'cardiac'], ['zh-Hans', '孩子掉进泳池，捞上来没有呼吸', 'breathing'],
  ['zh-Hans', '奶奶在浴室摔倒起不来，头一直在流血', 'head-injury'], ['zh-Hans', '我室友喝了很多酒，怎么叫都叫不醒', 'unconscious'],
  ['zh-Hans', '外公突然看不清东西，走路也不稳，说话怪怪的', 'stroke'], ['zh-Hans', '宝宝被蜜蜂蛰了以后全身起疹子，嗓子发紧', 'anaphylaxis'],
  ['zh-Hans', '我妈血糖很低，人有点迷糊，叫她不太答应', 'unconscious'], ['zh-Hans', '我觉得活着没意思，想结束这一切', 'self-harm'],
  ['zh-Hans', '我儿子说他想死', 'self-harm'], ['zh-Hant', '爸爸剛才突然說不出話，右手沒力', 'stroke'],
  ['en', 'My friend just texted that he took a whole bottle of pills', 'poisoning'], ['en', "my dad's speech is slurred and one side of his face looks droopy", 'stroke'],
  ['en', 'My daughter fell off the balcony and is not moving', 'trauma'], ['en', "there's a strong gas smell in our apartment and I feel dizzy", 'gas'],
  ['en', "my baby is turning blue and can't breathe", 'breathing'], ['en', 'My teenage son says he wants to end his life', 'self-harm'],
];
const H11_COMBINATIONS = [
  ['zh-Hant', '奶奶在浴室摔倒起不來，頭一直在流血', 'head-injury'], ['en', 'Grandma slipped in the bathroom and her head keeps bleeding', 'head-injury'],
  ['zh-Hant', '寶寶被蜜蜂螫了以後全身起疹子，喉嚨發緊', 'anaphylaxis'], ['zh-Hans', '孩子吃了虾以后嘴唇肿了', 'anaphylaxis'],
  ['en', 'My son was stung by a wasp and his throat feels tight', 'anaphylaxis'],
  ['zh-Hans', '孩子从阳台上摔下来了', 'trauma'], ['zh-Hant', '我兒子從二樓窗戶掉下去了', 'trauma'], ['zh-Hans', '爸爸从梯子上摔下来，一动不动', 'trauma'],
  ['en', 'My husband fell off the ladder and is not moving', 'trauma'],
  ['zh-Hant', '我老婆說胸悶，左手發麻，臉色很白', 'cardiac'], ['en', 'My dad has chest tightness and his left arm is numb', 'cardiac'],
  ['zh-Hant', '外公突然看不清東西，走路也不穩', 'stroke'],
];
const H11_NEAR_MISSES = [
  '手机从阳台掉下去了', 'My phone fell off the balcony', '孩子从床上摔下来了，现在没事，还在玩', '我去年从楼梯上摔下来过一次', '防坠楼安全讲座在哪里',
  '孩子摔倒了膝盖流血，头没事', 'My daughter fell off her bike and scraped her knee', 'The kid fell asleep in the car and is not moving an inch',
  '被蚊子叮了起了个包，有点痒', '感冒了嗓子有点肿，吃了药', '吃了辣的嗓子有点疼', 'My throat feels tight after singing all day',
  '我练完胸肌胸口有点紧，左手也酸', '胸闷是不是空气不好', 'I ate too much and my chest feels heavy',
  '外公突然看不清东西，眼镜找不到了', '血糖低的时候吃什么好', '老人防跌倒讲座', '我爸以前胸闷左手发麻过，现在好了',
  // Review of 3efe2b8: an object a person owns falls (他的手机 / 女儿的玩具 / 孩子的球), spicy food
  // and a limb that will not move are not the 911 card.
  '他的手机从阳台掉下去了，怎么办', '我女儿的玩具从窗户掉下去了', '孩子的球从二楼掉下去了，去哪买新的',
  '他的手機從陽台掉下去了，怎麼辦', '我女兒的玩具從窗戶掉下去了', '孩子的球從二樓掉下去了，去哪買新的', '孩子手机从阳台掉下去了',
  '吃了辣的嗓子有点肿', '吃了火锅以后嗓子有点紧', '吃了火鍋以後嗓子有點緊', 'I ate spicy noodles and my throat feels tight',
  "My son fell off his bike and can't move his arm",
];
// The same review: the person (not an object) falling, or not moving at all, is still the card.
const H11_REVIEW_POSITIVES = [
  ['zh-Hans', '他的孩子从阳台摔下来了', 'trauma'], ['zh-Hant', '我女兒的朋友從三樓窗戶掉下去了', 'trauma'],
  ['en', "My son fell off the ladder and can't move", 'trauma'], ['zh-Hans', '吃了花生以后嗓子发紧', 'anaphylaxis'],
];
test('H11 review: a person falling or not moving at all stays the 911 card', () => {
  assert.deepEqual(H11_REVIEW_POSITIVES.filter(([locale, message, topic]) => emergencyResponse(message, locale)?.emergencyTopic !== topic).map(([, message]) => `${message} -> ${currentEmergencyTopic(message)}`), []);
});

test('H11: the 10-13 audit\'s 20 fresh phrasings and the four new combinations get the 911 card in every language', () => {
  const missed = [...AUDIT_1013_FRESH, ...H11_COMBINATIONS].filter(([locale, message, topic]) => emergencyResponse(message, locale)?.emergencyTopic !== topic);
  assert.deepEqual(missed.map(([, message, topic]) => `${message} -> ${topic} (got ${currentEmergencyTopic(message)})`), []);
  for (const [locale, message] of [...AUDIT_1013_FRESH, ...H11_COMBINATIONS]) assert.ok(emergencyResponse(message, locale).answer.startsWith(FIRST_SENTENCE[locale]), message);
  assert.deepEqual(new Set(H11_COMBINATIONS.map(([locale]) => locale)), new Set(['zh-Hans', 'zh-Hant', 'en']));
});

test('H11: near misses around falls, stings, chest tightness and vision stay questions (0 false positives)', () => {
  const flagged = [...H11_NEAR_MISSES, ...NEAR_MISSES].filter(message => emergencyResponse(message, /[㐀-鿿]/u.test(message) ? 'zh-Hans' : 'en'));
  assert.deepEqual(flagged.map(message => `${message} -> ${currentEmergencyTopic(message)}`), []);
});
