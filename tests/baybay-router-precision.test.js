// API-BB-QUALITY (BBL-04, BBENG-02): professional-topic routing reads the asked task
// first and the asker's status second. SSN, Medi-Cal and DMV questions from a green-card
// holder or a new immigrant are tasks, not immigration; H-1B / OPT / visa-status
// questions are immigration; medication and dosing questions are medical; small claims,
// lawsuits and withheld deposits are legal. Table-driven, zh-Hans / zh-Hant / en.
const test = require('node:test');
const assert = require('node:assert/strict');
const { professionalTopics, safetyResponse, professionalGuard } = require('../lib/safetyRouting');

const TABLE = [
  // The BB-LIVE 10-11 misroutes (T1, T2, T3, S2, S3) and their variants.
  ['刚拿移民签证来美国，社安号 SSN 怎么申请？要带什么？', ['ssa']],
  ['剛拿移民簽證來美國，社安號怎麼申請？', ['ssa']],
  ['How do I get a Social Security number after arriving on an immigrant visa?', ['ssa']],
  ['I just got my green card, how do I apply for an SSN?', ['ssa']],
  ['社会安全卡丢了怎么补办？', ['ssa']],
  ['我爸妈 67 岁刚拿绿卡来湾区，可以申请 Medi-Cal 吗？去哪里申请？', ['insurance']],
  ['我爸媽剛拿綠卡，可以申請 Medi-Cal 嗎？', ['insurance']],
  ['My parents just got green cards. Can they apply for Medi-Cal?', ['insurance']],
  ['加州驾照笔试可以考中文吗？一定要先预约吗？', []],
  ['加州駕照筆試可以考中文嗎？', []],
  ['Can I take the California driving knowledge test in Chinese?', []],
  ['有绿卡的人怎么办加州驾照？', []],
  ['刚拿绿卡，怎么开银行账户？', []],
  ['孩子发烧 38.5 度两天了，要不要给他吃抗生素？', ['medical']],
  ['孩子發燒要不要吃退燒藥？吃幾片？', ['medical']],
  ['可以再吃泰诺吗？剂量多少？', ['medical']],
  ['My son has had a fever for two days. Should I give him antibiotics?', ['medical']],
  ['Can I take Tylenol with ibuprofen? What dose?', ['medical']],
  ['我 H-1B 被裁员了，60 天宽限期内找不到工作会怎样？需要请律师吗？', ['immigration']],
  ['我 H-1B 被裁員了，寬限期怎麼算？', ['immigration']],
  ['I was laid off on H-1B. What happens in the 60-day grace period?', ['immigration']],
  ['我的 F-1 OPT 快到期了，怎么办？', ['immigration']],
  ['My OPT expires next month, what are my options?', ['immigration']],
  ['推荐两个 San Jose 会讲中文的移民律师，咨询一次多少钱？', ['immigration']],
  ['我在等绿卡面试，SSN 什么时候能办？', ['immigration', 'ssa']],
  ['房东搬走后三个星期都不退押金，可以去小额法庭告他吗？', ['legal']],
  ['房東不退押金，可以去小額法庭嗎？', ['legal']],
  ['My landlord kept my deposit. Can I sue him in small claims court?', ['legal']],
  ['我想找律师写遗嘱', ['legal']],
  // Still not professional: life stages, places, shopping and plain how-tos.
  ['我们一家刚移民来湾区，第一个月要先办哪些事？', []],
  ['周末带刚移民来的爸妈去哪玩', []],
  ['律师事务所开业活动有什么', []],
  ['I want to opt out of the newsletter', []],
  ['这家药店周末几点开门？', []],
  ['Social Security 退休金怎么申请', []],
  ['Fleet Week 有驱逐舰开放参观吗？', []],
  // Unchanged G12 must-route cases.
  ['绿卡面试要准备什么', ['immigration']],
  ['移民律师怎么找比较靠谱？', ['immigration']],
  ['Medi-Cal 的牙科能看吗', ['insurance']],
  ['房东要驱逐我，我该怎么办', ['legal']],
];

test('professional-topic table: >= 30 zh-Hans / zh-Hant / en phrasings route to the asked task', () => {
  assert.ok(TABLE.length >= 30);
  const locales = new Set(TABLE.map(([message]) => /[們個這來綠簽發燒裁寬東額駕試嗎]/u.test(message) ? 'zh-Hant' : /[㐀-鿿]/u.test(message) ? 'zh-Hans' : 'en'));
  assert.deepEqual([...locales].sort(), ['en', 'zh-Hans', 'zh-Hant']);
  for (const [message, topics] of TABLE) assert.deepEqual(professionalTopics(message), topics, message);
});

test('SSN questions get the SSA card (free, 1-800-772-1213, number-and-card page), never the USCIS card', () => {
  for (const locale of ['zh-Hans', 'zh-Hant', 'en']) {
    const result = safetyResponse('刚拿移民签证来美国，社安号 SSN 怎么申请？要带什么？', locale);
    assert.equal(result.safetyTopic, 'ssa');
    assert.deepEqual(result.safety.resources.map(row => row.id), ['ssa']);
    assert.equal(result.safety.resources[0].href, 'tel:+18007721213');
    assert.match(result.answer, /1-800-772-1213/);
    assert.match(result.answer, /DS-260/);
    assert.doesNotMatch(result.answer, /USCIS|入籍/);
  }
  // A Medi-Cal question from green-card holders gets HICAP and DHCS, not USCIS.
  const medi = professionalGuard(professionalTopics('我爸妈 67 岁刚拿绿卡来湾区，可以申请 Medi-Cal 吗？'), 'zh-Hans');
  assert.deepEqual(medi.resources.map(row => row.id), ['hicap', 'medi-cal']);
});
