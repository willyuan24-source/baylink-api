const emergency = /胸(?:口)?(?:很|非常|剧烈|劇烈)?(?:痛|疼)|呼吸困难|呼吸困難|喘不过气|喘不過氣|不能呼吸|中毒|(?:误吞|誤吞|误食|誤食|吞(?:了|下)?|(?:不小心)?喝(?:了|下)).{0,12}(?:清洁剂|清潔劑|洗涤剂|洗滌劑|漂白水|药|藥)|不想(?:再)?活(?:了|下去)?|活不下去|想(?:自杀|自殺|自伤|自傷|死)|(?:chest pain|can(?:not|['’]t) breathe|difficulty breathing|poison(?:ing|ed)?|(?:swallowed|drank|ingested).{0,30}(?:cleaner|detergent|bleach|medicine|pills)|(?:do not|don['’]t) want to (?:live|be alive)(?: anymore| any more)?|suicid(?:e|al)|kill myself|hurt myself)/gi;

function hasCurrentEmergency(message) {
  const clauses = message.split(/[。.!！？?;；，,\n]|(?:但是|但现在|但現在|\bbut\b)/i);
  for (const clause of clauses) {
    for (const match of clause.matchAll(emergency)) {
      const prefix = clause.slice(0, match.index);
      const last = pattern => [...prefix.matchAll(pattern)].at(-1)?.index ?? -1;
      const current = last(/现在|現在|目前|刚刚|剛剛|刚才|剛才|\b(?:now|today|just)\b/gi);
      // A news report, translation exercise or past account is not evidence
      // that the speaker is currently in danger. A later present-tense cue
      // keeps a real current disclosure from being hidden by an earlier frame.
      const noncurrent = last(/以前|过去|過去|曾经|曾經|历史|歷史|新闻|新聞|报道|報導|文章|小说|小說|电影|電影|翻译|翻譯|例句|\b(?:history of|in the past|used to|previously|news|article|report|novel|movie|fictional|translate|translation|example sentence)\b/gi);
      if (noncurrent >= 0 && current <= noncurrent) continue;
      const nearby = prefix.slice(-40).replace(/["'“”‘’]\s*$/, '').trim();
      if (/(?:不是|没有|沒有|并非|並非|否认|否認|从未|從未|未|无|無|不)\s*(?:真的|再|已经|已經|发生|發生|觉得|覺得|表示|说|說)?\s*$|\b(?:no|not|never|(?:did|do|does|have|has) not|(?:didn['’]t|don['’]t|doesn['’]t|haven['’]t|hasn['’]t))\s*(?:have|feel|feeling|experience|experienced|say|saying)?\s*$/i.test(nearby)) continue;
      return true;
    }
  }
  return false;
}
function safetyResponse(message, locale = 'zh-Hans') {
  if (typeof message !== 'string' || message.length > 5000) return null;
  const en = locale === 'en', traditional = locale === 'zh-Hant';
  if (hasCurrentEmergency(message)) {
    const answer = en ? 'If this is happening now, call 911 for severe chest pain, trouble breathing or immediate danger. For a possible poisoning, call Poison Control at 1-800-222-1222; for suicide or emotional crisis, call or text 988. Do not wait for BayBay or rely on a generated diagnosis.' : traditional ? '若正在發生嚴重胸痛、呼吸困難或有立即危險，請立即撥打 911。疑似中毒可聯絡 Poison Control：1-800-222-1222；自殺或情緒危機可撥打或傳簡訊至 988。不要等待 BayBay 回覆，也不要依賴生成的診斷。' : '若正在发生严重胸痛、呼吸困难或有立即危险，请立即拨打 911。疑似中毒可联系 Poison Control：1-800-222-1222；自杀或情绪危机可拨打或发短信至 988。不要等待 BayBay 回复，也不要依赖生成的诊断。';
    return { ok: true, answer, safetyRoute: 'emergency', responseMode: 'safety', degraded: false, sources: [{ id: 'safety-911', title: '911', url: 'https://www.911.gov/' }, { id: 'safety-poison', title: 'Poison Control', url: 'https://www.poisonhelp.org/' }, { id: 'safety-988', title: '988 Lifeline', url: 'https://988lifeline.org/' }], suggestedGuides: [], suggestedActions: [], matchingPosts: [], interactiveCards: [], followups: [] };
  }
  const topics = [
    ['immigration', /绿卡|綠卡|移民|庇护|庇護|\b(?:green card|immigration|asylum)\b/i, 'USCIS', 'https://www.uscis.gov/'],
    ['medicare', /\bmedicare\b/i, 'Medicare', 'https://www.medicare.gov/'],
    ['insurance', /医保|醫保|\bhealth insurance\b/i, 'Covered California', 'https://www.coveredca.com/coverage-basics/'],
    ['medical', /医疗|醫療|诊断|診斷|处方|處方|\b(?:medical diagnosis|prescription)\b/i, 'MedlinePlus', 'https://medlineplus.gov/'],
    ['tax', /报税|報稅|税务|稅務|\b(?:tax return|tax advice|tax filing)\b/i, 'IRS', 'https://www.irs.gov/'],
    ['legal', /法律意见|法律意見|法律咨询|法律諮詢|驱逐|驅逐|\b(?:legal advice|eviction)\b/i, 'California Courts Self-Help', 'https://selfhelp.courts.ca.gov/'],
  ];
  const topic = topics.find(([, pattern]) => pattern.test(message));
  if (topic) {
    const [kind, , title, url] = topic;
    return { ok: true, answer: en ? `Start with ${title}'s official resource. Rules depend on your circumstances and the current published requirements. Avoid sharing full IDs, case numbers, home addresses or medical records here. For a personal determination, contact the appropriate qualified professional or the official service.` : traditional ? `先從 ${title} 的官方入口核對。適用規則取決於你的具體情況和最新公布要求。請勿在此提供完整證件、案件號、住址或病歷；個人判定應由合資格專業人士或官方服務確認。` : `先从 ${title} 的官方入口核对。适用规则取决于你的具体情况和最新公布要求。请勿在此提供完整证件、案件号、住址或病历；个人判定应由合资格专业人士或官方服务确认。`, safetyRoute: 'professional', safetyTopic: kind, responseMode: 'safety', degraded: false, sources: [{ id: `safety-${kind}`, title, url }], suggestedGuides: [], suggestedActions: [], matchingPosts: [], interactiveCards: [], followups: [] };
  }
  return null;
}
module.exports = { safetyResponse };
