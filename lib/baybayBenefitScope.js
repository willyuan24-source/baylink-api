// Preserve the scope of editorial evidence. These labels classify services;
// they supply no eligibility rules. Every restriction below is extracted from
// this turn's actual source paragraphs, not a prewritten library answer.
const { normalExcerpt } = require('./baybayAnswerQuality');
const TOPICS = {
  printing: /打印|列印|\bprint(?:ing|ers?)?\b/i,
  kanopy: /\bkanopy\b/i,
  museum_passes: /discover\s*(?:&|and)\s*go|馆票|館票|门票|門票|museum passes/i,
  // API-BB-10 (live 10-17, Q3): a rule for getting or holding a card, not every sentence that mentions one. "持 SFPL 图书证借用"
  // (a radon-detector loan) is a card benefit; a bare 图书证 made that loan paragraph the card rule the repair cited.
  card_eligibility: /(?<![举舉])[办辦](?:理)?\s{0,2}(?:一?[张張]\s{0,2})?(?:[A-Za-z]{2,8}\s{0,2}|(?:公共)?(?:图书馆|圖書館))?\s{0,2}(?:卡|图书证|圖書證|借书证|借書證)(?![通牌片])|申[请請].{0,8}(?:卡|图书证|圖書證)|[领領]卡|ecard|[实實]体卡|(?:图书证|圖書證|借书证|借書證|library card).{0,20}(?:居民|居住|就[学學]|年[满滿]|\d+\s*[岁歲]|[证證]件)|(?:居民|居住|就[学學]|年[满滿]).{0,20}(?:图书证|圖書證|借书证|借書證)|\b(?:apply|application|(?:sign(?:ing)? up for|get) (?:a |an |your )?(?:free )?(?:\w+ )?(?:library )?card)\b|\blibrary card\b.{0,30}\b(?:eligib\w*|residents?|age)\b|\b(?:residents?\b|age[ds]?\s{0,2}\d{1,2}\b).{0,80}\blibrary card\b/i,
  // Review round 3: residents / an age before "library card" too ("Sonoma County residents age 15+ need a regular library card"),
  // as the zh form reads 居民 / 年满 before 图书证; "sign up for" only with a card (not "Sign up for live classes").
};
// A clause that says how to get the card ("…完成 Kanopy 账户绑定；加州居民可免费办 SFPL 卡") is a card rule under any heading.
// Review round 1: 办/办理 with at most a library name or 一张 before the card noun, never 举办 or 卡通/卡牌/卡片. Review round 3:
// "apply for" / "sign up for" only with a card as the object.
const CARD_ISSUANCE = /(?<![举舉])[办辦](?:理)?\s{0,2}(?:一?[张張]\s{0,2})?(?:[A-Za-z]{2,8}\s{0,2}|(?:公共)?(?:图书馆|圖書館))?\s{0,2}(?:卡|图书证|圖書證|借书证|借書證)(?![通牌片])|申[请請].{0,8}(?:卡|图书证|圖書證)|[领領]卡|\b(?:apply for|sign(?:ing)? up for|get) (?:a |an |your )?(?:free )?(?:\w+ )?(?:library )?card\b/i;
// Review round 6: a clause that names another service (Discover & Go, printing, Kanopy), or that only requires holding a card
// first ("…须年满 18 岁并已办 SFPL 卡", "需先办理图书证", "需先领卡", "who get a library card first"), is that service's rule, not
// how to get the card: its residence or age rule never becomes a card rule.
const CARD_PREREQUISITE = /(?:须|需|需要|必须|必須|已|先)\s{0,2}(?:先\s{0,2})?(?:[办辦](?:理|好)?|[领領](?:取)?|持(?:有)?)|\b(?:who|must|need(?:s)?\s{1,3}to)\s{1,3}(?:first\s{1,3})?(?:get|have|hold|already\s{1,3}have)\b|\bcard\s{1,3}first\b/i;
const issuanceClause = part => CARD_ISSUANCE.test(part) && !CARD_PREREQUISITE.test(part) && !TOPICS.museum_passes.test(part) && !TOPICS.printing.test(part) && !TOPICS.kanopy.test(part);
// One sentence can hold a service's rule and, after a ；, how to get the card (scopeStatements). A clause ends as a sentence.
const clauses =sentence => sentence.split(/(?<=[；;])\s*/).map(part => part.trim().replace(/；$/, '。').replace(/;$/, '.')).filter(Boolean);
const normalize = value => String(value || '').normalize('NFKD').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
const urlKey = value => { try { const u = new URL(value, 'https://www.baylink.us'); u.hash = ''; return u.href.replace(/\/$/, ''); } catch { return ''; } };
const withoutUrls = value => String(value || '').replace(/https?:\/\/[^\s<>）)]+/g, '').replace(/^[^\n。]{0,80}[：:]\s*$/gm, '').trim();
const sentences = text => withoutUrls(text).split(/(?<=[。！？])\s*|[.!?](?=\s|$)|\n+/).filter(Boolean);

const PLACE_LABEL = /^(?:旧金山|舊金山|北湾|北灣|东湾|東灣|南湾|南灣|半岛|半島|San Francisco|North Bay|East Bay|South Bay|Peninsula)$/i;
function evidenceScopes(guides, store) {
  const seen = new Set();
  return (guides || []).flatMap(guide => {
    if (!guide.text || seen.has(guide.evidenceId || guide.text)) return [];
    seen.add(guide.evidenceId || guide.text);
    const heading = guide.sectionHeading || guide.text.split('\n')[0];
    // API-BB-9: a place label before the institution ("旧金山 · SFPL Discover & Go：…", web #48's library starter guide)
    // names where the service is, not who runs it; the institution's acronym after it is the entity, so its pass
    // statement owns the SF-residence restriction and the repair can correct "SFPL需旧金山居民" for Kanopy and the card.
    const [first = '', second = ''] = heading.split(/[：:·]/).map(part => part.trim());
    const entity = PLACE_LABEL.test(first) && /^[A-Z]{3,8}\b/.test(second) ? second.match(/^[A-Z]{3,8}/)[0] : first;
    const words = entity.match(/[A-Za-z]+/g) || [];
    const key = /librar(?:y|ies)$/i.test(words.at(-1) || '') ? words.map(word => /^[A-Z]{2}$/.test(word) ? word : word[0]).join('').toLowerCase() : normalize(entity);
    const links = [guide.url, ...(guide.text.match(/https?:\/\/[^\s<>）)]+/g) || [])].map(urlKey);
    const sourceIds = [...store.sources.values()].filter(source => links.includes(urlKey(source.url))).map(source => source.id).slice(0, 4);
    return [{ id: guide.evidenceId || `scope-${seen.size}`, heading, entity, entityKey: key,
      text: guide.text, sourceIds, basis: 'site-snapshot', checkedAt: guide.updatedAt || null }];
  }).slice(0, 16);
}

function restrictions(text) {
  const found = [];
  for (const match of text.matchAll(/(?:年满|年滿)\s*(\d{1,2})\s*[岁歲]|(\d{1,2})\s*[岁歲]\s*(?:及以上|以上|起)|\b(?:age[ds]?\s*)?(\d{1,2})\s*(?:\+|and (?:over|older))/gi)) found.push(`age:${match[1] || match[2] || match[3]}`);
  // Sources may express the same exclusion as lacking the free allowance.
  // Recognize that wording on its own service instead of attributing it only
  // to a different benefit whose source happens to say "not eligible".
  if (/e-?cards?.{0,30}(?:不含|不适用|不適用|不接受|不享(?:免费|免費)(?:额度|額度)|not (?:accepted|eligible|valid)|does not include|do not receive the free allowance|exclude)|(?:不接受|不支持|exclude).{0,12}e-?cards?/i.test(text)) found.push('ecard:excluded');
  for (const match of text.matchAll(/([^，,；;。\n]{1,65}?)(?:居民|\bresidents?\b)/gi)) {
    let place = match[1].split(/[:：]|(?:需|须|須|限|是|为|為|要求|住在|居住在)|\b(?:must be|requires?|only|to|for|of)\b/i).at(-1).trim();
    place = place.replace(/^(?:持卡人|用户|用戶|the|a)\s*/i, '');
    if (place && place.length <= 35) found.push(`residence:${normalize(place).replace(/^sanfrancisco(?:city|county|cityandcounty)?$|^(?:旧金山|舊金山)(?:市县|市縣|市)?$/, 'sanfrancisco')}`);
  }
  return [...new Set(found)];
}

function statementTopic(sentence, heading) {
  // A named benefit owns the restrictions in that statement; the fact that it
  // uses a library card does not turn its restrictions into card-issuance rules.
  if (TOPICS.museum_passes.test(sentence)) return 'museum_passes';
  if (TOPICS.printing.test(sentence)) return 'printing';
  if (TOPICS.kanopy.test(sentence)) return 'kanopy';
  const headingBenefits = ['printing', 'kanopy', 'museum_passes'].filter(topic => TOPICS[topic].test(heading));
  if (headingBenefits.length === 1) return headingBenefits[0];
  if (TOPICS.card_eligibility.test(sentence)) return 'card_eligibility';
  return Object.keys(TOPICS).find(topic => TOPICS[topic].test(heading)) || null;
}

/**
 * The statements a library scope makes, each with its topic and restrictions. API-BB-10 review round 3: each sentence is still
 * classified whole and keeps its restrictions (card-benefit sentences without restrictions no longer get the card topic, see
 * TOPICS.card_eligibility); a clause of it that says how to get the card ("…完成 Kanopy 账户绑定；加州居民可免费办 SFPL 卡，首次
 * 领卡需到馆核验照片证件。") is also a card rule of its own. No clause ever leaves the service its sentence names ("eCards are
 * excluded …" after a Discover & Go rule stays the pass's). Review round 6: the added clause names no other service and is not
 * a prerequisite (issuanceClause), so a pass's, printing's or Kanopy's residence or age rule is never added as a card rule.
 */
function scopeStatements(scope) {
  const statements = [];
  for (const sentence of sentences(scope.text).slice(1)) {
    const topic = statementTopic(sentence, scope.heading);
    statements.push({ text: sentence, topic, restrictions: restrictions(sentence), scope });
    const parts = clauses(sentence);
    if (topic === 'card_eligibility' || parts.length < 2) continue;
    for (const part of parts) if (issuanceClause(part)) statements.push({ text: part, topic: 'card_eligibility', restrictions: restrictions(part), scope, clauseOf: sentence });
  }
  return statements;
}

function repairBenefitCoverage(coverage, scopes, locale, sources = new Map()) {
  const groups = new Map();
  for (const scope of scopes) {
    // Require an explicit institutional heading. Generic editorial prose is
    // useful context, but cannot supply an institution's eligibility rule.
    if (!/librar/i.test(scope.entity) && !/^[A-Z]{3,8}$/.test(scope.entity)) continue;
    const group = groups.get(scope.entityKey) || { aliases: [], records: [], statements: [] };
    group.aliases.push(normalize(scope.entity), scope.entityKey); group.records.push(scope);
    group.statements.push(...scopeStatements(scope));
    groups.set(scope.entityKey, group);
  }
  let changed = false;
  const items = coverage.items.map(item => {
    if (!TOPICS[item.id]) return item;
    let previousGroup = null;
    const conflicts = new Set(), currentAmbiguities = new Map(), claims = [];
    for (const sentence of sentences(item.summary)) {
      const named = [...groups.values()].filter(group => group.aliases.some(alias => normalize(sentence).includes(alias)));
      const group = named.length === 1 ? named[0] : !named.length ? previousGroup : null;
      if (named.length === 1) previousGroup = group;
      claims.push({ sentence, group });
      if (!group) continue;
      const topic = TOPICS.museum_passes.test(sentence) ? 'museum_passes' : item.id;
      const hosts = new Set(group.records.flatMap(record => record.sourceIds).map(id => { try { return new URL(sources.get(id)?.url).hostname; } catch { return null; } }).filter(Boolean));
      const current = item.sourceIds.map(id => sources.get(id)).filter(source => source?.verification === 'page-read' && source.text && (() => { try { return hosts.has(new URL(source.url).hostname); } catch { return false; } })());
      for (const restriction of restrictions(sentence)) {
        const owners = group.statements.filter(statement => statement.restrictions.includes(restriction)).map(statement => statement.topic);
        if (!owners.length || owners.includes(topic)) continue;
        const freshStatements = current.flatMap(source => sentences(source.text).map(text => ({ text, source, topic: statementTopic(text, `${source.title || ''} ${source.url || ''}`) })));
        // A newer read of this institution's actual service takes precedence
        // over editorial snapshots. Exact service + restriction support keeps
        // the new conclusion. Ambiguous fresh evidence becomes a conflict to
        // check, never an automatic assertion of the older snapshot rule.
        if (freshStatements.some(row => row.topic === topic && restrictions(row.text).includes(restriction))) continue;
        const fresh = freshStatements.find(row => row.topic === topic || !row.topic && restrictions(row.text).includes(restriction));
        if (fresh) { currentAmbiguities.set(group, fresh); conflicts.add(group); }
        else if (!/不要求|不需要|不限|无需|無需|\b(?:does not require|not limited to|need not)\b/i.test(sentence)) conflicts.add(group);
      }
      // "Not listed" (the 10-12 guide wording) is as weak as "not found": neither says the card excludes the service.
      if (item.id === 'kanopy' && /不包含|不提供|不能使用|\b(?:does not (?:include|offer)|cannot use|not available)\b/i.test(sentence)
        && group.statements.some(statement => TOPICS.kanopy.test(statement.text) && /未找到|尚未建立|没有列出|沒有列出|未列出|not (?:found|established|listed)|have not found|lists no|does not list/i.test(statement.text))) conflicts.add(group);
    }
    if (!conflicts.size) return item;
    changed = true;
    const rows = [];
    for (const group of conflicts) {
      if (currentAmbiguities.has(group)) {
        const fresh = currentAmbiguities.get(group);
        rows.push({ text: `${locale === 'en' ? 'Current read-page evidence differs or needs interpretation for this service: ' : '本次已读资料与站内规则存在差异，适用范围仍需确认：'}${fresh.text}`, scope: { sourceIds: [fresh.source.id] } });
        continue;
      }
      const direct = group.records.filter(scope => TOPICS[item.id].test(scope.heading));
      // Preserve whole sentences from the correct service. For card issuance,
      // a museum-pass sentence is never promoted to a general card condition.
      const statements = group.statements.filter(statement => statement.topic === item.id || item.id === 'kanopy' && statement.topic === 'card_eligibility');
      const chosen = statements.length ? statements : direct.flatMap(scope => sentences(scope.text).slice(1).map(text => ({ text, scope })));
      // A card clause whose whole sentence is already a row adds nothing (a Kanopy repair reads both).
      for (const statement of chosen) if (!rows.some(row => row.text === statement.text || (statement.clauseOf && row.text === statement.clauseOf))) rows.push(statement);
    }
    if (!rows.length) return { ...item, status: 'unknown', summary: locale === 'en' ? 'The cited restriction belongs to another service. Eligibility for this service remains unconfirmed.' : '所引资格限制属于其他服务；本项目的适用资格仍需确认。' };
    const factText = [...claims.filter(claim => !conflicts.has(claim.group)).map(claim => claim.sentence), ...rows.map(row => row.text)].join(' ');
    // A repaired answer is deliberately partial: it preserves sourced facts,
    // without claiming that quote extraction completed personal eligibility.
    return { ...item, status: 'unknown', summary: normalExcerpt(`${locale === 'en' ? 'Relevant source records: ' : '按对应项目的来源记录：'}${factText}`, 1200),
      sourceIds: [...new Set([...rows.flatMap(row => row.scope.sourceIds), ...(claims.some(claim => !conflicts.has(claim.group)) ? item.sourceIds : [])])].slice(0, 4) };
  });
  return { changed, coverage: { ...coverage, status: items.some(item => item.status !== 'answered') ? 'partial' : coverage.status, items } };
}
module.exports = { evidenceScopes, repairBenefitCoverage };
