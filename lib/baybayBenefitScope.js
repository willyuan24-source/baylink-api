// Preserve the scope of editorial evidence. These labels classify services;
// they supply no eligibility rules. Every restriction below is extracted from
// this turn's actual source paragraphs, not a prewritten library answer.
const { normalExcerpt } = require('./baybayAnswerQuality');
const TOPICS = {
  printing: /打印|列印|\bprint(?:ing|ers?)?\b/i,
  kanopy: /\bkanopy\b/i,
  museum_passes: /discover\s*(?:&|and)\s*go|馆票|館票|门票|門票|museum passes/i,
  card_eligibility: /办卡|辦卡|申请.{0,8}(?:卡|图书证)|申請.{0,8}(?:卡|圖書證)|图书证|圖書證|ecard|(?:apply|application|library card)/i,
};
const normalize = value => String(value || '').normalize('NFKD').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
const urlKey = value => { try { const u = new URL(value, 'https://www.baylink.us'); u.hash = ''; return u.href.replace(/\/$/, ''); } catch { return ''; } };
const withoutUrls = value => String(value || '').replace(/https?:\/\/[^\s<>）)]+/g, '').replace(/^[^\n。]{0,80}[：:]\s*$/gm, '').trim();
const sentences = text => withoutUrls(text).split(/(?<=[。！？])\s*|[.!?](?=\s|$)|\n+/).filter(Boolean);

function evidenceScopes(guides, store) {
  const seen = new Set();
  return (guides || []).flatMap(guide => {
    if (!guide.text || seen.has(guide.evidenceId || guide.text)) return [];
    seen.add(guide.evidenceId || guide.text);
    const heading = guide.sectionHeading || guide.text.split('\n')[0];
    const entity = heading.split(/[：:·]/)[0].trim();
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
  if (/e-?card.{0,30}(?:不含|不适用|不適用|不接受|not (?:accepted|eligible|valid)|does not include)|(?:不接受|不支持|exclude).{0,12}e-?card/i.test(text)) found.push('ecard:excluded');
  for (const match of text.matchAll(/([^，,；;。\n]{1,65}?)(?:居民|\bresidents?\b)/gi)) {
    let place = match[1].split(/[:：]|(?:需|须|須|限|是|为|為|要求|住在|居住在)|\b(?:must be|requires?|only|to|for|of)\b/i).at(-1).trim();
    place = place.replace(/^(?:持卡人|用户|用戶|the|a)\s*/i, '');
    if (place && place.length <= 35) found.push(`residence:${normalize(place).replace(/^sanfrancisco$|^旧金山$|^舊金山$/, 'sanfrancisco')}`);
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

function repairBenefitCoverage(coverage, scopes, locale, sources = new Map()) {
  const groups = new Map();
  for (const scope of scopes) {
    // Require an explicit institutional heading. Generic editorial prose is
    // useful context, but cannot supply an institution's eligibility rule.
    if (!/librar/i.test(scope.entity) && !/^[A-Z]{3,8}$/.test(scope.entity)) continue;
    const group = groups.get(scope.entityKey) || { aliases: [], records: [], statements: [] };
    group.aliases.push(normalize(scope.entity), scope.entityKey); group.records.push(scope);
    for (const sentence of sentences(scope.text).slice(1)) {
      const topic = statementTopic(sentence, scope.heading);
      group.statements.push({ text: sentence, topic, restrictions: restrictions(sentence), scope });
    }
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
      if (item.id === 'kanopy' && /不包含|不提供|不能使用|\b(?:does not (?:include|offer)|cannot use|not available)\b/i.test(sentence)
        && group.statements.some(statement => TOPICS.kanopy.test(statement.text) && /未找到|尚未建立|not (?:found|established)|have not found/i.test(statement.text))) conflicts.add(group);
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
      for (const statement of chosen) if (!rows.some(row => row.text === statement.text)) rows.push(statement);
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
