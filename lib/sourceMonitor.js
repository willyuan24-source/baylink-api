// Fixed editorial sources only. A fetch proves reachability, never factual verification.
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');
const crypto = require('node:crypto');
const registryData = require('../data/source-registry.json');
const { createAiGovernance, createAiGovernanceModel } = require('./aiGovernance');
const { createSourceTriage, createDigestScheduler, createItemIndex, buildDigest, triageFlag, digestState, freshnessFields } = require('./sourceTriage');

const INTERVAL_MS = 6 * 60 * 60 * 1000;
const BATCH_LIMIT = 40;
const BATCH_MAX_MS = 10 * 60 * 1000;
const BACKLOG_DELAY_MS = 60000;
// Modern official sites can put 800 KB of CSS/navigation before <main>.
// Keep a hard response limit, while allowing their actual visitor information
// to arrive; normalized text and model context have separate, smaller caps.
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_TEXT = 24000;
const hash = text => crypto.createHash('sha256').update(text).digest('hex');
const dateInBayArea = now => new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Los_Angeles', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(now));
const monitorError = code => Object.assign(new Error(code), { code });

function isPublicAddress(address) {
  if (net.isIP(address) === 4) {
    const [a, b] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && [0, 2, 168].includes(b))
      || (a === 198 && [18, 19, 51].includes(b)) || (a === 203 && b === 0));
  }
  // Require ordinary global unicast IPv6; reject mapped IPv4, local and documentation ranges.
  if (net.isIP(address) === 6) {
    const [first, second] = address.split(':').map(part => parseInt(part || '0', 16));
    return /^[23]/i.test(address) && first !== 0x2002 && first !== 0x3fff
      && !(first === 0x2001 && (second <= 0x1ff || second === 0xdb8));
  }
  return false;
}

function allowedHostsFor(source) {
  const host = new URL(source.url).hostname.toLowerCase();
  const hosts = new Set([host]);
  // Canonical www redirects are the only implicit aliases. Other redirect hosts
  // must be individually reviewed and checked into the registry.
  hosts.add(host.startsWith('www.') ? host.slice(4) : `www.${host}`);
  for (const alias of source.redirectHosts || []) hosts.add(alias.toLowerCase());
  return hosts;
}

async function checkedUrl(value, source, lookup = dns.lookup.bind(dns)) {
  let url;
  try { url = new URL(value); } catch { throw monitorError('unsafe-url'); }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')
    || !allowedHostsFor(source).has(url.hostname.toLowerCase()) || net.isIP(url.hostname)) throw monitorError('unsafe-url');
  const addresses = await lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(item => !isPublicAddress(item.address))) throw monitorError('unsafe-address');
  return { url, address: addresses[0] };
}

function requestOnce(url, { signal, address }) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      signal, method: 'GET', headers: { 'User-Agent': 'BAYLINK-SourceMonitor/1.0 (+https://www.baylink.us/about)', Accept: 'text/html,text/plain', 'Accept-Encoding': 'identity' },
      // Pin the validated DNS result for the actual connection to close DNS-rebinding races.
      lookup: (_hostname, options, callback) => options?.all
        ? callback(null, [address]) : callback(null, address.address, address.family),
    }, response => {
      const status = response.statusCode || 0;
      if (status < 200 || status >= 300) { response.resume(); return resolve({ status, headers: response.headers, body: '' }); }
      if (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') { response.destroy(); return reject(monitorError('unsupported-encoding')); }
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > MAX_BYTES) response.destroy(monitorError('page-too-large')); else chunks.push(chunk); });
      response.on('end', () => resolve({ status, headers: response.headers, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end();
  });
}

async function fetchSource(source, { fetch: request = requestOnce, lookup, timeoutMs = 12000, signal } = {}) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let target = source.url;
    for (let redirects = 0; redirects <= 4; redirects++) {
      const { url, address } = await Promise.race([
        checkedUrl(target, source, lookup),
        new Promise((_, reject) => { if (controller.signal.aborted) reject(monitorError('timeout')); else controller.signal.addEventListener('abort', () => reject(monitorError('timeout')), { once: true }); }),
      ]);
      const response = await request(url, { signal: controller.signal, address });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (!response.headers.location || redirects === 4) throw monitorError('redirect-limit');
        target = new URL(response.headers.location, url).href;
        continue;
      }
      if (response.status === 403 || response.status === 429) throw monitorError(`http-${response.status}`);
      if (response.status < 200 || response.status >= 300) throw monitorError(`http-${response.status}`);
      if (!/^(?:text\/html|text\/plain|application\/xhtml\+xml)\b/i.test(response.headers['content-type'] || '')) throw monitorError('unsupported-content');
      if (Buffer.byteLength(response.body, 'utf8') > MAX_BYTES) throw monitorError('page-too-large');
      const text = normalizeBody(response.body);
      if (text.length < 100 || /(?:just a moment|verify you are human|enable javascript.{0,30}(?:continue|view)|checking your browser)/i.test(text.slice(0, 400))) throw monitorError('manual-required');
      return { text, finalUrl: url.href, links: relatedVisitorLinks(response.body, source.url, url.href), media: mediaCandidates(response.body, url.href) };
    }
    throw monitorError('redirect-limit');
  } catch (error) {
    if (controller.signal.aborted) throw monitorError('timeout');
    throw error;
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

function relatedVisitorLinks(html, sourceUrl, finalUrl) {
  const source = new URL(sourceUrl), base = new URL(finalUrl), links = new Map();
  const clean = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style|noscript|svg|iframe|form)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '');
  for (const match of clean.matchAll(/<a\b[^>]*\bhref\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a\s*>/gi)) {
    const title = normalizeMarkup(match[3]).replace(/\s+/g, ' ').trim();
    if (!title || title.length > 180 || !/eligib|terms|admission|opening|hours|tickets?|discount|accessibility|visit|资格|資格|条款|條款|门票|門票|开放|開放|营业|營業|优惠|優惠/i.test(title)) continue;
    try {
      const target = new URL(normalizeMarkup(match[2]), base);
      // Discover only links actually present on this public source. Reading
      // another page remains a separate tool call with all DNS/HTTPS checks.
      if (target.origin !== source.origin || target.protocol !== 'https:' || target.username || target.password || target.href.length > 2000) continue;
      target.hash = '';
      if (target.href === base.href || /\.(?:pdf|zip|exe|dmg)$/i.test(target.pathname)) continue;
      const previous = links.get(target.href);
      const rank = /eligib|资格|資格/i.test(title) ? 0 : /discount|admission|优惠|優惠|门票|門票/i.test(title) ? 1 : 2;
      if (!previous || rank < previous.rank) links.set(target.href, { title, url: target.href, rank });
    } catch { /* A malformed link is not a discoverable source. */ }
  }
  return [...links.values()].sort((a, b) => a.rank - b.rank).slice(0, 24).map(({ title, url }) => ({ title, url }));
}

// Organiser image candidates from the page head: og:image (+ alt, declared size),
// twitter:image and <title>. Recorded as text for the owner's per-item approval
// list only; nothing here downloads, proxies or displays an image.
// Matched against the file name: logos, icons, favicons, sprites and site-wide default share images.
const LOGO_LIKE = /logo|favicon|sprite|placeholder|apple-touch|default[-_]?(?:image|share|og)|(?:^|[^a-z])icons?(?:[^a-z]|$)/i;
// A size in the file name ("..._258x258.png") stands in for a missing og:image:width.
const NAMED_SIZE = /(?:^|\D)(\d{2,4})x\d{2,4}(?:\D|$)/;
function mediaCandidates(html, pageUrl) {
  const head = html.slice(0, 300000).replace(/<!--[\s\S]*?-->/g, '').split(/<body\b/i)[0];
  const meta = new Map();
  for (const [tag] of head.matchAll(/<meta\b[^>]*>/gi)) {
    const attributes = {};
    for (const match of tag.matchAll(/([a-zA-Z][\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g)) attributes[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
    const key = (attributes.property || attributes.name || '').trim().toLowerCase();
    if (key && attributes.content !== undefined && !meta.has(key)) meta.set(key, normalizeMarkup(attributes.content).replace(/\s+/g, ' ').trim());
  }
  const image = value => {
    if (!value || value.length > 2000) return '';
    try {
      const target = new URL(value, pageUrl);
      return ['https:', 'http:'].includes(target.protocol) && !target.username && !target.password ? target.href : '';
    } catch { return ''; }
  };
  const size = value => /^\d{1,5}$/.test(value || '') ? Number(value) : null;
  const titleMatch = head.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i);
  const candidate = {
    ogImage: image(meta.get('og:image:secure_url') || meta.get('og:image') || meta.get('og:image:url')),
    ogImageAlt: (meta.get('og:image:alt') || '').slice(0, 300),
    ogImageWidth: size(meta.get('og:image:width')), ogImageHeight: size(meta.get('og:image:height')),
    twitterImage: image(meta.get('twitter:image') || meta.get('twitter:image:src')),
    title: titleMatch ? normalizeMarkup(titleMatch[1]).replace(/\s+/g, ' ').trim().slice(0, 300) : '',
  };
  const urls = [candidate.ogImage, candidate.twitterImage].filter(Boolean);
  // Heuristic only (content.md §4.3): logo-like file names or a declared width
  // under 600 px are rarely usable covers. The owner still reviews every item.
  const fileName = url => { const name = new URL(url).pathname.split('/').pop() || ''; try { return decodeURIComponent(name); } catch { return name; } };
  const namedWidth = url => Number(NAMED_SIZE.exec(fileName(url))?.[1] || 0);
  candidate.likelyLogo = urls.length > 0 && (urls.every(url => LOGO_LIKE.test(fileName(url)))
    || (candidate.ogImageWidth !== null && candidate.ogImageWidth < 600)
    || urls.every(url => namedWidth(url) > 0 && namedWidth(url) < 600));
  return Object.fromEntries(Object.entries(candidate).filter(([, value]) => value !== '' && value !== null));
}

function normalizeBody(html) {
  const clean = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style|noscript|svg|iframe|form)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '');
  // Visitor hours are sometimes published only in the footer (e.g. SFMOMA).
  // Retain that labelled context, including distinct museum/store schedules,
  // while ordinary navigation and copyright footers stay out of snapshots.
  const schedule = /\b(?:mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)\b[^\n]{0,50}(?:\d|closed|noon|midnight)|(?:周|週|星期)[一二三四五六日天][^\n]{0,50}(?:\d|闭|閉)/i;
  const visitorFooters = [...clean.matchAll(/<footer\b[^>]*>([\s\S]*?)<\/footer\s*>/gi)]
    .map(match => normalizeMarkup(match[1]))
    .filter(text => /\b(?:hours|opening times)\b|营业时间|營業時間|开放时间|開放時間/i.test(text)
      && schedule.test(text))
    .map(text => {
      // Skip large navigation blocks before the first schedule, retaining its
      // nearby heading so a store's hours remain labelled as store hours.
      const lines = text.split('\n'), at = lines.findIndex(line => schedule.test(line));
      return lines.slice(Math.max(0, at - 3)).join('\n').slice(0, 1500);
    });
  let body = clean.replace(/<(nav|header|footer)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '');
  const main = body.match(/<main\b[^>]*>([\s\S]*?)<\/main\s*>/i) || body.match(/<article\b[^>]*>([\s\S]*?)<\/article\s*>/i);
  if (main) body = main[1];
  const mainText = normalizeMarkup(body);
  const appendix = [...new Set(visitorFooters)].filter(text => !mainText.includes(text)).join('\n').slice(0, 1500);
  if (!appendix) return mainText.slice(0, MAX_TEXT).trim();
  const labelled = `\nVisitor information in page footer (separate schedules retain their labels):\n${appendix}`;
  // Put the labelled schedule before long exhibition prose: downstream source
  // storage/model contexts are bounded, and must not discard the sole hours.
  return labelled.trimStart() + '\n' + mainText.slice(0, MAX_TEXT - labelled.length - 1);
}

function normalizeMarkup(body) {
  return body.replace(/<\/(?:p|div|li|h[1-6]|section|tr)>|<br\s*\/?\s*>/gi, '\n').replace(/<[^>]+>/g, ' ')
    .replace(/&#(x[\da-f]+|\d+);/gi, (_, entity) => { const code = entity[0].toLowerCase() === 'x' ? parseInt(entity.slice(1), 16) : Number(entity); return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : ''; })
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (_, entity) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' })[entity.toLowerCase()])
    .split('\n').map(line => line.replace(/\s+/g, ' ').trim()).filter(line => line && !/^(?:copyright|©)\s/i.test(line))
    .join('\n').trim();
}

// `detectedAt` is the latest detection; `firstDetectedAt` is when this still
// unreviewed change was first seen (the editor's 48-hour window starts there).
function changeEvidence(before, after, fetchedAt, firstDetectedAt = fetchedAt) {
  const previous = new Set(before.split('\n')); const current = new Set(after.split('\n'));
  const removed = [...previous].filter(line => !current.has(line)).slice(0, 12);
  const added = [...current].filter(line => !previous.has(line)).slice(0, 12);
  return { before, after, removed, added, detectedAt: fetchedAt, firstDetectedAt, hash: hash(after), summary: `${removed.length}${removed.length === 12 ? '+' : ''} removed / ${added.length}${added.length === 12 ? '+' : ''} added lines` };
}

function createMongoStore(mongoose, models = {}) {
  const Snapshot = models.SourceMonitorSnapshot || mongoose.models.SourceMonitorSnapshot || mongoose.model('SourceMonitorSnapshot', new mongoose.Schema({
    sourceId: { type: String, required: true, unique: true }, status: String, errorCode: String, lastFetchedAt: Number, lastAttemptAt: Number,
    text: String, hash: String, finalUrl: String, reviewStatus: String, pendingChange: mongoose.Schema.Types.Mixed,
    lastReviewedAt: Number, reviewedBy: String, reviewNote: String, reviewedHash: String,
    // API-FRESH-TRIAGE: the triage decision for the current hash, and organiser
    // image candidates from the page head (text only; never downloaded).
    triage: mongoose.Schema.Types.Mixed, mediaCandidates: mongoose.Schema.Types.Mixed,
    // The last review by an editor; automatic triage overwrites lastReviewedAt, never these.
    lastEditorReviewAt: Number, lastEditorReviewedBy: String,
  }, { timestamps: true }));
  const Lease = models.SourceMonitorLease || mongoose.models.SourceMonitorLease || mongoose.model('SourceMonitorLease', new mongoose.Schema({
    _id: String, owner: String, expiresAt: Number, lastStartedAt: Number,
    // `triage-calls:YYYY-MM-DD` documents count triage model calls per Pacific day.
    calls: Number,
  }));
  return {
    models: { SourceMonitorSnapshot: Snapshot, SourceMonitorLease: Lease },
    // The public view carries what the freshness endpoint derives its fields from;
    // reviewer identities and hashes are read but never returned (see the endpoint).
    list: publicView => Snapshot.find({}).select(publicView ? 'sourceId status lastFetchedAt lastAttemptAt reviewStatus lastReviewedAt reviewedBy hash pendingChange.detectedAt pendingChange.firstDetectedAt triage.hash triage.material triage.fields' : '-text').lean(),
    get: sourceId => Snapshot.findOne({ sourceId }).lean(),
    pendingForTriage: () => Snapshot.find({ reviewStatus: 'pending', pendingChange: { $exists: true } })
      .select('sourceId hash status reviewStatus reviewedBy lastReviewedAt lastEditorReviewAt triage pendingChange.removed pendingChange.added pendingChange.summary pendingChange.detectedAt pendingChange.firstDetectedAt').lean(),
    // The full page texts of one pending change, read only when its stored diff was cut off.
    pendingText: sourceId => Snapshot.findOne({ sourceId }).select('hash pendingChange.before pendingChange.after').lean(),
    // Triage model calls per Pacific day, shared by every instance and kept across restarts.
    triageCalls: async day => (await Lease.findOne({ _id: `triage-calls:${day}` }).select('calls').lean())?.calls || 0,
    addTriageCalls: (day, calls) => Lease.updateOne({ _id: `triage-calls:${day}` }, { $inc: { calls }, $setOnInsert: { owner: 'source-triage', expiresAt: 0, lastStartedAt: 0 } }, { upsert: true }),
    digestRows: since => Snapshot.find({ $or: [{ reviewStatus: 'pending' }, { reviewedBy: 'auto-triage', lastReviewedAt: { $gte: since } }] })
      .select('sourceId hash status reviewStatus reviewedBy lastReviewedAt triage pendingChange.detectedAt pendingChange.firstDetectedAt').lean(),
    // Compare-and-set: only the still-pending text that was triaged is updated, so a
    // newer page version or an editor's review always wins over an automatic decision.
    triage: (sourceId, expectedHash, patch) => Snapshot.findOneAndUpdate({ sourceId, hash: expectedHash, reviewStatus: 'pending' }, { $set: patch }, { new: true }).lean(),
    async claimDigest(day, now) {
      try { await Lease.create({ _id: `digest:${day}`, owner: 'source-digest', expiresAt: now, lastStartedAt: now }); return true; }
      catch (error) { if (error.code === 11000) return false; throw error; }
    },
    releaseDigest: day => Lease.deleteOne({ _id: `digest:${day}` }),
    async save(sourceId, patch) {
      try {
        return await Snapshot.findOneAndUpdate({ sourceId, $or: [{ lastAttemptAt: { $exists: false } }, { lastAttemptAt: { $lte: patch.lastAttemptAt } }] }, { $set: patch }, { upsert: true, new: true }).lean();
      } catch (error) {
        // A late batch cannot replace a newer attempt after losing its lease.
        if (error.code === 11000) return null;
        throw error;
      }
    },
    review: (sourceId, expectedHash, patch) => Snapshot.findOneAndUpdate({ sourceId, hash: expectedHash }, { $set: patch }, { new: true }).lean(),
    async acquire(owner, now) {
      try { return !!await Lease.findOneAndUpdate({ _id: 'batch', expiresAt: { $lte: now }, lastStartedAt: { $lte: now - 60000 } }, { $set: { owner, expiresAt: now + 20 * 60000, lastStartedAt: now } }, { upsert: true, new: true }); }
      catch (error) { if (error.code === 11000) return false; throw error; }
    },
    release: (owner, now) => Lease.updateOne({ _id: 'batch', owner }, { $set: { expiresAt: now } }),
    ownsLease: async (owner, now) => !!await Lease.findOne({ _id: 'batch', owner, expiresAt: { $gt: now } }).select('_id').lean(),
  };
}

function createSourceMonitor({ store, registry = registryData, now = Date.now, fetch, lookup, delay = ms => new Promise(resolve => setTimeout(resolve, ms)), logger = console, config = {}, triage }) {
  let running = false; let timer; let stopped = false; let currentRun = null; let backlog = false;
  const sources = new Map(registry.map(row => [row.id, row]));
  const today = () => dateInBayArea(now());
  async function checkOne(source, assertLease) {
    const previous = await store.get(source.id); const fetchedAt = now();
    if (assertLease) await assertLease();
    let patch;
    try {
      const result = await fetchSource(source, { fetch, lookup });
      const digest = hash(result.text);
      patch = { lastAttemptAt: fetchedAt, lastFetchedAt: fetchedAt, text: result.text, hash: digest, finalUrl: result.finalUrl, errorCode: '', status: previous?.hash ? 'unchanged' : 'baseline' };
      if (result.media && Object.keys(result.media).some(key => key !== 'likelyLogo')) patch.mediaCandidates = { ...result.media, seenAt: fetchedAt };
      if (!previous?.hash) patch.reviewStatus = 'baseline';
      else if (previous.hash !== digest) {
        patch.status = 'changed'; patch.reviewStatus = 'pending';
        const unreviewed = previous.reviewStatus === 'pending' && previous.pendingChange?.before ? previous.pendingChange : null;
        patch.pendingChange = changeEvidence(unreviewed ? unreviewed.before : previous.text, result.text, fetchedAt,
          unreviewed ? unreviewed.firstDetectedAt || unreviewed.detectedAt || fetchedAt : fetchedAt);
      }
    } catch (error) {
      const code = /^[a-z0-9-]{1,40}$/.test(error.code || '') ? error.code : 'fetch-failed';
      patch = { lastAttemptAt: fetchedAt, status: ['http-403', 'http-429', 'manual-required', 'unsupported-content', 'unsupported-encoding', 'page-too-large'].includes(code) ? 'manual-required' : 'error', errorCode: code };
    }
    if (assertLease) await assertLease();
    await store.save(source.id, patch);
  }
  async function acquireRun(force) {
    if (running) return false;
    running = true;
    const owner = crypto.randomUUID();
    try {
      if (!await store.acquire(owner, now())) { running = false; return false; }
      const startedAt = now();
      const assertLease = async () => {
        if (store.ownsLease && !await store.ownsLease(owner, now())) throw monitorError('lease-lost');
      };
      currentRun = (async () => {
        try {
          const snapshots = new Map((await store.list(true)).map(row => [row.sourceId, row]));
          // Oldest attempts first makes progress durable across restarts and
          // repeated manual batches; failed pages cannot starve unseen sources.
          const eligible = registry.filter(source => (!source.endDate || source.endDate >= today())
            && (force || !snapshots.get(source.id)?.lastAttemptAt || now() - snapshots.get(source.id).lastAttemptAt >= INTERVAL_MS))
            .sort((a, b) => (snapshots.get(a.id)?.lastAttemptAt || 0) - (snapshots.get(b.id)?.lastAttemptAt || 0) || a.id.localeCompare(b.id));
          let checked = 0;
          backlog = eligible.length > BATCH_LIMIT;
          for (const source of eligible.slice(0, BATCH_LIMIT)) {
            if (stopped || now() - startedAt >= BATCH_MAX_MS) { backlog = true; break; }
            await assertLease();
            await checkOne(source, assertLease); checked++;
            if (checked < Math.min(eligible.length, BATCH_LIMIT)) await delay(1000);
          }
          if (checked < eligible.length) backlog = true;
          // Triage pending changes while this instance still holds the lease, so two
          // instances never pay for the same classification. Off unless SOURCE_TRIAGE is on.
          if (triage && !stopped) {
            try { await triage.run({ assertLease }); }
            catch (error) { if (error.code === 'lease-lost') throw error; logger.error('Source triage failed:', error.code || 'triage-failed'); }
          }
        } finally { try { await store.release(owner, now()); } finally { running = false; } }
      })();
      currentRun.catch(error => logger.error('Source monitor batch failed:', error.code || 'storage-unavailable'));
      return true;
    } catch (error) { running = false; throw error; }
  }
  async function list(publicView = false) {
    const existing = new Map((await store.list(publicView)).map(row => [row.sourceId, row]));
    return registry.map(source => {
      const row = existing.get(source.id) || {};
      return { ...source, status: source.endDate && source.endDate < today() ? 'expired' : row.status || 'not-checked', errorCode: row.errorCode || '',
        lastFetchedAt: row.lastFetchedAt || null, lastAttemptAt: row.lastAttemptAt || null, reviewStatus: row.reviewStatus || 'none',
        lastReviewedAt: row.lastReviewedAt || null, reviewedBy: row.reviewedBy || '', reviewNote: row.reviewNote || '',
        lastEditorReviewAt: row.lastEditorReviewAt || null, lastEditorReviewedBy: row.lastEditorReviewedBy || '',
        hash: row.hash || '', pendingChange: row.pendingChange || null, triage: row.triage || null, mediaCandidates: row.mediaCandidates || null };
    });
  }
  return {
    registry, sources, list, checkOne, isRunning: () => running,
    enqueue: (force = false) => acquireRun(force),
    async run(force = false) { const started = await acquireRun(force); if (started) await currentRun; return started; },
    async review(id, expectedHash, decision, note, userId) {
      if (!sources.has(id)) return null;
      const at = now();
      return store.review(id, expectedHash, { reviewStatus: decision, lastReviewedAt: at, reviewedBy: userId, reviewNote: note, reviewedHash: expectedHash, lastEditorReviewAt: at, lastEditorReviewedBy: userId });
    },
    start() {
      if (timer || config.NODE_ENV === 'test' || config.SOURCE_MONITOR_ENABLED === 'false') return;
      stopped = false;
      // Schedule from completion, so slower sources in a batch are not accidentally
      // considered too recent at the next tick and deferred for another six hours.
      const tick = async () => { try { if (await acquireRun(false)) await currentRun; else if (running && currentRun) await currentRun; } catch { backlog = false; logger.error('Source monitor could not acquire storage lease'); } finally { if (!stopped) { timer = setTimeout(tick, backlog ? BACKLOG_DELAY_MS : INTERVAL_MS); timer.unref?.(); } } };
      timer = setTimeout(tick, 30000); timer.unref?.();
    },
    stop() { stopped = true; if (timer) clearTimeout(timer); timer = null; },
  };
}

function registerSourceMonitor(app, { authenticateToken, requireAdmin, mongoose, models, config = {}, store: suppliedStore, registry = registryData, fetch, lookup, now = Date.now, delay, logger = console, checkRateLimit, getClientIp,
  triageRequest, triageFetch, recordSpend, sendEmail, items: suppliedItems }) {
  const store = suppliedStore || createMongoStore(mongoose, models);
  // Spend ledger for triage calls: the shared AiGovernance documents, built on first use.
  let ledger;
  const spend = recordSpend || (mongoose ? billing => (ledger ||= createAiGovernance({ Model: createAiGovernanceModel(mongoose, models || {}), config, now })).recordSpend(billing) : undefined);
  const items = suppliedItems || createItemIndex();
  const triage = createSourceTriage({ store, registry, config, now, logger, items, recordSpend: spend, ...(triageRequest ? { requestJson: triageRequest } : {}), ...(triageFetch ? { fetchImpl: triageFetch } : {}) });
  const digest = createDigestScheduler({ store, registry, config, now, logger, sendEmail, items });
  const service = createSourceMonitor({ store, registry, config, fetch, lookup, now, delay, logger, triage });
  const triageOn = () => triageFlag(config) === 'on';
  // Defense in depth: no route relies on callers remembering an admin middleware.
  const admin = (req, res, next) => req.user?.role === 'admin' ? (requireAdmin ? requireAdmin(req, res, next) : next()) : res.status(403).json({ error: '仅管理员可访问来源监测。' });
  const unavailable = res => res.status(503).json({ error: '来源监测暂不可用，请稍后重试。' });
  app.get('/api/admin/source-monitor', authenticateToken, admin, async (_req, res) => {
    res.set('Cache-Control', 'no-store');
    try { res.json({ sources: await service.list(), running: service.isRunning(), intervalHours: 6, batchLimit: BATCH_LIMIT, triage: { ...triage.state(), ...triage.usage(), digest: digestState(config).reason } }); } catch { unavailable(res); }
  });
  // The digest an owner would receive now (nothing is sent). Null when nothing needs attention.
  app.get('/api/admin/source-monitor/digest', authenticateToken, admin, async (_req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const at = now(), rows = store.digestRows ? await store.digestRows(at - 86400000) : await store.list(false);
      res.json({ digest: buildDigest({ rows, registry, items, now: at, state: triage.state() }), delivery: digestState(config).reason });
    } catch { unavailable(res); }
  });
  // Organiser image candidates (og:image / twitter:image / title) for the owner's
  // per-item approval list (RC-32). URLs only: nothing is downloaded or displayed.
  app.get('/api/admin/source-monitor/media-candidates', authenticateToken, admin, async (_req, res) => {
    res.set('Cache-Control', 'no-store');
    try { res.json({ candidates: mediaCandidateList(await service.list(), items, dateInBayArea(now())) }); } catch { unavailable(res); }
  });
  app.post('/api/admin/source-monitor/run', authenticateToken, admin, async (req, res) => {
    if (req.body && Object.keys(req.body).length) return res.status(400).json({ error: '此操作只检查已登记的官方来源。' });
    try { const started = await service.enqueue(true); res.status(started ? 202 : 409).json(started ? { started: true } : { error: '检查已在进行或刚完成，请稍后刷新。' }); } catch { unavailable(res); }
  });
  app.patch('/api/admin/source-monitor/:id/review', authenticateToken, admin, async (req, res) => {
    const body = req.body || {};
    if (!['acknowledged', 'dismissed'].includes(body.decision) || !/^[a-f0-9]{64}$/.test(body.expectedHash || '')
      || (body.note !== undefined && (typeof body.note !== 'string' || body.note.length > 500)) || Object.keys(body).some(key => !['decision', 'expectedHash', 'note'].includes(key))) return res.status(400).json({ error: '请提供当前版本、复核结果及 500 字以内备注。' });
    if (!service.sources.has(req.params.id)) return res.status(404).json({ error: '来源不存在。' });
    try {
      const row = await service.review(req.params.id, body.expectedHash, body.decision, (body.note || '').trim(), req.user.id);
      if (!row) return res.status(409).json({ error: '来源内容已变化，请刷新后重新复核。' });
      res.json({ reviewed: true, lastReviewedAt: row.lastReviewedAt });
    } catch { unavailable(res); }
  });
  app.get('/api/sources/freshness', async (req, res) => {
    if (checkRateLimit && !checkRateLimit(`source-freshness:${getClientIp?.(req) || req.ip}`, { windowMs: 60000, maxRequests: 120 })) return res.status(429).json({ error: '查询过于频繁，请稍后重试。' });
    const raw = req.query.ids;
    if (typeof raw !== 'string' || raw.length > 12000 || !raw || raw.split(',').length > 100 || raw.split(',').some(id => !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,119}$/.test(id))) return res.status(400).json({ error: '请提供 1–100 个有效内容编号。' });
    try {
      const ids = new Set(raw.split(','));
      const rows = (await service.list(true)).filter(row => ids.has(row.id) || row.contentIds.some(id => ids.has(id)));
      res.set('Cache-Control', 'public, max-age=120');
      // With SOURCE_TRIAGE off the response is exactly the pre-triage shape.
      const extended = triageOn();
      res.json({ sources: rows.map(row => ({ sourceId: row.id, contentIds: row.contentIds, lastFetchedAt: row.lastFetchedAt, lastAttemptAt: row.lastAttemptAt,
        status: row.status, needsReview: row.reviewStatus === 'pending', lastReviewedAt: row.lastReviewedAt, ...(extended ? freshnessFields(row) : {}) })) });
    } catch { unavailable(res); }
  });
  return {
    start() { service.start(); digest.start(); },
    stop() { service.stop(); digest.stop(); },
    service, triage, digest, models: store.models || {},
  };
}

/** Admin view of organiser image candidates: listings that still run, nearest date first. */
function mediaCandidateList(rows, items, today) {
  const withImage = rows.filter(row => row.status !== 'expired' && row.mediaCandidates && (row.mediaCandidates.ogImage || row.mediaCandidates.twitterImage));
  // A URL shared by three or more sources of one host is usually a site-wide default image.
  const shared = new Map();
  for (const row of withImage) {
    const key = `${new URL(row.url).hostname}|${row.mediaCandidates.ogImage || row.mediaCandidates.twitterImage}`;
    shared.set(key, (shared.get(key) || 0) + 1);
  }
  return withImage.map(row => {
    const listings = items.items(row.contentIds);
    const nextDate = listings.flatMap(item => item.dates || []).filter(date => typeof date === 'string' && date >= today).sort()[0] || null;
    const image = row.mediaCandidates.ogImage || row.mediaCandidates.twitterImage;
    return { sourceId: row.id, kind: row.kind, title: row.title, url: row.url, contentIds: row.contentIds, nextDate,
      listings: listings.slice(0, 3).map(item => ({ title: item.title, path: item.path })),
      ...row.mediaCandidates, siteDefault: shared.get(`${new URL(row.url).hostname}|${image}`) >= 3 };
  }).sort((a, b) => (a.nextDate || '9999').localeCompare(b.nextDate || '9999') || a.sourceId.localeCompare(b.sourceId)).slice(0, 300);
}

module.exports = { registerSourceMonitor, createSourceMonitor, createMongoStore, fetchSource, normalizeBody, mediaCandidates, changeEvidence, isPublicAddress, checkedUrl, INTERVAL_MS, BATCH_LIMIT, BATCH_MAX_MS, BACKLOG_DELAY_MS };
