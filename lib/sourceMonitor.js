// Fixed editorial sources only. A fetch proves reachability, never factual verification.
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');
const crypto = require('node:crypto');
const registryData = require('../data/source-registry.json');

const INTERVAL_MS = 6 * 60 * 60 * 1000;
const MAX_BYTES = 350000;
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

async function fetchSource(source, { fetch: request = requestOnce, lookup, timeoutMs = 12000 } = {}) {
  const controller = new AbortController();
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
      return { text, finalUrl: url.href };
    }
    throw monitorError('redirect-limit');
  } catch (error) {
    if (controller.signal.aborted) throw monitorError('timeout');
    throw error;
  } finally { clearTimeout(timer); }
}

function normalizeBody(html) {
  let body = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style|noscript|svg|iframe|nav|header|footer|form)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '');
  const main = body.match(/<main\b[^>]*>([\s\S]*?)<\/main\s*>/i) || body.match(/<article\b[^>]*>([\s\S]*?)<\/article\s*>/i);
  if (main) body = main[1];
  return body.replace(/<\/(?:p|div|li|h[1-6]|section|tr)>|<br\s*\/?\s*>/gi, '\n').replace(/<[^>]+>/g, ' ')
    .replace(/&#(x[\da-f]+|\d+);/gi, (_, entity) => { const code = entity[0].toLowerCase() === 'x' ? parseInt(entity.slice(1), 16) : Number(entity); return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : ''; })
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (_, entity) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' })[entity.toLowerCase()])
    .split('\n').map(line => line.replace(/\s+/g, ' ').trim()).filter(line => line && !/^(?:copyright|©)\s/i.test(line))
    .join('\n').slice(0, MAX_TEXT).trim();
}

function changeEvidence(before, after, fetchedAt) {
  const previous = new Set(before.split('\n')); const current = new Set(after.split('\n'));
  const removed = [...previous].filter(line => !current.has(line)).slice(0, 12);
  const added = [...current].filter(line => !previous.has(line)).slice(0, 12);
  return { before, after, removed, added, detectedAt: fetchedAt, hash: hash(after), summary: `${removed.length}${removed.length === 12 ? '+' : ''} removed / ${added.length}${added.length === 12 ? '+' : ''} added lines` };
}

function createMongoStore(mongoose, models = {}) {
  const Snapshot = models.SourceMonitorSnapshot || mongoose.models.SourceMonitorSnapshot || mongoose.model('SourceMonitorSnapshot', new mongoose.Schema({
    sourceId: { type: String, required: true, unique: true }, status: String, errorCode: String, lastFetchedAt: Number, lastAttemptAt: Number,
    text: String, hash: String, finalUrl: String, reviewStatus: String, pendingChange: mongoose.Schema.Types.Mixed,
    lastReviewedAt: Number, reviewedBy: String, reviewNote: String, reviewedHash: String,
  }, { timestamps: true }));
  const Lease = models.SourceMonitorLease || mongoose.models.SourceMonitorLease || mongoose.model('SourceMonitorLease', new mongoose.Schema({
    _id: String, owner: String, expiresAt: Number, lastStartedAt: Number,
  }));
  return {
    models: { SourceMonitorSnapshot: Snapshot, SourceMonitorLease: Lease },
    list: publicView => Snapshot.find({}).select(publicView ? 'sourceId status lastFetchedAt lastAttemptAt reviewStatus lastReviewedAt' : '-text').lean(),
    get: sourceId => Snapshot.findOne({ sourceId }).lean(),
    save: (sourceId, patch) => Snapshot.findOneAndUpdate({ sourceId }, { $set: patch }, { upsert: true, new: true }).lean(),
    review: (sourceId, expectedHash, patch) => Snapshot.findOneAndUpdate({ sourceId, hash: expectedHash }, { $set: patch }, { new: true }).lean(),
    async acquire(owner, now) {
      try { return !!await Lease.findOneAndUpdate({ _id: 'batch', expiresAt: { $lte: now }, lastStartedAt: { $lte: now - 60000 } }, { $set: { owner, expiresAt: now + 20 * 60000, lastStartedAt: now } }, { upsert: true, new: true }); }
      catch (error) { if (error.code === 11000) return false; throw error; }
    },
    release: (owner, now) => Lease.updateOne({ _id: 'batch', owner }, { $set: { expiresAt: now } }),
  };
}

function createSourceMonitor({ store, registry = registryData, now = Date.now, fetch, lookup, delay = ms => new Promise(resolve => setTimeout(resolve, ms)), logger = console, config = {} }) {
  let running = false; let timer; let stopped = false; let currentRun = null;
  const sources = new Map(registry.map(row => [row.id, row]));
  const today = () => dateInBayArea(now());
  async function checkOne(source) {
    const previous = await store.get(source.id); const fetchedAt = now();
    try {
      const result = await fetchSource(source, { fetch, lookup });
      const digest = hash(result.text);
      const patch = { lastAttemptAt: fetchedAt, lastFetchedAt: fetchedAt, text: result.text, hash: digest, finalUrl: result.finalUrl, errorCode: '', status: previous?.hash ? 'unchanged' : 'baseline' };
      if (!previous?.hash) patch.reviewStatus = 'baseline';
      else if (previous.hash !== digest) {
        patch.status = 'changed'; patch.reviewStatus = 'pending';
        patch.pendingChange = changeEvidence(previous.reviewStatus === 'pending' && previous.pendingChange?.before ? previous.pendingChange.before : previous.text, result.text, fetchedAt);
      }
      await store.save(source.id, patch);
    } catch (error) {
      const code = /^[a-z0-9-]{1,40}$/.test(error.code || '') ? error.code : 'fetch-failed';
      await store.save(source.id, { lastAttemptAt: fetchedAt, status: ['http-403', 'http-429', 'manual-required', 'unsupported-content', 'unsupported-encoding', 'page-too-large'].includes(code) ? 'manual-required' : 'error', errorCode: code });
    }
  }
  async function acquireRun(force) {
    if (running) return false;
    running = true;
    const owner = crypto.randomUUID();
    try {
      if (!await store.acquire(owner, now())) { running = false; return false; }
      currentRun = (async () => {
        try {
          for (const source of registry) {
            if (stopped) break;
            if (source.endDate && source.endDate < today()) continue;
            const previous = await store.get(source.id);
            if (!force && previous?.lastAttemptAt && now() - previous.lastAttemptAt < INTERVAL_MS) continue;
            await checkOne(source); await delay(1000);
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
        hash: row.hash || '', pendingChange: row.pendingChange || null };
    });
  }
  return {
    registry, sources, list, checkOne, isRunning: () => running,
    enqueue: (force = false) => acquireRun(force),
    async run(force = false) { const started = await acquireRun(force); if (started) await currentRun; return started; },
    async review(id, expectedHash, decision, note, userId) {
      if (!sources.has(id)) return null;
      return store.review(id, expectedHash, { reviewStatus: decision, lastReviewedAt: now(), reviewedBy: userId, reviewNote: note, reviewedHash: expectedHash });
    },
    start() {
      if (timer || config.NODE_ENV === 'test' || config.SOURCE_MONITOR_ENABLED === 'false') return;
      stopped = false;
      // Schedule from completion, so slower sources in a batch are not accidentally
      // considered too recent at the next tick and deferred for another six hours.
      const tick = async () => { try { if (await acquireRun(false)) await currentRun; else if (running && currentRun) await currentRun; } catch { logger.error('Source monitor could not acquire storage lease'); } finally { if (!stopped) { timer = setTimeout(tick, INTERVAL_MS); timer.unref?.(); } } };
      timer = setTimeout(tick, 30000); timer.unref?.();
    },
    stop() { stopped = true; if (timer) clearTimeout(timer); timer = null; },
  };
}

function registerSourceMonitor(app, { authenticateToken, requireAdmin, mongoose, models, config = {}, store: suppliedStore, registry, fetch, lookup, now, delay, logger, checkRateLimit, getClientIp }) {
  const store = suppliedStore || createMongoStore(mongoose, models);
  const service = createSourceMonitor({ store, registry, config, fetch, lookup, now, delay, logger });
  // Defense in depth: no route relies on callers remembering an admin middleware.
  const admin = (req, res, next) => req.user?.role === 'admin' ? (requireAdmin ? requireAdmin(req, res, next) : next()) : res.status(403).json({ error: '仅管理员可访问来源监测。' });
  const unavailable = res => res.status(503).json({ error: '来源监测暂不可用，请稍后重试。' });
  app.get('/api/admin/source-monitor', authenticateToken, admin, async (_req, res) => {
    res.set('Cache-Control', 'no-store');
    try { res.json({ sources: await service.list(), running: service.isRunning(), intervalHours: 6 }); } catch { unavailable(res); }
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
      res.json({ sources: rows.map(row => ({ sourceId: row.id, contentIds: row.contentIds, lastFetchedAt: row.lastFetchedAt, lastAttemptAt: row.lastAttemptAt,
        status: row.status, needsReview: row.reviewStatus === 'pending', lastReviewedAt: row.lastReviewedAt })) });
    } catch { unavailable(res); }
  });
  return { start: service.start, stop: service.stop, service, models: store.models || {} };
}

module.exports = { registerSourceMonitor, createSourceMonitor, createMongoStore, fetchSource, normalizeBody, changeEvidence, isPublicAddress, checkedUrl, INTERVAL_MS };
