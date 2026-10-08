// Error responses and 5xx logging for the Express app.
// Every error becomes a JSON body, and every 5xx response (from the error handler
// or from a route that answers 5xx itself) produces exactly one structured log line.
// The line never contains request bodies, URLs, IPs, user ids or error messages,
// which can echo user input: only the route pattern, status and error name/code.

const SAFE_NAME = /^[A-Za-z][A-Za-z0-9_]{0,59}$/;
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
const safeName = value => typeof value === 'string' && SAFE_NAME.test(value) ? value : undefined;
const safeCode = value => (typeof value === 'number' && Number.isFinite(value)) || (typeof value === 'string' && SAFE_CODE.test(value)) ? value : undefined;

function describeFailure(failure) {
  if (!failure || typeof failure !== 'object') return { error: typeof failure };
  const code = safeCode(failure.code);
  const cause = failure.cause && typeof failure.cause === 'object' ? {
    ...(safeName(failure.cause.name) ? { name: safeName(failure.cause.name) } : {}),
    ...(safeCode(failure.cause.code) !== undefined ? { code: safeCode(failure.cause.code) } : {}),
  } : {};
  return {
    error: safeName(failure.name) || safeName(failure.constructor?.name) || 'Error',
    ...(code !== undefined ? { code } : {}),
    ...(Object.keys(cause).length ? { cause } : {}),
  };
}

const routePattern = req => {
  const path = req.route?.path;
  if (typeof path === 'string') return `${req.baseUrl || ''}${path}`;
  return path ? 'pattern' : 'unmatched';
};

const releaseOf = config => /^[a-f0-9]{40}$/i.test(config?.RENDER_GIT_COMMIT || '') ? config.RENDER_GIT_COMMIT.slice(0, 12).toLowerCase() : null;
const defaultLog = line => console.error(JSON.stringify(line));

const statusOf = failure => {
  const status = Number(failure?.status ?? failure?.statusCode);
  return Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500;
};
const genericMessage = status => status === 403 ? '不允许此来源访问' : status === 413 ? '提交内容过大' : status === 400 ? '请求内容格式无效'
  : status === 429 ? '今日额度或请求频率已达到上限，请稍后重试。' : '操作失败，请稍后再试';

function createServerErrors({ config = {}, log = defaultLog, clock = () => performance.now() } = {}) {
  const release = releaseOf(config);
  const failures = new WeakMap();
  const watched = new WeakSet();
  const watch = (req, res) => {
    if (watched.has(res)) return;
    watched.add(res);
    const started = clock();
    res.once('finish', () => {
      if (res.statusCode < 500) return;
      try {
        log({ level: 'error', event: 'http_5xx', method: req.method, route: routePattern(req), status: res.statusCode,
          ...(failures.has(res) ? describeFailure(failures.get(res)) : {}), release, ms: Math.round(clock() - started) });
      } catch { /* Logging must never affect a response. */ }
    });
  };
  // Mounted first so the timer starts before body parsing and authentication.
  const middleware = (req, res, next) => { watch(req, res); next(); };
  // Express recognises error middleware by its four parameters.
  const handler = (failure, req, res, _next) => {
    watch(req, res);
    failures.set(res, failure);
    if (res.headersSent) {
      // A stream that already sent its status cannot change it; record the failure
      // once here unless the finish hook will log it as a 5xx.
      if (res.statusCode < 500) {
        try { log({ level: 'error', event: 'http_error_after_headers', method: req.method, route: routePattern(req), status: res.statusCode, ...describeFailure(failure), release }); } catch { /* ignore */ }
      }
      return res.end();
    }
    const status = statusOf(failure);
    if (failure?.publicSafe === true) return res.status(status).json({ code: failure.code, error: failure.message });
    // Only string AI_* codes are part of the public contract; numeric driver codes
    // (Mongo 40, 11000, ...) stay in the log line.
    const aiCode = typeof failure?.code === 'string' && failure.code.startsWith('AI_') ? { code: failure.code } : {};
    return res.status(status).json({ ...aiCode, error: genericMessage(status) });
  };
  return { middleware, handler, watch };
}

module.exports = { createServerErrors, describeFailure, routePattern, safeName, safeCode };
