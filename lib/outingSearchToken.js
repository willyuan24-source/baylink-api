const crypto = require('node:crypto');
const { plain, validDate } = require('./planner');

const TTL = 2 * 60 * 60 * 1000;
const MAX_LENGTH = 4096;
const fail = () => Object.assign(new Error('Invalid outing search continuation'), { status: 400, code: 'INVALID_OUTING_SEARCH_TOKEN' });
const sign = (payload, secret) => crypto.createHmac('sha256', secret).update(`baylink-outing-search-v1:${payload}`).digest();

function cleanState(state) {
  const keys = ['filters', 'cityKnown', 'dateKnown', 'unsupported', 'unsupportedTopics', 'dateIssue'];
  if (!plain(state) || Object.keys(state).some(key => !keys.includes(key)) || !plain(state.filters)
    || ['cityKnown', 'dateKnown', 'unsupported', 'unsupportedTopics'].some(key => typeof state[key] !== 'boolean')
    || (state.dateIssue !== undefined && !['date', 'conflict', 'range'].includes(state.dateIssue))) throw fail();
  const value = state.filters;
  if (Object.keys(value).some(key => !['sort', 'city', 'date', 'dateFrom', 'dateTo', 'q', 'language', 'seats'].includes(key)) || value.sort !== 'soonest'
    || value.city !== undefined && (typeof value.city !== 'string' || value.city.length > 80 || !/^[\p{L}][\p{L} .'-]*$/u.test(value.city))
    || value.q !== undefined && (typeof value.q !== 'string' || value.q.length > 120 || !/^[\p{L}][\p{L} -]*$/u.test(value.q))
    || ['date', 'dateFrom', 'dateTo'].some(key => value[key] !== undefined && !validDate(value[key]))
    || value.date !== undefined && (value.dateFrom !== undefined || value.dateTo !== undefined)
    || value.dateFrom && value.dateTo && value.dateFrom > value.dateTo
    || value.language !== undefined && !['zh', 'en'].includes(value.language)
    || value.seats !== undefined && value.seats !== 'open'
    || !state.cityKnown && value.city !== undefined
    || !state.dateKnown && ['date', 'dateFrom', 'dateTo'].some(key => value[key] !== undefined)) throw fail();
  return { filters: { ...value }, cityKnown: state.cityKnown, dateKnown: state.dateKnown, unsupported: state.unsupported, unsupportedTopics: state.unsupportedTopics,
    ...(state.dateIssue ? { dateIssue: state.dateIssue } : {}) };
}

/** A signed, short-lived search preference. It carries no account or authorization claims. */
function issueOutingSearchToken(state, secret, now = Date.now()) {
  if (typeof secret !== 'string' || !secret || !Number.isSafeInteger(now)) throw fail();
  const payload = Buffer.from(JSON.stringify({ v: 1, iat: now, exp: now + TTL, state: cleanState(state) })).toString('base64url');
  const token = `${payload}.${sign(payload, secret).toString('base64url')}`;
  if (token.length > MAX_LENGTH) throw fail();
  return token;
}

function readOutingSearchToken(token, secret, now = Date.now()) {
  if (typeof token !== 'string' || token.length > MAX_LENGTH || typeof secret !== 'string' || !secret || !Number.isSafeInteger(now)) throw fail();
  const parts = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!parts) throw fail();
  const raw = Buffer.from(parts[1], 'base64url'), signature = Buffer.from(parts[2], 'base64url');
  if (raw.length > 2048 || raw.toString('base64url') !== parts[1] || signature.toString('base64url') !== parts[2] || signature.length !== 32
    || !crypto.timingSafeEqual(signature, sign(parts[1], secret))) throw fail();
  let payload;
  try { payload = JSON.parse(raw.toString('utf8')); } catch { throw fail(); }
  if (!plain(payload) || Object.keys(payload).length !== 4 || Object.keys(payload).some(key => !['v', 'iat', 'exp', 'state'].includes(key))
    || payload.v !== 1 || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.iat < 0
    || payload.exp - payload.iat !== TTL || payload.iat > now + 60000 || payload.exp <= now) throw fail();
  return cleanState(payload.state);
}

module.exports = { issueOutingSearchToken, readOutingSearchToken, OUTING_SEARCH_TOKEN_TTL: TTL, OUTING_SEARCH_TOKEN_MAX_LENGTH: MAX_LENGTH };
