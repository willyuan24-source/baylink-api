// Small value helpers shared by the BayBay engine modules (H40 split of lib/baybayAgent.js).
const str = (v, n = 500) => typeof v === 'string' ? v.trim().slice(0, n) : '';
const obj = v => v && typeof v === 'object' && !Array.isArray(v);
const arr = (v, n = 10) => Array.isArray(v) ? v.filter(x => typeof x === 'string').slice(0, n) : [];
const positive = (v, d, max) => Number.isInteger(Number(v)) && Number(v) > 0 ? Math.min(Number(v), max) : d;
const copy = (locale, zh, en) => locale === 'en' ? en : zh;
const localeIndex = locale => locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0;

module.exports = { str, obj, arr, positive, copy, localeIndex };
