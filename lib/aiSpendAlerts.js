// API-BB-CUTOVER: owner e-mails about Claude spend and the credit window.
//
// - Month-to-date spend crosses $100 / $150 / $180 (AI_ALERT_MTD_USD): once per threshold per month.
// - Today's spend reaches the hard cap (AI_SPEND_HARD_DAILY_USD, $10): once per Pacific day.
// - 7 / 3 / 1 days before ANTHROPIC_USE_UNTIL: once per stage per cutoff value. A server that
//   starts late sends only the most urgent stage that is still due.
//
// Delivery reuses the existing Resend path and gates: NOTIFICATION_DELIVERY_ENABLED=true and an
// owner address (AI_ALERT_EMAIL, else OWNER_DIGEST_EMAIL). Never in tests. Each alert is claimed
// once across instances by an `ai-alert:…` AiGovernance document (atomic upsert); a failed send
// releases the claim so a later tick retries, and Resend's idempotency key stops duplicates.
// Spend figures come from the in-app ledger (lib/aiGovernance.js), an estimate at list prices;
// the Console Usage page is the bill.
const TICK_MS = 10 * 60 * 1000;
const FIRST_TICK_MS = 60 * 1000;
const DEFAULT_MTD_USD = Object.freeze([100, 150, 180]);
const USE_UNTIL_STAGES = Object.freeze([1, 3, 7]);
const MAX_ATTEMPTS = 3;
const DAY_MS = 86400000;
const KEEP_DAYS = Object.freeze({ mtd: 400, hard: 62, until: 400 });

const validEmail = value => typeof value === 'string' && /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(value.trim());
const usd = micro => `$${(Math.max(0, Number(micro) || 0) / 1e6).toFixed(2)}`;
const pacific = (at, options) => new Intl.DateTimeFormat('zh-CN', { timeZone: 'America/Los_Angeles', ...options }).format(new Date(at));
const pacificDay = at => pacific(at, { month: 'long', day: 'numeric' });
const pacificTime = at => pacific(at, { month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });

/** Month-to-date thresholds in USD: AI_ALERT_MTD_USD ("100,150,180"), positive, ascending; default 100/150/180. */
function mtdThresholds(config = {}) {
  const parts = String(config.AI_ALERT_MTD_USD ?? '').split(',').map(part => part.trim()).filter(Boolean);
  const values = [...new Set(parts.map(Number).filter(value => Number.isFinite(value) && value > 0 && value <= 100000))].sort((a, b) => a - b);
  return values.length ? values : [...DEFAULT_MTD_USD];
}

/** Whether alerts can be sent, and to whom. The owner address comes only from the environment. */
function alertState(config = {}) {
  if (config.NODE_ENV === 'test') return { enabled: false, reason: 'test' };
  if (config.NOTIFICATION_DELIVERY_ENABLED !== 'true') return { enabled: false, reason: 'delivery-disabled' };
  const to = [config.AI_ALERT_EMAIL, config.OWNER_DIGEST_EMAIL].find(validEmail);
  if (!to) return { enabled: false, reason: 'no-owner-email' };
  return { enabled: true, reason: 'on', to: to.trim() };
}

function levelLine(spend) {
  const logged = spend.caps?.enforced === false ? '（AI_SPEND_CAPS=off：只记录，没有拦截）' : '';
  if (spend.level === 'hard') return `已到硬上限 $${spend.caps.hardDailyUsd}${logged || '（今天 BayBay 只用站内资料回答，其他 AI 功能暂停到太平洋时间午夜）'}`;
  if (spend.level === 'soft') return `已过软上限 $${spend.caps.softDailyUsd}${logged || '（BayBay 只用站内资料快速回答，不联网）'}`;
  return '正常';
}
const FOOTER = Object.freeze([
  '',
  '数字来自站内账本（按官方价目估算），准确账单以 Claude Console 的 Usage 页为准。',
  '查看：/api/admin/ai-metrics 的 spend 一栏。',
  '立即停用 BayBay 的 AI：Render 环境变量设 BAYBAY_PAUSED=true（紧急 911 卡片不受影响）。',
  '调整每日上限：AI_SPEND_SOFT_DAILY_USD / AI_SPEND_HARD_DAILY_USD；只记录不拦截：AI_SPEND_CAPS=off。',
  '',
  '— BAYLINK 自动提醒（API-BB-CUTOVER）',
]);

/**
 * The alerts due now: [{id, keepDays, subject, text}]. Pure; `spend` is aiGovernance.getSpendState()
 * (or null when the ledger is unreadable). Alerts already sent are filtered by the claim, not here.
 */
function dueAlerts({ spend, config = {}, now }) {
  const alerts = [];
  if (spend && Number.isSafeInteger(spend.monthMicroUsd)) {
    const thresholds = mtdThresholds(config);
    // Only the highest crossed threshold is due; a lower one that was never sent is skipped.
    const top = thresholds.filter(value => spend.monthMicroUsd >= Math.round(value * 1e6)).at(-1);
    if (top !== undefined) alerts.push({ id: `ai-alert:mtd:${spend.month}:${top}`, keepDays: KEEP_DAYS.mtd,
      subject: `BAYLINK：本月 Claude 花费已过 $${top}`,
      text: [`截至 ${pacificTime(now)}（太平洋时间），本月 BAYLINK 的 Claude 花费约 ${usd(spend.monthMicroUsd)}。`,
        `今天：${usd(spend.dayMicroUsd)}，状态：${levelLine(spend)}。`,
        `提醒档位：${thresholds.map(value => `$${value}`).join(' / ')}，每档每月只发一次。`, ...FOOTER].join('\n') });
    if (spend.level === 'hard') alerts.push({ id: `ai-alert:hard:${spend.day}`, keepDays: KEEP_DAYS.hard,
      subject: `BAYLINK：今天 AI 花费已到每日硬上限 $${spend.caps.hardDailyUsd}`,
      text: [`${pacificDay(now)}（太平洋时间）BAYLINK 的 Claude 花费约 ${usd(spend.dayMicroUsd)}，状态：${levelLine(spend)}。`,
        ...(spend.caps?.enforced === false ? [] : ['到太平洋时间午夜之前：BayBay 只用站内资料回答，并显示"今日 AI 名额已满"；翻译、发帖助手等 AI 功能返回同样的提示；紧急 911 卡片照常。']),
        `本月至今约 ${usd(spend.monthMicroUsd)}。如果是正常流量，可以调高 AI_SPEND_HARD_DAILY_USD；如果像是滥用，先看 /api/admin/ai-metrics。`, ...FOOTER].join('\n') });
  }
  const until = Date.parse(String(config.ANTHROPIC_USE_UNTIL || '').trim());
  if (Number.isFinite(until) && String(config.ANTHROPIC_API_KEY || '').trim() && until > now) {
    const daysLeft = (until - now) / DAY_MS;
    const stage = USE_UNTIL_STAGES.find(days => daysLeft <= days);
    if (stage !== undefined) alerts.push({ id: `ai-alert:until:${new Date(until).toISOString()}:${stage}`, keepDays: KEEP_DAYS.until,
      subject: `BAYLINK：Claude 额度 ${stage} 天内到期（ANTHROPIC_USE_UNTIL）`,
      text: [`ANTHROPIC_USE_UNTIL = ${new Date(until).toISOString()}（太平洋时间 ${pacificTime(until)}），还剩约 ${daysLeft.toFixed(1)} 天。`,
        '到期后：BayBay 改为站内资料并显示"AI 助手暂停"（911 卡片不变）；翻译、发帖助手、联网查询、来源自动分诊也会停。',
        '要继续用 Claude：先在 Claude Console 绑卡或购买额度，再删掉或延后 ANTHROPIC_USE_UNTIL（只删不充值，调用会因余额不足失败）。',
        '要切回 OpenAI：BAYBAY_AI_PROVIDER=openai（先跑同一套评测）。',
        ...(spend ? [`本月至今 Claude 花费约 ${usd(spend.monthMicroUsd)}。`] : []),
        '提醒档位：到期前 7 / 3 / 1 天，每档只发一次。', ...FOOTER].join('\n') });
  }
  return alerts;
}

/** The claim store on the AiGovernance collection: one `ai-alert:…` document per sent alert. */
function governanceAlertStore(Model) {
  return {
    async claim(id, { now, keepDays }) {
      try {
        const result = await Model.updateOne({ id }, { $setOnInsert: { id, claimedAt: new Date(now), expiresAt: new Date(now + keepDays * DAY_MS) } }, { upsert: true, setDefaultsOnInsert: false });
        return result?.upsertedCount === 1;
      } catch (error) {
        if (error.code === 11000) return false;
        throw error;
      }
    },
    release: id => Model.deleteOne({ id }),
  };
}

/**
 * The alert scheduler. `governance` is the aiGovernance instance (getSpendState), `store` the
 * claim store, `sendEmail` an injected sender (default: the Resend sender, built only when an
 * alert is about to go out). start() ticks one minute after boot, then every 10 minutes.
 */
function createAiSpendAlerts({ governance, store, config = {}, now = Date.now, logger = console, sendEmail }) {
  let timer = null, firstTimer = null;
  const attempts = new Map(), logged = new Set();
  const sender = () => sendEmail || (sendEmail = require('./sourceTriage').resendSender(config));
  async function tick() {
    const at = now(), state = alertState(config);
    let spend = null;
    try { spend = await governance.getSpendState(); } catch { /* the credit-window alert does not need the ledger */ }
    const due = dueAlerts({ spend, config, now: at }).filter(alert => (attempts.get(alert.id) || 0) < MAX_ATTEMPTS);
    if (!due.length) return { sent: [], reason: 'nothing-due' };
    if (!state.enabled) {
      // One server-log line per alert, with no address and no amount beyond the threshold.
      for (const alert of due) if (!logged.has(alert.id)) { logged.add(alert.id); logger.info?.(`[ai-alerts] due, not sent (${state.reason}): ${alert.id}`); }
      return { sent: [], reason: state.reason };
    }
    const send = sender();
    if (!send) return { sent: [], reason: 'no-sender' };
    const sent = [];
    for (const alert of due) {
      if (!await Promise.resolve().then(() => store.claim(alert.id, { now: at, keepDays: alert.keepDays })).catch(() => false)) continue;
      try {
        await send({ to: state.to, subject: alert.subject, text: alert.text, idempotencyKey: `baylink-${alert.id}` });
        sent.push(alert.id); attempts.delete(alert.id);
      } catch (error) {
        await Promise.resolve().then(() => store.release(alert.id)).catch(() => {});
        attempts.set(alert.id, (attempts.get(alert.id) || 0) + 1);
        logger.error?.('[ai-alerts] send failed:', error?.status || error?.code || 'send-failed');
      }
    }
    return { sent, reason: sent.length ? 'sent' : 'claimed-elsewhere' };
  }
  return {
    tick,
    start() {
      if (timer || config.NODE_ENV === 'test') return;
      firstTimer = setTimeout(() => { tick().catch(() => {}); }, FIRST_TICK_MS); firstTimer.unref?.();
      timer = setInterval(() => { tick().catch(() => {}); }, TICK_MS); timer.unref?.();
    },
    stop() { clearTimeout(firstTimer); clearInterval(timer); timer = null; firstTimer = null; },
  };
}

module.exports = { createAiSpendAlerts, governanceAlertStore, dueAlerts, alertState, mtdThresholds, DEFAULT_MTD_USD, USE_UNTIL_STAGES, TICK_MS };
