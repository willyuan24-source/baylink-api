// Aggregate stage durations only: never queries, tokens, account identifiers or
// source text. measure calls must not nest; orchestration time is the remainder.
const STAGES = ['stateMs', 'siteMs', 'monitorMs', 'quotaMs', 'searchMs', 'readMs', 'modelMs', 'finalMs', 'routeMs', 'weatherMs', 'planMs'];
function createStageTimer(started = Date.now()) {
  const values = Object.fromEntries(STAGES.map(key => [key, 0]));
  const add = (stage, began) => { if (Object.hasOwn(values, stage)) values[stage] += Math.max(0, Date.now() - began); };
  return {
    sync(stage, work) { const began = Date.now(); try { return work(); } finally { add(stage, began); } },
    async measure(stage, work) { const began = Date.now(); try { return await work(); } finally { add(stage, began); } },
    record: add,
    snapshot() { const totalMs = Math.max(0, Date.now() - started); return { ...values, otherMs: Math.max(0, totalMs - Object.values(values).reduce((sum, value) => sum + value, 0)), totalMs }; },
  };
}

async function boundedOperation(work, timeoutMs, code) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(code), { code })), Math.max(1, timeoutMs));
    })]);
  } finally { clearTimeout(timer); }
}
module.exports = { createStageTimer, boundedOperation, STAGES };
