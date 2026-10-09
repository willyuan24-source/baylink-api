// Arm resolution for the local eval: what each arm in arms.json actually runs.
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const { aiRoute } = require(path.join(ROOT, 'lib/aiModels'));

/** The resolved agent, professional and fast routes (model, effort, thinking) of an arm's config, and its engine. */
export function armRoutes(config = {}) {
  const pick = name => { const route = aiRoute(name, { BAYBAY_AI_PROVIDER: 'anthropic', ...config }); return { model: route.model, effort: route.effort, thinking: route.thinking }; };
  return { agent: pick('baybay_agent'), professional: pick('baybay_professional'), fast: pick('baybay_fast'), engine: String(config.BAYBAY_ENGINE || '').toLowerCase() === 'v2' ? 'v2' : 'v1' };
}
