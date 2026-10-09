// Arm resolution for the local eval: what each arm in arms.json actually runs.
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const { aiRoute } = require(path.join(ROOT, 'lib/aiModels'));
// The engine rule is the router's own (v2 by default since API-BB-CUTOVER).
const { baybayEngine } = require(path.join(ROOT, 'lib/baybayRouter'));

/** The resolved agent, professional and fast routes (model, effort, thinking) of an arm's config, and its engine. */
export function armRoutes(config = {}) {
  const pick = name => { const route = aiRoute(name, { BAYBAY_AI_PROVIDER: 'anthropic', ...config }); return { model: route.model, effort: route.effort, thinking: route.thinking }; };
  return { agent: pick('baybay_agent'), professional: pick('baybay_professional'), fast: pick('baybay_fast'), engine: baybayEngine(config) };
}
