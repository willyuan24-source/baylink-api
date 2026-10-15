const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// H40 (API-BB-4A): the BayBay engine lives in lib/baybayEngine/, one module per stage.
// These checks keep the layering that lets v1 be deleted and v2 be changed stage by stage.
const ENGINE = path.join(__dirname, '..', 'lib', 'baybayEngine');
const modules = fs.readdirSync(ENGINE).filter(file => file.endsWith('.js')).map(file => file.slice(0, -3)).sort();
const requiresOf = name => [...fs.readFileSync(path.join(ENGINE, `${name}.js`), 'utf8').matchAll(/require\('\.\/([A-Za-z0-9]+)'\)/g)].map(match => match[1]);

test('baybayAgent keeps its public exports', () => {
  const agent = require('../lib/baybayAgent');
  assert.deepEqual(Object.keys(agent).sort(), ['TOOLS', 'createBayBayAssistant', 'dbKeepAliveInterval', 'parseDraft', 'renderCitations', 'sourceContextText', 'stripLoginPitch', 'warmInterval']);
  for (const name of ['createBayBayAssistant', 'parseDraft', 'renderCitations', 'stripLoginPitch', 'sourceContextText']) assert.equal(typeof agent[name], 'function', name);
  assert.deepEqual(agent.TOOLS.map(tool => tool.name), ['search_site', 'search_web', 'read_source', 'verify_candidate', 'get_route', 'get_weather', 'create_plan']);
  const assistant = agent.createBayBayAssistant({ isTest: true });
  assert.deepEqual(Object.keys(assistant).sort(), ['capabilities', 'run', 'startWarmUp', 'status', 'warmStatus', 'warmUp']);
});

test('engine modules form an acyclic graph and each one is used', () => {
  assert.deepEqual(modules, ['answer', 'evidence', 'fallback', 'prompt', 'research', 'router', 'stream', 'util', 'v1']);
  const graph = new Map(modules.map(name => [name, requiresOf(name)]));
  for (const [name, deps] of graph) for (const dep of deps) assert.ok(graph.has(dep), `${name} requires unknown ./${dep}`);
  const state = new Map();
  const visit = (name, trail) => {
    if (state.get(name) === 'done') return;
    assert.notEqual(state.get(name), 'open', `require cycle: ${[...trail, name].join(' -> ')}`);
    state.set(name, 'open');
    for (const dep of graph.get(name)) visit(dep, [...trail, name]);
    state.set(name, 'done');
  };
  for (const name of modules) visit(name, []);
  const agentSource = fs.readFileSync(path.join(__dirname, '..', 'lib', 'baybayAgent.js'), 'utf8');
  const used = new Set([...graph.values()].flat().concat([...agentSource.matchAll(/require\('\.\/baybayEngine\/([A-Za-z0-9]+)'\)/g)].map(match => match[1])));
  for (const name of modules) assert.ok(used.has(name), `${name}.js is not required by anything`);
});

test('engine v1 stays separable: only research.js and baybayAgent.js load v1.js', () => {
  for (const name of modules) {
    if (name === 'research' || name === 'v1') continue;
    assert.ok(!requiresOf(name).includes('v1'), `${name}.js must not require ./v1`);
  }
});
