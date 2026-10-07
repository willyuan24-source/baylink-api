#!/usr/bin/env node
// Validate by default. Writes require --write and a separately exported registry.
// Generate that registry with the frontend's generate-source-registry.ts using
// this backend's data/source-registry.json as --existing; do not reset identities.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { loadPlannerCatalog } = require('../lib/planner');
const { loadEventCatalog } = require('../lib/eventEngagement');
const root = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
if (args.some(arg => arg !== '--write' && !arg.startsWith('--frontend=') && !arg.startsWith('--registry='))) throw new Error('Unknown argument');
const frontend = args.find(arg => arg.startsWith('--frontend='))?.slice(11);
const registryPath = args.find(arg => arg.startsWith('--registry='))?.slice(11);
if (!frontend || !registryPath) throw new Error('Usage: node scripts/sync-editorial-catalogs.js --frontend=<frontend root> --registry=<staged registry JSON> [--write]');
const pairs = [
  ['baybay-guides.json', 'guide-catalog.json'], ['baybay-guides.en.json', 'guide-catalog.en.json'],
  ['event-catalog.json', 'event-catalog.json'], ['planner-catalog.json', 'planner-catalog.json'],
  ['discovery-context.json', 'discoveries.json'], ['discovery-context.en.json', 'discoveries.en.json'],
];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const snapshots = pairs.map(([source, destination]) => ({ source: path.resolve(frontend, 'public', source), destination: path.join(root, 'data', destination) }));
snapshots.push({ source: path.resolve(registryPath), destination: path.join(root, 'data', 'source-registry.json') });
for (const row of snapshots) { row.bytes = fs.readFileSync(row.source); row.data = JSON.parse(row.bytes.toString('utf8')); }
const data = name => snapshots.find(row => path.basename(row.destination) === name).data;
const planner = loadPlannerCatalog(data('planner-catalog.json'));
const eventMap = loadEventCatalog(data('event-catalog.json'));
assert.ok(planner && eventMap, 'Exported catalogs must pass production loaders');
assert.deepEqual([...eventMap.keys()].sort(), planner.events.map(row => row.id).sort(), 'Event catalogs must cover identical IDs');
for (const row of data('event-catalog.json')) {
  const rich = planner.events.find(event => event.id === row.id);
  for (const field of ['startDate', 'endDate', 'occurrenceDates']) assert.deepEqual(row[field], rich[field], `${row.id}.${field}`);
}
const identity = (rows, field) => { assert.ok(Array.isArray(rows)); const ids = rows.map(row => row[field]); assert.equal(new Set(ids).size, ids.length); return ids.sort(); };
assert.deepEqual(identity(data('guide-catalog.json'), 'slug'), identity(data('guide-catalog.en.json'), 'slug'));
assert.deepEqual(identity(data('guide-catalog.json'), 'slug'), identity(planner.guides, 'slug'));
const discoveryKeys = rows => { assert.ok(Array.isArray(rows)); const keys = rows.map(row => `${row.kind}:${row.id}`); assert.equal(new Set(keys).size, keys.length); return keys.sort(); };
assert.deepEqual(discoveryKeys(data('discoveries.json').items), discoveryKeys(data('discoveries.en.json').items));
const registry = data('source-registry.json');
assert.ok(Array.isArray(registry));
const byUrl = new Map(registry.map(row => [row.url, row]));
assert.equal(byUrl.size, registry.length);
assert.equal(new Set(registry.map(row => row.id)).size, registry.length);
for (const row of registry) {
  assert.equal(new URL(row.url).protocol, 'https:');
  assert.ok(Array.isArray(row.contentIds) && row.contentIds.length);
  assert.equal(row.verifiedAt, undefined, 'Registration is not editorial verification');
}
const canonical = value => { const url = new URL(value); url.hash = ''; return url.href; };
for (const row of [...planner.events, ...data('discoveries.json').items]) {
  const source = byUrl.get(canonical(row.officialUrl || row.sourceUrl));
  assert.ok(source?.contentIds.includes(row.id), `Missing monitored source association: ${row.id}`);
}
const registeredContent = new Set(registry.flatMap(row => row.contentIds));
for (const row of data('guide-catalog.json')) assert.ok(registeredContent.has(row.slug), `Missing guide sources: ${row.slug}`);
const previous = JSON.parse(fs.readFileSync(path.join(root, 'data/source-registry.json'), 'utf8'));
for (const row of previous) {
  const next = byUrl.get(row.url);
  assert.equal(next?.id, row.id, `Lost source identity: ${row.url}`);
  assert.deepEqual(next.redirectHosts, row.redirectHosts, `Changed reviewed redirect hosts: ${row.id}`);
  for (const id of row.contentIds) assert.ok(next.contentIds.includes(id), `Lost historical association: ${row.id}/${id}`);
}
// All input bytes are read and validated before the first destination is written.
// Re-check sources immediately before writing to detect a concurrent generation.
for (const row of snapshots) assert.equal(hash(fs.readFileSync(row.source)), hash(row.bytes), `Source changed during validation: ${row.source}`);
if (args.includes('--write')) for (const row of snapshots) fs.writeFileSync(row.destination, row.bytes);
const files = snapshots.map(row => ({ source: row.source, destination: row.destination, bytes: row.bytes.length,
  sha256: hash(row.bytes), destinationMatches: hash(fs.readFileSync(row.destination)) === hash(row.bytes) }));
if (args.includes('--write')) assert.ok(files.every(row => row.destinationMatches));
console.log(JSON.stringify({ mode: args.includes('--write') ? 'written-and-verified' : 'validated-without-writing',
  counts: { events: eventMap.size, guides: planner.guides.length, discoveries: data('discoveries.json').items.length,
    sources: registry.length, retainedSourceIds: previous.length }, files }, null, 2));
