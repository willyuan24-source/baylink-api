const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');

// scripts/sync-editorial-catalogs.js since API-SYNC-3b (WEB-HOLDOUT): the API copies the web's complete
// public/planner-catalog.full.json and only checks /opus-bay's held public/planner-catalog.json against it.
// A fake web export is built from this repository's own data; the script runs without --write and never touches data/.
const root = path.resolve(__dirname, '..');
const script = path.join(root, 'scripts', 'sync-editorial-catalogs.js');
const read = name => fs.readFileSync(path.join(root, 'data', name));
// The fake export holds back the first three SF events of the shipped catalog, whatever later syncs add or prune.
const HELD = JSON.parse(read('planner-catalog.json').toString('utf8')).events.filter(row => row.region === 'sf').slice(0, 3).map(row => row.id).sort();
assert.equal(HELD.length, 3, 'the shipped planner catalog has at least three SF events');
const json = value => `${JSON.stringify(value, null, 2)}\n`;

function webExport(t, change = () => {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'baylink-sync-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const pub = path.join(dir, 'public');
  fs.mkdirSync(pub);
  const full = JSON.parse(read('planner-catalog.json').toString('utf8'));
  const files = {
    'baybay-guides.json': read('guide-catalog.json'), 'baybay-guides.en.json': read('guide-catalog.en.json'),
    'event-catalog.json': read('event-catalog.json'), 'planner-catalog.full.json': json(full),
    'planner-catalog.json': json({ ...full, events: full.events.filter(row => !HELD.includes(row.id)) }),
    'discovery-context.json': read('discoveries.json'), 'discovery-context.en.json': read('discoveries.en.json'),
  };
  change(files, full);
  for (const [name, bytes] of Object.entries(files)) if (bytes !== undefined) fs.writeFileSync(path.join(pub, name), bytes);
  const registry = path.join(dir, 'source-registry.staged.json');
  fs.writeFileSync(registry, read('source-registry.json'));
  return { dir, registry };
}
const dataHashes = () => fs.readdirSync(path.join(root, 'data')).filter(name => name.endsWith('.json')).map(name => [name, createHash('sha256').update(read(name)).digest('hex')]);
function sync(t, change) {
  const { dir, registry } = webExport(t, change);
  const result = spawnSync(process.execPath, [script, `--frontend=${dir}`, `--registry=${registry}`], { encoding: 'utf8', timeout: 60000 });
  return { status: result.status, out: result.stdout, err: result.stderr };
}

test('a complete web export validates: the full planner catalog is the copy, the held one is only checked', t => {
  const before = dataHashes();
  const run = sync(t);
  assert.equal(run.status, 0, run.err);
  const report = JSON.parse(run.out);
  assert.equal(report.mode, 'validated-without-writing');
  const events = JSON.parse(read('event-catalog.json').toString('utf8')).length;
  assert.equal(report.counts.events, events);
  assert.equal(report.counts.opusBayEvents, events - HELD.length);
  assert.deepEqual([...report.heldOutOfOpusBay].sort(), HELD);
  const planner = report.files.find(row => row.destination.endsWith(`${path.sep}planner-catalog.json`));
  assert.ok(planner.source.endsWith(`${path.sep}planner-catalog.full.json`), planner.source);
  assert.ok(report.checkedOnly.source.endsWith(`${path.sep}public${path.sep}planner-catalog.json`));
  assert.ok(!report.files.some(row => row.source === report.checkedOnly.source), 'the held file is never a copy source');
  assert.deepEqual(dataHashes(), before, 'validation never writes');
});

test('a web main without the full planner catalog stops instead of copying the held file', t => {
  const run = sync(t, files => { files['planner-catalog.full.json'] = undefined; });
  assert.notEqual(run.status, 0);
  assert.match(run.err, /public\/planner-catalog\.full\.json is missing/);
  assert.match(run.err, /never copy the held file/);
  const held = sync(t, files => { files['planner-catalog.json'] = undefined; });
  assert.notEqual(held.status, 0);
  assert.match(held.err, /public\/planner-catalog\.json is missing/);
});

test('the held file in the full file\'s place fails the identical-ids check against the complete event catalog', t => {
  const run = sync(t, files => { files['planner-catalog.full.json'] = files['planner-catalog.json']; });
  assert.notEqual(run.status, 0);
  assert.match(run.err, /Event catalogs must cover identical IDs/);
});

test('swapped planner files fail even when the event catalog was filtered the same way', t => {
  const run = sync(t, (files, full) => {
    const events = JSON.parse(files['event-catalog.json'].toString('utf8')).filter(row => !HELD.includes(row.id));
    files['event-catalog.json'] = json(events);
    [files['planner-catalog.full.json'], files['planner-catalog.json']] = [files['planner-catalog.json'], json(full)];
  });
  assert.notEqual(run.status, 0);
  assert.match(run.err, /which public\/planner-catalog\.full\.json lacks: swapped or stale planner files/);
});

// The script's WORLD_HELD_FIELDS mirrors web src/data/public-catalog-holdout.ts (web #47): /opus-bay's copy keeps this
// row's dateLabel at the value an opus test pins. Remove these cases with the mirror line once the web drops the hold.
const WORLD_HELD_ID = 'sf-marina-library-open-house-oct17-2026';
const holdRow = (full, id, change) => json({ ...full, events: full.events.filter(row => !HELD.includes(row.id)).map(row => row.id === id ? { ...row, ...change(row) } : row) });

test('the held copy may keep only the fields WORLD_HELD_FIELDS names, and the report lists them', t => {
  const full = JSON.parse(read('planner-catalog.json').toString('utf8'));
  assert.ok(full.events.some(row => row.id === WORLD_HELD_ID) && !HELD.includes(WORLD_HELD_ID), 'the held row is in both fake files');
  const before = dataHashes();
  const run = sync(t, (files, rows) => { files['planner-catalog.json'] = holdRow(rows, WORLD_HELD_ID, () => ({ dateLabel: 'pinned label' })); });
  assert.equal(run.status, 0, run.err);
  const report = JSON.parse(run.out);
  const fullRow = full.events.find(row => row.id === WORLD_HELD_ID);
  assert.deepEqual(report.worldHeld, [{ id: WORLD_HELD_ID, field: 'dateLabel', full: fullRow.dateLabel, held: 'pinned label' }]);
  assert.deepEqual(report.unusedWorldHolds, []);
  assert.deepEqual(dataHashes(), before, 'validation never writes; the API keeps the full row');
  const unused = JSON.parse(sync(t).out);
  assert.deepEqual(unused.worldHeld, []);
  assert.deepEqual(unused.unusedWorldHolds, [WORLD_HELD_ID], 'a hold the web dropped is reported, not refused');
});

test('any other difference in a held row, or the same field in another row, is still refused', t => {
  const otherField = sync(t, (files, rows) => { files['planner-catalog.json'] = holdRow(rows, WORLD_HELD_ID, row => ({ dateLabel: 'pinned label', costLabel: `${row.costLabel || ''} (stale)` })); });
  assert.notEqual(otherField.status, 0);
  assert.match(otherField.err, new RegExp(`\\(${WORLD_HELD_ID}\\) differs from ${WORLD_HELD_ID} beyond the fields WORLD_HELD_FIELDS holds`));
  const dropped = sync(t, (files, rows) => { files['planner-catalog.json'] = holdRow(rows, WORLD_HELD_ID, () => ({ dateLabel: undefined })); });
  assert.notEqual(dropped.status, 0, 'a held row keeps the held field itself');
  const other = JSON.parse(read('planner-catalog.json').toString('utf8')).events.find(row => !HELD.includes(row.id) && row.id !== WORLD_HELD_ID && row.dateLabel);
  const otherRow = sync(t, (files, rows) => { files['planner-catalog.json'] = holdRow(rows, other.id, row => ({ dateLabel: `${row.dateLabel} (stale)` })); });
  assert.notEqual(otherRow.status, 0);
  assert.match(otherRow.err, /regenerate both from one web build/);
});

test('a full file that was not regenerated with the held one is refused, row by row and for places and guides', t => {
  const staleRow = sync(t, (files, full) => {
    const events = full.events.filter(row => !HELD.includes(row.id)).map((row, index) => index === 0 ? { ...row, costLabel: `${row.costLabel || ''} (changed in a later content merge)` } : row);
    files['planner-catalog.json'] = json({ ...full, events });
  });
  assert.notEqual(staleRow.status, 0);
  assert.match(staleRow.err, /events must equal the same rows of public\/planner-catalog\.full\.json in the same order; row 1 \(/);
  const places = sync(t, (files, full) => { files['planner-catalog.json'] = json({ ...full, events: full.events.filter(row => !HELD.includes(row.id)), places: full.places.slice(1) }); });
  assert.notEqual(places.status, 0);
  assert.match(places.err, /public\/planner-catalog\.json places must equal public\/planner-catalog\.full\.json places/);
  const order = sync(t, (files, full) => { files['planner-catalog.json'] = json({ ...full, events: full.events.filter(row => !HELD.includes(row.id)).reverse() }); });
  assert.notEqual(order.status, 0, 'the held copy keeps the full catalog\'s order');
  assert.match(order.err, /regenerate both from one web build/);
});
