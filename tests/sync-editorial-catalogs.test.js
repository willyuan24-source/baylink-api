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

// API-BB-9: the web's public/weekend-picks.json (WEB-PICKS-EXPORT) is copied when present; a web main without it still syncs.
const PICKS_FIXTURE = fs.readFileSync(path.join(__dirname, 'fixtures', 'weekend-picks-web.json'));

test('the weekend picks file is optional: absent, nothing about picks; present, it is copied and reported', t => {
  const before = dataHashes();
  const without = JSON.parse(sync(t).out);
  // Once API-SYNC-3H ships data/weekend-picks.json, an export without picks reports that copy as stale (test below).
  if (fs.existsSync(path.join(root, 'data', 'weekend-picks.json'))) assert.deepEqual(without.weekendPicks, { staleLocalFile: 'data/weekend-picks.json', removed: false });
  else assert.equal(without.weekendPicks, null);
  assert.ok(!without.files.some(row => row.destination.endsWith(`${path.sep}weekend-picks.json`)));
  const run = sync(t, files => { files['weekend-picks.json'] = PICKS_FIXTURE; });
  assert.equal(run.status, 0, run.err);
  const report = JSON.parse(run.out);
  const copy = report.files.find(row => row.destination.endsWith(`${path.sep}data${path.sep}weekend-picks.json`));
  assert.ok(copy && copy.source.endsWith(`${path.sep}public${path.sep}weekend-picks.json`), JSON.stringify(report.files));
  assert.deepEqual(Object.keys(report.weekendPicks.weekends), ['2026-10-17', '2026-10-24', '2026-10-31']);
  assert.equal(report.weekendPicks.weekends['2026-10-24'][0], 'r2-petaluma-lumafest-20261024');
  assert.deepEqual(report.weekendPicks.notOnTheirDay, []);
  assert.deepEqual(dataHashes(), before, 'validation never writes');
});

test('picks naming an event the catalog lacks, or a weekend that is not Saturday to Sunday, are refused', t => {
  const picks = JSON.parse(PICKS_FIXTURE.toString('utf8'));
  const unknown = sync(t, files => { files['weekend-picks.json'] = json({ ...picks, weekends: [{ ...picks.weekends[1], picks: [{ ...picks.weekends[1].picks[0], id: 'not-a-catalog-event-2026' }] }] }); });
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.err, /pick not-a-catalog-event-2026 \(2026-10-24\) is not in public\/planner-catalog\.full\.json: stale picks/);
  const friday = sync(t, files => { files['weekend-picks.json'] = json({ ...picks, weekends: [{ ...picks.weekends[1], start: '2026-10-23', end: '2026-10-24' }] }); });
  assert.notEqual(friday.status, 0);
  assert.match(friday.err, /weekend 2026-10-23 must start on a Saturday/);
  const outside = sync(t, files => { files['weekend-picks.json'] = json({ ...picks, weekends: [{ ...picks.weekends[1], picks: [{ ...picks.weekends[1].picks[0], dates: ['2026-10-31'] }] }] }); });
  assert.notEqual(outside.status, 0);
  assert.match(outside.err, /lists 2026-10-31, outside its weekend 2026-10-24/);
});

// Review of API-BB-9: a web main that stops exporting the picks leaves the API's older copy unvalidated. Run in a copy of
// the script, lib/ and data/ (with a synced picks file) so the real data/ is never written.
test('an API picks copy the web no longer exports is reported as stale, and --write removes it', t => {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'baylink-sync-api-'));
  t.after(() => fs.rmSync(copy, { recursive: true, force: true }));
  for (const name of ['lib', 'data']) fs.cpSync(path.join(root, name), path.join(copy, name), { recursive: true });
  fs.mkdirSync(path.join(copy, 'scripts'));
  fs.copyFileSync(script, path.join(copy, 'scripts', 'sync-editorial-catalogs.js'));
  const stale = path.join(copy, 'data', 'weekend-picks.json');
  fs.writeFileSync(stale, PICKS_FIXTURE);
  const { dir, registry } = webExport(t);
  const run = write => spawnSync(process.execPath, [path.join(copy, 'scripts', 'sync-editorial-catalogs.js'), `--frontend=${dir}`, `--registry=${registry}`, ...(write ? ['--write'] : [])],
    { encoding: 'utf8', timeout: 60000, env: { ...process.env, NODE_PATH: path.join(root, 'node_modules') } });
  const validated = run(false);
  assert.equal(validated.status, 0, validated.stderr);
  assert.deepEqual(JSON.parse(validated.stdout).weekendPicks, { staleLocalFile: 'data/weekend-picks.json', removed: false });
  assert.ok(fs.existsSync(stale), 'validation never removes it');
  const written = run(true);
  assert.equal(written.status, 0, written.stderr);
  assert.deepEqual(JSON.parse(written.stdout).weekendPicks, { staleLocalFile: 'data/weekend-picks.json', removed: true });
  assert.ok(!fs.existsSync(stale));
});
