# Official source monitor

The production application registers the monitor without opening network connections. After MongoDB connects and the two model indexes initialize, `start()` schedules the first check after 30 seconds. Bounded batches continue after one minute while untouched eligible sources remain, then resume every six hours. Each source's attempts are at least six hours apart during scheduled work. `NODE_ENV=test` never starts the scheduler. `SOURCE_MONITOR_ENABLED=false` disables scheduled checks; an authorized administrator can still request a manual batch. No additional paid service, API key, or AI call is required.

`data/source-registry.json` is the complete network allowlist: 1,259 distinct public HTTPS source URLs from the site's 827 event, offer, opening, guide and bulletin records. The 48 original source IDs and all their content associations remain stable, preserving database snapshots and review history. `contentIds` connect each source to existing website cards. Sources shared by several dated records retain the latest end date; an evergreen association keeps its source active. Expired entries remain in admin history and are skipped. There is no user-supplied URL API. Registration means a source is scheduled, not already fetched or editorially verified.

Regenerate from the frontend's reviewed catalog with `scripts/generate-source-registry.ts --existing=<API registry path> --output=<API registry path>` through the existing frontend tsx runtime. Explicit paths are required. The generator reports unsupported references for manual access, preserves IDs and reviewed redirect aliases, and never creates a verification date. Commit the resulting API registry and run both repositories' checks when source coverage changes.

## Data and review semantics

- `SourceMonitorSnapshot` stores the latest successful normalized text, its SHA-256 hash, successful-fetch and attempt timestamps, before/after change evidence, and editorial review records. A first fetch establishes a baseline; it is not a change notification or factual verification.
- An unreviewed change remains pending after subsequent identical fetches. Additional changes retain the original unreviewed before-text and latest after-text. The current pending evidence is retained after review until the next detected change; this is not an unlimited revision archive.
- `acknowledged` means an editor has seen and acknowledged the evidence; `dismissed` marks irrelevant text changes. Review requests include the current hash and fail with HTTP 409 if newer content arrived. Review records contain the administrator's user ID, date, and optional note. Neither action changes an event/offer, its published verified date, or its cancellation status.
- HTTP errors, access blocks, unsupported formats, JS-only responses, and timeouts have separate error states. They preserve the last successful snapshot and never imply cancellation. The initial release detects textual changes, not their meaning; editors confirm date, price, closure, and reservation changes on the official site.

## Network and workload boundaries

Only HTTPS on port 443 is permitted. Every redirect is manually processed (at most four), host checked, and DNS checked. Only the source's hostname and its canonical `www` variant are automatically allowed. Additional redirect hosts require a reviewed `redirectHosts` registry entry. Private, loopback, link-local, reserved and mapped addresses are rejected; a validated public address is pinned into the HTTPS connection to prevent DNS rebinding. TLS hostname verification remains enabled. There are no browser sessions, cookies, authentication secrets, or bypasses for website access blocks.

Each request chain has a 12-second timeout, response bodies are capped at 2 MiB, normalized text is capped at 24,000 characters, and checks are sequential with a one-second pause. A batch handles at most 40 sources and stops starting new reads after ten minutes. Oldest attempts go first, so failed or manually rechecked pages cannot starve untouched sources; durable attempt timestamps preserve rotation after a restart. Scripts, styles, ordinary navigation, footers and forms are removed; labelled visitor hours in a footer remain with their venue labels. Changes outside the retained text, hidden/JavaScript-loaded content, PDFs and images require manual review. This extractor can still report irrelevant content changes.

`SourceMonitorLease` provides a MongoDB-wide 20-minute lease and one-minute minimum start interval, in addition to the in-process lock. Lease ownership is checked before reading and before persisting each result; lost ownership discards in-flight results. Snapshot updates compare attempt timestamps so a late batch cannot replace a newer result. On completion the lease is released; after a crash it expires. Scheduler and manual runs share the lock and the same 40-source bound. Storage failure backs off rather than repeatedly issuing requests. `server.close` stops future work; an active request finishes within its timeout. A full first sweep is gradual and actual success/error/manual-review states must be read independently; no coverage claim implies all sources are currently reachable.

## Endpoints

All admin routes require the existing JWT authentication and current administrator role.

- `GET /api/admin/source-monitor`: registry, timestamps, status and retained evidence.
- `POST /api/admin/source-monitor/run` with `{}`: starts a background batch (202); an active/recent batch returns 409. URLs and unknown body fields are rejected.
- `PATCH /api/admin/source-monitor/:id/review`: `{ "expectedHash": "<64 hex characters>", "decision": "acknowledged|dismissed", "note": "optional, at most 500 characters" }`.
- `GET /api/sources/freshness?ids=<comma-separated source or content IDs>`: at most 100 IDs; returns source/content IDs, last fetch/attempt time, current fetch status, whether a change needs review and the latest review time. It excludes captured text, source URLs, notes and reviewer identities. Unregistered content returns no source row. Public successful responses are cacheable for two minutes.

The frontend admin component is `src/features/source-monitor/AdminSourceMonitor.tsx`. `SourceFreshness` is an optional detail-page provenance hint; API failure leaves the existing official link usable. The UI must keep the distinction between successful fetch and editorial verification visible.

## Validation

`node --test tests/sourceMonitor.test.js` covers first baselines, pending diffs, stale-review protection, 403 handling, noise normalization, fixed registry coverage, private/mixed DNS answers, prohibited protocols and redirect hosts, pinned public addresses, DNS timeout, expiration, throttling/concurrency, non-admin rejection and public evidence redaction. Frontend review tests confirm evidence is visible and no review is sent until the editor acts.
