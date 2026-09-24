# Official source monitor

The production application registers the monitor without opening network connections. After MongoDB connects and the two model indexes initialize, `start()` schedules the first check after 30 seconds and subsequent batches every six hours. `NODE_ENV=test` never starts the scheduler. `SOURCE_MONITOR_ENABLED=false` disables scheduled checks; an authorized administrator can still request a manual batch. No additional paid service, API key, or AI call is required.

`data/source-registry.json` is the complete network allowlist: 48 distinct official URLs (including the eight new AI/Tech Week events) selected from the published event and offer directories, covering all five Bay Area regions and dates through October 31, 2026. `contentIds` connect each source to existing website cards. Sources shared by several cards retain all associations and the latest end date; sources with an ongoing association remain active. Maintain this version-controlled registry as editorial coverage changes. Expired entries remain in the admin history but are not fetched again. There is no user-supplied URL API.

## Data and review semantics

- `SourceMonitorSnapshot` stores the latest successful normalized text, its SHA-256 hash, successful-fetch and attempt timestamps, before/after change evidence, and editorial review records. A first fetch establishes a baseline; it is not a change notification or factual verification.
- An unreviewed change remains pending after subsequent identical fetches. Additional changes retain the original unreviewed before-text and latest after-text. The current pending evidence is retained after review until the next detected change; this is not an unlimited revision archive.
- `acknowledged` means an editor has seen and acknowledged the evidence; `dismissed` marks irrelevant text changes. Review requests include the current hash and fail with HTTP 409 if newer content arrived. Review records contain the administrator's user ID, date, and optional note. Neither action changes an event/offer, its published verified date, or its cancellation status.
- HTTP errors, access blocks, unsupported formats, JS-only responses, and timeouts have separate error states. They preserve the last successful snapshot and never imply cancellation. The initial release detects textual changes, not their meaning; editors confirm date, price, closure, and reservation changes on the official site.

## Network and workload boundaries

Only HTTPS on port 443 is permitted. Every redirect is manually processed (at most four), host checked, and DNS checked. Only the source's hostname and its canonical `www` variant are automatically allowed. Additional redirect hosts require a reviewed `redirectHosts` registry entry. Private, loopback, link-local, reserved and mapped addresses are rejected; a validated public address is pinned into the HTTPS connection to prevent DNS rebinding. TLS hostname verification remains enabled. There are no browser sessions, cookies, authentication secrets, or bypasses for website access blocks.

Each request chain has a 12-second timeout, response bodies are capped at 350 KB, normalized text is capped at 24,000 characters, and checks are sequential with a one-second pause. Scripts, styles, navigation, footers and forms are removed; main/article content is preferred; whitespace and common HTML entities are normalized. Changes outside the retained text, hidden/JavaScript-loaded content, PDFs and images require manual review. This simple extractor can still report irrelevant content changes.

`SourceMonitorLease` provides a MongoDB-wide 20-minute lease and one-minute minimum start interval, in addition to the in-process lock. The lease outlasts the bounded 48-source batch. On normal completion it is released; after a process crash it expires automatically. Scheduler and manual runs share the same lock. Failed storage operations are logged without secrets. `server.close` stops future scheduled work; an active request finishes within its request timeout.

## Endpoints

All admin routes require the existing JWT authentication and current administrator role.

- `GET /api/admin/source-monitor`: registry, timestamps, status and retained evidence.
- `POST /api/admin/source-monitor/run` with `{}`: starts a background batch (202); an active/recent batch returns 409. URLs and unknown body fields are rejected.
- `PATCH /api/admin/source-monitor/:id/review`: `{ "expectedHash": "<64 hex characters>", "decision": "acknowledged|dismissed", "note": "optional, at most 500 characters" }`.
- `GET /api/sources/freshness?ids=<comma-separated source or content IDs>`: at most 100 IDs; returns source/content IDs, last fetch/attempt time, current fetch status, whether a change needs review and the latest review time. It excludes captured text, source URLs, notes and reviewer identities. Unregistered content returns no source row. Public successful responses are cacheable for two minutes.

The frontend admin component is `src/features/source-monitor/AdminSourceMonitor.tsx`. `SourceFreshness` is an optional detail-page provenance hint; API failure leaves the existing official link usable. The UI must keep the distinction between successful fetch and editorial verification visible.

## Validation

`node --test tests/sourceMonitor.test.js` covers first baselines, pending diffs, stale-review protection, 403 handling, noise normalization, fixed registry coverage, private/mixed DNS answers, prohibited protocols and redirect hosts, pinned public addresses, DNS timeout, expiration, throttling/concurrency, non-admin rejection and public evidence redaction. Frontend review tests confirm evidence is visible and no review is sent until the editor acts.
