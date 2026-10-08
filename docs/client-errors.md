# Client error aggregates

The web reports browser errors as anonymous daily counts so a broken page shows up in admin without collecting what the reader saw or typed.

## Beacon

`POST /api/client-errors`, JSON with only these keys:

```json
{ "kind": "render", "route": "/events/:id", "release": "a5d63fbe3e17", "fp": "3fa9c01b" }
```

| Key | Required | Rule |
| --- | --- | --- |
| `kind` | yes | `render` (React error boundary), `error` (`window.onerror`), `rejection` (`unhandledrejection`) or `chunk` (a lazy chunk failed to load) |
| `fp` | yes | 6–16 lowercase letters or digits: the client's short hash of the error name plus the first 60 characters of the message with digits and URLs removed. **Never the message itself** |
| `route` | no | Route template, mapped through the same allowlist as product events (`lib/routeTemplates.js`); anything else, or absent, becomes `other`. A non-string is 400 |
| `release` | no | The web build: a commit (stored as its first 12 hex digits) or a short label such as `dev`. Anything else, or absent, becomes `unknown`. A non-string is 400 |

Any other key (stack, message, URL, user agent, user id …) returns 400 and nothing is written. Success is 200 `{ "ok": true }`. `DNT: 1` or `Sec-GPC: 1` returns `{ "ok": true, "skipped": true }`, the same rule as product events. Storage errors return 503; the page must not retry or surface them.

Send it the way product events are sent: `fetch(…, { method: 'POST', keepalive: true, credentials: 'omit', referrerPolicy: 'no-referrer', headers: { 'Content-Type': 'application/json' } })`. Deduplicate in the page (one beacon per fingerprint per page load).

## Limits

Own in-memory limiter keyed by the visitor key: 30 beacons a minute and 200 a day per visitor. The key is never stored or logged.

Cardinality is bounded: after 2,000 distinct buckets in one process on one Pacific day, new combinations are counted in an overflow bucket per kind and route (`release` and `fp` = `overflow`). Buckets seen before the cap keep counting.

## Storage

`ClientErrorMetric`: one row per Pacific day + kind + route template + release + fingerprint with a `count`. The `_id` is that deterministic key. A TTL index removes rows 30 days after their day. The schema is strict, `route` must be an allowlisted template, and there are no per-request records, timestamps, IPs or user ids.

## Admin report

`GET /api/admin/client-errors` (administrators only, no query parameters) covers today and the 29 days before:

```json
{
  "days": 30, "from": "2026-09-09", "through": "2026-10-08", "total": 8,
  "groups": [{ "kind": "render", "route": "/events/:id", "release": "a5d63fbe3e17", "fp": "3fa9c01b", "count": 7, "firstDay": "2026-10-01", "lastDay": "2026-10-08" }],
  "groupsTruncated": false,
  "daily": [{ "day": "2026-10-08", "kind": "render", "count": 5 }]
}
```

The report is grouped in Mongo, so `total` and `daily` count every stored row of the 30 days, however many fingerprints there are. `groups` is ranked by count (then most recent `lastDay`) and capped at 200; `groupsTruncated` says when more groups exist. A flood of one-off fingerprints can push small groups out of the top 200 but cannot hide a day. A spike on one `release` right after a deploy is the signal to roll back. The `client_error` product event keeps counting separately for old clients.

Tests: `tests/client-errors.test.js`.
