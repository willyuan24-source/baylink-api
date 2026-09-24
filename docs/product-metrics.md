# Product action aggregates

The site records first-party action counts to evaluate its planner and saved-plan features. These are submitted action counts, **not unique people, conversion rates, retention or verified attendance**. Automated requests, repeated clicks and dropped requests can affect totals. No third-party analytics service is used.

## Public ingestion

`POST /api/product-events` accepts JSON containing exactly:

```json
{ "event": "plan_saved", "locale": "zh-Hans" }
```

Allowed events: `planner_recommendation`, `plan_saved`, `plan_shared`, `official_source_click`, `favorite_saved`, `planner_map_opened`. Locale may be `zh-Hans`, `zh-Hant` or `en`; omitting it selects `zh-Hans`. Other keys, events and locales return 400. Success returns 200 with `{ "ok": true }`. The public endpoint does not read or authenticate a session.

The existing in-memory rate limiter allows 60 submissions per client IP per minute. The IP is used only by this temporary abuse control and is not persisted by the metrics model. Responses use `Cache-Control: no-store`. Storage errors return 503, and the frontend should let the main user action complete normally. The server does not retry uncertain writes; it retries only a duplicate-key insertion race.

## Storage

Mongo `ProductMetric` stores one row per **Pacific calendar day + event + locale**, an incrementing count, and a day-level expiration value. It has a unique compound index on those three dimensions and a TTL index on `expiresAt`. Expiration is set to the UTC midnight of the bucket's calendar date plus 180 days. Mongo's TTL cleanup is asynchronous.

No user ID, session ID, IP, message, URL, content ID, destination, request-level time, referrer or device information is stored in this collection. Its Mongo identifier is the deterministic day/event/locale aggregate key, avoiding the first-action timestamp that a default ObjectId would encode. There are no individual action records. The schema rejects additional fields. Startup initializes both indexes before serving the API.

## Administrator report

`GET /api/admin/product-metrics` requires a currently valid administrator account. Its fixed window includes today and the preceding 29 Pacific calendar dates; query parameters are rejected.

```json
{
  "days": 30,
  "from": "2026-08-25",
  "through": "2026-09-23",
  "counts": {
    "planner_recommendation": 0,
    "plan_saved": 5,
    "plan_shared": 0,
    "official_source_click": 0,
    "favorite_saved": 0,
    "planner_map_opened": 0
  },
  "daily": [{ "day": "2026-09-23", "event": "plan_saved", "locale": "en", "count": 5 }]
}
```

All six total keys are always present. Only nonempty stored day/event/locale rows appear in `daily`. Database identifiers and expiration fields are excluded. At most 540 daily rows can be returned (30 days × 6 events × 3 locales).

Run `node --test tests/productMetrics.test.js` for validation, privacy allowlisting, authorization, concurrent increments, Pacific-midnight, retention-index, failure and rate-limit checks. Tests use injected isolated models and never contact production storage.
