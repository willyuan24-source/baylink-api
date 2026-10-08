# Product action aggregates

The site records first-party action counts to evaluate its features. These are submitted action counts, **not unique people, conversion rates, retention or verified attendance**. Automated requests, repeated clicks and dropped requests can affect totals. No third-party analytics service is used.

## Public ingestion

`POST /api/product-events` accepts JSON containing only these keys:

```json
{ "event": "page_view", "locale": "zh-Hans", "route": "/guides/:slug" }
```

- `event` (required): one of `PRODUCT_EVENTS` in `lib/productMetrics.js`, except the server-only events `message_request_started`, `owner_reply_24h` and `signup_completed`. The list includes the BayBay latency buckets `baybay_latency_lt3`, `baybay_latency_3to8`, `baybay_latency_8to15`, `baybay_latency_gt15` and the feedback funnel `feedback_open`, `feedback_sent`.
- `locale` (optional): `zh-Hans`, `zh-Hant` or `en`. Omitting it selects `zh-Hans`.
- `route` (optional, added 2026-10): the page's **route template** from the web route table, for example `/events/:id`. The server maps it onto the allowlist in `lib/routeTemplates.js`: about 30 locale-free templates plus `other`. It accepts a template with any parameter name (`/category/:categorySlug` → `/category/:slug`) or a concrete path (`/en/events/fleet-week?date=…` → `/events/:id`); a locale prefix, query and hash are dropped. Any other string is counted as `other`. **The raw value is never stored.** A `route` that is not a string returns 400.

Other keys, events and locales return 400. Success returns 200 with `{ "ok": true }`. Requests with `DNT: 1` or `Sec-GPC: 1` return `{ "ok": true, "skipped": true }` and write nothing. The public endpoint does not read or authenticate a session.

Old clients that send no `route` keep working; their counts appear only in the totals.

### Limits

Ingestion has **its own in-memory limiter** (capacity 50,000 keys), keyed by the visitor key (`req.ip`, see `docs/client-ip-rollout.md`): 60 submissions per minute and 300 per day per visitor. Before 2026-10 these day-long keys shared the 20,000-key auth limiter, where a full table makes new login and registration keys fail; they no longer can. The visitor key is used only by this temporary abuse control and is never persisted, logged or returned. A 20-page browsing session sends about 40 events, well under both limits.

Responses use `Cache-Control: no-store`. Storage errors return 503, and the frontend should let the main user action complete normally. The server does not retry uncertain writes; it retries only a duplicate-key insertion race.

## Storage

| Collection | One row per | Written when |
| --- | --- | --- |
| `ProductMetric` | Pacific day + event + locale | every accepted event |
| `ProductRouteMetric` | Pacific day + event + locale + route template | the payload has a `route` |

Each row holds an incrementing `count` and a day-level `expiresAt` (UTC midnight of the bucket's date plus 180 days, removed by a TTL index; Mongo's TTL cleanup is asynchronous). Each collection has a unique compound index on its dimensions. The route breakdown is a separate collection so the existing `{day, event, locale}` index needs no production migration.

No user ID, session ID, IP, message, URL, query, content ID, destination, request-level time, referrer or device information is stored. The Mongo `_id` is the deterministic aggregate key (`day:event:locale[:route]`), avoiding the first-action timestamp that a default ObjectId would encode. There are no individual action records. Both schemas reject additional fields, and `route` must be one of the allowlisted templates. Startup initializes all indexes before serving the API.

## Administrator report

`GET /api/admin/product-metrics` requires a currently valid administrator account. Its fixed window includes today and the preceding 29 Pacific calendar dates; query parameters are rejected.

```json
{
  "days": 30, "from": "2026-09-09", "through": "2026-10-08",
  "counts": { "page_view": 5, "plan_saved": 0, "...": 0 },
  "daily": [{ "day": "2026-10-08", "event": "page_view", "locale": "en", "count": 5 }],
  "routes": [{ "event": "page_view", "route": "/events/:id", "count": 3 }],
  "routeDaily": [{ "day": "2026-10-08", "event": "page_view", "route": "/events/:id", "count": 3 }],
  "routesTruncated": false
}
```

- `counts` always has every event key; `daily` lists only nonempty day/event/locale rows.
- `routes` sums each event × route template over the window (locales combined), sorted by event, then count. It is grouped in Mongo, counts every stored row of the window and has at most one row per allowlisted event and template, so it is never capped.
- `routeDaily` is the same per day, oldest first. It returns at most 20,000 day × event × route rows, chosen newest first, so when `routesTruncated` is true it is the oldest days that are incomplete; `routes` still covers all 30 days.
- If the route collection cannot be read, `routes` and `routeDaily` are `null` and the totals still answer.

Run `node --test tests/productMetrics.test.js tests/product-route-metrics.test.js` for validation, privacy allowlisting, route mapping, authorization, concurrent increments, Pacific-midnight, retention-index, limiter isolation, failure and rate-limit checks. Tests use injected isolated models and never contact production storage.
