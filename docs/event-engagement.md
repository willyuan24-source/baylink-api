# Event interest and local buddies

The official event catalog is `data/event-catalog.json`, an array of `{ id, title, startDate, endDate, occurrenceDates? }` (`occurrenceDates`: the confirmed days; `[]` means none is confirmed). The frontend repository exports it from the same event data used by the calendar. The editorial `status` (`postponed`, `cancelled`, `sold_out`; web `EditorialStatus`) is not in that export: the loader takes it from `data/planner-catalog.json`, which carries the overlay (an unreadable planner file leaves sign-ups as they were without statuses). It is loaded once when the application starts. Missing, malformed, duplicate-ID or invalid-date catalogs (including confirmed days outside the event's range) make these endpoints return 503; arbitrary client event IDs cannot become database records.

`EventInterest` stores a single document per `(eventId, userId)` with `interested`, `lookingForBuddy`, `createdAt` and `updatedAt`. Looking for a buddy requires interest. Production startup waits for the compound unique index before listening. Concurrent upsert duplicate-key races retry an explicit update to the existing document. Cancelling an absent registration does not insert an empty document. There are no seeded participant counts and no messages are sent by these endpoints.

## Read engagement

`GET /api/events/engagement?ids=event-a,event-b`

Accepts 1–200 IDs (the web sends batches of 100), de-duplicates them and keeps the requested order. Malformed IDs or lists return 400; 429 and 503 (no catalog, storage error) are unchanged. An absent Authorization header is allowed. An invalid or expired supplied token is rejected rather than silently treated as anonymous.

An ID this copy of the catalog does not know (a web event between its content merge and the next API-SYNC) no longer fails the batch (API-SYNC-3b, H07): the known IDs get their entries in `events` and the others are listed in `unknown`. Every requested ID comes back exactly once, in one of the two lists, each in request order. `unknown` is always an array (empty when every ID is known). A legacy ID that resolves to a catalog event (`lib/eventId.js`) is known, and its entry keeps the requested ID as `eventId`. Web builds before WEB-HOLDOUT ignore `unknown`; they see fewer entries than requested and show the same retry state they showed for the old 404. Interest writes and buddy pages for an unknown ID still answer 404.

```json
{
  "events": [
    {
      "eventId": "event-a",
      "interestedCount": 12,
      "buddyCount": 3,
      "me": { "interested": true, "lookingForBuddy": false }
    }
  ],
  "unknown": ["event-not-synced-yet"]
}
```

Numbers above are response-shape examples, not defaults. `me` is `null` for anonymous readers. For signed-in readers with no registration, both state booleans are false. Counts come from distinct interested users in the database, joined to existing available accounts. Banned, limited, suspended and deleted accounts do not contribute. The counts are public global aggregates; they do not vary to disclose a viewer's block relationships.

## Read buddy profiles

`GET /api/events/:eventId/buddies?limit=20&cursor=...`

`limit` defaults to 20 and must be 1–20. `cursor` is the opaque `nextCursor` returned by the previous page. Results are sorted by user ID. Block relationships and account restrictions are applied before pagination.

```json
{
  "eventId": "event-a",
  "buddies": [
    { "id": "member-id", "nickname": "Neighbor", "avatar": "https://example.test/avatar.webp", "city": "Oakland" }
  ],
  "nextCursor": null
}
```

Only users who explicitly selected both `interested` and `lookingForBuddy` appear. Ordinary interest never exposes a member profile. The profile payload is an allowlist of `id`, `nickname`, `avatar`, and `city`; it never includes email, phone, contact preferences, credentials or verification secrets. Anonymous readers can see the public opt-in list. Signed-in readers cannot see people they blocked or people who blocked them. `buddyCount` may therefore be larger than the viewer-visible list.

## Set or withdraw interest

`PUT /api/events/:eventId/interest`, with a valid Bearer token:

```json
{ "interested": true, "lookingForBuddy": true }
```

Both fields must be booleans. Missing fields, extra fields (including forged user IDs) and `{ "interested": false, "lookingForBuddy": true }` return 400. The member ID always comes from the current validated session. Successful writes return one engagement object (the object inside `events` above).

The operation is an idempotent set, not a toggle. To withdraw from the buddy list while retaining interest, send true/false. To withdraw fully, send false/false. No DELETE endpoint is needed. New interest or a buddy opt-in is refused, with `{ "code": "...", "error": "..." }`, when (dates are America/Los_Angeles calendar days):

| Code | HTTP | When |
|---|---|---|
| `EVENT_CANCELLED` | 410 | the editorial status is `cancelled` |
| `EVENT_POSTPONED` | 409 | the editorial status is `postponed` (no new date yet) |
| `EVENT_ENDED` | 410 | `endDate` precedes today, or every confirmed day in `occurrenceDates` does |
| `EVENT_NO_CONFIRMED_DATE` | 409 | `occurrenceDates` is `[]` (for example San Mateo's 11/5 market, which the official calendar does not list) |

`error` is localized: `?locale=en|zh-Hant|zh-Hans` (the body takes no extra keys), else the first `Accept-Language` tag (`en…` → English, `zh-Hant`/`zh-TW`/`zh-HK`/`zh-MO` → Traditional), else Simplified Chinese. The final local date is still eligible. A `sold_out` event still takes place, so interest and buddy opt-in stay open. Withdrawing (false/false, or true/false that only leaves the buddy list while an interest exists) is always allowed. Limited accounts cannot join or opt in, but can withdraw. Standard authentication still rejects banned or suspended accounts.

Use `POST /api/conversations/open-or-create` with `{ "targetUserId": "member-id" }` when the user explicitly chooses to open a conversation. Existing message authorization and block checks remain in force. The event endpoints never create conversations or send messages.

## Limits and failures

Reads share a one-minute limit of 180/IP and 120/authenticated user. Writes share 120/IP and 40/user, using the existing process-local rate-limit helper. Limit violations return 429. All responses use the application's `Cache-Control: no-store`; personalized profiles and state must not enter shared caches. Database failures return 503 rather than zero counts or a claimed successful registration. If a write completed but response aggregation failed, clients can safely retry the identical set or refetch current state.

Tests inject `options.models`, `options.eventCatalog` and `options.eventNow` to avoid production databases, credentials and clocks. Run `node --test tests/event-engagement.test.js`, then `npm test` for existing authentication, privacy and messaging regression coverage.
