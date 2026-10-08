# Planner favorites (♡ 收藏)

`PUT /api/planner/favorites/:kind/:id` saves one item to the signed-in account and `DELETE` removes it. Both return `{ "favorites": [{ "kind", "id" }, …] }`, the account's full list in save order. Only the `{kind, id}` pair is stored; titles, covers and links come from the web catalog at render time. An account holds at most 150 favorites across all kinds.

| kind | Backed by | Id |
| --- | --- | --- |
| `event` | `data/planner-catalog.json` `events` | event id; legacy ids are canonicalised (`lib/eventId.js`), so an old and a new id are one favorite |
| `place` | `data/planner-catalog.json` `places` | place id |
| `guide` | `data/planner-catalog.json` `guides` | guide slug |
| `offer` | `data/discoveries.json` items with `kind: "offer"` | offer id (`/offers/:id`) |
| `opening` | `data/discoveries.json` items with `kind: "opening"` | opening id (`/openings/:id`) |

`offer` and `opening` were added for the single save model (D19, gate G15). Web builds from before WEB-SAVES do not know these kinds. A guest list read from browser storage filters them out, but the signed-in path shows `/api/planner/me` (and the lists returned by `PUT`/`DELETE`) as it is, so a stale signed-in tab shows an offer or opening saved elsewhere with its raw id as the title and a `/guides/` link until it is reloaded onto the WEB-SAVES build. Nothing breaks, and no such favorite can exist before WEB-SAVES ships.

**For WEB-SAVES:** every consumer of server favorites (saved-items lists, ♡ state, title and link helpers, guest import) must handle `offer` and `opening`, and should skip, not mislabel, any kind it does not recognise.

## Responses

| Status | Body | Meaning |
| --- | --- | --- |
| 200 | `{ favorites }` | Saved (idempotent: saving twice keeps one row) or removed |
| 400 | `{ error }` | Unknown kind, malformed id, or a request body |
| 401 / 403 | `{ error }` | Not signed in, or the account is restricted |
| 404 | `{ error, code: "ITEM_NOT_IN_CATALOG" }` | **Save only.** The API's copy of the catalog has no item with this kind and id |
| 409 | `{ error }` | Another device kept winning the revision race five times; reread and retry |
| 429 | `{ error }` | More than 60 writes a minute from this visitor or account |
| 503 | `{ error }` | Storage unavailable, or (event, place, guide only) the planner catalog failed to load |

`DELETE` never answers 404: an item that was retired in a later catalog refresh can always be removed.

## Catalog lag and the web fallback (RC-15)

The API serves copies of the web's catalogs (`scripts/sync-editorial-catalogs.js`). Between a content merge on the web and the next API sync (API-SYNC), the web can show an offer, opening or event whose id the API does not know yet. Saving it then answers `404 ITEM_NOT_IN_CATALOG`.

The web must treat that code as "not yet", not as an error:

1. Keep the item saved locally (the same local list a guest uses) and show it as saved. Do not show an error toast.
2. Retry the `PUT` later: on the next `/api/planner/me` load, when the tab regains focus, or after at most one day. Stop retrying when the item leaves the web catalog.
3. Any other 4xx is a real failure: undo the optimistic ♡ and show the error.

API-SYNC runs after every content merge, including GPT content PRs, so the window is normally hours. On 2026-10-08 the API copy and web `main` held the same 269 discoveries (209 offers, 60 openings).

Tests: `tests/planner-favorites-discoveries.test.js` (kinds, 404 code, retired removal, catalog independence, shipped catalog) and `tests/planner.test.js`.
