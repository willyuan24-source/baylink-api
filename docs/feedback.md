# Reader feedback (gate G9)

One endpoint takes the footer feedback sheet, "这条信息有误？" on event, offer, opening and guide pages, and the reasons behind a BayBay 👎. It needs no account.

## Submit

`POST /api/feedback`, JSON with only these keys:

```json
{
  "kind": "content",
  "routeTemplate": "/events/:id",
  "reason": "wrong-time",
  "text": "Parade starts at 11, not 12.",
  "contact": "reader@example.com",
  "entity": { "kind": "event", "id": "fleet-week-2026" },
  "locale": "zh-Hans",
  "readingSize": "large",
  "release": "a5d63fbe3e17",
  "website": ""
}
```

| Key | Required | Rule |
| --- | --- | --- |
| `kind` | yes | `page` (footer sheet), `content` (这条信息有误), `baybay` (👎 reasons) |
| `reason` | yes | One chip from the kind's list below |
| `routeTemplate` | no | Route template, mapped through `lib/routeTemplates.js`; anything else or absent becomes `other`. **Never the URL or query** |
| `text` | no | What the reader typed, at most 500 characters (code points). Trimmed; control characters and bidirectional marks, embeddings, overrides and isolates (U+061C, U+200E–U+200F, U+202A–U+202E, U+2066–U+2069) removed; line breaks kept |
| `contact` | no | Optional reply address the reader chose to give, at most 80 characters. Not validated as email or phone (WeChat ids are common) |
| `entity` | no | `{kind, id}` of the item the report is about. kind ∈ event, place, guide, offer, opening, post; id is a catalog id. Content reports should always send it |
| `locale` | no | `zh-Hans` (default), `zh-Hant`, `en` |
| `readingSize` | no | `standard` (default), `large`, `extra-large` |
| `release` | no | Web build: commit (stored as 12 hex digits) or a short label; otherwise `unknown` |
| `website` | no | Honeypot. Render it hidden and leave it empty |

Reasons (codes are stable; the web owns the labels):

| kind | reason codes and suggested zh labels |
| --- | --- |
| `page` (我在做什么) | `find-events` 找活动 · `get-help` 办事 · `ask-baybay` 问 BayBay · `plan` 计划 · `other` 其他 |
| `content` (哪里不对) | `outdated` 已过期 · `wrong-time` 时间不对 · `wrong-place` 地点不对 · `wrong-price` 价格不对 · `broken-link` 链接打不开 · `closed` 已取消或关门 · `other` 其他 |
| `baybay` (👎) | `wrong-answer` 答错了 · `too-slow` 太慢 · `not-answered` 没答到 · `other` 其他 |

Do not attach the page URL, the BayBay conversation, the account or anything the reader did not type into the sheet.

### Responses

Errors carry a stable `code` for the web to localise.

| Status | `code` | Meaning |
| --- | --- | --- |
| 202 | — | `{ "ok": true }`: stored. A filled honeypot gets the same answer and nothing is written |
| 400 | `FEEDBACK_INVALID` | Unknown key, wrong reason for the kind, wrong type, or text/contact too long. Nothing is written and no daily quota is used; the attempt still counts toward the per-minute limit |
| 429 | `FEEDBACK_RATE_LIMIT` | More than 5 submissions a minute from this visitor |
| 429 | `FEEDBACK_DAILY_LIMIT` | This visitor already sent 10 today (Pacific day) |
| 429 | `FEEDBACK_GLOBAL_LIMIT` | The site already accepted 500 today |
| 503 | `FEEDBACK_UNAVAILABLE` | Storage unavailable; keep the reader's text in the sheet so they can retry |

## Limits and privacy

- The per-minute limit is in memory, keyed by the visitor key (`req.ip`, see `docs/client-ip-rollout.md`), on its own limiter.
- The daily limits are durable in Mongo (`FeedbackQuota`), so a deploy does not reset them. A visitor's counter id is `day:visitor:HMAC-SHA256(JWT_SECRET, "feedback:v1:" + day + ":" + visitor key)`. The visitor key itself is never stored, and the digest changes every day, so counters cannot be linked across days. Counters expire after 2 days. The visitor counter is reserved before the site-wide one, so a visitor past their own limit cannot use up the site-wide cap; when the site-wide cap refuses a submission or storing it fails, the reserved slots are given back (best effort).
- `Feedback` rows hold only the fields above plus `createdAt` and `expiresAt`. No IP, visitor key, user id, URL, user agent or referrer. Rows are deleted 90 days after submission by a TTL index (Mongo removes expired rows asynchronously).
- Feedback is not linked to an account, so account deletion has nothing to erase here. A reader who asks to delete what they sent is handled by an administrator with the delete endpoint.

## Admin

Administrators only. Both routes answer `Cache-Control: no-store` and have their own per-minute limit.

- `GET /api/admin/feedback` lists entries newest first: `{ items: [{ id, kind, reason, route, text, contact?, entity?, locale, readingSize, release, createdAt }], nextBefore?, retentionDays: 90 }`. Query: `kind` (page, content, baybay), `limit` (1–200, default 100), `before` (pass the previous page's `nextBefore`). Any other parameter is 400.
- `DELETE /api/admin/feedback/:id` removes one entry (spam, or a reader's deletion request). 404 when it does not exist or has expired.

Not built yet: the owner's daily digest email (needs `NOTIFICATION_DELIVERY_ENABLED` and a sender, gate G5) and the admin panel UI (web).

Tests: `tests/feedback.test.js`.
