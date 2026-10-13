// Editorial event status (API-STATUS). The web's editorial overlay sets `status` on an event only from a
// dated source read (web src/data/monthly-types.ts `EditorialStatus`, copied here by
// scripts/sync-editorial-catalogs.js):
//   postponed — no confirmed day yet (occurrenceDates: [], the original date in dateNote); not "ended";
//   cancelled — will not take place;
//   sold_out  — takes place, but nothing is on sale now.
// A leaf module (no requires): planner.js, eventEngagement.js and outings.js all read it.
const EVENT_STATUSES = Object.freeze(['postponed', 'cancelled', 'sold_out']);
const FULL = /^(?:sold[_ -]?out|full|waitlist|waitlisted|unavailable)$/i;

/** 'cancelled' | 'postponed' | 'sold_out' | null. "canceled" and the legacy `cancelled: true` flag read as cancelled. */
function eventStatus(row) {
  if (!row || typeof row !== 'object') return null;
  if (row.status === 'cancelled' || row.status === 'canceled' || row.cancelled === true) return 'cancelled';
  return row.status === 'postponed' || row.status === 'sold_out' ? row.status : null;
}
/** Cancelled or postponed: no confirmed day, so it never occurs on a date, is not active and takes no sign-ups. */
const eventHalted = row => ['cancelled', 'postponed'].includes(eventStatus(row));
/** Nothing on sale: the editorial sold_out status, or a candidate's own full/waitlist availability. */
const soldOut = row => eventStatus(row) === 'sold_out' || row?.soldOut === true
  || FULL.test(String(row?.availability || row?.planning?.availability || '').trim());

const LABELS = {
  cancelled: ['已取消', '已取消', 'cancelled'],
  postponed: ['已延期，新日期未公布', '已延期，新日期未公佈', 'postponed, no new date yet'],
  sold_out: ['已售罄', '已售罄', 'sold out'],
};
const eventStatusLabel = (status, locale = 'zh-Hans') => LABELS[status]?.[locale === 'en' ? 2 : locale === 'zh-Hant' ? 1 : 0];
/** The note a model sees beside a record with a status: it may be mentioned with that status, never recommended. */
const STATUS_NOTES = {
  sold_out: 'Sold out: BAYLINK\'s dated read of the official page found nothing on sale. Say it is sold out; never recommend it, give it as an option or put it in a plan.',
  cancelled: 'Cancelled: it will not take place. Say so; never recommend it, give it as an option or put it in a plan.',
  postponed: 'Postponed with no confirmed new date. Say so and give no date for it; never recommend it, give it as an option or put it in a plan.',
};
const eventStatusNote = status => STATUS_NOTES[status];

module.exports = { EVENT_STATUSES, eventStatus, eventHalted, soldOut, eventStatusLabel, eventStatusNote };
