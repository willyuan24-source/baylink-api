// JSON schemas for the Claude JSON helpers (lib/anthropicJson.js requires one on
// every call and sends it as output_config.format). The schemas describe the
// shape each caller already validates; the callers keep their own validators
// for lengths, ranges and grounding. Every object sets additionalProperties:
// false, which Claude's structured outputs require. Bounds such as maxLength
// are left out on purpose (anthropicSchema strips them anyway).

const string = Object.freeze({ type: 'string' });
const strings = Object.freeze({ type: 'array', items: string });
// `required` defaults to every property; an empty list (all optional) is left out.
const object = (properties, required = Object.keys(properties)) => Object.freeze({ type: 'object', additionalProperties: false,
  ...(required.length ? { required } : {}), properties });

// lib/postTranslation.js: the four public post fields, all present.
const TRANSLATION_FIELDS = Object.freeze(['title', 'description', 'budget', 'timeInfo']);
const POST_TRANSLATION_SCHEMA = object(Object.fromEntries(TRANSLATION_FIELDS.map(field => [field, string])));

// server.js post-assist draft. The category and cover lists come from server.js
// so the schema never drifts from AI_POST_ASSIST_CATEGORIES / AI_DEFAULT_COVERS.
function postAssistSchema({ categories, covers }) {
  return object({
    title: string, description: string,
    category: { type: 'string', enum: [...categories] },
    type: { type: 'string', enum: ['client', 'provider'] },
    area: string, budget: string, timeInfo: string, quickTags: strings, safetyTip: string,
    coverSuggestion: { type: 'string', enum: [...covers] },
  });
}

// lib/outingDraft.js: draft fields are optional (an unknown field stays absent).
const OUTING_DRAFT_SCHEMA = object({
  answer: string,
  questions: strings,
  draft: object({
    title: string, description: string, date: string, startTime: string, endTime: string, city: string, venue: string,
    capacity: { type: 'integer' }, costNote: string,
    transport: { type: 'string', enum: ['own', 'transit', 'walk'] },
    language: { type: 'string', enum: ['any', 'zh', 'en'] },
  }, []),
});

// lib/planner.js ranking: filters the model may parse (all optional) plus ranked IDs.
function plannerSchema({ regions, settings, travelModes }) {
  return object({
    filters: object({
      date: string, region: { type: 'string', enum: ['all', ...regions] }, city: string, budget: { type: 'number' },
      childAge: { type: 'integer' }, setting: { type: 'string', enum: [...settings] }, travelMode: { type: 'string', enum: [...travelModes] },
    }, []),
    rankedEventIds: strings,
    rankedPlaceIds: strings,
  });
}

// lib/localAi.js event screenshot: every field is a string ('' when unknown).
const EVENT_FIELDS = Object.freeze(['title', 'date', 'startTime', 'endTime', 'city', 'venue', 'address', 'price', 'sourceUrl', 'description']);
const EVENT_EXTRACT_SCHEMA = object({ draft: object(Object.fromEntries(EVENT_FIELDS.map(field => [field, string]))), dateText: string });

// lib/localAi.js conversation translate / reply draft.
const CONVERSATION_TEXT_SCHEMA = object({ text: string });

module.exports = { TRANSLATION_FIELDS, POST_TRANSLATION_SCHEMA, postAssistSchema, OUTING_DRAFT_SCHEMA, plannerSchema, EVENT_FIELDS, EVENT_EXTRACT_SCHEMA, CONVERSATION_TEXT_SCHEMA };
