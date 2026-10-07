# BayBay direct Claude rollout

This optional provider supports the existing frontend contract. No frontend key or new dependency is needed. Default `BAYBAY_AI_PROVIDER=openai` preserves the installed provider until the server is configured.

## Server configuration

| Variable | Value / behavior |
| --- | --- |
| `BAYBAY_AI_PROVIDER` | `anthropic` |
| `ANTHROPIC_API_KEY` | Secret stored only in hosting environment settings |
| `ANTHROPIC_WORKSPACE_ID` | Console workspace ID; required for organization-scoped identity keys |
| `ANTHROPIC_BAYBAY_MODEL` | `claude-opus-5-5` |
| `ANTHROPIC_BAYBAY_EFFORT` | `medium` default; `low` for a deliberate latency/cost tradeoff |
| `ANTHROPIC_USE_UNTIL` | Optional ISO UTC cutoff; expired or invalid nonempty cutoff disables new Claude calls |

Promotional credits belong to the Console organization. Check the actual credit applicability and expiry in Billing; the application cannot infer remaining dollars from request quotas. For the October 2026 trial, the observed credit expiry date is October 30 UTC. The deployment uses the conservative cutoff `2026-10-30T00:00:00Z` because the UI exposes a date rather than an exact expiry time. At the cutoff, site help remains available; changing provider after the trial is a separate operator decision. No payment method, auto-reload or purchase is configured by this release.

## Protocol and cost boundaries

Direct HTTPS requests go only to `api.anthropic.com/v1/messages`, with `Authorization: Bearer`, `anthropic-version: 2023-06-01`, and the optional workspace header. Existing cancellation, concurrency and shared database quotas are used. There are no automatic cross-provider retries.

Opus 5.5 uses adaptive thinking. Returned text and tool calls are selected by block type; private thinking/signatures are retained only inside an individual tool loop and are never returned to the browser. System instructions, model and tool definitions remain stable during that loop. Tool results and current evidence append to the conversation. Synthesis sets `tool_choice: none` while retaining tool definitions. Application validators still enforce candidate IDs, citations, geography, answer length and plan constraints after schema decoding.

Request `max_tokens` includes both reasoning and visible answers. Usage accounting includes cache creation/read input and counts output (including hidden thinking) once. The existing admin metrics recognize the fixed Claude model name, without storing prompts or credentials. These request/token controls do not constitute a dollar-denominated hard cap.

Native Claude web search is bounded to at most two tool uses and 35 seconds. Agent model calls allow up to 25 seconds for research or 28 seconds for synthesis, shortened to the remaining stage deadline; the complete agent run retains its 75-second budget. The tool dispatcher requires the full search window before starting a lookup, preserving time for a final answer. Only native citations pass into the existing public-URL and source validation. Private plans/history are not sent to the web-search request. The Claude search path does not run the OpenAI extraction step. Other independently configured non-BayBay features remain on their existing provider.

## Release and verification

1. Run `npm run check`, the complete backend test suite and dependency audit.
2. Verify the API key/workspace/model against the direct Models endpoint and one small Messages request. Keep credentials out of scripts, command arguments, logs and the repository.
3. Deploy the backend commit, configure the hosting variables, and verify `/api/health` reports that exact commit.
4. Verify `/api/ai/baybay-capabilities` reports the intended provider and model. Configuration alone does not verify access.
5. Send bounded public site-only and authenticated web questions. Inspect actual response model, complete/nondegraded output, source links and native tool usage. Confirm ordinary site browsing and default-provider regression tests still pass.
6. To roll back the provider, set `BAYBAY_AI_PROVIDER=openai` and redeploy the environment; existing OpenAI variables remain untouched. Do not ship the independent frontend design preview as part of this backend release.

## Official references

- [Opus 5.5 migration](https://platform.claude.com/docs/en/models/opus-5-5/migration-guide)
- [Authentication and workspace selection](https://platform.claude.com/docs/en/manage-claude/authentication)
- [Preserved thinking](https://platform.claude.com/docs/en/build-with-claude/preserved-thinking)
- [Structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
- [Web search](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool)
