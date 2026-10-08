// What one Anthropic Messages request asked for, without its content: enough to
// show that a run exercised a tool round (tool_use, then tool_result, then the
// tool_choice:none synthesis) and that the body kept the model's rules (explicit
// effort, no thinking:disabled or sampling fields on Sonnet 5.5). The harness
// stores it on every provider call; no message text, tool input or key is kept.

const blocksOf = (messages, role) => messages.filter(message => message?.role === role)
  .flatMap(message => Array.isArray(message.content) ? message.content : []);

/** Shape of a request body. */
export function requestShape(body = {}) {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const assistant = blocksOf(messages, 'assistant'), user = blocksOf(messages, 'user');
  return {
    maxTokens: body.max_tokens ?? null,
    toolChoice: body.tool_choice?.type ?? null,
    effort: body.output_config?.effort ?? null,
    thinking: body.thinking?.type ?? null,
    sampling: ['temperature', 'top_p', 'top_k'].filter(key => Object.hasOwn(body, key)),
    tools: Array.isArray(body.tools) ? body.tools.length : 0,
    messages: messages.length,
    replayedThinking: assistant.filter(block => ['thinking', 'redacted_thinking'].includes(block?.type)).length,
    replayedToolUse: assistant.filter(block => block?.type === 'tool_use').length,
    toolResults: user.filter(block => block?.type === 'tool_result').length,
  };
}

/** Block types of a response, e.g. ['thinking', 'tool_use']. */
export const responseShape = data => Array.isArray(data?.content) ? data.content.map(block => block?.type) : [];

/** The tool rounds of one result row: each tool_use answer followed by a call
 * that replays it with its tool_result. `final` marks the tool_choice:none call. */
export function toolRounds(calls = []) {
  const model = calls.filter(call => call.kind === 'assistant' && call.request);
  const rounds = [];
  for (const [index, call] of model.entries()) {
    if (call.stopReason !== 'tool_use') continue;
    const next = model[index + 1];
    rounds.push({ toolUse: { status: call.status, model: call.responseModel || call.model, toolChoice: call.request.toolChoice, maxTokens: call.request.maxTokens },
      next: next ? { status: next.status, model: next.responseModel || next.model, stopReason: next.stopReason, toolChoice: next.request.toolChoice, maxTokens: next.request.maxTokens,
        toolResults: next.request.toolResults, replayedThinking: next.request.replayedThinking, replayedToolUse: next.request.replayedToolUse } : null });
  }
  return rounds;
}
