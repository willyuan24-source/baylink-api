// Test support for API-BB-STREAM: Anthropic Messages SSE bodies built from a
// non-streamed message (wire format as in tests/fixtures/anthropic-stream/*.sse),
// delivered in byte chunks so UTF-8 characters and JSON lines split anywhere.
const event = (name, data) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;

/** The SSE text of `message`: text and thinking in `piece`-character deltas, the
 * signature as one signature_delta, tool input as input_json_delta fragments. */
function sseFor(message, { piece = 5, cut } = {}) {
  const parts = text => { const out = []; for (let index = 0; index < text.length; index += piece) out.push(text.slice(index, index + piece)); return out; };
  let body = event('message_start', { type: 'message_start', message: { ...message, content: [], stop_reason: null, stop_sequence: null, usage: { ...message.usage, output_tokens: 1 } } });
  for (const [index, block] of message.content.entries()) {
    if (block.type === 'text') {
      body += event('content_block_start', { type: 'content_block_start', index, content_block: { type: 'text', text: '' } });
      for (const text of parts(block.text)) body += event('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'text_delta', text } });
    } else if (block.type === 'thinking') {
      body += event('content_block_start', { type: 'content_block_start', index, content_block: { type: 'thinking', thinking: '', signature: '' } });
      for (const thinking of parts(block.thinking)) body += event('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'thinking_delta', thinking } });
      body += event('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'signature_delta', signature: block.signature } });
    } else if (block.type === 'tool_use') {
      body += event('content_block_start', { type: 'content_block_start', index, content_block: { ...block, input: {} } });
      for (const partial_json of parts(JSON.stringify(block.input))) body += event('content_block_delta', { type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json } });
    } else body += event('content_block_start', { type: 'content_block_start', index, content_block: block });
    body += event('content_block_stop', { type: 'content_block_stop', index });
  }
  body += event('message_delta', { type: 'message_delta', delta: { stop_reason: message.stop_reason, stop_sequence: null }, usage: { output_tokens: message.usage.output_tokens } });
  body += event('message_stop', { type: 'message_stop' });
  return cut ? body.slice(0, cut) : body;
}

function byteChunks(text, size = 7) {
  const buffer = Buffer.from(text, 'utf8'), chunks = [];
  for (let index = 0; index < buffer.length; index += size) chunks.push(buffer.subarray(index, index + size));
  return chunks;
}

/** A fetch Response whose body streams `text` in `size`-byte chunks; `hold` keeps the
 * stream open after the last chunk (a stalled provider) until the request aborts. */
function sseResponse(text, { size = 7, hold = false, signal } = {}) {
  const chunks = byteChunks(text, size);
  return new Response(new ReadableStream({
    pull(controller) {
      if (chunks.length) return controller.enqueue(chunks.shift());
      if (!hold) return controller.close();
      return new Promise((_, reject) => signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true }));
    },
  }), { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

module.exports = { sseFor, byteChunks, sseResponse };
