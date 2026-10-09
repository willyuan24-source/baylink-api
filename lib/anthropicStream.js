// Anthropic Messages streaming (`stream: true`) over raw fetch (overhaul
// API-BB-STREAM, baybay.md §3.5). The backend has no SDK dependency, so this is
// the small parser the SDK's messages.stream() + finalMessage() would otherwise be.
//
//   sse parser        bytes -> {event, data}. Bytes may split anywhere, including
//                     inside a multi-byte UTF-8 character or between CR and LF.
//   accumulator       events -> the complete message, the same object a
//                     non-streaming call returns: message_start (id, model, input
//                     usage), content_block_start/delta/stop (text_delta,
//                     thinking_delta, signature_delta, input_json_delta,
//                     citations_delta), message_delta (stop_reason, stop_details,
//                     final usage), message_stop, ping, error. Thinking blocks and
//                     their signatures are kept verbatim, so a streamed turn can be
//                     replayed in a tool loop exactly like a non-streamed one.
//                     Unknown events, block types (fallback, server tool results)
//                     and delta types are kept or ignored, never fatal.
//   json fields       the string values of chosen JSON paths (the fast path's
//                     `lead` and `points[i].text`) as the model writes them.

const clone = value => JSON.parse(JSON.stringify(value));
const streamError = (message, extra = {}) => Object.assign(new Error(message), { code: 'AI_PROVIDER_STREAM_ERROR', ...extra });

/** Server-sent-event framing (WHATWG rules): LF, CRLF or CR line ends, `:` comments,
 * multi-line data joined with \n, an event dispatched on a blank line. A trailing
 * event without its blank line is discarded at the end, as the spec says. */
function createSseParser(onEvent) {
  let buffer = '', name = '', data = [];
  const line = text => {
    if (text === '') {
      if (data.length) onEvent({ event: name || 'message', data: data.join('\n') });
      name = ''; data = []; return;
    }
    if (text.startsWith(':')) return;
    const colon = text.indexOf(':');
    const field = colon < 0 ? text : text.slice(0, colon);
    let value = colon < 0 ? '' : text.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') name = value;
    else if (field === 'data') data.push(value);
  };
  return {
    push(text) {
      buffer += text;
      let start = 0;
      for (let index = 0; index < buffer.length; index++) {
        const char = buffer[index];
        if (char !== '\n' && char !== '\r') continue;
        // A CR at the end of a chunk may be the first half of CRLF: wait for more.
        if (char === '\r' && index === buffer.length - 1) break;
        line(buffer.slice(start, index));
        if (char === '\r' && buffer[index + 1] === '\n') index++;
        start = index + 1;
      }
      buffer = buffer.slice(start);
    },
    end() { if (buffer.endsWith('\r')) line(buffer.slice(0, -1)); buffer = ''; name = ''; data = []; },
  };
}

// Blocks whose `input` arrives as input_json_delta fragments.
const INPUT_BLOCKS = new Set(['tool_use', 'server_tool_use', 'mcp_tool_use']);

/** Rebuilds one streamed message. `onDelta({type:'text'|'thinking'|'input_json', index, blockType, text})`
 * reports content as it arrives; callback errors never reach the stream. */
function createMessageAccumulator({ onDelta } = {}) {
  let message = null, stopped = false;
  const partialInput = new Map();
  const report = value => { try { onDelta?.(value); } catch { /* a listener cannot break the provider call */ } };
  const block = index => {
    const value = message?.content?.[index];
    if (!value || typeof value !== 'object') throw streamError('AI provider stream sent a delta for an unknown content block');
    return value;
  };
  function apply({ event, data }) {
    let value;
    try { value = JSON.parse(data); } catch { throw streamError('AI provider stream sent an invalid event'); }
    const type = value?.type || event;
    if (type === 'ping') return;
    if (type === 'error') {
      const providerType = typeof value?.error?.type === 'string' && /^[a-z_]{1,60}$/.test(value.error.type) ? value.error.type : 'unknown_error';
      throw streamError(`AI provider stream error ${providerType}`, { providerErrorType: providerType });
    }
    if (type === 'message_start') {
      if (!value.message || typeof value.message !== 'object') throw streamError('AI provider stream sent an invalid message_start');
      message = clone(value.message);
      if (!Array.isArray(message.content)) message.content = [];
      if (!message.usage || typeof message.usage !== 'object') message.usage = {};
      return;
    }
    if (!message) {
      // Anything before message_start other than ping/error is not this protocol.
      if (['content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop'].includes(type)) throw streamError('AI provider stream event before message_start');
      return;
    }
    if (type === 'content_block_start') {
      if (!Number.isInteger(value.index) || value.index < 0 || !value.content_block || typeof value.content_block !== 'object') throw streamError('AI provider stream sent an invalid content block');
      message.content[value.index] = clone(value.content_block);
      if (INPUT_BLOCKS.has(value.content_block.type)) partialInput.set(value.index, '');
      return;
    }
    if (type === 'content_block_delta') {
      const target = block(value.index), delta = value.delta || {};
      if (delta.type === 'text_delta' && typeof delta.text === 'string') {
        target.text = (typeof target.text === 'string' ? target.text : '') + delta.text;
        report({ type: 'text', index: value.index, blockType: target.type, text: delta.text });
      } else if (delta.type === 'thinking_delta' && typeof delta.thinking === 'string') {
        target.thinking = (typeof target.thinking === 'string' ? target.thinking : '') + delta.thinking;
        report({ type: 'thinking', index: value.index, blockType: target.type, text: delta.thinking });
      } else if (delta.type === 'signature_delta' && typeof delta.signature === 'string') {
        target.signature = (typeof target.signature === 'string' ? target.signature : '') + delta.signature;
      } else if (delta.type === 'input_json_delta' && typeof delta.partial_json === 'string' && partialInput.has(value.index)) {
        partialInput.set(value.index, partialInput.get(value.index) + delta.partial_json);
        report({ type: 'input_json', index: value.index, blockType: target.type, text: delta.partial_json });
      } else if (delta.type === 'citations_delta' && delta.citation) {
        target.citations = [...(Array.isArray(target.citations) ? target.citations : []), clone(delta.citation)];
      }
      return;
    }
    if (type === 'content_block_stop') {
      const target = block(value.index);
      if (partialInput.has(value.index)) {
        const raw = partialInput.get(value.index);
        partialInput.delete(value.index);
        // A tool input that does not parse is never executed: the adapter fails a
        // tool_use block without an object input.
        try { target.input = raw.trim() ? JSON.parse(raw) : {}; } catch { target.input = null; }
      }
      return;
    }
    if (type === 'message_delta') {
      for (const [key, field] of Object.entries(value.delta || {})) if (key !== 'usage') message[key] = clone(field);
      // message_delta usage is cumulative: it replaces message_start's counts.
      for (const [key, count] of Object.entries(value.usage || {})) if (count !== null && count !== undefined) message.usage[key] = clone(count);
      return;
    }
    if (type === 'message_stop') stopped = true;
    // Unknown events are ignored (forward compatible).
  }
  return {
    apply,
    /** The complete message; throws when the stream ended before message_stop. */
    finish() {
      if (!message) throw streamError('AI provider stream ended before message_start');
      if (!stopped) throw streamError('AI provider stream ended before message_stop');
      for (const index of partialInput.keys()) message.content[index].input = null;
      message.content = message.content.filter(Boolean);
      return message;
    },
    /** What has arrived so far (for a usage estimate after an abort or timeout). */
    partial: () => message ? clone({ ...message, content: message.content.filter(Boolean) }) : null,
    stopped: () => stopped,
  };
}

/** Read an SSE body (fetch Response.body, a Node stream or any async iterable of
 * bytes or strings) into the complete message. */
async function readMessageStream(body, accumulator = createMessageAccumulator()) {
  if (!body || typeof body[Symbol.asyncIterator] !== 'function') throw streamError('AI provider stream has no readable body');
  const decoder = new TextDecoder('utf-8');
  const parser = createSseParser(event => accumulator.apply(event));
  for await (const chunk of body) {
    parser.push(typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true }));
    // Nothing after message_stop matters; stop reading so a proxy cannot hold the call open.
    if (accumulator.stopped()) break;
  }
  if (!accumulator.stopped()) { parser.push(decoder.decode()); parser.end(); }
  return accumulator.finish();
}

// Rough output-token estimate for a cut-off stream (no message_delta usage):
// one token per CJK character, one per four other characters.
function estimateTokens(text) {
  const value = String(text || '');
  const cjk = (value.match(/[　-鿿가-힯豈-﫿＀-￯]/g) || []).length;
  return cjk + Math.ceil((value.length - cjk) / 4);
}
/** Usage for a partial message: message_start input counts as reported; output is the
 * larger of the reported count and an estimate from the text received. Thinking that
 * the API did not display (empty thinking text) cannot be estimated. */
function estimatedUsage(partial) {
  if (!partial || typeof partial !== 'object') return null;
  const usage = { ...(partial.usage || {}) };
  const text = (partial.content || []).map(block => [block.text, block.thinking, block.input && typeof block.input === 'object' ? JSON.stringify(block.input) : ''].filter(value => typeof value === 'string').join('')).join('');
  const reported = Number.isSafeInteger(usage.output_tokens) && usage.output_tokens >= 0 ? usage.output_tokens : 0;
  usage.output_tokens = Math.max(reported, estimateTokens(text));
  return usage;
}

/** Streams the string values of JSON paths chosen by `match(path)` while the JSON is
 * still being written. `onText(target, text)` gets decoded characters (escapes,
 * including \uXXXX split across chunks, resolved); `onDone(target)` fires when the
 * string closes. Invalid JSON never throws: the extractor just stops matching. */
function createJsonFieldStream({ match, onText, onDone }) {
  const stack = [];
  let inString = false, isKey = false, escape = false, hex = null, key = '', target = null, broken = false;
  const path = () => stack.map(frame => frame.kind === '{' ? frame.key : frame.index);
  const call = (fn, ...args) => { try { fn?.(...args); } catch { /* listeners cannot break parsing */ } };
  return {
    push(chunk) {
      if (broken || typeof chunk !== 'string') return;
      let out = '';
      const emit = char => { if (isKey) key += char; else if (target) out += char; };
      const flush = () => { if (out && target) call(onText, target, out); out = ''; };
      for (const char of chunk) {
        if (inString) {
          if (hex !== null) {
            if (!/^[0-9a-fA-F]$/.test(char)) { broken = true; break; }
            hex += char;
            if (hex.length === 4) { emit(String.fromCharCode(parseInt(hex, 16))); hex = null; }
          } else if (escape) {
            escape = false;
            if (char === 'u') hex = '';
            else emit({ n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' }[char] ?? char);
          } else if (char === '\\') escape = true;
          else if (char === '"') {
            inString = false;
            if (isKey) { const frame = stack.at(-1); if (frame) frame.key = key; isKey = false; }
            else if (target) { flush(); call(onDone, target); target = null; }
          } else emit(char);
          continue;
        }
        const frame = stack.at(-1);
        if (char === '"') {
          inString = true;
          if (frame?.kind === '{' && frame.key === null) { isKey = true; key = ''; }
          else target = match(path()) || null;
        } else if (char === '{' || char === '[') {
          if (stack.length >= 32) { broken = true; break; }
          stack.push(char === '{' ? { kind: '{', key: null } : { kind: '[', index: 0 });
        } else if (char === '}' || char === ']') stack.pop();
        else if (char === ',') { if (frame?.kind === '{') frame.key = null; else if (frame) frame.index++; }
      }
      flush();
    },
  };
}

/** The fast-path draft fields (lib/baybayFastPath.js FAST_FORMAT): lead and points[i].text. */
const fastDraftField = path => path.length === 1 && path[0] === 'lead' ? { field: 'lead' }
  : path.length === 3 && path[0] === 'points' && Number.isInteger(path[1]) && path[2] === 'text' ? { field: 'point', index: path[1] } : null;

module.exports = { createSseParser, createMessageAccumulator, readMessageStream, estimatedUsage, estimateTokens, createJsonFieldStream, fastDraftField };
