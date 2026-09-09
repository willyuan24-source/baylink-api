const crypto = require('crypto');

const PROFILE_THEMES = new Set(['bay', 'sunset', 'redwood', 'lavender']);
const MESSAGE_REACTIONS = ['👍', '❤️', '😂', '🎉', '🙏', '👀'];
const PROFILE_IMAGE_MAX_BYTES = 4 * 1024 * 1024;
const PROFILE_IMAGE_ERROR = '图片请使用不超过 4 MB 的 PNG、JPEG、WebP 或 GIF 文件。';

// Only user-owned current URLs may pass through unchanged. New images must be
// bounded raster uploads; SVG and arbitrary remote URLs are deliberately excluded.
function validateProfileImage(value, currentUrl) {
  if (value === undefined) return { ok: true, action: 'keep' };
  if (value === '') return { ok: true, action: 'remove' };
  if (typeof value !== 'string') return { ok: false, error: PROFILE_IMAGE_ERROR };
  if (value === currentUrl && /^https:\/\//.test(value)) return { ok: true, action: 'keep' };
  if (value.length > Math.ceil(PROFILE_IMAGE_MAX_BYTES / 3) * 4 + 50) return { ok: false, error: PROFILE_IMAGE_ERROR };
  const match = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match || match[2].length % 4 !== 0) return { ok: false, error: PROFILE_IMAGE_ERROR };
  const bytes = Buffer.from(match[2], 'base64');
  if (!bytes.length || bytes.length > PROFILE_IMAGE_MAX_BYTES || bytes.toString('base64') !== match[2]) return { ok: false, error: PROFILE_IMAGE_ERROR };
  const signatures = {
    png: bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])),
    jpeg: bytes.length >= 3 && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255,
    gif: ['GIF87a', 'GIF89a'].includes(bytes.subarray(0, 6).toString('ascii')),
    webp: bytes.subarray(0, 4).toString('ascii') === 'RIFF' && bytes.subarray(8, 12).toString('ascii') === 'WEBP',
  };
  return signatures[match[1]] ? { ok: true, action: 'upload', data: value } : { ok: false, error: PROFILE_IMAGE_ERROR };
}

const reactionKey = userId => crypto.createHash('sha256').update(userId).digest('hex');

function publicMessage(message) {
  const value = typeof message?.toObject === 'function' ? message.toObject({ flattenMaps: true }) : message;
  const voteValues = value.reactionVotes instanceof Map ? [...value.reactionVotes.values()] : Object.values(value.reactionVotes || {});
  const reactions = MESSAGE_REACTIONS.flatMap(emoji => {
    const userIds = [...new Set(voteValues.filter(vote => vote?.emoji === emoji && typeof vote.userId === 'string').map(vote => vote.userId))];
    return userIds.length ? [{ emoji, userIds }] : [];
  });
  return {
    id: value.id, conversationId: value.conversationId, senderId: value.senderId,
    type: value.type, messageType: value.messageType || (value.type === 'contact_card' ? 'contact_card' : 'text'),
    content: value.content, createdAt: value.createdAt,
    ...(value.type === 'contact_card' || value.messageType === 'contact_card' ? { contactCard: value.contactCard } : {}),
    ...(value.replyTo?.id ? { replyTo: { id: value.replyTo.id, senderId: value.replyTo.senderId, content: value.replyTo.content } } : {}),
    reactions, reactionVersion: Number(value.reactionVersion) || 0,
  };
}

function buildReplyPreview(message) {
  const text = Array.from(String(message.content || '').replace(/\s+/g, ' ').trim());
  return { id: message.id, senderId: message.senderId, content: text.slice(0, 160).join('') + (text.length > 160 ? '…' : '') };
}

module.exports = { PROFILE_THEMES, MESSAGE_REACTIONS, PROFILE_IMAGE_MAX_BYTES, validateProfileImage, reactionKey, publicMessage, buildReplyPreview };
