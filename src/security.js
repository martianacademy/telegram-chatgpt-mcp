import crypto from "node:crypto";

function normalizeChatId(value) {
  return String(value).trim();
}

export function parseAllowedChatIds(value) {
  const values = Array.isArray(value)
    ? value
    : String(value ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);

  const ids = new Set(values.map(normalizeChatId).filter(Boolean));
  if (ids.size === 0) {
    throw new Error("ALLOWED_CHAT_IDS is required and must contain at least one chat ID");
  }
  return ids;
}

export function createChatPolicy(allowedChatIds) {
  const allowed = allowedChatIds instanceof Set
    ? new Set([...allowedChatIds].map(normalizeChatId))
    : parseAllowedChatIds(allowedChatIds);

  const assertAllowed = (chatId) => {
    const normalized = normalizeChatId(chatId);
    if (!allowed.has(normalized)) {
      throw new Error(`Chat ID ${normalized} is not allowed`);
    }
    return chatId;
  };

  const isAllowed = (chatId) =>
    chatId !== undefined &&
    chatId !== null &&
    allowed.has(normalizeChatId(chatId));

  return { allowed, assertAllowed, isAllowed };
}

export function extractUpdateChatId(update) {
  return (
    update?.message?.chat?.id ??
    update?.edited_message?.chat?.id ??
    update?.channel_post?.chat?.id ??
    update?.edited_channel_post?.chat?.id ??
    update?.callback_query?.message?.chat?.id ??
    update?.my_chat_member?.chat?.id ??
    update?.chat_member?.chat?.id ??
    update?.chat_join_request?.chat?.id
  );
}

export function filterAllowedUpdates(updates, isAllowed) {
  return Array.isArray(updates)
    ? updates.filter((update) => isAllowed(extractUpdateChatId(update)))
    : [];
}

function secureEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export function isValidBearerAuthorization(header, authToken) {
  if (!authToken) return false;
  const match = /^Bearer\s+(.+)$/i.exec(String(header ?? ""));
  const supplied = match?.[1] ?? "";
  return Boolean(supplied) && secureEqual(supplied, authToken);
}
