import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createChatPolicy, filterAllowedUpdates } from "./security.js";
import { createOAuthProvider, installOAuthRoutes } from "./oauth.js";

export function createOAuthMcpAuthMiddleware(oauth) {
  return function mcpAuth(req, res, next) {
    const header = String(req.get("authorization") || "");
    const match = /^Bearer\s+(.+)$/i.exec(header);
    try {
      if (!match) throw new Error("invalid_token");
      req.oauth = oauth.verifyAccessToken(match[1]);
      return next();
    } catch (error) {
      const challenge = [
        "Bearer",
        `resource_metadata="${oauth.metadataUrl}"`,
        `resource="${oauth.resource}"`,
        `error="${error.message || "invalid_token"}"`
      ].join(", ");
      res.set("WWW-Authenticate", challenge);
      return res.status(401).json({ error: "Unauthorized" });
    }
  };
}

function normalizeFormValue(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function filenameFromUrl(value, fallback) {
  try {
    const pathname = new URL(value).pathname;
    const name = pathname.split("/").filter(Boolean).pop();
    return name || fallback;
  } catch {
    return fallback;
  }
}

export function createTelegramClient({ token, fetchImpl = fetch }) {
  if (!token) throw new Error("TELEGRAM_BOT_TOKEN is required");
  const apiBase = `https://api.telegram.org/bot${token}`;

  async function parseTelegramResponse(response, method) {
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error(`Telegram API ${method} returned an invalid response`);
    }
    if (!response.ok || !data.ok) {
      throw new Error(data.description || `Telegram API ${method} failed`);
    }
    return data.result;
  }

  async function json(method, payload = {}) {
    const response = await fetchImpl(`${apiBase}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    return parseTelegramResponse(response, method);
  }

  async function multipart(method, payload = {}, fileField, fileSpec = {}) {
    const form = new FormData();
    for (const [key, value] of Object.entries(payload || {})) {
      const normalized = normalizeFormValue(value);
      if (normalized !== null) form.append(key, normalized);
    }

    let blob;
    let filename = fileSpec.filename || "upload.bin";
    const mimeType = fileSpec.mime_type || "application/octet-stream";

    if (fileSpec.base64) {
      const clean = String(fileSpec.base64).replace(/^data:[^;]+;base64,/, "");
      const buffer = Buffer.from(clean, "base64");
      if (!buffer.length) throw new Error("Uploaded base64 file is empty");
      blob = new Blob([buffer], { type: mimeType });
    } else if (fileSpec.url) {
      const remote = await fetchImpl(fileSpec.url);
      if (!remote.ok) throw new Error(`Unable to fetch upload URL: HTTP ${remote.status}`);
      blob = await remote.blob();
      filename = fileSpec.filename || filenameFromUrl(fileSpec.url, "upload.bin");
    } else {
      throw new Error("Provide file_base64 or file_url");
    }

    form.append(fileField, blob, filename);
    const response = await fetchImpl(`${apiBase}/${method}`, {
      method: "POST",
      body: form
    });
    return parseTelegramResponse(response, method);
  }

  return { json, multipart };
}

const out = (value) => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }]
});

const rawParamsSchema = z.record(z.string(), z.any()).optional().default({});

function assertPayloadChatsAllowed(payload, assertAllowed) {
  if (!payload || typeof payload !== "object") return;
  for (const [key, value] of Object.entries(payload)) {
    if ((key === "chat_id" || key.endsWith("_chat_id")) && value !== undefined && value !== null) {
      assertAllowed(value);
    }
  }
}

function registerRawMethod(server, name, method, description, telegram, assertAllowed, annotations = {}) {
  server.registerTool(name, {
    title: method,
    description,
    inputSchema: z.object({ params: rawParamsSchema }),
    annotations
  }, async ({ params }) => {
    assertPayloadChatsAllowed(params, assertAllowed);
    return out(await telegram.json(method, params));
  });
}

export function createMcpServer(telegram, chatPolicy) {
  const server = new McpServer({ name: "telegram", version: "1.4.0" });
  const { assertAllowed, isAllowed } = chatPolicy;

  server.registerTool("telegram_get_me", {
    title: "Get Telegram bot info",
    description: "Returns information about the connected Telegram bot.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true }
  }, async () => out(await telegram.json("getMe")));

  server.registerTool("telegram_get_chat", {
    title: "Get Telegram chat",
    description: "Get information about an allowed Telegram chat, group, supergroup, or channel.",
    inputSchema: z.object({ chat_id: z.union([z.string(), z.number()]) }),
    annotations: { readOnlyHint: true }
  }, async ({ chat_id }) => {
    assertAllowed(chat_id);
    return out(await telegram.json("getChat", { chat_id }));
  });

  server.registerTool("telegram_send_message", {
    title: "Send Telegram message",
    description: "Send a text message to an allowed Telegram user, group, supergroup, or channel.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      text: z.string().min(1).max(4096),
      parse_mode: z.enum(["HTML", "MarkdownV2"]).optional(),
      disable_notification: z.boolean().optional(),
      protect_content: z.boolean().optional()
    }),
    annotations: { readOnlyHint: false, destructiveHint: false }
  }, async ({ chat_id, text, parse_mode, disable_notification, protect_content }) => {
    assertAllowed(chat_id);
    return out(await telegram.json("sendMessage", {
      chat_id,
      text,
      ...(parse_mode ? { parse_mode } : {}),
      ...(disable_notification !== undefined ? { disable_notification } : {}),
      ...(protect_content !== undefined ? { protect_content } : {})
    }));
  });

  server.registerTool("telegram_send_photo", {
    title: "Send Telegram photo",
    description: "Send a photo to an allowed chat. Supports Telegram file_id/public URL, a downloadable file_url, or base64/data-URI upload. For ChatGPT-generated local images, use photo_base64 when the file bytes are available.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      photo: z.string().optional(),
      photo_base64: z.string().optional(),
      file_url: z.string().url().optional(),
      filename: z.string().optional(),
      mime_type: z.string().optional(),
      caption: z.string().max(1024).optional(),
      parse_mode: z.enum(["HTML", "MarkdownV2"]).optional(),
      disable_notification: z.boolean().optional()
    }).refine((v) => Boolean(v.photo || v.photo_base64 || v.file_url), {
      message: "Provide photo, photo_base64, or file_url"
    }),
    annotations: { readOnlyHint: false, destructiveHint: false }
  }, async ({ chat_id, photo, photo_base64, file_url, filename, mime_type, caption, parse_mode, disable_notification }) => {
    assertAllowed(chat_id);
    const payload = {
      chat_id,
      ...(caption ? { caption } : {}),
      ...(parse_mode ? { parse_mode } : {}),
      ...(disable_notification !== undefined ? { disable_notification } : {})
    };
    if (photo_base64 || file_url) {
      return out(await telegram.multipart("sendPhoto", payload, "photo", {
        base64: photo_base64,
        url: file_url,
        filename: filename || "image.png",
        mime_type: mime_type || "image/png"
      }));
    }
    return out(await telegram.json("sendPhoto", { ...payload, photo }));
  });

  server.registerTool("telegram_send_document", {
    title: "Send Telegram document",
    description: "Send a document using Telegram file_id/public URL or upload it from base64 or a downloadable URL.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      document: z.string().optional(),
      file_base64: z.string().optional(),
      file_url: z.string().url().optional(),
      filename: z.string().optional(),
      mime_type: z.string().optional(),
      caption: z.string().max(1024).optional(),
      parse_mode: z.enum(["HTML", "MarkdownV2"]).optional()
    }).refine((v) => Boolean(v.document || v.file_base64 || v.file_url), {
      message: "Provide document, file_base64, or file_url"
    }),
    annotations: { readOnlyHint: false, destructiveHint: false }
  }, async ({ chat_id, document, file_base64, file_url, filename, mime_type, caption, parse_mode }) => {
    assertAllowed(chat_id);
    const payload = { chat_id, ...(caption ? { caption } : {}), ...(parse_mode ? { parse_mode } : {}) };
    if (file_base64 || file_url) {
      return out(await telegram.multipart("sendDocument", payload, "document", {
        base64: file_base64,
        url: file_url,
        filename: filename || "document.bin",
        mime_type: mime_type || "application/octet-stream"
      }));
    }
    return out(await telegram.json("sendDocument", { ...payload, document }));
  });

  server.registerTool("telegram_upload_file", {
    title: "Upload file to any Telegram Bot API method",
    description: "Generic multipart Telegram upload. Use for photos, videos, audio, voice, stickers, documents, thumbnails, chat photos, and other Bot API methods that accept file uploads.",
    inputSchema: z.object({
      method: z.string().regex(/^[A-Za-z][A-Za-z0-9]*$/),
      params: rawParamsSchema,
      file_field: z.string().min(1),
      file_base64: z.string().optional(),
      file_url: z.string().url().optional(),
      filename: z.string().optional(),
      mime_type: z.string().optional()
    }).refine((v) => Boolean(v.file_base64 || v.file_url), {
      message: "Provide file_base64 or file_url"
    }),
    annotations: { readOnlyHint: false, destructiveHint: false }
  }, async ({ method, params, file_field, file_base64, file_url, filename, mime_type }) => {
    assertPayloadChatsAllowed(params, assertAllowed);
    return out(await telegram.multipart(method, params, file_field, {
      base64: file_base64,
      url: file_url,
      filename,
      mime_type
    }));
  });

  server.registerTool("telegram_api_call", {
    title: "Call any Telegram Bot API method",
    description: "Generic JSON passthrough for any current or future Telegram Bot API method. This gives full Bot API coverage beyond the named tools. Any chat_id/from_chat_id fields must be in ALLOWED_CHAT_IDS.",
    inputSchema: z.object({
      method: z.string().regex(/^[A-Za-z][A-Za-z0-9]*$/),
      params: rawParamsSchema
    }),
    annotations: { readOnlyHint: false }
  }, async ({ method, params }) => {
    assertPayloadChatsAllowed(params, assertAllowed);
    return out(await telegram.json(method, params));
  });

  server.registerTool("telegram_get_updates", {
    title: "Read allowed Telegram bot updates",
    description: "Read recent bot updates, filtered so only updates belonging to ALLOWED_CHAT_IDS are returned. Do not use while a webhook is configured.",
    inputSchema: z.object({
      offset: z.number().int().optional(),
      limit: z.number().int().min(1).max(100).optional(),
      timeout: z.number().int().min(0).max(50).optional(),
      allowed_updates: z.array(z.string()).optional()
    }),
    annotations: { readOnlyHint: true }
  }, async ({ offset, limit, timeout, allowed_updates }) => {
    const updates = await telegram.json("getUpdates", {
      ...(offset !== undefined ? { offset } : {}),
      ...(limit !== undefined ? { limit } : {}),
      ...(timeout !== undefined ? { timeout } : {}),
      ...(allowed_updates ? { allowed_updates } : {})
    });
    return out(filterAllowedUpdates(updates, isAllowed));
  });

  registerRawMethod(server, "telegram_forward_message", "forwardMessage", "Forward a message to an allowed chat.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_forward_messages", "forwardMessages", "Forward multiple messages to an allowed chat.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_copy_message", "copyMessage", "Copy a message to an allowed chat.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_copy_messages", "copyMessages", "Copy multiple messages to an allowed chat.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_audio", "sendAudio", "Send audio by URL or Telegram file_id. Use telegram_upload_file for binary upload.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_video", "sendVideo", "Send video by URL or Telegram file_id. Use telegram_upload_file for binary upload.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_animation", "sendAnimation", "Send animation/GIF by URL or Telegram file_id.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_voice", "sendVoice", "Send voice message by URL or Telegram file_id.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_video_note", "sendVideoNote", "Send a video note.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_media_group", "sendMediaGroup", "Send an album/media group.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_location", "sendLocation", "Send a location.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_venue", "sendVenue", "Send a venue.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_contact", "sendContact", "Send a contact.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_poll", "sendPoll", "Send a poll.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_dice", "sendDice", "Send an animated dice/emoji.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_send_sticker", "sendSticker", "Send a sticker.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_edit_message_text", "editMessageText", "Edit a Telegram message's text.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_edit_message_caption", "editMessageCaption", "Edit a media caption.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_edit_message_media", "editMessageMedia", "Replace message media.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_edit_message_reply_markup", "editMessageReplyMarkup", "Edit inline keyboard markup.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_delete_message", "deleteMessage", "Delete a message.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_delete_messages", "deleteMessages", "Delete multiple messages.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_set_message_reaction", "setMessageReaction", "Set a reaction on a message.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_pin_chat_message", "pinChatMessage", "Pin a message in an allowed chat.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_unpin_chat_message", "unpinChatMessage", "Unpin a message in an allowed chat.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_unpin_all_chat_messages", "unpinAllChatMessages", "Unpin all messages in an allowed chat.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_get_chat_administrators", "getChatAdministrators", "Get chat administrators.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_get_chat_member_count", "getChatMemberCount", "Get chat member count.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_get_chat_member", "getChatMember", "Get information about a chat member.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_ban_chat_member", "banChatMember", "Ban a chat member.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_unban_chat_member", "unbanChatMember", "Unban a chat member.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_restrict_chat_member", "restrictChatMember", "Restrict a chat member.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_promote_chat_member", "promoteChatMember", "Promote or demote a chat member.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_set_chat_administrator_custom_title", "setChatAdministratorCustomTitle", "Set an administrator custom title.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_set_chat_permissions", "setChatPermissions", "Set default chat permissions.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_set_chat_title", "setChatTitle", "Set chat title.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_set_chat_description", "setChatDescription", "Set chat description.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_create_chat_invite_link", "createChatInviteLink", "Create a chat invite link.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_edit_chat_invite_link", "editChatInviteLink", "Edit a chat invite link.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_revoke_chat_invite_link", "revokeChatInviteLink", "Revoke a chat invite link.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_approve_chat_join_request", "approveChatJoinRequest", "Approve a join request.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_decline_chat_join_request", "declineChatJoinRequest", "Decline a join request.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_leave_chat", "leaveChat", "Make the bot leave an allowed chat.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_get_user_chat_boosts", "getUserChatBoosts", "Get boosts added by a user.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_get_file", "getFile", "Get a Telegram file path for download.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_answer_callback_query", "answerCallbackQuery", "Answer an inline keyboard callback.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_answer_inline_query", "answerInlineQuery", "Answer an inline query.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_answer_web_app_query", "answerWebAppQuery", "Answer a Web App query.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_set_my_commands", "setMyCommands", "Set bot commands.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_delete_my_commands", "deleteMyCommands", "Delete bot commands.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_get_my_commands", "getMyCommands", "Get bot commands.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_set_my_name", "setMyName", "Set bot name.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_get_my_name", "getMyName", "Get bot name.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_set_my_description", "setMyDescription", "Set bot description.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_get_my_description", "getMyDescription", "Get bot description.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_set_my_short_description", "setMyShortDescription", "Set bot short description.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_get_my_short_description", "getMyShortDescription", "Get bot short description.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_set_chat_menu_button", "setChatMenuButton", "Set chat menu button.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_get_chat_menu_button", "getChatMenuButton", "Get chat menu button.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_set_my_default_administrator_rights", "setMyDefaultAdministratorRights", "Set default admin rights.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_get_my_default_administrator_rights", "getMyDefaultAdministratorRights", "Get default admin rights.", telegram, assertAllowed, { readOnlyHint: true });
  registerRawMethod(server, "telegram_create_forum_topic", "createForumTopic", "Create a forum topic.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_edit_forum_topic", "editForumTopic", "Edit a forum topic.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_close_forum_topic", "closeForumTopic", "Close a forum topic.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_reopen_forum_topic", "reopenForumTopic", "Reopen a forum topic.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_delete_forum_topic", "deleteForumTopic", "Delete a forum topic.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_unpin_all_forum_topic_messages", "unpinAllForumTopicMessages", "Unpin all messages in a forum topic.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_set_webhook", "setWebhook", "Set a Telegram webhook. This disables getUpdates until deleted.", telegram, assertAllowed, { readOnlyHint: false });
  registerRawMethod(server, "telegram_delete_webhook", "deleteWebhook", "Delete the current Telegram webhook.", telegram, assertAllowed, { readOnlyHint: false, destructiveHint: true });
  registerRawMethod(server, "telegram_get_webhook_info", "getWebhookInfo", "Get webhook status.", telegram, assertAllowed, { readOnlyHint: true });

  return server;
}

export function createApp({ token, authToken, allowedChatIds, baseUrl, fetchImpl = fetch } = {}) {
  const telegram = createTelegramClient({ token, fetchImpl });
  const chatPolicy = createChatPolicy(allowedChatIds);
  const oauth = createOAuthProvider({ baseUrl, secret: authToken });
  const mcpAuth = createOAuthMcpAuthMiddleware(oauth);
  const app = express();

  app.use(express.json({ limit: "25mb" }));
  app.use(express.urlencoded({ extended: false, limit: "1mb" }));

  app.get("/", (_req, res) => res.json({
    name: "Telegram ChatGPT MCP",
    version: "1.4.0",
    status: "ok",
    endpoint: "/mcp",
    authentication: "OAuth 2.1 + PKCE",
    capabilities: ["json Bot API passthrough", "multipart uploads", "base64 uploads", "allowlisted chats"]
  }));
  app.get("/health", (_req, res) => res.json({ ok: true, oauth: true, version: "1.4.0" }));

  installOAuthRoutes(app, oauth);

  app.all("/mcp", mcpAuth, async (req, res) => {
    const server = createMcpServer(telegram, chatPolicy);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

    res.on("close", () => void transport.close());

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error(error);
      if (!res.headersSent) res.status(500).json({ error: "MCP request failed" });
    }
  });

  return app;
}
