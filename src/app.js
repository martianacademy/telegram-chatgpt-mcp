import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createChatPolicy, filterAllowedUpdates, isValidBearerAuthorization } from "./security.js";

export function createMcpAuthMiddleware(authToken) {
  if (!authToken) throw new Error("MCP_AUTH_TOKEN is required");

  return function mcpAuth(req, res, next) {
    if (!isValidBearerAuthorization(req.get("authorization"), authToken)) {
      res.set("WWW-Authenticate", 'Bearer realm="telegram-mcp"');
      return res.status(401).json({ error: "Unauthorized" });
    }

    return next();
  };
}

export function createTelegramClient({ token, fetchImpl = fetch }) {
  if (!token) throw new Error("TELEGRAM_BOT_TOKEN is required");
  const apiBase = `https://api.telegram.org/bot${token}`;

  return async function telegram(method, payload = {}) {
    const response = await fetchImpl(`${apiBase}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.description || `Telegram API ${method} failed`);
    }
    return data.result;
  };
}

const out = (value) => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }]
});

export function createMcpServer(telegram, chatPolicy) {
  const server = new McpServer({ name: "telegram", version: "1.2.0" });
  const { assertAllowed, isAllowed } = chatPolicy;

  server.registerTool("telegram_get_me", {
    title: "Get Telegram bot info",
    description: "Returns information about the connected Telegram bot.",
    inputSchema: z.object({})
  }, async () => out(await telegram("getMe")));

  server.registerTool("telegram_get_chat", {
    title: "Get Telegram chat",
    description: "Get information about an allowed Telegram chat, group, supergroup, or channel.",
    inputSchema: z.object({ chat_id: z.union([z.string(), z.number()]) })
  }, async ({ chat_id }) => {
    assertAllowed(chat_id);
    return out(await telegram("getChat", { chat_id }));
  });

  server.registerTool("telegram_send_message", {
    title: "Send Telegram message",
    description: "Send a text message to an allowed Telegram user, group, supergroup, or channel where the bot has permission.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      text: z.string().min(1).max(4096),
      parse_mode: z.enum(["HTML", "MarkdownV2"]).optional(),
      disable_notification: z.boolean().optional()
    })
  }, async ({ chat_id, text, parse_mode, disable_notification }) => {
    assertAllowed(chat_id);
    return out(await telegram("sendMessage", {
      chat_id,
      text,
      ...(parse_mode ? { parse_mode } : {}),
      ...(disable_notification !== undefined ? { disable_notification } : {})
    }));
  });

  server.registerTool("telegram_send_photo", {
    title: "Send Telegram photo",
    description: "Send a photo by public URL or Telegram file_id to an allowed chat.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      photo: z.string().min(1),
      caption: z.string().max(1024).optional(),
      parse_mode: z.enum(["HTML", "MarkdownV2"]).optional()
    })
  }, async ({ chat_id, photo, caption, parse_mode }) => {
    assertAllowed(chat_id);
    return out(await telegram("sendPhoto", {
      chat_id,
      photo,
      ...(caption ? { caption } : {}),
      ...(parse_mode ? { parse_mode } : {})
    }));
  });

  server.registerTool("telegram_edit_message", {
    title: "Edit Telegram message",
    description: "Edit a text message previously sent by the bot in an allowed chat.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      message_id: z.number().int().positive(),
      text: z.string().min(1).max(4096),
      parse_mode: z.enum(["HTML", "MarkdownV2"]).optional()
    })
  }, async ({ chat_id, message_id, text, parse_mode }) => {
    assertAllowed(chat_id);
    return out(await telegram("editMessageText", {
      chat_id,
      message_id,
      text,
      ...(parse_mode ? { parse_mode } : {})
    }));
  });

  server.registerTool("telegram_delete_message", {
    title: "Delete Telegram message",
    description: "Delete a Telegram message from an allowed chat when the bot has permission.",
    inputSchema: z.object({
      chat_id: z.union([z.string(), z.number()]),
      message_id: z.number().int().positive()
    })
  }, async ({ chat_id, message_id }) => {
    assertAllowed(chat_id);
    return out(await telegram("deleteMessage", { chat_id, message_id }));
  });

  server.registerTool("telegram_get_updates", {
    title: "Read allowed Telegram bot updates",
    description: "Read recent bot updates, filtered so only updates belonging to ALLOWED_CHAT_IDS are returned. Do not use while a webhook is configured.",
    inputSchema: z.object({
      offset: z.number().int().optional(),
      limit: z.number().int().min(1).max(100).optional(),
      timeout: z.number().int().min(0).max(50).optional()
    })
  }, async ({ offset, limit, timeout }) => {
    const updates = await telegram("getUpdates", {
      ...(offset !== undefined ? { offset } : {}),
      ...(limit !== undefined ? { limit } : {}),
      ...(timeout !== undefined ? { timeout } : {})
    });

    const filtered = filterAllowedUpdates(updates, isAllowed);

    return out(filtered);
  });

  return server;
}

export function createApp({ token, authToken, allowedChatIds, fetchImpl = fetch } = {}) {
  const telegram = createTelegramClient({ token, fetchImpl });
  const chatPolicy = createChatPolicy(allowedChatIds);
  const mcpAuth = createMcpAuthMiddleware(authToken);
  const app = express();

  app.use(express.json({ limit: "1mb" }));
  app.get("/", (_req, res) => res.json({ name: "Telegram ChatGPT MCP", status: "ok", endpoint: "/mcp" }));
  app.get("/health", (_req, res) => res.json({ ok: true }));

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
