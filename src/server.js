import { createApp } from "./app.js";

const token = process.env.TELEGRAM_BOT_TOKEN || process.env.ELEGRAM_BOT_TOKEN;
const authToken = process.env.MCP_AUTH_TOKEN;
const allowedChatIds = process.env.ALLOWED_CHAT_IDS;
const railwayDomain = process.env.RAILWAY_PUBLIC_DOMAIN;
const baseUrl = (process.env.PUBLIC_BASE_URL || (railwayDomain ? `https://${railwayDomain}` : "")).replace(/\/+$/, "");

if (!token) throw new Error("TELEGRAM_BOT_TOKEN is required");
if (!authToken) throw new Error("MCP_AUTH_TOKEN is required");
if (!allowedChatIds) throw new Error("ALLOWED_CHAT_IDS is required");
if (!baseUrl) throw new Error("PUBLIC_BASE_URL or RAILWAY_PUBLIC_DOMAIN is required");

const app = createApp({ token, authToken, allowedChatIds, baseUrl });
const port = 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`Telegram MCP listening on 0.0.0.0:${port} — public ${baseUrl}/mcp`);
});
