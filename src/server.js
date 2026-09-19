import { createApp } from "./app.js";

const token = process.env.TELEGRAM_BOT_TOKEN;
const authToken = process.env.MCP_AUTH_TOKEN;
const allowedChatIds = process.env.ALLOWED_CHAT_IDS;

if (!token) throw new Error("TELEGRAM_BOT_TOKEN is required");
if (!authToken) throw new Error("MCP_AUTH_TOKEN is required");
if (!allowedChatIds) throw new Error("ALLOWED_CHAT_IDS is required");

const app = createApp({ token, authToken, allowedChatIds });
const port = Number(process.env.PORT || 3000);

app.listen(port, "0.0.0.0", () => {
  console.log(`Telegram MCP listening on http://0.0.0.0:${port}/mcp`);
});
