import pg from "pg";

const { Pool } = pg;

function normalizeChatId(value) {
  return String(value).trim();
}

function detectMediaKind(message) {
  if (Array.isArray(message?.photo) && message.photo.length) return "photo";
  if (message?.video) return "video";
  if (message?.animation) return "animation";
  if (message?.audio) return "audio";
  if (message?.voice) return "voice";
  if (message?.video_note) return "video_note";
  if (message?.document) return "document";
  if (message?.sticker) return "sticker";
  if (message?.poll) return "poll";
  if (message?.location) return "location";
  if (message?.venue) return "venue";
  if (message?.contact) return "contact";
  return "text";
}

function extractTelegramFileId(message) {
  if (Array.isArray(message?.photo) && message.photo.length) {
    return message.photo[message.photo.length - 1]?.file_id || null;
  }
  return (
    message?.video?.file_id ??
    message?.animation?.file_id ??
    message?.audio?.file_id ??
    message?.voice?.file_id ??
    message?.video_note?.file_id ??
    message?.document?.file_id ??
    message?.sticker?.file_id ??
    null
  );
}

function collectMessages(result) {
  if (!result) return [];
  if (Array.isArray(result)) {
    return result.filter((item) => item && typeof item === "object" && item.message_id && item.chat?.id !== undefined);
  }
  if (typeof result === "object" && result.message_id && result.chat?.id !== undefined) {
    return [result];
  }
  return [];
}

export async function createHistoryStore(databaseUrl) {
  if (!databaseUrl) throw new Error("DATABASE_URL is required");

  const pool = new Pool({
    connectionString: databaseUrl,
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });

  await pool.query("SELECT 1");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS telegram_post_history (
      id BIGSERIAL PRIMARY KEY,
      chat_id TEXT NOT NULL,
      message_id BIGINT,
      method TEXT NOT NULL,
      post_type TEXT NOT NULL DEFAULT 'message',
      text TEXT,
      caption TEXT,
      media_kind TEXT,
      telegram_file_id TEXT,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      telegram_created_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(chat_id, message_id)
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS telegram_post_history_chat_created_idx
    ON telegram_post_history (chat_id, created_at DESC)
  `);

  async function saveRecord(record) {
    const chatId = normalizeChatId(record.chat_id);
    const messageId = record.message_id ?? null;
    const result = await pool.query(
      `
        INSERT INTO telegram_post_history (
          chat_id, message_id, method, post_type, text, caption,
          media_kind, telegram_file_id, metadata, telegram_created_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
        ON CONFLICT (chat_id, message_id)
        DO UPDATE SET
          method = EXCLUDED.method,
          post_type = EXCLUDED.post_type,
          text = EXCLUDED.text,
          caption = EXCLUDED.caption,
          media_kind = EXCLUDED.media_kind,
          telegram_file_id = EXCLUDED.telegram_file_id,
          metadata = telegram_post_history.metadata || EXCLUDED.metadata,
          telegram_created_at = COALESCE(EXCLUDED.telegram_created_at, telegram_post_history.telegram_created_at)
        RETURNING *
      `,
      [
        chatId,
        messageId,
        record.method || "manual",
        record.post_type || "message",
        record.text ?? null,
        record.caption ?? null,
        record.media_kind ?? null,
        record.telegram_file_id ?? null,
        JSON.stringify(record.metadata || {}),
        record.telegram_created_at ?? null
      ]
    );
    return result.rows[0];
  }

  return {
    async recordTelegramResult({ method, payload, result }) {
      const messages = collectMessages(result);
      const saved = [];

      for (const message of messages) {
        const telegramCreatedAt = message.date
          ? new Date(Number(message.date) * 1000)
          : null;

        saved.push(await saveRecord({
          chat_id: message.chat.id,
          message_id: message.message_id,
          method,
          post_type: message.chat?.type === "channel" ? "channel_post" : "message",
          text: message.text ?? null,
          caption: message.caption ?? null,
          media_kind: detectMediaKind(message),
          telegram_file_id: extractTelegramFileId(message),
          telegram_created_at: telegramCreatedAt,
          metadata: {
            chat_title: message.chat?.title ?? null,
            chat_username: message.chat?.username ?? null,
            media_group_id: message.media_group_id ?? null,
            payload: payload || {}
          }
        }));
      }

      return saved;
    },

    async getRecent(chatId, limit = 10) {
      const safeLimit = Math.max(1, Math.min(Number(limit) || 10, 50));
      const result = await pool.query(
        `
          SELECT id, chat_id, message_id, method, post_type, text, caption,
                 media_kind, telegram_file_id, metadata, telegram_created_at, created_at
          FROM telegram_post_history
          WHERE chat_id = $1
          ORDER BY COALESCE(telegram_created_at, created_at) DESC, id DESC
          LIMIT $2
        `,
        [normalizeChatId(chatId), safeLimit]
      );
      return result.rows;
    },

    async saveManual(record) {
      return saveRecord({ ...record, method: record.method || "manual" });
    },

    async deleteRecord(chatId, historyId) {
      const result = await pool.query(
        `
          DELETE FROM telegram_post_history
          WHERE chat_id = $1 AND id = $2
          RETURNING id, chat_id, message_id
        `,
        [normalizeChatId(chatId), Number(historyId)]
      );
      return result.rows[0] || null;
    },

    async close() {
      await pool.end();
    }
  };
}
