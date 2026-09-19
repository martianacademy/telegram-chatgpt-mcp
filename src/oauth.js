import crypto from "node:crypto";

const ACCESS_TTL_SECONDS = 60 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
const CODE_TTL_SECONDS = 5 * 60;
const CLIENT_TTL_SECONDS = 365 * 24 * 60 * 60;
const SUPPORTED_SCOPES = ["telegram:read", "telegram:write", "offline_access"];

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function parseB64url(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function signPayload(payload, secret, prefix) {
  const encoded = b64url(JSON.stringify(payload));
  const signature = crypto.createHmac("sha256", secret).update(`${prefix}.${encoded}`).digest("base64url");
  return `${prefix}.${encoded}.${signature}`;
}

function verifySignedPayload(token, secret, expectedPrefix) {
  const [prefix, encoded, signature, ...rest] = String(token || "").split(".");
  if (rest.length || prefix !== expectedPrefix || !encoded || !signature) throw new Error("invalid_token");
  const expected = crypto.createHmac("sha256", secret).update(`${prefix}.${encoded}`).digest("base64url");
  if (!timingSafeEqualText(signature, expected)) throw new Error("invalid_token");
  let payload;
  try {
    payload = JSON.parse(parseB64url(encoded));
  } catch {
    throw new Error("invalid_token");
  }
  if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) throw new Error("expired_token");
  return payload;
}

function normalizeBaseUrl(baseUrl) {
  return String(baseUrl || "").replace(/\/+$/, "");
}

function normalizeScope(scope) {
  const values = String(scope || "")
    .split(/\s+/)
    .map((v) => v.trim())
    .filter(Boolean);
  const unique = [...new Set(values)];
  if (unique.some((scopeValue) => !SUPPORTED_SCOPES.includes(scopeValue))) {
    throw new Error("invalid_scope");
  }
  return unique.length ? unique.join(" ") : SUPPORTED_SCOPES.join(" ");
}

function appendQuery(url, values) {
  const target = new URL(url);
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== "") target.searchParams.set(key, String(value));
  }
  return target.toString();
}

function isAllowedChatGptRedirect(uri) {
  try {
    const url = new URL(uri);
    return url.protocol === "https:" && url.hostname === "chatgpt.com" && url.pathname.startsWith("/connector/oauth/");
  } catch {
    return false;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderAuthorizePage(params, errorMessage = "") {
  const hidden = Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Telegram MCP</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f9;margin:0;display:grid;place-items:center;min-height:100vh;color:#171717}
.card{width:min(420px,calc(100vw - 32px));background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:28px;box-shadow:0 16px 50px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 8px}p{line-height:1.5;color:#555}.err{background:#fff1f2;color:#9f1239;border-radius:10px;padding:10px 12px;margin:14px 0}label{display:block;font-weight:600;margin:18px 0 8px}input[type=password]{width:100%;box-sizing:border-box;padding:12px;border:1px solid #cfd4dc;border-radius:10px;font-size:16px}button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:10px;background:#111;color:white;font-size:16px;font-weight:650;cursor:pointer}.small{font-size:13px;color:#777}
</style>
</head>
<body><main class="card">
<h1>Authorize Telegram MCP</h1>
<p>Allow ChatGPT to use your Telegram bot with the chat/channel allowlist configured on Railway.</p>
${errorMessage ? `<div class="err">${escapeHtml(errorMessage)}</div>` : ""}
<form method="post" action="/oauth/authorize">
${hidden}
<label for="owner_key">Owner access key</label>
<input id="owner_key" name="owner_key" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Authorize ChatGPT</button>
</form>
<p class="small">Use the value currently stored as <code>MCP_AUTH_TOKEN</code> in Railway.</p>
</main></body></html>`;
}

export function createOAuthProvider({ baseUrl, secret }) {
  const issuer = normalizeBaseUrl(baseUrl);
  if (!issuer || !issuer.startsWith("https://")) throw new Error("OAuth baseUrl must be HTTPS");
  if (!secret) throw new Error("MCP_AUTH_TOKEN is required");

  const resource = `${issuer}/mcp`;
  const metadataUrl = `${issuer}/.well-known/oauth-protected-resource`;
  const consumedCodes = new Set();

  function createClientId(redirectUris) {
    const now = Math.floor(Date.now() / 1000);
    return signPayload({
      typ: "client",
      redirect_uris: redirectUris,
      iat: now,
      exp: now + CLIENT_TTL_SECONDS
    }, secret, "dcr");
  }

  function verifyClient(clientId) {
    const payload = verifySignedPayload(clientId, secret, "dcr");
    if (payload.typ !== "client" || !Array.isArray(payload.redirect_uris)) throw new Error("invalid_client");
    return payload;
  }

  function issueToken(type, { clientId, scope, audience = resource, ttlSeconds, extra = {} }) {
    const now = Math.floor(Date.now() / 1000);
    return signPayload({
      typ: type,
      iss: issuer,
      aud: audience,
      client_id: clientId,
      scope,
      iat: now,
      exp: now + ttlSeconds,
      ...extra
    }, secret, "oauth");
  }

  function verifyOAuthToken(token, expectedType) {
    const payload = verifySignedPayload(token, secret, "oauth");
    if (payload.typ !== expectedType || payload.iss !== issuer || payload.aud !== resource) throw new Error("invalid_token");
    return payload;
  }

  function validateAuthorizationParams(input) {
    const responseType = input.response_type;
    const clientId = input.client_id;
    const redirectUri = input.redirect_uri;
    const codeChallenge = input.code_challenge;
    const method = input.code_challenge_method;
    const requestedResource = input.resource || resource;
    if (responseType !== "code") throw new Error("unsupported_response_type");
    if (!clientId || !redirectUri) throw new Error("invalid_request");
    const client = verifyClient(clientId);
    if (!client.redirect_uris.includes(redirectUri)) throw new Error("invalid_redirect_uri");
    if (!codeChallenge || method !== "S256") throw new Error("invalid_request");
    if (requestedResource !== resource) throw new Error("invalid_target");
    const scope = normalizeScope(input.scope);
    return { clientId, redirectUri, codeChallenge, scope, requestedResource };
  }

  function makeAuthorizationCode(validated) {
    const now = Math.floor(Date.now() / 1000);
    return signPayload({
      typ: "code",
      client_id: validated.clientId,
      redirect_uri: validated.redirectUri,
      code_challenge: validated.codeChallenge,
      scope: validated.scope,
      resource: validated.requestedResource,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + CODE_TTL_SECONDS
    }, secret, "code");
  }

  function exchangeAuthorizationCode({ code, clientId, redirectUri, codeVerifier, requestedResource }) {
    const payload = verifySignedPayload(code, secret, "code");
    if (payload.typ !== "code" || !payload.jti || consumedCodes.has(payload.jti)) throw new Error("invalid_grant");
    if (payload.client_id !== clientId || payload.redirect_uri !== redirectUri) throw new Error("invalid_grant");
    if ((requestedResource || resource) !== payload.resource) throw new Error("invalid_target");
    const actualChallenge = crypto.createHash("sha256").update(String(codeVerifier || "")).digest("base64url");
    if (!timingSafeEqualText(actualChallenge, payload.code_challenge)) throw new Error("invalid_grant");
    consumedCodes.add(payload.jti);
    if (consumedCodes.size > 2000) consumedCodes.clear();
    const accessToken = issueToken("access", { clientId, scope: payload.scope, audience: payload.resource, ttlSeconds: ACCESS_TTL_SECONDS });
    const refreshToken = issueToken("refresh", { clientId, scope: payload.scope, audience: payload.resource, ttlSeconds: REFRESH_TTL_SECONDS });
    return { accessToken, refreshToken, scope: payload.scope };
  }

  function refreshAccessToken({ refreshToken, clientId, scope }) {
    const payload = verifyOAuthToken(refreshToken, "refresh");
    if (clientId && payload.client_id !== clientId) throw new Error("invalid_grant");
    const finalScope = scope ? normalizeScope(scope) : payload.scope;
    const previousScopes = new Set(String(payload.scope || "").split(/\s+/).filter(Boolean));
    if (finalScope.split(/\s+/).some((value) => !previousScopes.has(value))) throw new Error("invalid_scope");
    return {
      accessToken: issueToken("access", { clientId: payload.client_id, scope: finalScope, ttlSeconds: ACCESS_TTL_SECONDS }),
      refreshToken: issueToken("refresh", { clientId: payload.client_id, scope: finalScope, ttlSeconds: REFRESH_TTL_SECONDS }),
      scope: finalScope
    };
  }

  function verifyAccessToken(token) {
    const payload = verifyOAuthToken(token, "access");
    const scopes = new Set(String(payload.scope || "").split(/\s+/).filter(Boolean));
    if (!scopes.has("telegram:read") && !scopes.has("telegram:write")) throw new Error("insufficient_scope");
    return payload;
  }

  return {
    issuer,
    resource,
    metadataUrl,
    supportedScopes: [...SUPPORTED_SCOPES],
    protectedResourceMetadata: {
      resource,
      authorization_servers: [issuer],
      bearer_methods_supported: ["header"],
      scopes_supported: [...SUPPORTED_SCOPES]
    },
    authorizationServerMetadata: {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      registration_endpoint: `${issuer}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [...SUPPORTED_SCOPES]
    },
    registerClient(body = {}) {
      const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
      if (!redirectUris.length || redirectUris.some((uri) => !isAllowedChatGptRedirect(uri))) throw new Error("invalid_redirect_uri");
      if (body.token_endpoint_auth_method && body.token_endpoint_auth_method !== "none") throw new Error("invalid_client_metadata");
      const clientId = createClientId(redirectUris);
      return {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: redirectUris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"]
      };
    },
    validateAuthorizationParams,
    makeAuthorizationCode,
    exchangeAuthorizationCode,
    refreshAccessToken,
    verifyAccessToken,
    verifyOwnerKey(value) {
      return timingSafeEqualText(value || "", secret);
    },
    renderAuthorizePage,
    authorizationSuccessRedirect({ redirectUri, code, state }) {
      return appendQuery(redirectUri, { code, state });
    },
    authorizationErrorRedirect({ redirectUri, error, state }) {
      return appendQuery(redirectUri, { error, state });
    }
  };
}

export function installOAuthRoutes(app, oauth) {
  app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json(oauth.protectedResourceMetadata));
  app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => res.json(oauth.protectedResourceMetadata));
  app.get("/.well-known/oauth-authorization-server", (_req, res) => res.json(oauth.authorizationServerMetadata));

  app.post("/oauth/register", (req, res) => {
    try {
      res.status(201).json(oauth.registerClient(req.body));
    } catch (error) {
      res.status(400).json({ error: error.message || "invalid_client_metadata" });
    }
  });

  app.get("/oauth/authorize", (req, res) => {
    try {
      oauth.validateAuthorizationParams(req.query);
      res.type("html").send(oauth.renderAuthorizePage(req.query));
    } catch (error) {
      const redirectUri = req.query.redirect_uri;
      if (redirectUri && isAllowedChatGptRedirect(redirectUri)) {
        return res.redirect(302, oauth.authorizationErrorRedirect({ redirectUri, error: error.message || "invalid_request", state: req.query.state }));
      }
      res.status(400).json({ error: error.message || "invalid_request" });
    }
  });

  app.post("/oauth/authorize", (req, res) => {
    const params = { ...req.body };
    const ownerKey = params.owner_key;
    delete params.owner_key;
    try {
      const validated = oauth.validateAuthorizationParams(params);
      if (!oauth.verifyOwnerKey(ownerKey)) {
        return res.status(401).type("html").send(oauth.renderAuthorizePage(params, "Incorrect owner access key."));
      }
      const code = oauth.makeAuthorizationCode(validated);
      return res.redirect(302, oauth.authorizationSuccessRedirect({ redirectUri: validated.redirectUri, code, state: params.state }));
    } catch (error) {
      const redirectUri = params.redirect_uri;
      if (redirectUri && isAllowedChatGptRedirect(redirectUri)) {
        return res.redirect(302, oauth.authorizationErrorRedirect({ redirectUri, error: error.message || "invalid_request", state: params.state }));
      }
      return res.status(400).json({ error: error.message || "invalid_request" });
    }
  });

  app.post("/oauth/token", (req, res) => {
    try {
      const grantType = req.body.grant_type;
      if (grantType === "authorization_code") {
        const result = oauth.exchangeAuthorizationCode({
          code: req.body.code,
          clientId: req.body.client_id,
          redirectUri: req.body.redirect_uri,
          codeVerifier: req.body.code_verifier,
          requestedResource: req.body.resource
        });
        return res.json({
          access_token: result.accessToken,
          token_type: "Bearer",
          expires_in: ACCESS_TTL_SECONDS,
          refresh_token: result.refreshToken,
          scope: result.scope
        });
      }
      if (grantType === "refresh_token") {
        const result = oauth.refreshAccessToken({
          refreshToken: req.body.refresh_token,
          clientId: req.body.client_id,
          scope: req.body.scope
        });
        return res.json({
          access_token: result.accessToken,
          token_type: "Bearer",
          expires_in: ACCESS_TTL_SECONDS,
          refresh_token: result.refreshToken,
          scope: result.scope
        });
      }
      return res.status(400).json({ error: "unsupported_grant_type" });
    } catch (error) {
      return res.status(400).json({ error: error.message || "invalid_grant" });
    }
  });
}
