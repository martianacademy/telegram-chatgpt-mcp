import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createOAuthProvider } from "../src/oauth.js";

const baseUrl = "https://telegram.example.com";
const callback = "https://chatgpt.com/connector/oauth/test-callback";

function createFlow() {
  const oauth = createOAuthProvider({ baseUrl, secret: "test-secret-that-is-long-enough" });
  const client = oauth.registerClient({ redirect_uris: [callback], token_endpoint_auth_method: "none" });
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const validated = oauth.validateAuthorizationParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: callback,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: `${baseUrl}/mcp`
  });
  return { oauth, client, verifier, validated };
}

test("publishes OAuth metadata with PKCE and DCR", () => {
  const oauth = createOAuthProvider({ baseUrl, secret: "test-secret" });
  assert.equal(oauth.authorizationServerMetadata.registration_endpoint, `${baseUrl}/oauth/register`);
  assert.deepEqual(oauth.authorizationServerMetadata.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(oauth.authorizationServerMetadata.token_endpoint_auth_methods_supported, ["none"]);
  assert.equal(oauth.protectedResourceMetadata.resource, `${baseUrl}/mcp`);
});

test("DCR only accepts ChatGPT callback URLs", () => {
  const oauth = createOAuthProvider({ baseUrl, secret: "test-secret" });
  assert.throws(() => oauth.registerClient({ redirect_uris: ["https://evil.example/callback"] }), /invalid_redirect_uri/);
  const client = oauth.registerClient({ redirect_uris: [callback] });
  assert.ok(client.client_id.startsWith("dcr."));
});

test("authorization code + S256 PKCE issues and verifies access token", () => {
  const { oauth, client, verifier, validated } = createFlow();
  const code = oauth.makeAuthorizationCode(validated);
  const result = oauth.exchangeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: callback,
    codeVerifier: verifier,
    requestedResource: `${baseUrl}/mcp`
  });
  const claims = oauth.verifyAccessToken(result.accessToken);
  assert.equal(claims.aud, `${baseUrl}/mcp`);
  assert.match(claims.scope, /telegram:write/);
  assert.ok(result.refreshToken);
});

test("authorization code cannot be replayed", () => {
  const { oauth, client, verifier, validated } = createFlow();
  const code = oauth.makeAuthorizationCode(validated);
  const args = { code, clientId: client.client_id, redirectUri: callback, codeVerifier: verifier, requestedResource: `${baseUrl}/mcp` };
  oauth.exchangeAuthorizationCode(args);
  assert.throws(() => oauth.exchangeAuthorizationCode(args), /invalid_grant/);
});

test("refresh token creates a new valid access token", () => {
  const { oauth, client, verifier, validated } = createFlow();
  const code = oauth.makeAuthorizationCode(validated);
  const first = oauth.exchangeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: callback,
    codeVerifier: verifier,
    requestedResource: `${baseUrl}/mcp`
  });
  const next = oauth.refreshAccessToken({ refreshToken: first.refreshToken, clientId: client.client_id });
  assert.equal(oauth.verifyAccessToken(next.accessToken).client_id, client.client_id);
});
