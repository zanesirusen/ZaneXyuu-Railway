import http from "node:http";
import {spawn} from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import Busboy from "busboy";
import ffmpegPath from "ffmpeg-static";
import pg from "pg";

const { Pool } = pg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.ROBLOX_API_KEY || "";
const CREATOR_TYPE = (process.env.ROBLOX_CREATOR_TYPE || "user").toLowerCase();
const CREATOR_ID = process.env.ROBLOX_CREATOR_ID || "";
const FRONTEND_URL = (process.env.FRONTEND_URL || "https://zanexyuu-asset-uploader.vercel.app").replace(/\/$/, "");
const BACKEND_URL = (process.env.BACKEND_URL || "").replace(/\/$/, "");
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const DATABASE_URL = process.env.DATABASE_URL || "";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const ROBLOX_OAUTH_CLIENT_ID = process.env.ROBLOX_OAUTH_CLIENT_ID || "";
const ROBLOX_OAUTH_CLIENT_SECRET = process.env.ROBLOX_OAUTH_CLIENT_SECRET || "";
const ROBLOX_OAUTH_REDIRECT_URI = process.env.ROBLOX_OAUTH_REDIRECT_URI || "";
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID || "";
const DISCORD_PREMIUM_ROLE_ID = process.env.DISCORD_PREMIUM_ROLE_ID || "";
const OPERATION_ENCRYPTION_SECRET = process.env.OPERATION_ENCRYPTION_KEY || DISCORD_CLIENT_SECRET;
const FREE_DAILY_FILES = 10;
const SESSION_DAYS = 14;
const pool = DATABASE_URL ? new Pool({connectionString: DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? {rejectUnauthorized:false} : undefined}) : null;
const FREE_MAX_FILE_SIZE = 30 * 1024 * 1024;
const FREE_MAX_BATCH_FILES = 5;
const FREE_MAX_BATCH_SIZE = FREE_MAX_FILE_SIZE * FREE_MAX_BATCH_FILES;
const PREMIUM_MAX_FILE_SIZE = 50 * 1024 * 1024;
const PREMIUM_MAX_BATCH_SIZE = 250 * 1024 * 1024;
const PREMIUM_MAX_BATCH_FILES = 5;
const MAX_CONCURRENT_BODY_READS = 3;
const CONVERTER_MAX_FILE_SIZE = 50 * 1024 * 1024;
const MAX_CONCURRENT_CONVERSIONS = 2;
const PREMIUM_CACHE_MS = 30 * 1000;
const UPSTREAM_TIMEOUT_MS = 30 * 1000;
const OPERATION_TTL_MS = 60 * 60 * 1000;
const premiumCache = new Map();
const creatorValidationCache = new Map();
let activeBodyReads = 0;
let activeConversions = 0;
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

function log(message, details = {}) {
  const suffix = Object.entries(details).map(([key, value]) => `${key}=${JSON.stringify(String(value))}`).join(" ");
  console.log(`[${new Date().toISOString()}] ${message}${suffix ? ` ${suffix}` : ""}`);
}

const authConfigured = Boolean(pool && DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_BOT_TOKEN && DISCORD_GUILD_ID);
const googleAuthConfigured = Boolean(pool && GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
const robloxAuthConfigured = Boolean(pool && ROBLOX_OAUTH_CLIENT_ID && ROBLOX_OAUTH_CLIENT_SECRET && OPERATION_ENCRYPTION_SECRET);
const parseCookies = request => Object.fromEntries(String(request.headers.cookie || "").split(";").map(item => item.trim()).filter(Boolean).map(item => {
  const index = item.indexOf("=");
  return [index < 0 ? item : item.slice(0, index), decodeURIComponent(index < 0 ? "" : item.slice(index + 1))];
}));
const redirect = (res, location, headers = {}) => { res.writeHead(302, {Location:location, "Cache-Control":"no-store", ...headers}); res.end(); };
const backendOrigin = req => BACKEND_URL || `${req.headers["x-forwarded-proto"] || "https"}://${req.headers.host || ""}`;
const validRequestOrigin = req => String(req.headers.origin || "") === FRONTEND_URL;
const operationEncryptionKey = OPERATION_ENCRYPTION_SECRET ? createHash("sha256").update(OPERATION_ENCRYPTION_SECRET).digest() : null;

function encryptOperationKey(apiKey) {
  if (!operationEncryptionKey) throw new Error("Operation encryption is not configured on the server.");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", operationEncryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(apiKey, "utf8"), cipher.final()]);
  return `enc:v1:${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${encrypted.toString("base64url")}`;
}

function decryptOperationKey(value) {
  if (!value?.startsWith("enc:v1:") || !operationEncryptionKey) throw new Error("Upload credentials are no longer available. Please upload again.");
  const [ivValue, tagValue, encryptedValue] = value.slice(7).split(".");
  const decipher = createDecipheriv("aes-256-gcm", operationEncryptionKey, Buffer.from(ivValue, "base64url"));
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(encryptedValue, "base64url")), decipher.final()]).toString("utf8");
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    return await fetch(url, {...options, signal:controller.signal});
  } finally {
    clearTimeout(timeout);
  }
}

async function initializeDatabase() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discord_users (
      discord_id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      avatar TEXT,
      is_premium BOOLEAN NOT NULL DEFAULT FALSE,
      auth_provider TEXT NOT NULL DEFAULT 'discord',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE discord_users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'discord';
    ALTER TABLE discord_users ADD COLUMN IF NOT EXISTS linked_discord_id TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS discord_users_linked_discord_idx ON discord_users(linked_discord_id) WHERE linked_discord_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS discord_sessions (
      token TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS discord_sessions_expiry_idx ON discord_sessions(expires_at);
    CREATE TABLE IF NOT EXISTS daily_upload_usage (
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      usage_date DATE NOT NULL,
      file_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (discord_id, usage_date)
    );
    CREATE TABLE IF NOT EXISTS daily_ip_upload_usage (
      ip_hash TEXT NOT NULL,
      usage_date DATE NOT NULL,
      file_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (ip_hash, usage_date)
    );
    CREATE TABLE IF NOT EXISTS credential_bindings (
      credential_hash TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      creator_type TEXT NOT NULL,
      creator_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS saved_credentials (
      credential_id TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      encrypted_api_key TEXT NOT NULL,
      creator_type TEXT NOT NULL DEFAULT 'user',
      creator_id TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS saved_credentials_user_idx ON saved_credentials(discord_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS creator_bindings (
      creator_type TEXT NOT NULL,
      creator_id TEXT NOT NULL,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (creator_type, creator_id)
    );
    CREATE TABLE IF NOT EXISTS ip_rate_limits (
      ip_hash TEXT NOT NULL,
      route_key TEXT NOT NULL,
      window_start TIMESTAMPTZ NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (ip_hash, route_key, window_start)
    );
    CREATE INDEX IF NOT EXISTS ip_rate_limits_window_idx ON ip_rate_limits(window_start);
    CREATE TABLE IF NOT EXISTS oauth_states (
      state TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ NOT NULL
    );
    ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS link_user_id TEXT;
    ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS oauth_provider TEXT;
    ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS code_verifier TEXT;
    ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS access_mode TEXT;
    ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS group_id TEXT;
    CREATE TABLE IF NOT EXISTS roblox_connections (
      discord_id TEXT PRIMARY KEY REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      roblox_user_id TEXT NOT NULL,
      username TEXT,
      display_name TEXT,
      profile_url TEXT,
      avatar_url TEXT,
      refresh_token TEXT NOT NULL,
      scope TEXT,
      connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE roblox_connections ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'account';
    ALTER TABLE roblox_connections ADD COLUMN IF NOT EXISTS group_id TEXT;
    CREATE TABLE IF NOT EXISTS asset_operations (
      operation_id TEXT PRIMARY KEY,
      operation_token TEXT NOT NULL,
      api_key TEXT NOT NULL,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      filename TEXT,
      size_bytes INTEGER,
      asset_type TEXT,
      creator_type TEXT,
      creator_id TEXT,
      expires_at TIMESTAMPTZ NOT NULL
    );
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS filename TEXT;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS size_bytes INTEGER;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS asset_type TEXT;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS creator_type TEXT;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS creator_id TEXT;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS quota_reserved BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS quota_ip_hash TEXT;
    ALTER TABLE asset_operations ADD COLUMN IF NOT EXISTS quota_date DATE NOT NULL DEFAULT CURRENT_DATE;
    CREATE INDEX IF NOT EXISTS asset_operations_expiry_idx ON asset_operations(expires_at);
    CREATE TABLE IF NOT EXISTS upload_intents (
      intent_id TEXT PRIMARY KEY,
      operation_id TEXT,
      operation_token TEXT,
      api_key TEXT NOT NULL,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      filename TEXT,
      size_bytes INTEGER,
      asset_type TEXT,
      creator_type TEXT,
      creator_id TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      quota_reserved BOOLEAN NOT NULL DEFAULT FALSE,
      quota_ip_hash TEXT,
      quota_date DATE NOT NULL DEFAULT CURRENT_DATE,
      credential_hash TEXT,
      claimed_credential BOOLEAN NOT NULL DEFAULT FALSE,
      claimed_creator BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE upload_intents ADD COLUMN IF NOT EXISTS credential_hash TEXT;
    ALTER TABLE upload_intents ADD COLUMN IF NOT EXISTS claimed_credential BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE upload_intents ADD COLUMN IF NOT EXISTS claimed_creator BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS upload_intents_operation_idx ON upload_intents(operation_id);
    CREATE INDEX IF NOT EXISTS upload_intents_expiry_idx ON upload_intents(expires_at);
    CREATE TABLE IF NOT EXISTS analytics_visits (
      ip_hash TEXT NOT NULL,
      visit_date DATE NOT NULL,
      PRIMARY KEY (ip_hash, visit_date)
    );
    CREATE TABLE IF NOT EXISTS analytics_uploads (
      operation_id TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL REFERENCES discord_users(discord_id) ON DELETE CASCADE,
      filename TEXT,
      asset_type TEXT,
      asset_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE analytics_uploads ADD COLUMN IF NOT EXISTS asset_type TEXT;
  `);
  if (operationEncryptionKey) {
    const legacyOperations = await pool.query("SELECT operation_id, api_key FROM asset_operations WHERE api_key NOT LIKE 'enc:v1:%'");
    for (const operation of legacyOperations.rows) {
      await pool.query("UPDATE asset_operations SET api_key=$1 WHERE operation_id=$2", [encryptOperationKey(operation.api_key), operation.operation_id]);
    }
  }
  await cleanupExpiredOperations();
  log("DATABASE: schema ready");
}

async function getSession(req) {
  if (!pool) return null;
  const token = parseCookies(req).zane_session;
  if (!token) return null;
  const result = await pool.query(`
    SELECT u.discord_id, u.username, u.avatar, u.is_premium, u.auth_provider, u.linked_discord_id,
      COALESCE((SELECT file_count FROM daily_upload_usage d WHERE d.discord_id = u.discord_id AND d.usage_date = CURRENT_DATE), 0) AS used_today
    FROM discord_sessions s JOIN discord_users u ON u.discord_id = s.discord_id
    WHERE s.token = $1 AND s.expires_at > NOW()
  `, [token]);
  const user = result.rows[0] || null;
  if (user) await refreshPremiumStatus(user);
  return user;
}

function ipHash(req) {
  return createHash("sha256").update(`${FRONTEND_URL}:${clientIp(req)}`).digest("hex");
}

async function getIpRemaining(ipHashValue) {
  const result = await pool.query("SELECT file_count FROM daily_ip_upload_usage WHERE ip_hash=$1 AND usage_date=CURRENT_DATE", [ipHashValue]);
  return Math.max(0, FREE_DAILY_FILES - Number(result.rows[0]?.file_count || 0));
}

async function reserveQuota(user, fileCount, ipHashValue) {
  if (user.is_premium) return {allowed:true, remaining:null};
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const discord = await client.query(`
      INSERT INTO daily_upload_usage (discord_id, usage_date, file_count)
      VALUES ($1, CURRENT_DATE, $2)
      ON CONFLICT (discord_id, usage_date) DO UPDATE
        SET file_count = daily_upload_usage.file_count + EXCLUDED.file_count
        WHERE daily_upload_usage.file_count + EXCLUDED.file_count <= $3
      RETURNING file_count, usage_date
    `, [user.discord_id, fileCount, FREE_DAILY_FILES]);
    if (!discord.rowCount) {
      await client.query("ROLLBACK");
      return {allowed:false, remaining:Math.max(0, FREE_DAILY_FILES - Number(user.used_today)), reason:"discord"};
    }
    const ip = await client.query(`
      INSERT INTO daily_ip_upload_usage (ip_hash, usage_date, file_count)
      VALUES ($1, CURRENT_DATE, $2)
      ON CONFLICT (ip_hash, usage_date) DO UPDATE
        SET file_count = daily_ip_upload_usage.file_count + EXCLUDED.file_count
        WHERE daily_ip_upload_usage.file_count + EXCLUDED.file_count <= $3
      RETURNING file_count, usage_date
    `, [ipHashValue, fileCount, FREE_DAILY_FILES]);
    if (!ip.rowCount) {
      await client.query("ROLLBACK");
      return {allowed:false, remaining:Math.max(0, FREE_DAILY_FILES - Number((await client.query("SELECT file_count FROM daily_ip_upload_usage WHERE ip_hash=$1 AND usage_date=CURRENT_DATE", [ipHashValue])).rows[0]?.file_count || 0)), reason:"ip"};
    }
    await client.query("COMMIT");
    return {allowed:true, remaining:Math.min(FREE_DAILY_FILES - Number(discord.rows[0].file_count), FREE_DAILY_FILES - Number(ip.rows[0].file_count)), quotaDate:discord.rows[0].usage_date};
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function releaseQuota(user, fileCount, ipHashValue, quotaDate) {
  if (user.is_premium) return;
  const usageDate = quotaDate || new Date().toISOString().slice(0,10);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`UPDATE daily_upload_usage SET file_count = GREATEST(0, file_count - $2)
      WHERE discord_id=$1 AND usage_date=$3`, [user.discord_id, fileCount, usageDate]);
    await client.query(`UPDATE daily_ip_upload_usage SET file_count = GREATEST(0, file_count - $2)
      WHERE ip_hash=$1 AND usage_date=$3`, [ipHashValue, fileCount, usageDate]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function canUseBindings(user, apiKey, creatorType, creatorId) {
  const credentialHash = createHash("sha256").update(apiKey).digest("hex");
  const credential = await pool.query("SELECT discord_id FROM credential_bindings WHERE credential_hash=$1", [credentialHash]);
  const creator = await pool.query("SELECT discord_id FROM creator_bindings WHERE creator_type=$1 AND creator_id=$2", [creatorType, creatorId]);
  return (!credential.rowCount || credential.rows[0].discord_id === user.discord_id)
    && (!creator.rowCount || creator.rows[0].discord_id === user.discord_id);
}

async function claimBindings(user, apiKey, creatorType, creatorId) {
  const credentialHash = createHash("sha256").update(apiKey).digest("hex");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", [credentialHash, `${creatorType}:${creatorId}`]);
    const credential = await client.query("SELECT discord_id FROM credential_bindings WHERE credential_hash=$1", [credentialHash]);
    const creator = await client.query("SELECT discord_id FROM creator_bindings WHERE creator_type=$1 AND creator_id=$2", [creatorType, creatorId]);
    if ((credential.rowCount && credential.rows[0].discord_id !== user.discord_id) || (creator.rowCount && creator.rows[0].discord_id !== user.discord_id)) {
      await client.query("ROLLBACK");
      return {allowed:false, credentialHash, claimedCredential:false, claimedCreator:false};
    }
    const claimedCredential = !credential.rowCount;
    const claimedCreator = !creator.rowCount;
    if (claimedCredential) await client.query(`INSERT INTO credential_bindings (credential_hash, discord_id, creator_type, creator_id) VALUES ($1,$2,$3,$4)`, [credentialHash, user.discord_id, creatorType, creatorId]);
    if (claimedCreator) await client.query(`INSERT INTO creator_bindings (creator_type, creator_id, discord_id) VALUES ($1,$2,$3)`, [creatorType, creatorId, user.discord_id]);
    await client.query("COMMIT");
    return {allowed:true, credentialHash, claimedCredential, claimedCreator};
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function releaseBindingClaims(user, claims, creatorType, creatorId) {
  if (!claims?.allowed) return;
  if (claims.claimedCredential) await pool.query("DELETE FROM credential_bindings WHERE credential_hash=$1 AND discord_id=$2", [claims.credentialHash, user.discord_id]);
  if (claims.claimedCreator) await pool.query("DELETE FROM creator_bindings WHERE creator_type=$1 AND creator_id=$2 AND discord_id=$3", [creatorType, creatorId, user.discord_id]);
}

async function saveOAuthState(state, expiresAt, linkUserId = null, metadata = {}) {
  await pool.query("INSERT INTO oauth_states (state, expires_at, link_user_id, oauth_provider, code_verifier, access_mode, group_id) VALUES ($1,$2,$3,$4,$5,$6,$7)", [state, new Date(expiresAt), linkUserId, metadata.provider || null, metadata.codeVerifier || null, metadata.accessMode || null, metadata.groupId || null]);
}

async function consumeOAuthState(state) {
  const result = await pool.query("DELETE FROM oauth_states WHERE state=$1 AND expires_at > NOW() RETURNING state, link_user_id, oauth_provider, code_verifier, access_mode, group_id", [state]);
  return result.rows[0] || null;
}

async function getRobloxConnection(discordId) {
  if (!pool || !discordId) return null;
  const result = await pool.query("SELECT roblox_user_id, username, display_name, profile_url, avatar_url, scope, access_mode, group_id, connected_at, updated_at FROM roblox_connections WHERE discord_id=$1", [discordId]);
  return result.rows[0] || null;
}

function credentialSummary(row) {
  return {credentialId:row.credential_id, label:row.label, creatorType:row.creator_type, creatorId:row.creator_id, expiresAt:row.expires_at, createdAt:row.created_at, lastUsedAt:row.last_used_at, expired:Boolean(row.expires_at && new Date(row.expires_at).getTime() <= Date.now())};
}

async function getSavedCredentials(discordId) {
  const result = await pool.query("SELECT credential_id, label, creator_type, creator_id, expires_at, created_at, last_used_at FROM saved_credentials WHERE discord_id=$1 ORDER BY updated_at DESC", [discordId]);
  return result.rows.map(credentialSummary);
}

async function getSavedCredential(discordId, credentialId) {
  const result = await pool.query("SELECT * FROM saved_credentials WHERE credential_id=$1 AND discord_id=$2", [credentialId, discordId]);
  const row = result.rows[0];
  if (!row) throw Object.assign(new Error("Saved API key was not found."), {status:404});
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) throw Object.assign(new Error("Saved API key has expired."), {status:400});
  return row;
}

async function saveOperation(operationId, operationToken, apiKey, discordId, expiresAt, metadata = {}) {
  await pool.query(`INSERT INTO asset_operations (operation_id, operation_token, api_key, discord_id, filename, size_bytes, asset_type, creator_type, creator_id, expires_at, quota_reserved, quota_ip_hash, quota_date)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, [operationId, operationToken, encryptOperationKey(apiKey), discordId, metadata.filename || null, metadata.sizeBytes || null, metadata.assetType || null, metadata.creatorType || null, metadata.creatorId || null, new Date(expiresAt), Boolean(metadata.quotaReserved), metadata.quotaIpHash || null, metadata.quotaDate || new Date()]);
}

async function saveUploadIntent(intentId, apiKey, discordId, expiresAt, metadata = {}) {
  await pool.query(`INSERT INTO upload_intents (intent_id, api_key, discord_id, filename, size_bytes, asset_type, creator_type, creator_id, expires_at, quota_reserved, quota_ip_hash, quota_date, credential_hash, claimed_credential, claimed_creator)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, [intentId, encryptOperationKey(apiKey), discordId, metadata.filename || null, metadata.sizeBytes || null, metadata.assetType || null, metadata.creatorType || null, metadata.creatorId || null, new Date(expiresAt), Boolean(metadata.quotaReserved), metadata.quotaIpHash || null, metadata.quotaDate || new Date(), metadata.credentialHash || null, Boolean(metadata.claimedCredential), Boolean(metadata.claimedCreator)]);
}

async function updateUploadIntent(intentId, operationId, operationToken, expiresAt) {
  await pool.query("UPDATE upload_intents SET operation_id=$2, operation_token=$3, expires_at=$4, updated_at=NOW() WHERE intent_id=$1", [intentId, operationId, operationToken, new Date(expiresAt)]);
}

async function updateUploadIntentWithRetry(...args) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await updateUploadIntent(...args);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < 2) await sleep(250 * (attempt + 1));
    }
  }
  throw lastError;
}

async function deleteUploadIntent(intentId) {
  await pool.query("DELETE FROM upload_intents WHERE intent_id=$1", [intentId]);
}

async function releaseUploadIntentQuota(intent) {
  if (!intent?.quota_reserved || !intent.quota_ip_hash || !intent.quota_date) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const claimed = await client.query("UPDATE upload_intents SET quota_reserved=FALSE WHERE intent_id=$1 AND quota_reserved=TRUE RETURNING intent_id", [intent.intent_id]);
    if (claimed.rowCount) {
      await client.query("UPDATE daily_upload_usage SET file_count=GREATEST(0, file_count - 1) WHERE discord_id=$1 AND usage_date=$2", [intent.discord_id, intent.quota_date]);
      await client.query("UPDATE daily_ip_upload_usage SET file_count=GREATEST(0, file_count - 1) WHERE ip_hash=$1 AND usage_date=$2", [intent.quota_ip_hash, intent.quota_date]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function recoverUploadIntents() {
  if (!pool) return;
  const result = await pool.query(`SELECT intent_id, operation_id, operation_token, api_key, discord_id, filename, size_bytes, asset_type, creator_type, creator_id, expires_at, quota_reserved, quota_ip_hash, quota_date
    FROM upload_intents WHERE operation_id IS NOT NULL AND operation_token IS NOT NULL AND expires_at > NOW() ORDER BY created_at ASC`);
  for (const intent of result.rows) {
    try {
      await saveOperation(intent.operation_id, intent.operation_token, decryptOperationKey(intent.api_key), intent.discord_id, new Date(intent.expires_at).getTime(), {
        filename:intent.filename, sizeBytes:intent.size_bytes, assetType:intent.asset_type, creatorType:intent.creator_type, creatorId:intent.creator_id,
        quotaReserved:intent.quota_reserved, quotaIpHash:intent.quota_ip_hash, quotaDate:intent.quota_date
      });
      await deleteUploadIntent(intent.intent_id);
      log("RECOVERY: upload intent promoted", {intent:intent.intent_id, operation:intent.operation_id});
    } catch (error) {
      if (error.code === "23505") {
        await deleteUploadIntent(intent.intent_id);
        log("RECOVERY: upload intent matched existing operation", {intent:intent.intent_id, operation:intent.operation_id});
      } else {
        log("RECOVERY: upload intent still pending", {intent:intent.intent_id, operation:intent.operation_id, error:error.message});
      }
    }
  }
}

async function cleanupExpiredUploadIntents() {
  await pool.query("DELETE FROM upload_intents i USING asset_operations o WHERE i.operation_id=o.operation_id");
  const result = await pool.query(`SELECT i.intent_id, i.operation_id, i.discord_id, i.filename, i.creator_type, i.creator_id, i.quota_reserved, i.quota_ip_hash, i.quota_date, i.credential_hash, i.claimed_credential, i.claimed_creator
    FROM upload_intents i LEFT JOIN asset_operations o ON o.operation_id=i.operation_id WHERE i.expires_at <= NOW() AND o.operation_id IS NULL`);
  for (const intent of result.rows) {
    await releaseUploadIntentQuota(intent);
    await releaseBindingClaims({discord_id:intent.discord_id}, {allowed:true, credentialHash:intent.credential_hash, claimedCredential:intent.claimed_credential, claimedCreator:intent.claimed_creator}, intent.creator_type, intent.creator_id);
    await deleteUploadIntent(intent.intent_id);
    log("CLEANUP: expired upload intent removed", {intent:intent.intent_id, operation:intent.operation_id || "unlinked"});
  }
}

async function saveOperationWithRetry(...args) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await saveOperation(...args);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < 2) await sleep(250 * (attempt + 1));
    }
  }
  throw lastError;
}

async function getStoredOperation(operationId) {
  const result = await pool.query("SELECT operation_id, operation_token, api_key, discord_id, filename, size_bytes, asset_type, creator_type, creator_id, expires_at, quota_reserved, quota_ip_hash, quota_date FROM asset_operations WHERE operation_id=$1", [operationId]);
  const operation = result.rows[0];
  if (!operation) return null;
  return {...operation, api_key:decryptOperationKey(operation.api_key)};
}

async function getActiveOperations(discordId) {
  const result = await pool.query(`SELECT operation_id, operation_token, filename, size_bytes, asset_type, creator_type, creator_id, expires_at
    FROM asset_operations WHERE discord_id=$1 AND expires_at > NOW() ORDER BY expires_at ASC`, [discordId]);
  return result.rows;
}

async function deleteOperation(operationId) {
  await pool.query("DELETE FROM asset_operations WHERE operation_id=$1", [operationId]);
}

async function withOperationLock(operationId, callback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [operationId]);
    const result = await callback();
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function releaseStoredQuota(operation) {
  if (!operation?.quota_reserved || !operation.quota_ip_hash || !operation.quota_date) return;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const claimed = await client.query("UPDATE asset_operations SET quota_reserved=FALSE WHERE operation_id=$1 AND quota_reserved=TRUE RETURNING operation_id", [operation.operation_id]);
    if (claimed.rowCount) {
      await client.query("UPDATE daily_upload_usage SET file_count=GREATEST(0, file_count - 1) WHERE discord_id=$1 AND usage_date=$2", [operation.discord_id, operation.quota_date]);
      await client.query("UPDATE daily_ip_upload_usage SET file_count=GREATEST(0, file_count - 1) WHERE ip_hash=$1 AND usage_date=$2", [operation.quota_ip_hash, operation.quota_date]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function cleanupExpiredOperations() {
  if (!pool) return;
  await recoverUploadIntents();
  await cleanupExpiredUploadIntents();
  const expired = await pool.query("SELECT operation_id, discord_id, quota_reserved, quota_ip_hash, quota_date FROM asset_operations WHERE expires_at <= NOW()");
  for (const operation of expired.rows) {
    await releaseStoredQuota(operation);
    await deleteOperation(operation.operation_id);
  }
  await pool.query("DELETE FROM oauth_states WHERE expires_at <= NOW()");
  await pool.query("DELETE FROM discord_sessions WHERE expires_at <= NOW()");
}

async function recordVisit(req) {
  if (!pool) return;
  await pool.query(`INSERT INTO analytics_visits (ip_hash, visit_date) VALUES ($1, CURRENT_DATE) ON CONFLICT DO NOTHING`, [ipHash(req)]);
}

async function recordPublishedAsset(operationId, discordId, filename, assetType, assetId) {
  await pool.query(`INSERT INTO analytics_uploads (operation_id, discord_id, filename, asset_type, asset_id)
    VALUES ($1,$2,$3,$4,$5) ON CONFLICT (operation_id) DO NOTHING`, [operationId, discordId, filename, assetType, assetId]);
}

async function getUserStats(discordId) {
  const result = await pool.query(`SELECT
    COUNT(*)::INTEGER AS total,
    COUNT(*) FILTER (WHERE asset_type='Audio')::INTEGER AS audio,
    COUNT(*) FILTER (WHERE asset_type='Animation')::INTEGER AS animation
    FROM analytics_uploads WHERE discord_id=$1`, [discordId]);
  const row = result.rows[0] || {};
  return {total:Number(row.total || 0), audio:Number(row.audio || 0), animation:Number(row.animation || 0)};
}

async function getSiteStats(req) {
  await recordVisit(req);
  const result = await pool.query(`SELECT
    (SELECT COUNT(*)::INTEGER FROM discord_users) AS total_users,
    (SELECT COUNT(*)::INTEGER FROM analytics_uploads) AS total_uploads,
    (SELECT COUNT(*)::INTEGER FROM analytics_visits) AS total_visits`);
  const row = result.rows[0] || {};
  return {totalUsers:Number(row.total_users || 0), totalUploads:Number(row.total_uploads || 0), totalVisits:Number(row.total_visits || 0)};
}

function clientIp(req) {
  const forwarded = TRUST_PROXY ? String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() : "";
  return forwarded || String(req.socket?.remoteAddress || "unknown");
}

async function rateLimit(req, routeKey, maxRequests, windowSeconds) {
  if (!pool) return {allowed:true, remaining:maxRequests};
  const ipHash = createHash("sha256").update(`${FRONTEND_URL}:${clientIp(req)}`).digest("hex");
  const windowStart = new Date(Math.floor(Date.now() / (windowSeconds * 1000)) * windowSeconds * 1000);
  const result = await pool.query(`
    INSERT INTO ip_rate_limits (ip_hash, route_key, window_start, request_count)
    VALUES ($1,$2,$3,1)
    ON CONFLICT (ip_hash, route_key, window_start) DO UPDATE
      SET request_count = ip_rate_limits.request_count + 1
      WHERE ip_rate_limits.request_count < $4
    RETURNING request_count
  `, [ipHash, routeKey, windowStart, maxRequests]);
  if (!result.rowCount) return {allowed:false, remaining:0};
  await pool.query("DELETE FROM ip_rate_limits WHERE window_start < NOW() - INTERVAL '1 day'");
  return {allowed:true, remaining:Math.max(0, maxRequests - Number(result.rows[0].request_count))};
}

async function discordRequest(url, options = {}) {
  const response = await fetchWithTimeout(url, options);
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = {raw:text}; }
  if (!response.ok) throw new Error(data.message || `Discord returned HTTP ${response.status}`);
  return data;
}

async function getDiscordMember(discordId) {
  return discordRequest(`https://discord.com/api/v10/guilds/${encodeURIComponent(DISCORD_GUILD_ID)}/members/${encodeURIComponent(discordId)}`, {headers:{Authorization:`Bot ${DISCORD_BOT_TOKEN}`} });
}

async function refreshPremiumStatus(user) {
  const premiumDiscordId = user.auth_provider === "discord" ? user.discord_id : user.linked_discord_id;
  if (!premiumDiscordId) {
    user.is_premium = false;
    return;
  }
  if (!authConfigured) {
    user.is_premium = false;
    return;
  }
  const cached = premiumCache.get(user.discord_id);
  if (cached && cached.expiresAt > Date.now()) {
    user.is_premium = cached.isPremium;
    return;
  }
  try {
    const member = await getDiscordMember(premiumDiscordId);
    const isPremium = member.roles?.includes(DISCORD_PREMIUM_ROLE_ID) || false;
    user.is_premium = isPremium;
    premiumCache.set(user.discord_id, {isPremium, expiresAt:Date.now() + PREMIUM_CACHE_MS});
    await pool.query("UPDATE discord_users SET is_premium=$1, updated_at=NOW() WHERE discord_id=$2", [isPremium, user.discord_id]);
  } catch (error) {
    user.is_premium = false;
    premiumCache.set(user.discord_id, {isPremium:false, expiresAt:Date.now() + 10 * 1000});
    log("PREMIUM CHECK: denying premium after Discord request failed", {discordId:user.discord_id, error:error.message});
  }
}

async function initializeDatabaseWithRetry() {
  if (!pool) return false;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      await initializeDatabase();
      return true;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] DATABASE ERROR attempt=${attempt}/5: ${error.stack || error.message}`);
      if (attempt < 5) await sleep(Math.min(30000, 1000 * 2 ** (attempt - 1)));
    }
  }
  return false;
}

let databaseReady = initializeDatabaseWithRetry();
let databaseRetryInFlight = null;

async function ensureDatabaseReady() {
  if (await databaseReady) return true;
  if (!databaseRetryInFlight) {
    databaseRetryInFlight = initializeDatabaseWithRetry().then(result => {
      databaseReady = Promise.resolve(result);
      return result;
    }).finally(() => { databaseRetryInFlight = null; });
  }
  return databaseRetryInFlight;
}

async function requireDatabase(res) {
  if (await ensureDatabaseReady()) return true;
  send(res,503,{error:"Database is temporarily unavailable. Please try again shortly."});
  return false;
}

setInterval(() => cleanupExpiredOperations().catch(error => log("CLEANUP: failed", {error:error.message})), 5 * 60 * 1000).unref?.();

const TYPES = {
  audio: {
    assetType: "Audio",
    exts: [".mp3", ".ogg", ".wav", ".flac"],
    mimes: new Map([[".mp3","audio/mpeg"],[".ogg","audio/ogg"],[".wav","audio/wav"],[".flac","audio/flac"]])
  },
  animation: {
    assetType: "Animation",
    exts: [".rbxm"],
    mimes: new Map([[".rbxm","model/x-rbxm"]])
  }
};

function send(res, code, data, type="application/json") {
  res.writeHead(code, {
    "Content-Type": type,
    "Cache-Control":"no-store",
    "X-Request-Id":res.requestId || "unknown",
    "X-Content-Type-Options":"nosniff",
    "X-Frame-Options":"DENY",
    "Referrer-Policy":"no-referrer",
    "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'",
    "Access-Control-Allow-Origin":res.corsOrigin || FRONTEND_URL,
    "Access-Control-Allow-Credentials":"true",
    "Access-Control-Allow-Methods":"GET,POST,DELETE,OPTIONS",
    "Access-Control-Allow-Headers":"Content-Type,X-Operation-Token"
  });
  res.end(type === "application/json" ? JSON.stringify(data) : data);
}
async function readRequestJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw Object.assign(new Error("Request body is too large."), {status:413});
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); }
  catch { throw Object.assign(new Error("Request body must be valid JSON."), {status:400}); }
}
function parseMultipartRequest(req, maxBatchSize, maxBatchFiles, maxFileSize) {
  if (activeBodyReads >= MAX_CONCURRENT_BODY_READS) {
    const error = new Error("Upload service is busy. Please try again shortly.");
    error.status = 503;
    req.resume();
    return Promise.reject(error);
  }
  activeBodyReads++;
  return new Promise((resolve,reject)=>{
    const fields = {};
    const files = [];
    const fileIds = [];
    let totalSize = 0;
    let settled = false;
    const fail = error => {
      if (settled) return;
      settled = true;
      error.status ||= error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      req.unpipe(parser);
      req.resume();
      reject(error);
    };
    const parserLimits = {fileSize:maxFileSize, fieldSize:1024 * 1024};
    if (Number.isFinite(maxBatchFiles)) parserLimits.files = maxBatchFiles;
    const parser = Busboy({headers:req.headers, limits:parserLimits});
    parser.on("field", (name, value) => {
      if (name === "fileId") fileIds.push(value);
      else fields[name] = value;
    });
    parser.on("file", (name, stream, info) => {
      const chunks = [];
      stream.on("data", chunk => {
        if (settled) return;
        totalSize += chunk.length;
        if (totalSize > maxBatchSize) fail(Object.assign(new Error("Payload too large"), {status:413}));
        else chunks.push(chunk);
      });
      stream.on("limit", () => fail(Object.assign(new Error(`${info.filename} exceeds the ${Math.round(maxFileSize / 1024 / 1024)} MB limit.`), {status:413})));
      stream.on("error", fail);
      stream.on("end", () => { if (!settled) files.push({name, fileId:fileIds[files.length] || "", filename:info.filename, contentType:info.mimeType, content:Buffer.concat(chunks), headers:info}); });
    });
    if (Number.isFinite(maxBatchFiles)) parser.on("filesLimit", () => fail(Object.assign(new Error(`You can upload up to ${maxBatchFiles} files at once.`), {status:413})));
    parser.on("error", fail);
    parser.on("finish", () => { if (!settled) { settled = true; resolve({fields, files}); } });
    req.setTimeout(120000, () => fail(Object.assign(new Error("Upload request timed out."), {status:408})));
    req.on("error", fail);
    req.pipe(parser);
  }).finally(() => { activeBodyReads--; });
}
const CONVERSION_FORMATS = {
  mp3: {extension:".mp3", mime:"audio/mpeg", codec:["-c:a", "libmp3lame"]},
  wav: {extension:".wav", mime:"audio/wav", codec:["-c:a", "pcm_s16le"]},
  ogg: {extension:".ogg", mime:"audio/ogg", codec:["-c:a", "libvorbis"]},
  flac: {extension:".flac", mime:"audio/flac", codec:["-c:a", "flac"]}
};
const PREVIEW_PROVIDERS = [
  {name:"YouTube", hosts:["youtube.com", "www.youtube.com", "youtu.be", "m.youtube.com"], endpoint:"https://www.youtube.com/oembed?format=json&url="},
  {name:"Spotify", hosts:["open.spotify.com"], endpoint:"https://open.spotify.com/oembed?url="},
  {name:"SoundCloud", hosts:["soundcloud.com", "www.soundcloud.com", "on.soundcloud.com"], endpoint:"https://soundcloud.com/oembed?format=json&url="}
];
function getPreviewProvider(value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  if (!(["http:", "https:"].includes(url.protocol))) return null;
  const hostname = url.hostname.toLowerCase();
  return PREVIEW_PROVIDERS.find(provider => provider.hosts.includes(hostname)) ? {url, provider:PREVIEW_PROVIDERS.find(provider => provider.hosts.includes(hostname))} : null;
}
async function previewAudioLink(value) {
  const match = getPreviewProvider(value);
  if (!match) throw new Error("Only Spotify, YouTube, and SoundCloud links are supported.");
  let data = {};
  try {
    const response = await fetchWithTimeout(`${match.provider.endpoint}${encodeURIComponent(match.url.href)}`, {headers:{Accept:"application/json"}});
    if (response.ok) data = await response.json();
  } catch (error) {
    log("PREVIEW: provider metadata unavailable", {provider:match.provider.name, error:error.message});
  }
  return {provider:match.provider.name, url:match.url.href, title:String(data.title || "Untitled audio").slice(0,200), author:String(data.author_name || match.provider.name).slice(0,120), thumbnail:data.thumbnail_url || "", type:data.type || "music"};
}
function conversionNumber(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(maximum, Math.max(minimum, number)) : fallback;
}
function atempoFilters(speed) {
  const filters = [];
  let remaining = speed;
  while (remaining > 2) { filters.push("atempo=2"); remaining /= 2; }
  while (remaining < 0.5) { filters.push("atempo=0.5"); remaining /= 0.5; }
  if (Math.abs(remaining - 1) > 0.001) filters.push(`atempo=${remaining}`);
  return filters;
}
function runAudioConversion(input, output, options) {
  return new Promise((resolve, reject) => {
    const args = ["-hide_banner", "-loglevel", "error", "-y"];
    if (options.start > 0) args.push("-ss", String(options.start));
    args.push("-i", input);
    if (options.duration !== null) args.push("-t", String(options.duration));
    const filters = [];
    filters.push(...atempoFilters(options.speed));
    const gain = options.volume * (10 ** (options.amplifyDb / 20));
    if (gain !== 1) filters.push(`volume=${gain}`);
    if (options.fadeIn > 0) filters.push(`afade=t=in:st=0:d=${options.fadeIn}`);
    if (options.fadeOut > 0) {
      filters.push(options.duration === null
        ? `areverse,afade=t=in:st=0:d=${options.fadeOut},areverse`
        : `afade=t=out:st=${Math.max(0, options.duration - options.fadeOut)}:d=${options.fadeOut}`);
    }
    if (filters.length) args.push("-af", filters.join(","));
    args.push("-ar", String(options.sampleRate), "-ac", String(options.channels));
    args.push(...options.format.codec);
    if (options.format.extension === ".mp3") args.push("-b:a", `${options.bitrate}k`);
    if (options.title) args.push("-metadata", `title=${options.title}`);
    if (options.artist) args.push("-metadata", `artist=${options.artist}`);
    if (options.album) args.push("-metadata", `album=${options.album}`);
    args.push(output);
    const process = spawn(ffmpegPath, args, {windowsHide:true});
    let errorOutput = "";
    process.stderr.on("data", chunk => { errorOutput += chunk.toString(); });
    process.on("error", reject);
    process.on("close", code => code === 0 ? resolve() : reject(new Error(errorOutput.trim() || "Audio conversion failed.")));
  });
}
async function convertAudioFile(file, fields) {
  if (!ffmpegPath) throw new Error("Audio converter is unavailable on this server.");
  const format = CONVERSION_FORMATS[String(fields.format || "mp3").toLowerCase()];
  if (!format) throw new Error("format must be mp3, wav, ogg, or flac.");
  const extension = path.extname(file.filename).toLowerCase();
  if (!TYPES.audio.exts.includes(extension) || !hasValidMime(extension, file.contentType, file.content)) throw new Error("The input is not a supported audio file.");
  const start = conversionNumber(fields.start, 0, 0, 24 * 60 * 60);
  const end = String(fields.end || "").trim() ? conversionNumber(fields.end, start, start, 24 * 60 * 60) : null;
  const duration = end === null ? null : end - start;
  const fadeIn = conversionNumber(fields.fadeIn, 0, 0, duration === null ? 60 : duration);
  const fadeOut = conversionNumber(fields.fadeOut, 0, 0, duration === null ? 60 : duration);
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "zane-convert-"));
  const inputPath = path.join(tempRoot, `input${extension}`);
  const outputPath = path.join(tempRoot, `output${format.extension}`);
  const options = {format, start, duration, fadeIn, fadeOut, speed:conversionNumber(fields.speed, 1, .25, 4), amplifyDb:conversionNumber(fields.amplifyDb, 0, -30, 12), volume:conversionNumber(fields.volume, 1, 0, 3), sampleRate:conversionNumber(fields.sampleRate, 44100, 8000, 192000), channels:conversionNumber(fields.channels, 2, 1, 2), bitrate:conversionNumber(fields.bitrate, 192, 32, 320), title:String(fields.title || "").slice(0,100), artist:String(fields.artist || "").slice(0,100), album:String(fields.album || "").slice(0,100)};
  try {
    await fs.promises.writeFile(inputPath, file.content);
    await runAudioConversion(inputPath, outputPath, options);
    return {content:await fs.promises.readFile(outputPath), format, filename:`${normalizeAssetName(fields.filename || file.filename)}${format.extension}`};
  } finally {
    await fs.promises.rm(tempRoot, {recursive:true, force:true});
  }
}
function hasValidFileSignature(extension, content) {
  const ascii = offset => content.toString("ascii", offset, offset + 4);
  if (extension === ".mp3") return content.subarray(0, 3).toString("ascii") === "ID3" || (content.length >= 2 && content[0] === 0xff && (content[1] & 0xe0) === 0xe0);
  if (extension === ".ogg") return ascii(0) === "OggS";
  if (extension === ".wav") return ascii(0) === "RIFF" && content.toString("ascii", 8, 12) === "WAVE";
  if (extension === ".flac") return ascii(0) === "fLaC";
  if (extension === ".rbxm") return ascii(0) === "RBXM" || content.toString("utf8", 0, Math.min(content.length, 512)).includes("<roblox");
  return false;
}
function hasValidMime(extension, contentType, content) {
  const expected = TYPES.audio.mimes.get(extension) || TYPES.animation.mimes.get(extension);
  const declared = String(contentType || "").toLowerCase().split(";", 1)[0];
  const generic = !declared || declared === "application/octet-stream" || declared === "binary/octet-stream";
  return (generic || declared === expected) && hasValidFileSignature(extension, content);
}
function normalizeAssetName(filename) {
  return String(filename || "Asset").replace(/\.[^.]+$/, "").replace(/_\d+$/, "").trim().slice(0,100) || "Asset";
}
async function createAsset({assetType, displayName, description, filename, contentType, fileContent, apiKey, creatorType, creatorId}) {
  if (!apiKey) throw new Error("Roblox API key is required.");
  if (!creatorId) throw new Error("Creator ID is required.");
  const creator = creatorType === "group" ? {groupId: creatorId} : {userId: creatorId};
  log("PROCESSING: sending asset to Roblox", {assetType, filename, creatorType, creatorId});
  const form = new FormData();
  form.append("request", JSON.stringify({assetType, displayName, description, creationContext:{creator}}));
  form.append("fileContent", new Blob([fileContent], {type:contentType}), filename);
  const r = await fetchWithTimeout("https://apis.roblox.com/assets/v1/assets", {
    method:"POST",
    headers: {"x-api-key": apiKey},
    body: form
  });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = {raw:text}; }
  if (!r.ok) {
    const error = new Error(data.message || data.error || `Roblox API returned HTTP ${r.status}`);
    error.status = r.status;
    if (r.status === 401) error.message = "Roblox rejected the API key. Check that it is valid and has Assets permission.";
    if (r.status === 403) error.message = `Roblox rejected this API key for the selected ${creatorType === "group" ? "group" : "user"}. Check Assets Read & Write permission and creator access.`;
    throw error;
  }
  log("SUCCESS: Roblox accepted asset", {assetType, filename, operation: data.path || "unknown"});
  return data;
}
async function getOperation(operationId, apiKey) {
  if (!apiKey) throw new Error("Upload credentials are no longer available. Please upload again.");
  const r = await fetchWithTimeout(`https://apis.roblox.com/assets/v1/operations/${encodeURIComponent(operationId)}`, {
    headers: {"x-api-key": apiKey}
  });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data={raw:text}; }
  if (!r.ok) throw new Error(data.message || data.error || `Roblox API returned HTTP ${r.status}`);
  return data;
}

async function cancelOperation(operationId, apiKey) {
  if (!apiKey) throw new Error("Upload credentials are no longer available. Please upload again.");
  const response = await fetchWithTimeout(`https://apis.roblox.com/assets/v1/operations/${encodeURIComponent(operationId)}`, {
    method:"DELETE",
    headers:{"x-api-key":apiKey}
  });
  if (response.ok || response.status === 204) return;
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = {raw:text}; }
  const error = new Error(data.message || data.error || `Roblox returned HTTP ${response.status} while cancelling the operation.`);
  error.status = response.status === 404 || response.status === 405 ? 409 : response.status;
  throw error;
}

async function validateCreator(creatorType, creatorId) {
  const cacheKey = `${creatorType}:${creatorId}`;
  const cached = creatorValidationCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.promise;
  const url = creatorType === "group"
    ? `https://groups.roblox.com/v2/groups?groupIds=${encodeURIComponent(creatorId)}`
    : `https://users.roblox.com/v1/users/${encodeURIComponent(creatorId)}`;
  const promise = (async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      const response = await fetchWithTimeout(url);
      if (response.status === 429) {
        if (attempt === 2) throw new Error("Roblox rate-limited creator verification. Please wait a moment and try again.");
        const retryAfter = Number(response.headers.get("retry-after"));
        await sleep(Number.isFinite(retryAfter) ? Math.max(1000, retryAfter * 1000) : 1000 * (attempt + 1));
        continue;
      }
      if (response.status === 404 || response.status === 400) throw new Error(`${creatorType === "group" ? "Group" : "User"} ID ${creatorId} was not found.`);
      if (!response.ok) throw new Error(`Could not verify ${creatorType} ID. Roblox returned HTTP ${response.status}.`);
      const data = await response.json();
      if (creatorType === "group" && !data.data?.some(group => String(group.id) === creatorId)) throw new Error(`${creatorId} is not a valid Group ID. Use the group's ID, not a profile ID.`);
      return data;
    }
  })();
  creatorValidationCache.set(cacheKey, {promise, expiresAt:Date.now() + 60 * 1000});
  try {
    return await promise;
  } catch (error) {
    creatorValidationCache.delete(cacheKey);
    throw error;
  }
}

export async function handler(req,res) {
  try {
    res.requestId = req.headers["x-request-id"] || randomUUID();
    res.corsOrigin = validRequestOrigin(req) ? (req.headers.origin || FRONTEND_URL) : FRONTEND_URL;
    let requestAborted = false;
    req.once("aborted", () => { requestAborted = true; });
    const requestUrl = new URL(req.url || "/", "https://placeholder.local");

    if (req.method === "OPTIONS") return send(res,204,"");

    if (req.method === "GET" && requestUrl.pathname === "/health") {
      return send(res,200,{status:"ok", service:"zanexyuu-api", requestId:res.requestId});
    }
    if (req.method === "GET" && requestUrl.pathname === "/ready") {
      const database = await ensureDatabaseReady();
      const ready = database && Boolean(ffmpegPath);
      return send(res,ready ? 200 : 503,{status:ready ? "ready" : "not_ready", checks:{database, ffmpeg:Boolean(ffmpegPath)}, requestId:res.requestId});
    }
    if (req.method === "GET" && requestUrl.pathname === "/") return redirect(res, `${FRONTEND_URL}/`);

    if (req.method === "GET" && requestUrl.pathname === "/auth/roblox/connect") {
      if (!robloxAuthConfigured) return redirect(res, `${FRONTEND_URL}/?auth=roblox-not-configured`);
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      if (!user) return redirect(res, `${FRONTEND_URL}/?auth=login-required`);
      const state = randomBytes(24).toString("hex");
      const codeVerifier = randomBytes(32).toString("base64url");
      const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
      const accessMode = String(requestUrl.searchParams.get("accessMode") || "account").toLowerCase();
      const groupId = String(requestUrl.searchParams.get("groupId") || "").trim();
      if (!["account", "group", "both"].includes(accessMode)) return redirect(res, `${FRONTEND_URL}/?auth=roblox-invalid-scope`);
      if ((accessMode === "group" || accessMode === "both") && (!/^\d+$/.test(groupId) || groupId === "0")) return redirect(res, `${FRONTEND_URL}/?auth=roblox-invalid-group`);
      if (accessMode !== "account") {
        try { await validateCreator("group", groupId); }
        catch { return redirect(res, `${FRONTEND_URL}/?auth=roblox-invalid-group`); }
      }
      await saveOAuthState(state, Date.now() + 10 * 60 * 1000, user.discord_id, {provider:"roblox", codeVerifier, accessMode, groupId:accessMode === "account" ? null : groupId});
      const redirectUri = ROBLOX_OAUTH_REDIRECT_URI || `${backendOrigin(req)}/auth/roblox/callback`;
      const params = new URLSearchParams({client_id:ROBLOX_OAUTH_CLIENT_ID, redirect_uri:redirectUri, scope:"openid profile", response_type:"code", state, code_challenge:codeChallenge, code_challenge_method:"S256"});
      return redirect(res, `https://apis.roblox.com/oauth/v1/authorize?${params}`, {"Set-Cookie":`zane_roblox_state=${encodeURIComponent(state)}; HttpOnly; Secure; SameSite=None; Path=/auth/roblox; Max-Age=600`});
    }
    if (req.method === "GET" && requestUrl.pathname === "/auth/roblox/callback") {
      if (!robloxAuthConfigured) return redirect(res, `${FRONTEND_URL}/?auth=roblox-not-configured`);
      if (!await requireDatabase(res)) return;
      const state = requestUrl.searchParams.get("state");
      const stateCookie = parseCookies(req).zane_roblox_state;
      const clearStateCookie = "zane_roblox_state=; HttpOnly; Secure; SameSite=None; Path=/auth/roblox; Max-Age=0";
      const oauthState = state && stateCookie && state === stateCookie ? await consumeOAuthState(state) : null;
      const user = oauthState?.link_user_id ? (await pool.query("SELECT discord_id FROM discord_users WHERE discord_id=$1", [oauthState.link_user_id])).rows[0] : null;
      if (!oauthState || oauthState.oauth_provider !== "roblox" || !oauthState.code_verifier || !user) return redirect(res, `${FRONTEND_URL}/?auth=roblox-invalid-state`, {"Set-Cookie":clearStateCookie});
      const code = requestUrl.searchParams.get("code");
      if (!code) return redirect(res, `${FRONTEND_URL}/?auth=roblox-failed`, {"Set-Cookie":clearStateCookie});
      const redirectUri = ROBLOX_OAUTH_REDIRECT_URI || `${backendOrigin(req)}/auth/roblox/callback`;
      const tokenResponse = await fetchWithTimeout("https://apis.roblox.com/oauth/v1/token", {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:new URLSearchParams({client_id:ROBLOX_OAUTH_CLIENT_ID, client_secret:ROBLOX_OAUTH_CLIENT_SECRET, grant_type:"authorization_code", code, redirect_uri:redirectUri, code_verifier:oauthState.code_verifier})});
      const tokenData = await tokenResponse.json();
      if (!tokenResponse.ok || !tokenData.access_token || !tokenData.refresh_token) return redirect(res, `${FRONTEND_URL}/?auth=roblox-failed`, {"Set-Cookie":clearStateCookie});
      const profileResponse = await fetchWithTimeout("https://apis.roblox.com/oauth/v1/userinfo", {headers:{Authorization:`Bearer ${tokenData.access_token}`} });
      const profile = await profileResponse.json();
      if (!profileResponse.ok || !profile.sub) return redirect(res, `${FRONTEND_URL}/?auth=roblox-profile-failed`, {"Set-Cookie":clearStateCookie});
      await pool.query(`INSERT INTO roblox_connections (discord_id, roblox_user_id, username, display_name, profile_url, avatar_url, refresh_token, scope, access_mode, group_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (discord_id) DO UPDATE SET roblox_user_id=EXCLUDED.roblox_user_id, username=EXCLUDED.username, display_name=EXCLUDED.display_name, profile_url=EXCLUDED.profile_url, avatar_url=EXCLUDED.avatar_url, refresh_token=EXCLUDED.refresh_token, scope=EXCLUDED.scope, access_mode=EXCLUDED.access_mode, group_id=EXCLUDED.group_id, updated_at=NOW()`,
        [user.discord_id, String(profile.sub), profile.preferred_username || null, profile.name || profile.nickname || null, profile.profile || `https://www.roblox.com/users/${encodeURIComponent(profile.sub)}/profile`, profile.picture || null, encryptOperationKey(tokenData.refresh_token), tokenData.scope || "openid profile", oauthState.access_mode || "account", oauthState.group_id || null]);
      return redirect(res, `${FRONTEND_URL}/?auth=roblox-connected`, {"Set-Cookie":clearStateCookie});
    }

    if (req.method === "GET" && requestUrl.pathname === "/auth/discord") {
      if (!authConfigured) return redirect(res, `${FRONTEND_URL}/?auth=not-configured`);
      if (!await requireDatabase(res)) return;
      const loginLimit = await rateLimit(req, "discord-login", 10, 60);
      if (!loginLimit.allowed) return redirect(res, `${FRONTEND_URL}/?auth=rate-limited`);
      const state = randomBytes(24).toString("hex");
      await saveOAuthState(state, Date.now() + 10 * 60 * 1000);
      const params = new URLSearchParams({client_id:DISCORD_CLIENT_ID, response_type:"code", redirect_uri:`${backendOrigin(req)}/auth/discord/callback`, scope:"identify" , state});
      return redirect(res, `https://discord.com/oauth2/authorize?${params}`, {"Set-Cookie":`zane_oauth_state=${encodeURIComponent(state)}; HttpOnly; Secure; SameSite=Lax; Path=/auth/discord; Max-Age=600`});
    }
    if (req.method === "GET" && requestUrl.pathname === "/auth/discord/callback") {
      if (!await requireDatabase(res)) return;
      const state = requestUrl.searchParams.get("state");
      const stateCookie = parseCookies(req).zane_oauth_state;
      if (!state || !stateCookie || state !== stateCookie || !await consumeOAuthState(state)) return redirect(res, `${FRONTEND_URL}/?auth=invalid-state`, {"Set-Cookie":"zane_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/auth/discord; Max-Age=0"});
      const code = requestUrl.searchParams.get("code");
      if (!code || !authConfigured) return redirect(res, `${FRONTEND_URL}/?auth=failed`, {"Set-Cookie":"zane_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/auth/discord; Max-Age=0"});
      const callbackUrl = `${backendOrigin(req)}/auth/discord/callback`;
      const tokenBody = new URLSearchParams({client_id:DISCORD_CLIENT_ID, client_secret:DISCORD_CLIENT_SECRET, grant_type:"authorization_code", code, redirect_uri:callbackUrl});
      const token = await discordRequest("https://discord.com/api/v10/oauth2/token", {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:tokenBody});
      const profile = await discordRequest("https://discord.com/api/v10/users/@me", {headers:{Authorization:`Bearer ${token.access_token}`} });
      let isPremium = false;
      try {
        const member = await getDiscordMember(profile.id);
        isPremium = member.roles?.includes(DISCORD_PREMIUM_ROLE_ID) || false;
      } catch (error) {
        log("PREMIUM CHECK: user is not a member of the configured Discord server", {discordId:profile.id, error:error.message});
      }
      await pool.query(`INSERT INTO discord_users (discord_id, username, avatar, is_premium, auth_provider) VALUES ($1,$2,$3,$4,'discord')
        ON CONFLICT (discord_id) DO UPDATE SET username=EXCLUDED.username, avatar=EXCLUDED.avatar, is_premium=EXCLUDED.is_premium, auth_provider='discord', updated_at=NOW()`,
        [profile.id, profile.global_name || profile.username || profile.id, profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png?size=64` : null, isPremium]);
      const sessionToken = randomBytes(32).toString("hex");
      await pool.query("INSERT INTO discord_sessions (token, discord_id, expires_at) VALUES ($1,$2,NOW() + INTERVAL '14 days')", [sessionToken, profile.id]);
      return redirect(res, `${FRONTEND_URL}/?auth=success`, {"Set-Cookie":[`zane_session=${encodeURIComponent(sessionToken)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${SESSION_DAYS * 86400}`,"zane_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/auth/discord; Max-Age=0"]});
    }
    if (req.method === "GET" && requestUrl.pathname === "/auth/google") {
      if (!googleAuthConfigured) return redirect(res, `${FRONTEND_URL}/?auth=google-not-configured`);
      if (!await requireDatabase(res)) return;
      const loginLimit = await rateLimit(req, "google-login", 10, 60);
      if (!loginLimit.allowed) return redirect(res, `${FRONTEND_URL}/?auth=rate-limited`);
      const state = randomBytes(24).toString("hex");
      await saveOAuthState(state, Date.now() + 10 * 60 * 1000);
      const callbackUrl = `${backendOrigin(req)}/auth/google/callback`;
      const params = new URLSearchParams({client_id:GOOGLE_CLIENT_ID, response_type:"code", redirect_uri:callbackUrl, scope:"openid profile", access_type:"online", state});
      return redirect(res, `https://accounts.google.com/o/oauth2/v2/auth?${params}`, {"Set-Cookie":`zane_google_oauth_state=${encodeURIComponent(state)}; HttpOnly; Secure; SameSite=Lax; Path=/auth/google; Max-Age=600`});
    }
    if (req.method === "GET" && requestUrl.pathname === "/auth/google/callback") {
      if (!await requireDatabase(res)) return;
      const state = requestUrl.searchParams.get("state");
      const stateCookie = parseCookies(req).zane_google_oauth_state;
      const clearStateCookie = "zane_google_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/auth/google; Max-Age=0";
      if (!state || !stateCookie || state !== stateCookie || !await consumeOAuthState(state)) return redirect(res, `${FRONTEND_URL}/?auth=invalid-state`, {"Set-Cookie":clearStateCookie});
      const code = requestUrl.searchParams.get("code");
      if (!code || !googleAuthConfigured) return redirect(res, `${FRONTEND_URL}/?auth=failed`, {"Set-Cookie":clearStateCookie});
      const callbackUrl = `${backendOrigin(req)}/auth/google/callback`;
      const tokenBody = new URLSearchParams({client_id:GOOGLE_CLIENT_ID, client_secret:GOOGLE_CLIENT_SECRET, grant_type:"authorization_code", code, redirect_uri:callbackUrl});
      const token = await discordRequest("https://oauth2.googleapis.com/token", {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:tokenBody});
      const profile = await discordRequest("https://openidconnect.googleapis.com/v1/userinfo", {headers:{Authorization:`Bearer ${token.access_token}`} });
      if (!profile.sub) return redirect(res, `${FRONTEND_URL}/?auth=failed`, {"Set-Cookie":clearStateCookie});
      const userId = `google:${profile.sub}`;
      await pool.query(`INSERT INTO discord_users (discord_id, username, avatar, is_premium, auth_provider) VALUES ($1,$2,$3,FALSE,'google')
        ON CONFLICT (discord_id) DO UPDATE SET username=EXCLUDED.username, avatar=EXCLUDED.avatar, auth_provider='google', updated_at=NOW()`,
        [userId, profile.name || profile.email || userId, profile.picture || null]);
      const sessionToken = randomBytes(32).toString("hex");
      await pool.query("INSERT INTO discord_sessions (token, discord_id, expires_at) VALUES ($1,$2,NOW() + INTERVAL '14 days')", [sessionToken, userId]);
      return redirect(res, `${FRONTEND_URL}/?auth=success`, {"Set-Cookie":[`zane_session=${encodeURIComponent(sessionToken)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${SESSION_DAYS * 86400}`,clearStateCookie]});
    }
    if (req.method === "GET" && requestUrl.pathname === "/auth/discord/link") {
      if (!authConfigured) return redirect(res, `${FRONTEND_URL}/?auth=discord-link-not-configured`);
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      if (!user || user.auth_provider !== "google") return redirect(res, `${FRONTEND_URL}/?auth=discord-link-login`);
      const loginLimit = await rateLimit(req, "discord-link", 10, 60);
      if (!loginLimit.allowed) return redirect(res, `${FRONTEND_URL}/?auth=rate-limited`);
      const state = randomBytes(24).toString("hex");
      await saveOAuthState(state, Date.now() + 10 * 60 * 1000, user.discord_id);
      const callbackUrl = `${backendOrigin(req)}/auth/discord/link/callback`;
      const params = new URLSearchParams({client_id:DISCORD_CLIENT_ID, response_type:"code", redirect_uri:callbackUrl, scope:"identify", state});
      return redirect(res, `https://discord.com/oauth2/authorize?${params}`, {"Set-Cookie":`zane_discord_link_state=${encodeURIComponent(state)}; HttpOnly; Secure; SameSite=Lax; Path=/auth/discord/link; Max-Age=600`});
    }
    if (req.method === "GET" && requestUrl.pathname === "/auth/discord/link/callback") {
      if (!await requireDatabase(res)) return;
      const state = requestUrl.searchParams.get("state");
      const stateCookie = parseCookies(req).zane_discord_link_state;
      const clearStateCookie = "zane_discord_link_state=; HttpOnly; Secure; SameSite=Lax; Path=/auth/discord/link; Max-Age=0";
      const oauthState = state && stateCookie && state === stateCookie ? await consumeOAuthState(state) : null;
      if (!oauthState?.link_user_id) return redirect(res, `${FRONTEND_URL}/?auth=invalid-link-state`, {"Set-Cookie":clearStateCookie});
      const code = requestUrl.searchParams.get("code");
      if (!code || !authConfigured) return redirect(res, `${FRONTEND_URL}/?auth=discord-link-failed`, {"Set-Cookie":clearStateCookie});
      const linkedUser = (await pool.query("SELECT discord_id, auth_provider FROM discord_users WHERE discord_id=$1", [oauthState.link_user_id])).rows[0];
      if (!linkedUser || linkedUser.auth_provider !== "google") return redirect(res, `${FRONTEND_URL}/?auth=discord-link-failed`, {"Set-Cookie":clearStateCookie});
      const callbackUrl = `${backendOrigin(req)}/auth/discord/link/callback`;
      const tokenBody = new URLSearchParams({client_id:DISCORD_CLIENT_ID, client_secret:DISCORD_CLIENT_SECRET, grant_type:"authorization_code", code, redirect_uri:callbackUrl});
      const token = await discordRequest("https://discord.com/api/v10/oauth2/token", {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:tokenBody});
      const profile = await discordRequest("https://discord.com/api/v10/users/@me", {headers:{Authorization:`Bearer ${token.access_token}`} });
      try {
        await getDiscordMember(profile.id);
      } catch {
        return redirect(res, `${FRONTEND_URL}/?auth=discord-link-join-required`, {"Set-Cookie":clearStateCookie});
      }
      const existingLink = (await pool.query("SELECT discord_id FROM discord_users WHERE linked_discord_id=$1 AND discord_id<>$2", [profile.id, oauthState.link_user_id])).rows[0];
      if (existingLink) return redirect(res, `${FRONTEND_URL}/?auth=discord-link-already-used`, {"Set-Cookie":clearStateCookie});
      await pool.query("UPDATE discord_users SET linked_discord_id=$1, updated_at=NOW() WHERE discord_id=$2 AND auth_provider='google'", [profile.id, oauthState.link_user_id]);
      premiumCache.delete(oauthState.link_user_id);
      return redirect(res, `${FRONTEND_URL}/?auth=discord-linked`, {"Set-Cookie":clearStateCookie});
    }
    if (req.method === "GET" && requestUrl.pathname === "/api/auth/me") {
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      const remainingByIp = user?.is_premium ? null : await getIpRemaining(ipHash(req));
      const remainingByDiscord = user ? Math.max(0, FREE_DAILY_FILES - Number(user.used_today)) : null;
      const remaining = user?.is_premium ? null : Math.min(remainingByDiscord, remainingByIp);
      const avatar = user?.auth_provider === "discord" && user.avatar && !user.avatar.startsWith("http")
        ? `https://cdn.discordapp.com/avatars/${user.discord_id}/${user.avatar}.png?size=64`
        : user?.avatar || null;
      const roblox = user ? await getRobloxConnection(user.discord_id) : null;
      return send(res,200,{authenticated:Boolean(user), robloxConfigured:robloxAuthConfigured, user:user ? {id:user.discord_id, username:user.username, avatar, provider:user.auth_provider, discordLinked:Boolean(user.linked_discord_id), premium:user.is_premium, usedToday:Number(user.used_today), dailyLimit:user.is_premium ? null : FREE_DAILY_FILES, remaining, robloxConnected:Boolean(roblox), roblox:roblox ? {userId:roblox.roblox_user_id, username:roblox.username, displayName:roblox.display_name, profileUrl:roblox.profile_url, avatar:roblox.avatar_url, accessMode:roblox.access_mode, groupId:roblox.group_id, connectedAt:roblox.connected_at} : null} : null});
    }
    if (req.method === "POST" && requestUrl.pathname === "/api/roblox/access") {
      if (!await requireDatabase(res)) return;
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login before changing Roblox access."});
      const body = await readRequestJson(req);
      const accessMode = String(body.accessMode || "").toLowerCase();
      const groupId = String(body.groupId || "").trim();
      if (!["account", "group", "both"].includes(accessMode)) return send(res,400,{error:"accessMode must be account, group, or both."});
      if ((accessMode === "group" || accessMode === "both") && (!/^\d+$/.test(groupId) || groupId === "0")) return send(res,400,{error:"A valid Group ID is required for this access mode."});
      const connection = await getRobloxConnection(user.discord_id);
      if (!connection) return send(res,403,{error:"Connect Roblox before selecting access."});
      if (accessMode !== "account") {
        try { await validateCreator("group", groupId); }
        catch (error) { return send(res,400,{error:error.message}); }
      }
      await pool.query("UPDATE roblox_connections SET access_mode=$1, group_id=$2, updated_at=NOW() WHERE discord_id=$3", [accessMode, accessMode === "account" ? null : groupId, user.discord_id]);
      return send(res,200,{accessMode, groupId:accessMode === "account" ? null : groupId});
    }
    if (req.method === "POST" && requestUrl.pathname === "/api/auth/logout") {
      if (!await requireDatabase(res)) return;
      if (req.headers.origin !== FRONTEND_URL) return send(res,403,{error:"Invalid request origin."});
      const token = parseCookies(req).zane_session;
      if (pool && token) await pool.query("DELETE FROM discord_sessions WHERE token=$1", [token]);
      res.writeHead(204, {"Set-Cookie":"zane_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0", "Access-Control-Allow-Origin":FRONTEND_URL, "Access-Control-Allow-Credentials":"true"});
      return res.end();
    }
    if (req.method === "DELETE" && requestUrl.pathname === "/api/auth/roblox") {
      if (!await requireDatabase(res)) return;
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login before disconnecting Roblox."});
      await pool.query("DELETE FROM roblox_connections WHERE discord_id=$1", [user.discord_id]);
      log("ROBLOX: connection disconnected", {discordId:user.discord_id});
      return send(res,200,{disconnected:true});
    }

    if (req.method === "GET" && requestUrl.pathname === "/api/credentials") {
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login before viewing saved API keys."});
      return send(res,200,{credentials:await getSavedCredentials(user.discord_id)});
    }
    if (req.method === "POST" && requestUrl.pathname === "/api/credentials") {
      if (!await requireDatabase(res)) return;
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login before saving an API key."});
      const body = await readRequestJson(req);
      const label = String(body.label || "").trim().slice(0,80);
      const apiKey = String(body.apiKey || "").trim();
      const creatorType = String(body.creatorType || "user").toLowerCase();
      const creatorId = String(body.creatorId || "").trim() || null;
      const expiresAt = body.expiresAt ? new Date(body.expiresAt) : null;
      if (!label) return send(res,400,{error:"A label is required."});
      if (!apiKey) return send(res,400,{error:"API key is required."});
      if (!operationEncryptionKey) return send(res,503,{error:"Credential encryption is not configured."});
      if (!["user", "group"].includes(creatorType)) return send(res,400,{error:"creatorType must be user or group."});
      if (creatorId && (!/^\d+$/.test(creatorId) || creatorId === "0")) return send(res,400,{error:"Creator ID must be a positive number."});
      if (expiresAt && (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now())) return send(res,400,{error:"Expiry must be a future date."});
      const credentialId = randomUUID();
      await pool.query("INSERT INTO saved_credentials (credential_id, discord_id, label, encrypted_api_key, creator_type, creator_id, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)", [credentialId, user.discord_id, label, encryptOperationKey(apiKey), creatorType, creatorId, expiresAt]);
      log("CREDENTIAL: saved", {discordId:user.discord_id, credentialId});
      return send(res,201,{credential:{credentialId,label,creatorType,creatorId,expiresAt,expired:false}});
    }
    if (req.method === "DELETE" && requestUrl.pathname.startsWith("/api/credentials/")) {
      if (!await requireDatabase(res)) return;
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login before deleting a saved API key."});
      const credentialId = decodeURIComponent(requestUrl.pathname.split("/").pop());
      const result = await pool.query("DELETE FROM saved_credentials WHERE credential_id=$1 AND discord_id=$2 RETURNING credential_id", [credentialId, user.discord_id]);
      if (!result.rowCount) return send(res,404,{error:"Saved API key was not found."});
      log("CREDENTIAL: deleted", {discordId:user.discord_id, credentialId});
      return send(res,200,{deleted:true,credentialId});
    }

    if (req.method === "GET" && requestUrl.pathname === "/api/config") {
      return send(res,200,{configured:Boolean(API_KEY && CREATOR_ID), authConfigured, robloxAuthConfigured, databaseReady:await ensureDatabaseReady(), creatorType:CREATOR_TYPE, creatorId:CREATOR_ID || null, freeDailyFiles:FREE_DAILY_FILES, limits:{free:{maxFileSize:FREE_MAX_FILE_SIZE,maxBatchFiles:FREE_MAX_BATCH_FILES,maxBatchSize:FREE_MAX_BATCH_SIZE},premium:{maxFileSize:PREMIUM_MAX_FILE_SIZE,maxBatchFiles:PREMIUM_MAX_BATCH_FILES,maxBatchSize:PREMIUM_MAX_BATCH_SIZE},converter:{maxFileSize:CONVERTER_MAX_FILE_SIZE}}});
    }
    if (req.method === "GET" && requestUrl.pathname === "/api/preview") {
      if (req.headers.origin && !validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const sourceUrl = requestUrl.searchParams.get("url") || "";
      try { return send(res,200,await previewAudioLink(sourceUrl)); }
      catch (error) { return send(res,400,{error:error.message}); }
    }
    if (req.method === "POST" && requestUrl.pathname === "/api/convert") {
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      if (activeConversions >= MAX_CONCURRENT_CONVERSIONS) return send(res,429,{error:"The converter is busy. Please try again shortly."});
      if (!String(req.headers["content-type"] || "").toLowerCase().startsWith("multipart/form-data")) return send(res,400,{error:"Use multipart/form-data."});
      const {fields, files} = await parseMultipartRequest(req, CONVERTER_MAX_FILE_SIZE, 1, CONVERTER_MAX_FILE_SIZE);
      if (files.length !== 1) return send(res,400,{error:"Choose exactly one audio file."});
      activeConversions++;
      try {
        const result = await convertAudioFile(files[0], fields);
        res.writeHead(200, {"Content-Type":result.format.mime, "Content-Length":result.content.length, "Content-Disposition":`attachment; filename="${result.filename.replace(/[^a-zA-Z0-9._ -]/g, "_")}"`, "Cache-Control":"no-store", "Access-Control-Allow-Origin":FRONTEND_URL, "Access-Control-Allow-Credentials":"true"});
        return res.end(result.content);
      } catch (error) {
        log("CONVERTER: failed", {error:error.message});
        return send(res,400,{error:error.message});
      } finally {
        activeConversions--;
      }
    }
    if (req.method === "POST" && requestUrl.pathname === "/api/upload") {
      if (!await requireDatabase(res)) return;
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login before uploading."});
      const robloxConnection = await getRobloxConnection(user.discord_id);
      if (!robloxConnection) return send(res,403,{error:"Connect your Roblox account before publishing assets."});
      const maxBatchFiles = user.is_premium ? PREMIUM_MAX_BATCH_FILES : FREE_MAX_BATCH_FILES;
      const maxFileSize = user.is_premium ? PREMIUM_MAX_FILE_SIZE : FREE_MAX_FILE_SIZE;
      const maxBatchSize = user.is_premium ? PREMIUM_MAX_BATCH_SIZE : FREE_MAX_BATCH_SIZE;
      if (!user.is_premium) {
        const uploadLimit = await rateLimit(req, "upload", 10, 60);
        if (!uploadLimit.allowed) return send(res,429,{error:"Too many upload attempts from this network. Please wait one minute and try again."});
      }
      if (!String(req.headers["content-type"] || "").toLowerCase().startsWith("multipart/form-data")) return send(res,400,{error:"Use multipart/form-data."});
      const {fields, files} = await parseMultipartRequest(req, maxBatchSize, maxBatchFiles, maxFileSize);
      if (!files.length) return send(res,400,{error:"At least one file is required."});
      if (Number.isFinite(maxBatchFiles) && files.length > maxBatchFiles) return send(res,400,{error:`You can upload up to ${maxBatchFiles} files at once.`});
      const type = TYPES[fields.type];
      if (!type) return send(res,400,{error:"type must be audio or animation."});
      const totalSize = files.reduce((total, item) => total + item.content.length, 0);
      if (totalSize > maxBatchSize) return send(res,400,{error:`The total batch size cannot exceed ${Math.round(maxBatchSize / 1024 / 1024)} MB.`});
      const description = String(fields.description || "").slice(0,1000);
      const requestedCredentialId = String(fields.credentialId || "").trim() || (String(fields.apiKey || "").startsWith("saved:") ? String(fields.apiKey).slice(6) : "");
      const credentialId = requestedCredentialId;
      let savedCredential = null;
      if (credentialId) {
        try { savedCredential = await getSavedCredential(user.discord_id, credentialId); }
        catch (error) { return send(res,error.status || 400,{error:error.message}); }
      }
      const apiKey = savedCredential ? decryptOperationKey(savedCredential.encrypted_api_key).trim() : String(fields.apiKey || API_KEY).trim();
      const creatorType = String(fields.creatorType || savedCredential?.creator_type || CREATOR_TYPE).toLowerCase();
      const creatorId = String(fields.creatorId || savedCredential?.creator_id || CREATOR_ID).trim();
      if (!["user", "group"].includes(creatorType)) return send(res,400,{error:"creatorType must be user or group."});
      if (!apiKey) return send(res,400,{error:"API key is required for publishing."});
      if (!/^\d+$/.test(creatorId) || creatorId === "0") return send(res,400,{error:"Creator ID must be a positive number."});
      const accountAllowed = creatorType === "user" && creatorId === String(robloxConnection.roblox_user_id);
      const groupAllowed = creatorType === "group" && creatorId === String(robloxConnection.group_id || "");
      const modeAllowsCreator = robloxConnection.access_mode === "both" ? accountAllowed || groupAllowed : robloxConnection.access_mode === "group" ? groupAllowed : accountAllowed;
      if (!modeAllowsCreator) return send(res,403,{error:"The selected creator is not allowed by your Roblox access setting."});
      try {
        await validateCreator(creatorType, creatorId);
      } catch (error) {
        return send(res,400,{error:error.message});
      }
      for (const file of files) {
        const ext = path.extname(file.filename).toLowerCase();
        if (!type.exts.includes(ext)) return send(res,400,{error:`Unsupported ${fields.type} file type: ${file.filename}.`});
        if (file.content.length > maxFileSize) return send(res,400,{error:`${file.filename} exceeds the ${Math.round(maxFileSize / 1024 / 1024)} MB limit.`});
        if (!hasValidMime(ext, file.contentType, file.content)) return send(res,400,{error:`${file.filename} does not match a valid ${fields.type} file format.`});
      }
      if (!await canUseBindings(user, apiKey, creatorType, creatorId)) return send(res,403,{error:"These Roblox credentials or creator are already linked to another Discord account."});
      if (savedCredential) await pool.query("UPDATE saved_credentials SET last_used_at=NOW(), updated_at=NOW() WHERE credential_id=$1 AND discord_id=$2", [credentialId, user.discord_id]);
      const uploads = [];
      const failed = [];
      const requestIpHash = ipHash(req);
      for (const file of files) {
        if (requestAborted) break;
        const quota = await reserveQuota(user, 1, requestIpHash);
        if (!quota.allowed) {
          const subject = quota.reason === "ip" ? "this network" : "your Discord account";
          failed.push({fileId:file.fileId, filename:file.filename, error:`Free accounts can publish ${FREE_DAILY_FILES} files per day. ${subject} has ${quota.remaining} remaining, or use a premium Discord role.`});
          continue;
        }
        const ext = path.extname(file.filename).toLowerCase();
        const displayName = normalizeAssetName(fields.displayName || file.filename);
        log("UPLOAD: file received", {type:fields.type, filename:file.filename, sizeBytes:file.content.length, displayName, creatorType, creatorId});
        let bindingClaims = null;
        let assetAccepted = false;
        let operationId = "";
        let operationSaved = false;
        let intentId = randomUUID();
        let intentSaved = false;
        let cancellationError = null;
        let quotaReleased = false;
        try {
          bindingClaims = await claimBindings(user, apiKey, creatorType, creatorId);
          if (!bindingClaims.allowed) throw new Error("These Roblox credentials or creator are already linked to another Discord account.");
          const intentExpiresAt = Date.now() + OPERATION_TTL_MS;
          await saveUploadIntent(intentId, apiKey, user.discord_id, intentExpiresAt, {
            filename:file.filename, sizeBytes:file.content.length, assetType:type.assetType, creatorType, creatorId,
            quotaReserved:!user.is_premium, quotaIpHash:requestIpHash, quotaDate:quota.quotaDate,
            credentialHash:bindingClaims.credentialHash, claimedCredential:bindingClaims.claimedCredential, claimedCreator:bindingClaims.claimedCreator
          });
          intentSaved = true;
          const result = await createAsset({
            assetType:type.assetType, displayName, description,
            filename:file.filename, contentType:type.mimes.get(ext), fileContent:file.content,
            apiKey, creatorType, creatorId
          });
          assetAccepted = true;
          const operationPath = result.path || "";
          operationId = operationPath.split("/").pop();
          if (!operationId) throw new Error(`Roblox did not return an operation ID for ${file.filename}.`);
          const operationToken = randomUUID();
          const expiresAt = Date.now() + OPERATION_TTL_MS;
          try {
            await updateUploadIntentWithRetry(intentId, operationId, operationToken, expiresAt);
            await saveOperationWithRetry(operationId, operationToken, apiKey, user.discord_id, expiresAt, {
            filename:file.filename, sizeBytes:file.content.length, assetType:type.assetType, creatorType, creatorId,
              quotaReserved:!user.is_premium, quotaIpHash:requestIpHash, quotaDate:quota.quotaDate
            });
            operationSaved = true;
          } catch (error) {
            try {
              await cancelOperation(operationId, apiKey);
            } catch (cancelError) {
              cancellationError = cancelError;
            }
            throw error;
          }
          try {
            await deleteUploadIntent(intentId);
            intentSaved = false;
          } catch (error) {
            log("UPLOAD: operation saved but intent cleanup is pending", {intent:intentId, operation:operationId, error:error.message});
          }
          if (requestAborted) {
            try {
              await cancelOperation(operationId, apiKey);
              await deleteOperation(operationId);
              if (intentSaved) await deleteUploadIntent(intentId);
              intentSaved = false;
              await releaseQuota(user, 1, requestIpHash, quota.quotaDate);
              quotaReleased = true;
              operationSaved = false;
            } catch (cancelError) {
              cancellationError = cancelError;
            }
            const disconnectError = new Error("Upload client disconnected.");
            disconnectError.cancelled = true;
            throw disconnectError;
          }
          uploads.push({fileId:file.fileId, filename:file.filename, sizeBytes:file.content.length, operationId, operationToken, operationPath});
        } catch (error) {
          if (!assetAccepted) await releaseBindingClaims(user, bindingClaims, creatorType, creatorId);
          if (assetAccepted && !operationSaved && !cancellationError) await releaseBindingClaims(user, bindingClaims, creatorType, creatorId);
          if (!assetAccepted && intentSaved) await deleteUploadIntent(intentId);
          const canReleaseQuota = !assetAccepted || (!requestAborted && operationSaved) || (operationId && !cancellationError);
          if (canReleaseQuota && !quotaReleased) await releaseQuota(user, 1, requestIpHash, quota.quotaDate);
          const cancellationMessage = cancellationError ? ` Roblox operation ${operationId} could not be cancelled: ${cancellationError.message}` : "";
          if (!requestAborted) failed.push({fileId:file.fileId, filename:file.filename, error:`${error.message}${cancellationMessage}`});
        }
      }
      if (requestAborted) return;
      return send(res,failed.length ? 207 : 202,{message:failed.length ? "Some uploads failed." : "Uploads accepted by Roblox.", uploads, failed});
    }
    if (req.method === "GET" && requestUrl.pathname === "/api/operations/active") {
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login with Discord before checking upload status."});
      return send(res,200,{operations:await getActiveOperations(user.discord_id)});
    }
    if (req.method === "GET" && requestUrl.pathname === "/api/stats") {
      if (!await requireDatabase(res)) return;
      const statsLimit = await rateLimit(req, "stats", 30, 60);
      if (!statsLimit.allowed) return send(res,429,{error:"Too many statistics requests. Please try again shortly."});
      return send(res,200,pool ? await getSiteStats(req) : {totalUsers:0,totalUploads:0,totalVisits:0});
    }
    if (req.method === "GET" && requestUrl.pathname === "/api/user/stats") {
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login with Discord before checking account statistics."});
      return send(res,200,await getUserStats(user.discord_id));
    }
    if (req.method === "GET" && requestUrl.pathname === "/api/user/dashboard") {
      if (!await requireDatabase(res)) return;
      const user = await getSession(req);
      if (!user) return send(res,401,{error:"Login with Discord before checking the dashboard."});
      const ipRemaining = user.is_premium ? null : await getIpRemaining(ipHash(req));
      const remainingByDiscord = user.is_premium ? null : Math.max(0, FREE_DAILY_FILES - Number(user.used_today));
      return send(res,200,{quota:{premium:Boolean(user.is_premium), usedToday:Number(user.used_today), dailyLimit:user.is_premium ? null : FREE_DAILY_FILES, remaining:user.is_premium ? null : Math.min(remainingByDiscord, ipRemaining)}, stats:await getUserStats(user.discord_id), active:await getActiveOperations(user.discord_id)});
    }
    if (req.method === "GET" && requestUrl.pathname.startsWith("/api/operation/")) {
      if (!await requireDatabase(res)) return;
      const sessionUser = await getSession(req);
      if (!sessionUser) return send(res,401,{error:"Login with Discord before checking upload status."});
      const id = decodeURIComponent(requestUrl.pathname.split("/").pop());
      return await withOperationLock(id, async () => {
        const stored = await getStoredOperation(id);
        if (!stored || new Date(stored.expires_at).getTime() <= Date.now()) {
          if (stored) await releaseStoredQuota(stored);
          await deleteOperation(id);
          return send(res,410,{error:"Operation expired or server restarted. Please upload again."});
        }
        if (stored.discord_id !== sessionUser.discord_id) return send(res,403,{error:"You do not own this upload operation."});
        if (req.headers["x-operation-token"] !== stored.operation_token) return send(res,403,{error:"Invalid operation token."});
        const operation = await getOperation(id, stored.api_key);
        if (operation.done) {
          const assetId = operation.assetId || operation.response?.assetId || "unknown";
          await recordPublishedAsset(id, stored.discord_id, stored.filename, stored.asset_type, assetId);
          log("SUCCESS: asset published", {operation:id, assetId});
        }
        else if (operation.error) {
          await releaseStoredQuota(stored);
          const errorMessage = typeof operation.error === "string" ? operation.error : operation.error.message || JSON.stringify(operation.error);
          log("FAILED: Roblox processing failed", {operation:id, error:errorMessage});
        }
        else log("PROCESSING: Roblox is still processing", {operation:id});
        if (operation.done || operation.error) await deleteOperation(id);
        return send(res,200,operation);
      });
    }
    if (req.method === "DELETE" && requestUrl.pathname.startsWith("/api/operation/")) {
      if (!await requireDatabase(res)) return;
      if (!validRequestOrigin(req)) return send(res,403,{error:"Invalid request origin."});
      const sessionUser = await getSession(req);
      if (!sessionUser) return send(res,401,{error:"Login with Discord before cancelling upload status."});
      const id = decodeURIComponent(requestUrl.pathname.split("/").pop());
      return await withOperationLock(id, async () => {
        const stored = await getStoredOperation(id);
        if (!stored || new Date(stored.expires_at).getTime() <= Date.now()) {
          if (stored) {
            await releaseStoredQuota(stored);
            await deleteOperation(id);
          }
          return send(res,410,{error:"Operation expired or server restarted. Please upload again."});
        }
        if (stored.discord_id !== sessionUser.discord_id) return send(res,403,{error:"You do not own this upload operation."});
        if (req.headers["x-operation-token"] !== stored.operation_token) return send(res,403,{error:"Invalid operation token."});
        try {
          await cancelOperation(id, stored.api_key);
        } catch (error) {
          return send(res,error.status === 409 ? 409 : 502,{error:error.status === 409 ? "Roblox does not support cancelling this operation." : error.message});
        }
        await releaseStoredQuota(stored);
        await deleteOperation(id);
        log("CANCELLED: Roblox operation cancelled", {operation:id, discordId:sessionUser.discord_id});
        return send(res,200,{cancelled:true, operationId:id});
      });
    }
    if (req.method === "GET") {
      const requestPath = requestUrl.pathname;
      let file = requestPath === "/" ? "index.html" : requestPath.slice(1);
      if (!/^[a-zA-Z0-9._/-]+$/.test(file)) return send(res,404,{error:"Not found"});
      const publicRoot = path.resolve(__dirname,"public");
      const full = path.resolve(publicRoot,file);
      if (!full.startsWith(`${publicRoot}${path.sep}`)) return send(res,403,{error:"Forbidden"});
      if (!fs.existsSync(full) || fs.statSync(full).isDirectory()) return send(res,404,{error:"Not found"});
      const ext = path.extname(full);
      const mime = {".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".svg":"image/svg+xml",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp"}[ext] || "application/octet-stream";
      return send(res,200,fs.readFileSync(full),mime);
    }
    send(res,404,{error:"Not found"});
  } catch (error) {
    console.error(`[${new Date().toISOString()}] ERROR: ${error.message}`);
    send(res,error.status && error.status >= 400 && error.status < 600 ? error.status : 500,{error:error.message});
  }
}

if (!process.env.VERCEL && !process.env.VERCEL_ENV) {
  const server = http.createServer(handler);
  server.listen(PORT,()=>console.log(`ZaneXyuu Studio uploader running on Railway port ${PORT}`));
}

export default handler;
