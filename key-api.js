/**
 * PrxDigy Hub — Key System API
 * Node.js / Express
 *
 * Deploy: Railway, Render, Fly.io, or any Node host.
 * npm install express crypto-js nanoid node-cron
 *
 * ENV vars required:
 *   PORT            — default 3000
 *   API_SECRET      — random long string for signing keys (generate once, never change)
 *   LINKVERTISE_ID  — your LV publisher ID (for webhook validation, optional)
 *   ALLOWED_ORIGINS — comma-separated origins e.g. https://prxdigy.github.io
 */

'use strict';

const express    = require('express');
const crypto     = require('crypto');
const cron       = require('node-cron');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Secret used to sign keys. Change this once. Store in env. ───────────────
const API_SECRET = process.env.API_SECRET || 'REPLACE_WITH_LONG_RANDOM_SECRET_STRING';

// ─── In-memory stores (replace with Redis or SQLite for persistence) ──────────
const sessions  = new Map(); // token → { hwid, created, completed, key, expires_at }
const keyStore  = new Map(); // hwid  → { key, expires_at, issued_at, useCount }
const ipLimits  = new Map(); // ip    → { count, window_start }
const burnedTokens = new Set(); // tokens that have been used once

// ─── Constants ────────────────────────────────────────────────────────────────
const KEY_TTL_MS        = 24 * 60 * 60 * 1000; // 24 hours
const SESSION_TTL_MS    = 10 * 60 * 1000;       // 10 minutes — LV must be completed in this window
const IP_LIMIT_PER_HOUR = 6;                    // max key generations per IP per hour
const IP_WINDOW_MS      = 60 * 60 * 1000;       // 1 hour

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '16kb' }));

// CORS
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (!allowedOrigins.length || allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

/**
 * Rate-limit by IP. Returns true if the request is allowed.
 */
function checkIpLimit(ip) {
  const now  = Date.now();
  const slot = ipLimits.get(ip) || { count: 0, window_start: now };

  if (now - slot.window_start > IP_WINDOW_MS) {
    // Reset window
    ipLimits.set(ip, { count: 1, window_start: now });
    return true;
  }

  if (slot.count >= IP_LIMIT_PER_HOUR) return false;

  slot.count++;
  ipLimits.set(ip, slot);
  return true;
}

/**
 * HWID validation: must match HWID-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX format.
 * Reject anything that doesn't look like a real client-generated HWID.
 */
function isValidHWID(hwid) {
  if (typeof hwid !== 'string') return false;
  return /^HWID-[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}$/.test(hwid);
}

/**
 * Generate a signed key.
 * Format: PRXDIGY-XXXX-XXXX-XXXX-HMAC[8]
 * The HMAC binds the key to the HWID and the expiry timestamp.
 * Any modification to key text or use on a different HWID will fail validation.
 */
function generateKey(hwid, expiresAt) {
  const rand = crypto.randomBytes(8).toString('hex').toUpperCase();
  const body = [
    'PRXDIGY',
    rand.slice(0, 4),
    rand.slice(4, 8),
    Math.floor(expiresAt / 1000).toString(36).toUpperCase().padStart(6, '0'),
  ].join('-');

  // HMAC signs: key_body + hwid + expiry
  const payload = `${body}:${hwid}:${expiresAt}`;
  const sig = crypto
    .createHmac('sha256', API_SECRET)
    .update(payload)
    .digest('hex')
    .slice(0, 8)
    .toUpperCase();

  return `${body}-${sig}`;
}

/**
 * Validate a key against a claimed HWID.
 * Returns { valid: bool, expired: bool }
 */
function validateKey(key, hwid) {
  const parts = key.split('-');
  if (parts.length !== 5 || parts[0] !== 'PRXDIGY') return { valid: false, expired: false };

  const sigClaimed   = parts[4];
  const bodyWithoutSig = parts.slice(0, 4).join('-');

  // Recover expiry from the base-36 encoded segment
  let expiresAt;
  try {
    expiresAt = parseInt(parts[3], 36) * 1000;
  } catch (e) { return { valid: false, expired: false }; }

  // Recompute HMAC
  const payload = `${bodyWithoutSig}:${hwid}:${expiresAt}`;
  const expectedSig = crypto
    .createHmac('sha256', API_SECRET)
    .update(payload)
    .digest('hex')
    .slice(0, 8)
    .toUpperCase();

  if (!crypto.timingSafeEqual(Buffer.from(sigClaimed), Buffer.from(expectedSig))) {
    return { valid: false, expired: false };
  }

  const expired = Date.now() > expiresAt;
  return { valid: true, expired };
}

/**
 * Generate a one-time session token. Tied to HWID.
 */
function generateSessionToken(hwid) {
  const data = `${hwid}:${Date.now()}:${crypto.randomBytes(16).toString('hex')}`;
  return crypto.createHmac('sha256', API_SECRET).update(data).digest('hex').slice(0, 40).toUpperCase();
}

/**
 * Anti-bypass: check if an existing non-expired key is already stored for this HWID.
 */
function getExistingKey(hwid) {
  const record = keyStore.get(hwid);
  if (!record) return null;
  if (Date.now() > record.expires_at) {
    keyStore.delete(hwid);
    return null;
  }
  return record;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/session/create
 * Called by the web page before opening Linkvertise.
 * Returns a one-time session token tied to the HWID.
 *
 * Anti-bypass:
 * - HWID format validated
 * - IP rate-limited
 * - If a valid unexpired key already exists for this HWID, return it directly
 *   (user doesn't need to go through LV again)
 */
app.post('/api/session/create', (req, res) => {
  const { hwid } = req.body || {};
  const ip = getIp(req);

  if (!isValidHWID(hwid)) {
    return res.status(400).json({ error: 'invalid_hwid' });
  }

  if (!checkIpLimit(ip)) {
    return res.status(429).json({ error: 'rate_limited', message: 'Too many requests from this IP.' });
  }

  // If this HWID already has a live key, skip Linkvertise
  const existing = getExistingKey(hwid);
  if (existing) {
    return res.json({
      token: null,
      skip_linkvertise: true,
      key: existing.key,
      expires_at: new Date(existing.expires_at).toISOString(),
    });
  }

  const token = generateSessionToken(hwid);
  sessions.set(token, {
    hwid,
    created:     Date.now(),
    completed:   false,
    ip,
    key:         null,
    expires_at:  null,
  });

  // Sessions clean themselves up, but set a hard TTL via timeout
  setTimeout(() => { sessions.delete(token); }, SESSION_TTL_MS);

  return res.json({ token });
});

/**
 * GET /api/session/status?token=...
 * Polled by the web page while waiting for Linkvertise completion.
 */
app.get('/api/session/status', (req, res) => {
  const { token } = req.query || {};
  if (!token) return res.status(400).json({ error: 'missing_token' });

  const session = sessions.get(token);
  if (!session) return res.status(404).json({ error: 'session_not_found_or_expired' });

  return res.json({
    completed:  session.completed,
    key:        session.completed ? session.key        : null,
    expires_at: session.completed ? new Date(session.expires_at).toISOString() : null,
  });
});

/**
 * POST /api/key/generate
 * Called when the user returns from Linkvertise (via callback URL).
 *
 * Anti-bypass checklist:
 * 1. Token must exist in session store (not fabricated)
 * 2. Token must not be expired (SESSION_TTL_MS)
 * 3. Token must not have been used before (one-time burn)
 * 4. HWID in request must match HWID bound to the token
 * 5. IP rate limit check
 * 6. HWID must not already have a live key (prevents generating infinite keys
 *    by replaying the callback URL)
 */
app.post('/api/key/generate', (req, res) => {
  const { token, hwid } = req.body || {};
  const ip = getIp(req);

  if (!token || !isValidHWID(hwid)) {
    return res.status(400).json({ error: 'invalid_params' });
  }

  // ── Anti-bypass: burned token check ──────────────────────────────────────
  if (burnedTokens.has(token)) {
    return res.status(409).json({ error: 'token_already_used', message: 'This session was already redeemed.' });
  }

  // ── Session existence ─────────────────────────────────────────────────────
  const session = sessions.get(token);
  if (!session) {
    return res.status(404).json({ error: 'session_expired_or_invalid' });
  }

  // ── Session TTL ───────────────────────────────────────────────────────────
  if (Date.now() - session.created > SESSION_TTL_MS) {
    sessions.delete(token);
    return res.status(410).json({ error: 'session_expired', message: 'Linkvertise session timed out. Start over.' });
  }

  // ── HWID binding ──────────────────────────────────────────────────────────
  if (session.hwid !== hwid) {
    return res.status(403).json({ error: 'hwid_mismatch', message: 'HWID mismatch — key cannot be issued.' });
  }

  // ── IP limit ──────────────────────────────────────────────────────────────
  if (!checkIpLimit(ip)) {
    return res.status(429).json({ error: 'rate_limited' });
  }

  // ── Existing key check (prevent Linkvertise replay for free keys) ─────────
  const existing = getExistingKey(hwid);
  if (existing) {
    burnedTokens.add(token);
    sessions.delete(token);
    return res.json({
      key:        existing.key,
      expires_at: new Date(existing.expires_at).toISOString(),
      reused:     true,
    });
  }

  // ── Issue key ─────────────────────────────────────────────────────────────
  const expiresAt = Date.now() + KEY_TTL_MS;
  const key       = generateKey(hwid, expiresAt);

  keyStore.set(hwid, {
    key,
    expires_at: expiresAt,
    issued_at:  Date.now(),
    useCount:   0,
    ip,
  });

  // Burn the token — one use only
  burnedTokens.add(token);
  session.completed  = true;
  session.key        = key;
  session.expires_at = expiresAt;
  sessions.delete(token); // clean up session; result is in keyStore now

  return res.json({
    key,
    expires_at: new Date(expiresAt).toISOString(),
  });
});

/**
 * POST /api/key/validate
 * Called by the Lua executor (via HttpService) to verify a key is valid
 * before unlocking premium features.
 *
 * The Lua script sends: { key, hwid }
 * This validates the HMAC, checks expiry, and checks HWID binding.
 * Each validation increments useCount (anomaly detection: >200 per key = flag).
 */
app.post('/api/key/validate', (req, res) => {
  const { key, hwid } = req.body || {};

  if (!key || !isValidHWID(hwid)) {
    return res.status(400).json({ valid: false, reason: 'bad_params' });
  }

  const { valid, expired } = validateKey(key, hwid);

  if (!valid) {
    return res.json({ valid: false, reason: 'invalid_signature' });
  }

  if (expired) {
    return res.json({ valid: false, reason: 'expired' });
  }

  // Confirm the key is in our store and bound to this HWID
  const record = keyStore.get(hwid);
  if (!record || record.key !== key) {
    return res.json({ valid: false, reason: 'not_found_in_store' });
  }

  record.useCount++;
  // Anomaly flag: if a single key is being validated too frequently, something is off
  if (record.useCount > 500) {
    console.warn(`[ANOMALY] Key for HWID ${hwid} has ${record.useCount} validations — possible automation`);
  }

  return res.json({
    valid:      true,
    expires_at: new Date(record.expires_at).toISOString(),
    hwid,
  });
});

/**
 * GET /api/key/check?hwid=...
 * Lightweight check: does this HWID currently have a valid key?
 * Used by the web page to skip Linkvertise for users who still have time left.
 */
app.get('/api/key/check', (req, res) => {
  const { hwid } = req.query || {};
  if (!isValidHWID(hwid)) return res.status(400).json({ has_key: false });

  const record = getExistingKey(hwid);
  if (!record) return res.json({ has_key: false });

  return res.json({
    has_key:    true,
    expires_at: new Date(record.expires_at).toISOString(),
    ms_left:    record.expires_at - Date.now(),
  });
});

// ─── Cron: hourly cleanup ─────────────────────────────────────────────────────
cron.schedule('0 * * * *', () => {
  const now = Date.now();

  // Expired keys
  for (const [hwid, record] of keyStore.entries()) {
    if (now > record.expires_at) keyStore.delete(hwid);
  }

  // Expired sessions
  for (const [token, session] of sessions.entries()) {
    if (now - session.created > SESSION_TTL_MS) sessions.delete(token);
  }

  // Burned tokens older than 25 hours (no longer relevant)
  // Simple approach: clear all burned tokens hourly (they're only needed during session TTL)
  // For production: store burn timestamp and prune specifically
  if (burnedTokens.size > 50000) burnedTokens.clear();

  // IP limit windows that have expired
  for (const [ip, slot] of ipLimits.entries()) {
    if (now - slot.window_start > IP_WINDOW_MS) ipLimits.delete(ip);
  }

  console.log(`[CLEANUP] Keys: ${keyStore.size}, Sessions: ${sessions.size}, Burned: ${burnedTokens.size}`);
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`PrxDigy Key API running on port ${PORT}`);
});
