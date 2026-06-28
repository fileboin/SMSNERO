"use strict";

const express = require("express");
const http = require("http");
const crypto = require("crypto");
const QRCode = require("qrcode");
const { Pool } = require("pg");
const { WebSocketServer, WebSocket } = require("ws");
const https = require("https");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SWISS_API_KEY = process.env.SWISS_API_KEY;
const SWISS_SECRET_KEY = process.env.SWISS_SECRET_KEY;
const SWISS_API_URL = process.env.SWISS_API_URL || "https://api.swiss-bitcoin-pay.ch";
const SESSION_DURATION_HOURS = Number(process.env.SESSION_DURATION_HOURS) || 24;

if (!DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!JWT_SECRET) throw new Error("JWT_SECRET / SESSION_SECRET is required");
if (!ADMIN_PASSWORD) throw new Error("ADMIN_PASSWORD is required");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

const sockets = new Set();
const rateBuckets = new Map();

app.use(express.json({
  limit: "1mb",
  verify: function(req, _res, buf) { req.rawBody = buf; },
}));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

const JWT_TTL_SECONDS = 90 * 24 * 3600; // 90 days; admin tokens share the same TTL

function signToken(payload) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + JWT_TTL_SECONDS }));
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(header + "." + body)
    .digest("base64url");
  return header + "." + body + "." + signature;
}

function verifyToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const expected = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(parts[0] + "." + parts[1])
    .digest("base64url");
  const receivedBuffer = Buffer.from(parts[2]);
  const expectedBuffer = Buffer.from(expected);
  if (
    receivedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)
  ) {
    throw new Error("Invalid token signature");
  }
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
    throw new Error("Token expired");
  }
  return payload;
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = verifyToken(token);
    return next();
  } catch (e) {
    return res.status(403).json({ error: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  return next();
}

function rateLimit(req, res, next) {
  const key = req.ip || "unknown";
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + 60000 });
    return next();
  }
  if (bucket.count >= 120) {
    return res.status(429).json({ error: "Too many requests. Try again later." });
  }
  bucket.count += 1;
  return next();
}

function wrap(fn) {
  return function(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(function(err) {
      console.error(err);
      if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
    });
  };
}

function signPayload(payload) {
  if (!SWISS_SECRET_KEY) throw new Error("SWISS_SECRET_KEY is missing");
  return crypto.createHmac("sha256", SWISS_SECRET_KEY).update(JSON.stringify(payload)).digest("hex");
}

// Verify Swiss Bitcoin Pay webhook HMAC-SHA256 signature.
// SBP sends the signature in the "x-sbp-signature" or "x-webhook-signature" header.
// If SWISS_SECRET_KEY is not configured we allow the request through with a warning,
// so existing deployments without the secret key don't suddenly break.
function verifyWebhookSignature(req) {
  if (!SWISS_SECRET_KEY) {
    console.warn("SWISS_SECRET_KEY not set — webhook signature verification skipped");
    return true;
  }
  const sig = (req.headers["x-sbp-signature"] || req.headers["x-webhook-signature"] || "").toLowerCase();
  if (!sig) {
    // Swiss Bitcoin Pay may not always send a signature header on legacy plans; allow through.
    return true;
  }
  const raw = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
  const expected = crypto.createHmac("sha256", SWISS_SECRET_KEY).update(raw).digest("hex");
  return sig === expected;
}

function extractOTP(text) {
  const match = String(text || "").match(/\b\d{4,8}\b/);
  return match ? match[0] : null;
}

// ============ PROVIDER ADAPTERS ============
let _btcRate = 65000;
async function refreshBtcRate() {
  try {
    const r = await fetch("https://mempool.space/api/v1/prices");
    const d = await r.json();
    if (d && d.USD) { _btcRate = d.USD; }
  } catch(e) { console.error("BTC rate fetch error:", e.message); }
}
refreshBtcRate();
setInterval(refreshBtcRate, 5 * 60 * 1000);

function usdCentsToSats(cents) {
  return Math.ceil((cents / 100 / _btcRate) * 100000000);
}

async function getActiveProvider() {
  const r = await pool.query("SELECT * FROM sms_providers WHERE is_active = TRUE ORDER BY id ASC LIMIT 1");
  return r.rows[0] || null;
}

async function callProvider(provider, path, params) {
  const isGet = !params;
  if (provider.provider_type === "smspool" || provider.provider_type === "smspool") {
    const baseUrl = provider.api_url || "https://api.smspool.net";
    if (isGet) {
      const r = await fetch(baseUrl + path);
      return await r.json();
    }
    params.key = provider.api_key;
    const body = new URLSearchParams(params);
    const r = await fetch(baseUrl + path, { method: "POST", body });
    return await r.json();
  } else if (provider.provider_type === "5sim") {
    const baseUrl = provider.api_url || "https://5sim.net/v1";
    const headers = { Authorization: "Bearer " + provider.api_key, Accept: "application/json" };
    const r = await fetch(baseUrl + path, { headers });
    return await r.json();
  }
  throw new Error("Unknown provider type: " + provider.provider_type);
}

async function providerGetCountries(provider) {
  if (provider.provider_type === "smspool") {
    const data = await callProvider(provider, "/country/retrieve_all");
    if (!Array.isArray(data)) return [];
    return data.map(function(c) { return { id: String(c.ID || c.id || c.name), name: String(c.name || c.Name || c.country || c.ID), short_name: String(c.short_name || c.name || "").toLowerCase() }; }).filter(function(c) { return c.name; });
  } else if (provider.provider_type === "5sim") {
    const data = await callProvider(provider, "/guest/countries");
    if (!data || typeof data !== "object") return [];
    return Object.entries(data).map(function(entry) { return { id: entry[0], name: String(entry[1].text_en || entry[0]), short_name: entry[0] }; });
  }
  return [];
}

async function providerGetServices(provider, country) {
  if (provider.provider_type === "smspool") {
    const data = await callProvider(provider, "/service/retrieve_all");
    if (!Array.isArray(data)) return [];
    return data.map(function(s) { return { id: String(s.ID || s.id || s.name), name: String(s.name || s.Name || s.service), price_cents: Math.round((s.price || 0.5) * 100) }; }).filter(function(s) { return s.name; });
  } else if (provider.provider_type === "5sim") {
    if (!country) return [];
    const data = await callProvider(provider, "/guest/products/" + encodeURIComponent(country) + "/any");
    if (!data || typeof data !== "object") return [];
    return Object.entries(data).map(function(entry) { return { id: entry[0], name: String(entry[0]).replace(/_/g, " "), price_cents: Math.round((entry[1].Price || entry[1].price || 0.5) * 100), available: entry[1].Qty || entry[1].qty || 0 }; });
  }
  return [];
}

async function providerBuyNumber(provider, country, service) {
  if (provider.provider_type === "smspool") {
    const data = await callProvider(provider, "/purchase/sms", { country: country, service: service });
    if (!data.number && !data.phonenumber) throw new Error(data.message || data.error || "SMSPool purchase failed: " + JSON.stringify(data));
    const phone = String(data.number || data.phonenumber || "");
    return { phone: phone.startsWith("+") ? phone : ("+" + phone), orderId: String(data.order_id || data.orderId || data.id || "") };
  } else if (provider.provider_type === "5sim") {
    const c = encodeURIComponent(String(country).toLowerCase());
    const s = encodeURIComponent(String(service).toLowerCase());
    const data = await callProvider(provider, "/user/buy/activation/" + c + "/any/" + s);
    if (!data.phone) throw new Error(data.message || "5sim purchase failed: " + JSON.stringify(data));
    const phone = String(data.phone || "");
    return { phone: phone.startsWith("+") ? phone : ("+" + phone), orderId: String(data.id || "") };
  }
  throw new Error("Unknown provider type");
}

async function providerCheckSMS(provider, orderId) {
  if (provider.provider_type === "smspool") {
    const data = await callProvider(provider, "/sms/check", { orderid: orderId });
    return { sms: data.sms || null, status: String(data.status || "pending") };
  } else if (provider.provider_type === "5sim") {
    const data = await callProvider(provider, "/user/check/" + encodeURIComponent(orderId));
    const smsList = data.sms || [];
    const latest = smsList[smsList.length - 1];
    return { sms: latest ? String(latest.text || "") : null, status: String(data.status || "pending") };
  }
  return { sms: null, status: "pending" };
}

async function providerRefund(provider, orderId) {
  try {
    if (provider.provider_type === "smspool") {
      return await callProvider(provider, "/sms/refund", { orderid: orderId });
    } else if (provider.provider_type === "5sim") {
      return await callProvider(provider, "/user/cancel/" + encodeURIComponent(orderId));
    }
  } catch(e) { console.error("Provider refund error:", e.message); }
  return null;
}

async function pollProviderSessions() {
  try {
    const provider = await getActiveProvider();
    if (!provider) return;
    const sessions = await pool.query(
      "SELECT s.id, s.user_id, s.number_id, s.provider, s.provider_order_id FROM sessions s WHERE s.expires_at > NOW() AND s.provider IS NOT NULL AND s.provider_order_id IS NOT NULL"
    );
    for (const sess of sessions.rows) {
      try {
        const result = await providerCheckSMS(provider, sess.provider_order_id);
        if (result.sms) {
          const existing = await pool.query(
            "SELECT id FROM messages WHERE number_id = $1 AND text = $2 LIMIT 1",
            [sess.number_id, result.sms]
          );
          if (!existing.rows.length) {
            const otp = extractOTP(result.sms);
            await pool.query("INSERT INTO messages (number_id, phone_number, text, otp) VALUES ($1, $2, $3, $4)", [sess.number_id, "SMS", result.sms, otp]);
            broadcast({ type: "message", phoneNumber: "SMS", text: result.sms, otp: otp });
            console.log("Provider SMS received for session", sess.id, "otp:", otp);
          }
        }
      } catch(e) { console.error("Poll session", sess.id, "error:", e.message); }
    }
  } catch(e) { console.error("pollProviderSessions error:", e.message); }
}
// ============ END PROVIDER ADAPTERS ============

function broadcast(message) {
  const payload = JSON.stringify(message);
  for (const socket of sockets) {
    if (socket.readyState === WebSocket.OPEN) socket.send(payload);
  }
}

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS numbers (id SERIAL PRIMARY KEY, phone_number TEXT NOT NULL UNIQUE, price_sats INTEGER NOT NULL CHECK (price_sats > 0), active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invoices (id BIGSERIAL PRIMARY KEY, provider_payment_id TEXT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, number_id INTEGER NOT NULL REFERENCES numbers(id) ON DELETE CASCADE, amount_sats INTEGER NOT NULL CHECK (amount_sats > 0), status TEXT NOT NULL DEFAULT 'pending', checkout_url TEXT, qr TEXT, country TEXT, service TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, number_id INTEGER NOT NULL REFERENCES numbers(id) ON DELETE CASCADE, invoice_id BIGINT REFERENCES invoices(id) ON DELETE SET NULL, expires_at TIMESTAMPTZ NOT NULL, country TEXT, service TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS messages (id BIGSERIAL PRIMARY KEY, number_id INTEGER REFERENCES numbers(id) ON DELETE SET NULL, phone_number TEXT NOT NULL, text TEXT NOT NULL, otp TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`ALTER TABLE invoices ADD COLUMN IF NOT EXISTS country TEXT`);
  await pool.query(`ALTER TABLE invoices ADD COLUMN IF NOT EXISTS service TEXT`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country TEXT`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS service TEXT`);
  await pool.query(`CREATE TABLE IF NOT EXISTS p2p_listings (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, phone_number TEXT NOT NULL, price_sats INTEGER NOT NULL CHECK (price_sats > 0), description TEXT, active BOOLEAN NOT NULL DEFAULT TRUE, approved BOOLEAN NOT NULL DEFAULT FALSE, owner_earned_sats INTEGER NOT NULL DEFAULT 0, owner_paid_sats INTEGER NOT NULL DEFAULT 0, number_id INTEGER REFERENCES numbers(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`ALTER TABLE invoices ADD COLUMN IF NOT EXISTS p2p_listing_id BIGINT REFERENCES p2p_listings(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE p2p_listings ADD COLUMN IF NOT EXISTS number_id INTEGER REFERENCES numbers(id) ON DELETE SET NULL`);
  await pool.query(`CREATE TABLE IF NOT EXISTS send_numbers (id SERIAL PRIMARY KEY, phone_number TEXT NOT NULL UNIQUE, price_sats INTEGER NOT NULL CHECK (price_sats > 0), active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS outbox (id BIGSERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, send_number_id INTEGER REFERENCES send_numbers(id) ON DELETE SET NULL, recipient TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`ALTER TABLE outbox ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE outbox ADD COLUMN IF NOT EXISTS send_number_id INTEGER REFERENCES send_numbers(id) ON DELETE SET NULL`);
  await pool.query(`CREATE TABLE IF NOT EXISTS send_credits (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, send_number_id INTEGER NOT NULL REFERENCES send_numbers(id) ON DELETE CASCADE, invoice_id BIGINT, used BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`ALTER TABLE invoices ADD COLUMN IF NOT EXISTS send_number_id INTEGER REFERENCES send_numbers(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE invoices ALTER COLUMN number_id DROP NOT NULL`);
  await pool.query(`ALTER TABLE invoices ADD COLUMN IF NOT EXISTS is_deposit BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE TABLE IF NOT EXISTS wallets (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, balance_sats INTEGER NOT NULL DEFAULT 0)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS referral_codes (id SERIAL PRIMARY KEY, code TEXT UNIQUE NOT NULL, bonus_sats INTEGER NOT NULL DEFAULT 500, description TEXT, max_uses INTEGER NOT NULL DEFAULT 1000, uses_count INTEGER NOT NULL DEFAULT 0, is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS user_referrals (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, referral_code_id INTEGER NOT NULL REFERENCES referral_codes(id) ON DELETE CASCADE, used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(user_id, referral_code_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS announcements (id SERIAL PRIMARY KEY, title TEXT NOT NULL, body TEXT, is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS promo_ads (id SERIAL PRIMARY KEY, title TEXT NOT NULL, url TEXT NOT NULL, description TEXT, is_active BOOLEAN NOT NULL DEFAULT TRUE, sort_order INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sms_providers (id SERIAL PRIMARY KEY, name TEXT NOT NULL, provider_type TEXT NOT NULL DEFAULT 'smspool', api_key TEXT, api_secret TEXT, api_url TEXT, is_active BOOLEAN NOT NULL DEFAULT TRUE, notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`ALTER TABLE invoices ADD COLUMN IF NOT EXISTS provider TEXT`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS provider TEXT`);
  await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS provider_order_id TEXT`);
  await pool.query(`CREATE TABLE IF NOT EXISTS escrow_transactions (id TEXT PRIMARY KEY, listing_id BIGINT REFERENCES p2p_listings(id) ON DELETE SET NULL, buyer_id INTEGER REFERENCES users(id) ON DELETE SET NULL, seller_id INTEGER REFERENCES users(id) ON DELETE SET NULL, amount_sats INTEGER NOT NULL, seller_amount INTEGER NOT NULL, commission INTEGER NOT NULL, invoice_id TEXT, payment_request TEXT, status TEXT NOT NULL DEFAULT 'pending', dispute_reason TEXT, created_at BIGINT NOT NULL, paid_at BIGINT, released_at BIGINT)`);
  console.log("Database initialized.");
  setInterval(async function() {
    try {
      await pool.query("DELETE FROM messages WHERE created_at < NOW() - INTERVAL '24 hours'");
    } catch(e) { console.error("OTP cleanup error:", e.message); }
  }, 30 * 60 * 1000);
  setInterval(async function() {
    try {
      const cutoff = Date.now() - 30 * 60 * 1000;
      const result = await pool.query("SELECT * FROM escrow_transactions WHERE status='paid' AND paid_at < $1", [cutoff]);
      for (const tx of result.rows) {
        await releaseFunds(tx);
        console.log("Auto-released escrow:", tx.id);
      }
    } catch(e) { console.error("Escrow auto-release error:", e.message); }
  }, 60000);
}

let _newsCache = null;
let _newsCacheAt = 0;
const NEWS_TTL = 15 * 60 * 1000;
function fetchNewsFromUrl(url, resolve) {
  const opts = { headers: { "User-Agent": "SMSNero/1.0 (+https://smsnero.com)", "Accept": "application/rss+xml,application/xml,text/xml,*/*" } };
  const req = https.get(url, opts, function(resp) {
    if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
      return fetchNewsFromUrl(resp.headers.location, resolve);
    }
    let data = "";
    resp.on("data", function(c) { data += c; });
    resp.on("end", function() {
      try {
        const json = JSON.parse(data);
        if (json.status === "ok" && Array.isArray(json.items) && json.items.length) {
          const items = json.items.slice(0, 8).map(function(i) { return { title: String(i.title||"").trim(), link: String(i.link||i.url||"").trim() }; }).filter(function(i) { return i.title && i.link; });
          if (items.length) { _newsCache = items; _newsCacheAt = Date.now(); return resolve(items); }
        }
      } catch(e) {}
      const items = [];
      const re = /<item>[\s\S]*?<title[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>[\s\S]*?<link[^>]*>\s*([^\s<][^<]*)<\/link>/g;
      let m;
      while ((m = re.exec(data)) !== null && items.length < 8) {
        const title = m[1].replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").trim();
        const link = m[2].trim();
        if (title && link) items.push({ title, link });
      }
      if (items.length) { _newsCache = items; _newsCacheAt = Date.now(); return resolve(items); }
      resolve(_newsCache || []);
    });
  });
  req.on("error", function() { resolve(_newsCache || []); });
  req.setTimeout(8000, function() { req.destroy(); resolve(_newsCache || []); });
}
function fetchNews() {
  if (_newsCache && Date.now() - _newsCacheAt < NEWS_TTL) return Promise.resolve(_newsCache);
  return new Promise(function(resolve) {
    fetchNewsFromUrl("https://api.rss2json.com/v1/api.json?rss_url=https%3A%2F%2Fcointelegraph.com%2Frss&count=8", resolve);
  });
}

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SMSNero</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0c0f14">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="SMSNero">
  <link rel="manifest" href="/manifest.json">
  <link rel="apple-touch-icon" href="/icon-192.svg">
  <style>
    :root{--btn-a:#ff5500;--btn-b:#cc1a00;}
    *{box-sizing:border-box;}
    body{background-color:#0c0f14;background-image:radial-gradient(circle,#1c2535 1.5px,transparent 1.5px);background-size:22px 22px;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;}
    main{max-width:680px;margin:auto;padding:24px 16px;}
    h1{font-size:2em;font-weight:800;margin:0;background:linear-gradient(135deg,var(--btn-a),var(--btn-b));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;transition:background 0.3s;}
    h3{margin:4px 0 12px;font-size:1.1em;color:#e2e8f0;}
    h4{margin:0 0 10px;color:#e2e8f0;}
    .box{padding:18px;margin:12px 0;background:#131926;border-radius:16px;border:1px solid #1e2d40;box-shadow:0 2px 12px rgba(0,0,0,0.4);}
    button{background:linear-gradient(135deg,var(--btn-a),var(--btn-b));border:none;padding:10px 16px;cursor:pointer;margin:4px;font-weight:700;border-radius:10px;color:#fff;font-size:0.95em;transition:opacity 0.15s;}
    button:hover{opacity:0.85;}
    button:active{opacity:0.7;}
    .btn-secondary{background:linear-gradient(135deg,#2a3040,#1e2535)!important;color:#aab4c8!important;border:1px solid #2a3a50!important;}
    .btn-danger{background:linear-gradient(135deg,#7f1d1d,#450a0a)!important;color:#fca5a5!important;border:1px solid #ef4444!important;}
    .btn-theme{background:#1e2d40!important;border:1px solid #2a3a50!important;padding:0!important;width:38px;height:38px;border-radius:50%!important;font-size:1.15em;display:inline-flex;align-items:center;justify-content:center;transition:transform 0.2s!important;}
    .btn-theme:hover{transform:scale(1.15);opacity:1!important;}
    .btn-lang{background:#1e2d40!important;border:1px solid #2a3a50!important;padding:0 10px!important;height:38px;border-radius:20px!important;font-size:0.82em;font-weight:700;display:inline-flex;align-items:center;gap:5px;color:#aab4c8!important;letter-spacing:0.5px;transition:transform 0.2s!important;}
    .btn-lang:hover{transform:scale(1.07);opacity:1!important;color:#e2e8f0!important;}
    input,textarea,select{padding:10px 12px;margin:4px;border-radius:10px;border:1px solid #2a3a50;background:#0d1520;color:#e2e8f0;font-size:0.95em;}
    input::placeholder,textarea::placeholder{color:#4a5568;}
    a{color:#ff8040;}
    img{background:white;padding:8px;border-radius:10px;}
    .error{color:#fc8181;}
    .muted{color:#718096;}
    .row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;}
    .tabs{display:flex;gap:4px;margin:18px 0 0;background:#131926;border:1px solid #1e2d40;border-radius:14px;padding:5px;}
    .tab{background:none;border:none;color:#718096;padding:9px 0;font-size:0.95em;font-weight:600;border-radius:10px;cursor:pointer;margin:0;flex:1;transition:all 0.2s;}
    .tab.active{background:#ffffff;color:#0c0f14;}
    .badge{background:linear-gradient(135deg,var(--btn-a),var(--btn-b));color:#fff;border-radius:10px;padding:2px 8px;font-size:0.78em;margin-left:5px;}
    .ln-yellow{color:#fbbf24;font-weight:bold;}
  </style>
</head>
<body>
  <main>
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;">
      <h1>&#9889; SMSNero</h1>
      <div style="display:flex;gap:6px;align-items:center;">
        <button id="lang-btn" class="btn-lang" onclick="cycleLang()" title="Change language">&#127760; <span id="lang-label">EN</span></button>
        <button id="theme-btn" class="btn-theme" onclick="cycleTheme()" title="Change color theme">&#128293;</button>
      </div>
    </div>
    <p class="muted" id="subtitle">Rent phone numbers and receive SMS/OTP messages. Paid via Bitcoin Lightning.</p>
    <div class="box">
      <button id="btn-register" onclick="registerUser()">&#9889; <span data-i18n="register">Register</span></button>
      <button id="btn-logout" onclick="logout()" class="btn-secondary"><span data-i18n="logout">Logout</span></button>
      <div id="status" class="muted"></div>
      <div id="wallet-bar" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid #1e2d40;align-items:center;gap:10px;flex-wrap:wrap;">
        <span style="color:#fbbf24;font-weight:bold;font-size:1.05em;">&#9889; <span data-i18n="wallet">Wallet</span>: <span id="wallet-bal">0</span> sats</span>
        <button id="btn-deposit" onclick="showDepositForm()" style="padding:6px 14px;font-size:0.88em;">+ <span data-i18n="deposit">Deposit</span></button>
        <div id="deposit-form" style="display:none;width:100%;margin-top:10px;">
          <input id="dep-amount" type="number" min="100" placeholder="Amount in sats" style="width:160px">
          <button onclick="doDeposit()">&#9889; Pay via Lightning</button>
          <button onclick="cancelDeposit()" class="btn-secondary" style="padding:8px 14px;">Cancel</button>
          <div id="deposit-qr" style="margin-top:10px;"></div>
        </div>
      </div>
      <div id="referral-bar" style="display:none;width:100%;margin-top:10px;padding-top:10px;border-top:1px solid #1e2d40;">
        <div style="margin-bottom:8px;" id="available-ref-codes-box"></div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span class="muted" style="font-size:0.85em;">&#127381; <span data-i18n="ref_label">Referral code:</span></span>
          <input id="ref-code" placeholder="Enter code" style="width:130px;font-size:0.88em;padding:6px 10px;">
          <button onclick="useReferral()" style="padding:6px 14px;font-size:0.88em;"><span data-i18n="ref_apply">Apply</span></button>
        </div>
      </div>
    </div>
    <div id="admin" class="box" style="display:none"></div>
    <div class="tabs">
      <button class="tab active" id="tab-btn-rent" onclick="switchTab('rent')"><span data-i18n="tab_otp">Receive OTP</span></button>
      <button class="tab" id="tab-btn-p2p" onclick="switchTab('p2p')"><span data-i18n="tab_p2p">P2P Market</span></button>
      <button class="tab" id="tab-btn-send" onclick="switchTab('send')"><span data-i18n="tab_send">Send SMS</span></button>
    </div>
    <div id="tab-rent">
      <div id="qr"></div>
      <div id="provider-box" class="box" style="display:none;"></div>
      <div id="numbers" class="box"><p class="muted" style="font-size:0.9em;">Buy a number to receive a one-time OTP verification code (Telegram, WhatsApp, etc.).</p>Login or register to load numbers.</div>
      <div id="sessions" class="box"><h3>My active numbers</h3></div>
      <div id="otp" class="box"><h3>OTP Inbox</h3></div>
    </div>
    <div id="tab-p2p" style="display:none">
      <div class="box"><h3>P2P Market</h3><p class="muted">Numbers listed by the community. Escrow protected &mdash; seller gets <strong style="color:#4ade80;">92%</strong>, platform 8% fee. Funds auto-released after 30 min.</p><div id="p2p-market"><p class="muted">Login to view marketplace.</p></div></div>
      <div class="box" id="p2p-submit-box" style="display:none"><h3>List your number</h3><input id="p2p-phone" placeholder="+46700000001" style="width:180px"> <span style="display:inline-flex;align-items:center;gap:4px;"><input id="p2p-price" type="number" min="1" placeholder="0" style="width:110px"> <span class="ln-yellow">sats</span></span> <input id="p2p-desc" placeholder="Description (optional)" style="width:220px"><br><button onclick="submitP2P()">&#9889; Submit for approval</button><p class="muted" style="font-size:0.85em;margin-top:8px;">Your earnings (92%) paid directly to your wallet when buyer confirms. Price is in satoshis.</p></div>
      <div id="p2p-my-listings"></div>
      <div id="escrow-txs-box" class="box" style="display:none;margin-top:10px;"><div id="escrow-txs"></div><div id="withdraw-form" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid #1e2d40;"><input id="ln-address" placeholder="Lightning address (user@domain.com)" style="width:100%;margin-bottom:6px;"><button onclick="doWithdraw()">&#9889; Withdraw to Lightning</button></div></div>
    </div>
    <div id="tab-send" style="display:none">
      <div class="box" id="send-login-box" style="display:none"><p class="muted">Login or register to use Send SMS.</p></div>
      <!-- ADMIN view -->
      <div id="send-admin-panel" style="display:none">
        <div class="box">
          <h3>Send Numbers</h3>
          <p class="muted" style="font-size:0.88em;">Add numbers that clients can send SMS from (sent via MacroDroid from your phone).</p>
          <input id="sn-phone" placeholder="+46700000001" style="width:180px">
          <span style="display:inline-flex;align-items:center;gap:4px;"><input id="sn-price" type="number" min="1" placeholder="0" style="width:110px"><span style="color:#facc15;font-weight:bold;">sats</span></span>
          <button onclick="addSendNumber()">&#9889; Add number</button>
          <div id="send-numbers-admin-list" style="margin-top:10px;"></div>
        </div>
        <div class="box"><h3>Outbox</h3><div id="outbox-list"><p class="muted">No messages yet.</p></div></div>
        <div class="box" style="background:#1a1a2e;border:1px solid #3333aa;">
          <h4 style="color:#a5b4fc;">MacroDroid Setup (jednom)</h4>
          <ol style="color:#ccc;font-size:0.87em;line-height:1.9em;">
            <li><strong>Trigger:</strong> Periodic timer &mdash; svake <strong>30 sekundi</strong></li>
            <li><strong>Action 1:</strong> HTTP Request GET &rarr;<br>
              <code id="poll-url" style="color:#facc15;font-size:0.9em;word-break:break-all;"></code><br>
              <span style="color:#94a3b8;font-size:0.85em;">Header: <code style="color:#a5b4fc;">Authorization: Bearer <span id="macro-token-display" style="color:#fbbf24;font-size:0.92em;word-break:break-all;"></span></code></span>
            </li>
            <li><strong>Condition:</strong> HTTP response code = 200 (preskoči ako 204)</li>
            <li><strong>Action 2:</strong> Send SMS &rarr; primatelj: <code style="color:#a5b4fc;">{http_response_body:json_object:recipient}</code> &nbsp; tekst: <code style="color:#a5b4fc;">{http_response_body:json_object:message}</code></li>
            <li><strong>Action 3:</strong> HTTP Request GET &rarr;<br>
              <code id="ack-url" style="color:#4ade80;font-size:0.9em;word-break:break-all;"></code><br>
              <span style="color:#94a3b8;font-size:0.85em;">Header: Authorization: Bearer &lt;isti token&gt;</span>
            </li>
          </ol>
        </div>
      </div>
      <!-- CLIENT view -->
      <div id="send-client-panel" style="display:none">
        <div class="box"><h3>Send SMS</h3><p class="muted">Buy a credit to send one SMS from our number. Paid via Bitcoin Lightning.</p><div id="send-numbers-list"><p class="muted">Loading...</p></div></div>
        <div id="send-qr"></div>
        <div class="box" id="send-compose-box" style="display:none">
          <h3>Compose message</h3>
          <p class="muted" style="font-size:0.87em;">You have a send credit. Enter recipient and message:</p>
          <div style="display:flex;flex-direction:column;gap:8px;max-width:480px;">
            <input id="send-recipient" placeholder="Recipient number (+38761...)" style="width:100%">
            <textarea id="send-message" placeholder="Message text..." rows="4" style="width:100%;box-sizing:border-box;resize:vertical;"></textarea>
            <button onclick="submitMessage()" style="width:100%;">&#9889; Send Message</button>
          </div>
        </div>
        <div class="box" id="my-sent-box" style="display:none"><h3>My sent messages</h3><div id="my-sent-list"></div></div>
      </div>
    </div>
    <div id="announcements-box" class="box" style="display:none;margin-top:18px;"></div>
    <div id="promo-ads-box" class="box" style="display:none;margin-top:12px;"></div>
    <div id="news-box" class="box" style="margin-top:12px;"><p class="muted" style="font-size:0.9em;">Loading crypto news...</p></div>
    <div class="box" style="margin-top:12px;padding:14px 16px;">
      <p style="margin:0 0 8px;font-size:0.82em;color:#64748b;font-weight:600;letter-spacing:0.06em;">&#128274; ADMIN LOGIN</p>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <input id="adminPass" type="password" placeholder="Admin password" style="flex:1;min-width:140px;max-width:220px;">
        <button id="admin-login-btn" style="padding:8px 18px;font-size:0.9em;">Login</button>
      </div>
      <div id="admin-login-status" style="margin-top:8px;font-size:0.88em;min-height:1.2em;"></div>
    </div>
  </main>
  <script>
    var token=localStorage.getItem("smsnero_token")||"";
    var _myUserId=Number(localStorage.getItem("smsnero_uid")||0);
    var role=localStorage.getItem("smsnero_role")||"";
    var _activeTab="rent";
    var THEMES=[{e:"&#128293;",a:"#ff5500",b:"#cc1a00"},{e:"&#128153;",a:"#1d4ed8",b:"#1e40af"},{e:"&#128154;",a:"#16a34a",b:"#15803d"},{e:"&#128155;",a:"#7c3aed",b:"#6d28d9"},{e:"&#128156;",a:"#db2777",b:"#be185d"},{e:"&#129473;",a:"#0891b2",b:"#0e7490"},{e:"&#128149;",a:"#d97706",b:"#92400e"}];
    var _themeIdx=Number(localStorage.getItem("smsnero_theme")||0);
    function applyTheme(idx){var th=THEMES[idx%THEMES.length];document.documentElement.style.setProperty("--btn-a",th.a);document.documentElement.style.setProperty("--btn-b",th.b);var btn=document.getElementById("theme-btn");if(btn)btn.innerHTML=th.e;}
    function cycleTheme(){_themeIdx=(_themeIdx+1)%THEMES.length;localStorage.setItem("smsnero_theme",_themeIdx);applyTheme(_themeIdx);}
    var LANGS=[
      {code:"EN",flag:"&#127482;&#127480;",strings:{subtitle:"Rent phone numbers and receive SMS/OTP messages. Paid via Bitcoin Lightning.",register:"Register",logout:"Logout",wallet:"Wallet",deposit:"Deposit",ref_label:"Referral code:",ref_apply:"Apply",tab_otp:"Receive OTP",tab_p2p:"P2P Market",tab_send:"Send SMS",avail_nums:"Available numbers",no_nums:"No numbers available.",login_req:"Login or register to load numbers.",my_nums:"My active numbers",otp_inbox:"OTP Inbox",list_num:"List your number",get_num:"Get a Number",cancel:"Cancel",price:"Price",select_country:"Select country",select_service:"Select service"}},
      {code:"SR",flag:"&#127479;&#127480;",strings:{subtitle:"Iznajmi telefonski broj i primaj SMS/OTP poruke. Plaćanje putem Bitcoin Lightning.",register:"Registruj se",logout:"Odjava",wallet:"Novčanik",deposit:"Uplata",ref_label:"Promo kod:",ref_apply:"Primeni",tab_otp:"Primi OTP",tab_p2p:"P2P Tržnica",tab_send:"Pošalji SMS",avail_nums:"Dostupni brojevi",no_nums:"Nema dostupnih brojeva.",login_req:"Prijavi se ili registruj.",my_nums:"Moji aktivni brojevi",otp_inbox:"OTP Sandučić",list_num:"Oglasi svoj broj",get_num:"Nabavi broj",cancel:"Odustani",price:"Cena",select_country:"Odaberi državu",select_service:"Odaberi servis"}},
      {code:"DE",flag:"&#127465;&#127466;",strings:{subtitle:"Telefonnummern mieten und SMS/OTP empfangen. Zahlung per Bitcoin Lightning.",register:"Registrieren",logout:"Abmelden",wallet:"Wallet",deposit:"Einzahlen",ref_label:"Promo-Code:",ref_apply:"Anwenden",tab_otp:"OTP Empfangen",tab_p2p:"P2P Markt",tab_send:"SMS Senden",avail_nums:"Verfügbare Nummern",no_nums:"Keine Nummern verfügbar.",login_req:"Einloggen oder registrieren.",my_nums:"Meine aktiven Nummern",otp_inbox:"OTP Posteingang",list_num:"Deine Nummer anbieten",get_num:"Nummer besorgen",cancel:"Abbrechen",price:"Preis",select_country:"Land wählen",select_service:"Dienst wählen"}},
      {code:"RU",flag:"&#127479;&#127482;",strings:{subtitle:"Аренда номеров для получения SMS/OTP. Оплата через Bitcoin Lightning.",register:"Регистрация",logout:"Выйти",wallet:"Кошелёк",deposit:"Пополнить",ref_label:"Промо-код:",ref_apply:"Применить",tab_otp:"Получить OTP",tab_p2p:"P2P Рынок",tab_send:"Отправить SMS",avail_nums:"Доступные номера",no_nums:"Нет доступных номеров.",login_req:"Войдите или зарегистрируйтесь.",my_nums:"Мои активные номера",otp_inbox:"OTP Входящие",list_num:"Листинг номера",get_num:"Получить номер",cancel:"Отмена",price:"Цена",select_country:"Выберите страну",select_service:"Выберите сервис"}},
      {code:"ES",flag:"&#127466;&#127480;",strings:{subtitle:"Alquila números de teléfono y recibe SMS/OTP. Pago con Bitcoin Lightning.",register:"Registrarse",logout:"Cerrar sesión",wallet:"Cartera",deposit:"Depositar",ref_label:"Código de referido:",ref_apply:"Aplicar",tab_otp:"Recibir OTP",tab_p2p:"Mercado P2P",tab_send:"Enviar SMS",avail_nums:"Números disponibles",no_nums:"No hay números disponibles.",login_req:"Inicia sesión o regístrate.",my_nums:"Mis números activos",otp_inbox:"Bandeja OTP",list_num:"Listar tu número",get_num:"Obtener un número",cancel:"Cancelar",price:"Precio",select_country:"Seleccionar país",select_service:"Seleccionar servicio"}},
      {code:"TR",flag:"&#127481;&#127479;",strings:{subtitle:"Telefon numarası kirala ve SMS/OTP mesajları al. Bitcoin Lightning ile ödeme.",register:"Kayıt ol",logout:"Çıkış",wallet:"Cüzdan",deposit:"Para yatır",ref_label:"Referans kodu:",ref_apply:"Uygula",tab_otp:"OTP Al",tab_p2p:"P2P Pazar",tab_send:"SMS Gönder",avail_nums:"Mevcut numaralar",no_nums:"Mevcut numara yok.",login_req:"Giriş yap veya kayıt ol.",my_nums:"Aktif numaralarım",otp_inbox:"OTP Gelen Kutusu",list_num:"Numaranı listele",get_num:"Numara al",cancel:"İptal",price:"Fiyat",select_country:"Ülke seç",select_service:"Servis seç"}}
    ];
    var _langIdx=Number(localStorage.getItem("smsnero_lang")||0);
    function t(key){var l=LANGS[_langIdx%LANGS.length];return(l&&l.strings[key])||LANGS[0].strings[key]||key;}
    function cycleLang(){_langIdx=(_langIdx+1)%LANGS.length;localStorage.setItem("smsnero_lang",_langIdx);applyLang();loadNumbers();loadSessions();loadMessages();}
    function applyLang(){var l=LANGS[_langIdx%LANGS.length];var lb=document.getElementById("lang-label");if(lb)lb.innerHTML=l.flag+" "+l.code;var sub=document.getElementById("subtitle");if(sub)sub.textContent=t("subtitle");document.querySelectorAll("[data-i18n]").forEach(function(el){var k=el.getAttribute("data-i18n");if(k&&t(k))el.textContent=t(k);});var ri=document.getElementById("ref-code");if(ri)ri.placeholder=t("ref_label").replace(":","");var sh=document.querySelector("#sessions h3");if(sh)sh.textContent=t("my_nums");var oh=document.querySelector("#otp h3");if(oh)oh.textContent=t("otp_inbox");}
    function esc(v){return String(v).replace(/[&<>'"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]});}
    function setStatus(msg,err){var el=document.getElementById("status");el.className=err?"error":"muted";el.textContent=msg;}
    function authH(ex){return Object.assign({},ex||{},{Authorization:"Bearer "+token});}
    function saveSession(d){token=d.token;role=d.user.role;_myUserId=d.user.id||0;localStorage.setItem("smsnero_token",token);localStorage.setItem("smsnero_role",role);localStorage.setItem("smsnero_uid",String(_myUserId));requestNotifPerm();}
    function requestNotifPerm(){if(typeof Notification!=="undefined"&&Notification.permission==="default")Notification.requestPermission();}
    function showNotif(title,body){if(typeof Notification!=="undefined"&&Notification.permission==="granted"){try{new Notification(title,{body:body});}catch(e){}}}
    function playPling(freq,duration){try{var ctx=new(window.AudioContext||window.webkitAudioContext)();var o=ctx.createOscillator();var g=ctx.createGain();o.connect(g);g.connect(ctx.destination);o.type="sine";o.frequency.setValueAtTime(freq||880,ctx.currentTime);g.gain.setValueAtTime(0.4,ctx.currentTime);g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+(duration||0.6));o.start(ctx.currentTime);o.stop(ctx.currentTime+(duration||0.6));}catch(e){}}
    function playSaleAlert(){playPling(880,0.25);setTimeout(function(){playPling(1100,0.35);},200);}
    function playDisputeAlert(){playPling(440,0.4);setTimeout(function(){playPling(330,0.5);},350);}
    function countdown(expiresAt){var ms=new Date(expiresAt)-Date.now();if(ms<=0)return"Expired";var h=Math.floor(ms/3600000);var m=Math.floor((ms%3600000)/60000);return h>0?h+"h "+m+"m left":m+"m left";}
    async function loadAvailableRefCodes(){var box=document.getElementById("available-ref-codes-box");if(!box)return;try{var r=await fetch("/public/referral-codes");if(!r.ok)return;var data=await r.json();if(!data||!data.length){box.innerHTML="";return;}var h="<div style='font-size:0.82em;color:#94a3b8;margin-bottom:4px;'>&#127381; Active promo codes:</div><div style='display:flex;flex-wrap:wrap;gap:6px;'>";data.forEach(function(i){h+="<button data-code='"+esc(i.code)+"' onclick='applyRefCode(this.dataset.code)' style='padding:5px 12px;font-size:0.82em;background:linear-gradient(135deg,#1a1500,#2a1f00);border:1px solid #fbbf24;color:#fbbf24;border-radius:8px;cursor:pointer;display:flex;flex-direction:column;align-items:flex-start;gap:2px;'><strong>"+esc(i.code)+"</strong><span style='color:#4ade80;font-size:0.88em;'>+"+esc(String(i.bonus_sats))+" sats</span>"+(i.description?"<span style='color:#94a3b8;font-size:0.8em;'>"+esc(i.description)+"</span>":"")+"</button>";});h+="</div>";box.innerHTML=h;}catch(e){box.innerHTML="";}}
    function applyRefCode(code){var inp=document.getElementById("ref-code");if(inp){inp.value=code;useReferral();}}
    async function loadWalletBalance(){var bar=document.getElementById("wallet-bar");var refBar=document.getElementById("referral-bar");if(!token||role==="admin"){bar.style.display="none";if(refBar)refBar.style.display="none";return;}var r=await fetch("/wallet/balance",{headers:authH()});if(!r.ok)return;var d=await r.json();document.getElementById("wallet-bal").textContent=d.balance_sats;bar.style.display="flex";if(refBar){refBar.style.display="block";loadAvailableRefCodes();}}
    async function useReferral(){var code=document.getElementById("ref-code").value.trim().toUpperCase();if(!code)return setStatus("Enter a referral code.",true);var r=await fetch("/use-referral",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({code:code})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Invalid code.",true);setStatus("Code applied! +"+d.bonus_sats+" sats added to your wallet.",false);document.getElementById("ref-code").value="";loadWalletBalance();loadAvailableRefCodes();}
    async function loadAnnouncements(){var r=await fetch("/public/announcements");if(!r.ok)return;var data=await r.json();var box=document.getElementById("announcements-box");if(!data.length){box.style.display="none";return;}box.style.display="block";var h="<h3>&#128226; Announcements</h3>";data.forEach(function(i){h+="<div style='padding:10px 0;border-bottom:1px solid #1e2d40;'><strong>"+esc(i.title)+"</strong>"+(i.body?"<br><span class='muted' style='font-size:0.9em;'>"+esc(i.body)+"</span>":"")+"</div>";});box.innerHTML=h;}
    async function loadPromoAds(){var r=await fetch("/public/promo-ads");if(!r.ok)return;var data=await r.json();var box=document.getElementById("promo-ads-box");if(!data.length){box.style.display="none";return;}box.style.display="block";var h="<h3>&#127381; Sponsored</h3><div style='display:flex;flex-wrap:wrap;gap:10px;'>";data.forEach(function(i){h+="<a href='"+esc(i.url)+"' target='_blank' rel='noopener' style='display:block;background:#1a1500;border:1px solid #fbbf24;border-radius:12px;padding:12px 16px;color:#fbbf24;text-decoration:none;flex:1;min-width:180px;'><strong>"+esc(i.title)+"</strong>"+(i.description?"<br><span style='color:#94a3b8;font-size:0.85em;'>"+esc(i.description)+"</span>":"")+"</a>";});h+="</div>";box.innerHTML=h;}
    var _STATIC_NEWS=[{title:"Bitcoin Price & Charts — CoinTelegraph",link:"https://cointelegraph.com/bitcoin-price"},{title:"Lightning Network Stats — mempool.space",link:"https://mempool.space/lightning"},{title:"Bitcoin News — Bitcoin Magazine",link:"https://bitcoinmagazine.com/articles"},{title:"Crypto Markets — CoinGecko",link:"https://www.coingecko.com"},{title:"Bitcoin Fees — mempool.space",link:"https://mempool.space"}];
    async function loadCryptoNews(){var r=await fetch("/public/news");var data=r.ok?await r.json().catch(function(){return[];}):[]; if(!data||!data.length)data=_STATIC_NEWS;var box=document.getElementById("news-box");var h="<h3>&#128240; Crypto News</h3>";data.forEach(function(i){h+="<div style='padding:7px 0;border-bottom:1px solid #1e2d40;'><a href='"+esc(i.link)+"' target='_blank' rel='noopener' style='color:#e2e8f0;text-decoration:none;font-size:0.9em;line-height:1.4;'>"+esc(i.title)+"</a></div>";});h+="<div style='margin-top:8px;'><span class='muted' style='font-size:0.75em;'>Updates every 15 min &bull; Source: CoinTelegraph</span></div>";box.innerHTML=h;}
    function showDepositForm(){var f=document.getElementById("deposit-form");f.style.display=f.style.display==="none"?"block":"none";}
    function cancelDeposit(){document.getElementById("deposit-form").style.display="none";document.getElementById("deposit-qr").innerHTML="";}
    var _depositInvoice="";
    function copyDepositInvoice(){if(!_depositInvoice)return;navigator.clipboard.writeText(_depositInvoice).then(function(){setStatus("Copied!",false);}).catch(function(){setStatus("Copy failed.",true);});}
    async function doDeposit(){var amt=Number(document.getElementById("dep-amount").value);if(!amt||amt<100)return setStatus("Minimum deposit is 100 sats.",true);var r=await fetch("/wallet/deposit",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({amountSats:amt})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);_depositInvoice=d.lightning_invoice||"";var lnHtml=_depositInvoice?"<textarea style='width:100%;box-sizing:border-box;background:#111;color:#facc15;border:1px solid #444;border-radius:8px;padding:8px;font-size:0.75em;resize:none;margin-top:6px;' rows='2' readonly>"+esc(_depositInvoice)+"</textarea><br><button onclick='copyDepositInvoice()' style='margin-top:4px;padding:4px 10px;font-size:0.85em;'>Copy Invoice</button>":"";var chkHtml=d.checkout_url?"<br><a href='"+esc(d.checkout_url)+"' target='_blank' style='font-size:0.9em;'>Open in wallet</a>":"";document.getElementById("deposit-qr").innerHTML="<img src='"+esc(d.qr)+"' width='160' style='display:block;margin-bottom:6px;'>"+lnHtml+chkHtml;setStatus("Scan QR to deposit "+amt+" sats. Wallet updates automatically.",false);}
    async function loadAdminStats(){if(role!=="admin")return;var r=await fetch("/admin/stats",{headers:authH()});if(!r.ok)return;var d=await r.json();var svc=d.top_services.map(function(s){return esc(s.service)+" ("+s.cnt+")";}).join(", ")||"—";var h="<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:14px;'>";h+="<div class='box' style='margin:0;text-align:center;'><div class='muted' style='font-size:0.8em;'>Total Revenue</div><div style='font-size:1.4em;font-weight:bold;color:#facc15;'>"+d.total_revenue+"</div><div class='muted' style='font-size:0.75em;'>sats</div></div>";h+="<div class='box' style='margin:0;text-align:center;'><div class='muted' style='font-size:0.8em;'>Today</div><div style='font-size:1.4em;font-weight:bold;color:#4ade80;'>"+d.today_revenue+"</div><div class='muted' style='font-size:0.75em;'>sats</div></div>";h+="<div class='box' style='margin:0;text-align:center;'><div class='muted' style='font-size:0.8em;'>Active Sessions</div><div style='font-size:1.4em;font-weight:bold;'>"+d.active_sessions+"</div></div>";h+="<div class='box' style='margin:0;text-align:center;'><div class='muted' style='font-size:0.8em;'>P2P Revenue</div><div style='font-size:1.4em;font-weight:bold;color:#a5b4fc;'>"+d.p2p_revenue+"</div><div class='muted' style='font-size:0.75em;'>sats</div></div>";h+="<div class='box' style='margin:0;text-align:center;'><div class='muted' style='font-size:0.8em;'>SMS Sent</div><div style='font-size:1.4em;font-weight:bold;'>"+d.sms_sent+"</div></div>";h+="</div><p class='muted' style='font-size:0.85em;'>Top services: "+svc+"</p>";return h;}
    function switchTab(name){_activeTab=name;["rent","p2p","send"].forEach(function(t){document.getElementById("tab-"+t).style.display=t===name?"block":"none";var btn=document.getElementById("tab-btn-"+t);btn.classList.toggle("active",t===name);});if(name==="p2p"&&token){loadP2PMarket();loadMyP2PListings();loadEscrowTxs();}if(name==="send"){renderSendTab();}}
    function logout(){token="";role="";_myUserId=0;localStorage.removeItem("smsnero_token");localStorage.removeItem("smsnero_role");localStorage.removeItem("smsnero_uid");setStatus("Logged out.",false);renderAdmin();document.getElementById("wallet-bar").style.display="none";document.getElementById("referral-bar").style.display="none";document.getElementById("deposit-form").style.display="none";document.getElementById("deposit-qr").innerHTML="";document.getElementById("numbers").innerHTML=t("login_req");document.getElementById("sessions").innerHTML="<h3>"+t("my_nums")+"</h3>";document.getElementById("otp").innerHTML="<h3>"+t("otp_inbox")+"</h3>";document.getElementById("p2p-market").innerHTML="<p class='muted'>Login to view marketplace.</p>";document.getElementById("p2p-submit-box").style.display="none";document.getElementById("p2p-my-listings").innerHTML="";}
    async function registerUser(){var r=await fetch("/register",{method:"POST"});var d=await r.json();if(!r.ok)return setStatus(d.error||"Register error.",true);saveSession(d);setStatus("Registered. Token saved.",false);refreshAll();}
    function showWithdrawForm(){var el=document.getElementById("withdraw-form");if(el)el.style.display="block";}
    function setAdminStatus(msg,err){var el=document.getElementById("admin-login-status");if(el){el.style.color=err?"#fc8181":"#4ade80";el.textContent=msg;}setStatus(msg,err);}
    async function adminLogin(){var btn=document.getElementById("admin-login-btn");try{var pw=document.getElementById("adminPass").value;if(!pw)return setAdminStatus("Enter admin password.",true);if(btn)btn.disabled=true;setAdminStatus("Logging in...",false);var r=await fetch("/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pw})});var d=await r.json().catch(function(){return{error:"Server error"};});if(!r.ok){if(btn)btn.disabled=false;return setAdminStatus(d.error||"Wrong password.",true);}saveSession(d);setAdminStatus("Admin logged in!",false);refreshAll();}catch(e){if(btn)btn.disabled=false;setAdminStatus("Error: "+e.message,true);}}
    async function testSMS(){var n=prompt("Phone number (e.g. +46705536378):");if(!n)return;var t=prompt("SMS text (e.g. Your code is 123456):");if(!t)return;var r=await fetch("/test-sms",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({number:n,text:t})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Test SMS injected! OTP: "+(d.otp||"none"),false);loadMessages();}
    async function renderAdmin(){var box=document.getElementById("admin");if(role!=="admin"){box.style.display="none";box.innerHTML="";return;}box.style.display="block";var statsHtml=await loadAdminStats()||"";box.innerHTML="<h3>&#9889; Admin panel</h3>"+statsHtml+"<input id='an' placeholder='+46700000001'> <input id='ap' type='number' min='1' placeholder='sats'> <button onclick='addNum()'>&#9889; Add number</button> <button onclick='testSMS()' class='btn-secondary'>Test SMS</button><div id='adminList'></div><hr style='border-color:#1e2d40;margin:16px 0'><h4>P2P Listings</h4><div id='adminP2PList'></div><hr style='border-color:#1e2d40;margin:16px 0'><h4>&#127381; Referral Codes</h4><div id='adminRefCodes'></div><hr style='border-color:#1e2d40;margin:16px 0'><h4>&#128226; Announcements</h4><div id='adminAnnouncements'></div><hr style='border-color:#1e2d40;margin:16px 0'><h4>&#127381; Promo Ads (Affiliate Links)</h4><p class='muted' style='font-size:0.85em;'>Your Binance, Nexo, and other referral links shown as banners to all users.</p><div id='adminPromoAds'></div><hr style='border-color:#1e2d40;margin:16px 0'><h4>&#128241; SMS Provider APIs</h4><p class='muted' style='font-size:0.85em;'>Connect SMSPool, SMSHero, Twilio, Vonage, Sinch and others. API keys stored securely. Unlimited providers.</p><div id='adminSmsProviders'></div><hr style='border-color:#1e2d40;margin:16px 0'><h4>&#128274; Escrow Disputes</h4><p class='muted' style='font-size:0.85em;'>Transactions in dispute. Resolve manually — choose winner: buyer (refund) or seller (release funds).</p><div id='adminEscrowList'></div>";loadAdminNums();loadAdminP2P();loadAdminRefCodes();loadAdminAnnouncements();loadAdminPromoAds();loadAdminSmsProviders();loadAdminEscrow();}
    var _refCodesData={};
    async function loadAdminRefCodes(){if(role!=="admin")return;var r=await fetch("/admin/referral-codes",{headers:authH()});if(!r.ok)return;var data=await r.json();_refCodesData={};var h="<div style='display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;'><input id='rc-code' placeholder='Code (e.g. SUMMER25)' style='width:150px'><input id='rc-sats' type='number' placeholder='Bonus sats' style='width:120px'><input id='rc-desc' placeholder='Description' style='width:180px'><button onclick='addRefCode()'>&#9889; Add Code</button></div>";data.forEach(function(i){_refCodesData[i.id]=i;h+="<div class='box row'><span><strong style='color:#fbbf24;'>"+esc(i.code)+"</strong> &mdash; <span class='ln-yellow'>+"+esc(i.bonus_sats)+" sats</span> &mdash; used "+esc(i.uses_count)+"/"+esc(i.max_uses)+" &mdash; <span style='color:"+(i.is_active?"#4ade80":"#fc8181")+"'>"+(i.is_active?"active":"disabled")+"</span>"+(i.description?"<br><span class='muted' style='font-size:0.85em;'>"+esc(i.description)+"</span>":"")+"</span><button onclick='deleteRefCode("+i.id+")' class='btn-danger' style='padding:6px 12px;'>Disable</button></div>";});document.getElementById("adminRefCodes").innerHTML=h||"<p class='muted'>No referral codes yet.</p>";}
    async function addRefCode(){var code=document.getElementById("rc-code").value.trim().toUpperCase();var sats=Number(document.getElementById("rc-sats").value);var desc=document.getElementById("rc-desc").value.trim();if(!code||!sats)return setStatus("Enter code and bonus sats.",true);var r=await fetch("/admin/referral-codes",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({code:code,bonusSats:sats,description:desc})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Referral code created: "+code,false);document.getElementById("rc-code").value="";document.getElementById("rc-sats").value="";document.getElementById("rc-desc").value="";loadAdminRefCodes();}
    async function deleteRefCode(id){if(!confirm("Disable this referral code?"))return;var r=await fetch("/admin/referral-codes/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Code disabled.",false);loadAdminRefCodes();}
    var _announcementsData={};
    async function loadAdminAnnouncements(){if(role!=="admin")return;var r=await fetch("/admin/announcements",{headers:authH()});if(!r.ok)return;var data=await r.json();_announcementsData={};var h="<div style='display:flex;flex-direction:column;gap:6px;margin-bottom:10px;'><input id='ann-title' placeholder='Title' style='width:100%;'><textarea id='ann-body' placeholder='Body text (optional)' rows='2' style='width:100%;resize:vertical;'></textarea><button onclick='addAnnouncement()' style='width:fit-content;'>&#128226; Post Announcement</button></div>";data.forEach(function(i){_announcementsData[i.id]=i;h+="<div class='box row'><span><strong>"+esc(i.title)+"</strong>"+(i.body?"<br><span class='muted' style='font-size:0.85em;'>"+esc(i.body)+"</span>":"")+"<br><span class='muted' style='font-size:0.8em;'>"+esc(new Date(i.created_at).toLocaleString())+"</span></span><button onclick='deleteAnnouncement("+i.id+")' class='btn-danger' style='padding:6px 12px;'>Delete</button></div>";});document.getElementById("adminAnnouncements").innerHTML=h||"<p class='muted'>No announcements.</p>";}
    async function addAnnouncement(){var title=document.getElementById("ann-title").value.trim();var body=document.getElementById("ann-body").value.trim();if(!title)return setStatus("Enter a title.",true);var r=await fetch("/admin/announcements",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({title:title,body:body})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Announcement posted.",false);document.getElementById("ann-title").value="";document.getElementById("ann-body").value="";loadAdminAnnouncements();loadAnnouncements();}
    async function deleteAnnouncement(id){if(!confirm("Delete this announcement?"))return;var r=await fetch("/admin/announcements/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Deleted.",false);loadAdminAnnouncements();loadAnnouncements();}
    var _promoAdsData={};
    async function loadAdminPromoAds(){if(role!=="admin")return;var r=await fetch("/admin/promo-ads",{headers:authH()});if(!r.ok)return;var data=await r.json();_promoAdsData={};var h="<div style='display:flex;flex-direction:column;gap:6px;margin-bottom:10px;'><input id='pa-title' placeholder='Title (e.g. Binance - Best Exchange)' style='width:100%;'><input id='pa-url' placeholder='Your referral URL (https://...)' style='width:100%;'><input id='pa-desc' placeholder='Short description (optional)' style='width:100%;'><button onclick='addPromoAd()' style='width:fit-content;'>&#127381; Add Ad</button></div>";data.forEach(function(i){_promoAdsData[i.id]=i;h+="<div class='box row'><span><strong>"+esc(i.title)+"</strong><br><a href='"+esc(i.url)+"' target='_blank' style='font-size:0.85em;color:#ff8040;word-break:break-all;'>"+esc(i.url.length>55?i.url.slice(0,55)+"...":i.url)+"</a>"+(i.description?"<br><span class='muted' style='font-size:0.85em;'>"+esc(i.description)+"</span>":"")+"</span><button onclick='deletePromoAd("+i.id+")' class='btn-danger' style='padding:6px 12px;flex-shrink:0;'>Remove</button></div>";});document.getElementById("adminPromoAds").innerHTML=h||"<p class='muted'>No promo ads yet.</p>";}
    async function addPromoAd(){var title=document.getElementById("pa-title").value.trim();var url=document.getElementById("pa-url").value.trim();var desc=document.getElementById("pa-desc").value.trim();if(!title||!url)return setStatus("Enter title and URL.",true);if(!url.startsWith("http"))return setStatus("URL must start with https://",true);var r=await fetch("/admin/promo-ads",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({title:title,url:url,description:desc})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Promo ad added.",false);document.getElementById("pa-title").value="";document.getElementById("pa-url").value="";document.getElementById("pa-desc").value="";loadAdminPromoAds();loadPromoAds();}
    async function deletePromoAd(id){if(!confirm("Remove this promo ad?"))return;var r=await fetch("/admin/promo-ads/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Removed.",false);loadAdminPromoAds();loadPromoAds();}
    var _smsProvidersData={};
    async function loadAdminSmsProviders(){if(role!=="admin")return;var r=await fetch("/admin/sms-providers",{headers:authH()});if(!r.ok)return;var data=await r.json();_smsProvidersData={};var h="<div style='display:flex;flex-direction:column;gap:6px;margin-bottom:12px;'><div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;'><input id='sp-name' placeholder='Provider name (e.g. SMSPool)'><input id='sp-type' placeholder='Type (smspool / twilio / other)'><input id='sp-key' type='password' placeholder='API Key'></div><div style='display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:4px;'><input id='sp-secret' type='password' placeholder='API Secret (if needed)'><input id='sp-url' placeholder='API URL (optional)'></div><input id='sp-notes' placeholder='Notes (optional)' style='margin-top:4px;'><button onclick='addSmsProvider()' style='width:fit-content;margin-top:6px;'>&#128241; Add Provider</button></div>";if(!data.length){h+="<p class='muted'>No providers added yet. Add SMSPool, Twilio, SMSHero, Vonage, Sinch, etc. Keys are hidden from clients.</p>";}data.forEach(function(i){_smsProvidersData[i.id]=i;var badge=i.is_active?"<span style='color:#4ade80;font-size:0.8em;'>&#9679; Active</span>":"<span style='color:#fc8181;font-size:0.8em;'>&#9679; Inactive</span>";h+="<div class='box row'><span><strong>"+esc(i.name)+"</strong> <span class='muted' style='font-size:0.85em;'>["+esc(i.provider_type)+"]</span> "+badge+(i.notes?"<br><span class='muted' style='font-size:0.82em;'>"+esc(i.notes)+"</span>":"")+"<br><span class='muted' style='font-size:0.8em;'>Added: "+esc(new Date(i.created_at).toLocaleDateString())+"</span></span><div style='display:flex;gap:6px;align-items:center;flex-shrink:0;'><button onclick='toggleSmsProvider("+i.id+","+(i.is_active?"false":"true")+")' class='btn-secondary' style='padding:5px 10px;font-size:0.82em;'>"+(i.is_active?"Disable":"Enable")+"</button><button onclick='deleteSmsProvider("+i.id+")' class='btn-danger' style='padding:5px 10px;font-size:0.82em;'>Remove</button></div></div>";});document.getElementById("adminSmsProviders").innerHTML=h;}
    async function addSmsProvider(){var name=document.getElementById("sp-name").value.trim();var ptype=document.getElementById("sp-type").value.trim()||"other";var key=document.getElementById("sp-key").value.trim();var secret=document.getElementById("sp-secret").value.trim();var url=document.getElementById("sp-url").value.trim();var notes=document.getElementById("sp-notes").value.trim();if(!name)return setStatus("Enter provider name.",true);var r=await fetch("/admin/sms-providers",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({name:name,provider_type:ptype,api_key:key,api_secret:secret,api_url:url,notes:notes})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Provider added.",false);["sp-name","sp-type","sp-key","sp-secret","sp-url","sp-notes"].forEach(function(id){var el=document.getElementById(id);if(el)el.value="";});loadAdminSmsProviders();}
    async function toggleSmsProvider(id,active){var r=await fetch("/admin/sms-providers/"+id,{method:"PATCH",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({is_active:active})});if(!r.ok)return setStatus("Error.",true);loadAdminSmsProviders();}
    async function deleteSmsProvider(id){if(!confirm("Remove this SMS provider? API key will be deleted."))return;var r=await fetch("/admin/sms-providers/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Provider removed.",false);loadAdminSmsProviders();}
    var _escrowAdminMap={};
    async function loadAdminEscrow(){if(role!=="admin")return;var r=await fetch("/api/admin/escrow",{headers:authH()});if(!r.ok)return;var data=await r.json();_escrowAdminMap={};var disputed=data.filter(function(i){return i.status==="disputed";});var h="";if(!disputed.length)h="<p class='muted'>No disputes to resolve. All P2P escrow transactions listed if any are in dispute.</p>";disputed.forEach(function(i,idx){_escrowAdminMap[idx]=i.id;h+="<div class='box' style='border:1px solid #fc8181;'><div class='row'><span><strong style='color:#fc8181;'>DISPUTE</strong> &nbsp;TX: "+esc(i.id.slice(0,14))+"...<br>Buyer: <strong>"+esc(i.buyer_name||String(i.buyer_id))+"</strong> &bull; Seller: <strong>"+esc(i.seller_name||String(i.seller_id))+"</strong><br>Amount: <span class='ln-yellow'>"+esc(String(i.amount_sats))+" sats</span> &bull; Seller receives: "+esc(String(i.seller_amount))+" sats<br><span class='muted' style='font-size:0.85em;'>Reason: "+esc(i.dispute_reason||"—")+"</span></span></div><div style='margin-top:8px;display:flex;gap:6px;'><button data-idx='"+idx+"' data-winner='seller' onclick='resolveEscrowEl(this)' style='background:#166534;color:#4ade80;border:1px solid #4ade80;padding:6px 12px;font-size:0.88em;'>&#10003; Release to Seller</button><button data-idx='"+idx+"' data-winner='buyer' onclick='resolveEscrowEl(this)' class='btn-danger' style='padding:6px 12px;font-size:0.88em;'>&#8592; Refund Buyer</button></div></div>";});document.getElementById("adminEscrowList").innerHTML=h;}
    function resolveEscrowEl(el){var idx=el.getAttribute("data-idx");var winner=el.getAttribute("data-winner");resolveEscrow(_escrowAdminMap[idx],winner);}
    async function resolveEscrow(txId,winner){if(!txId)return;if(!confirm("Resolve in favor of "+winner+"? This is irreversible."))return;var r=await fetch("/api/admin/resolve/"+txId,{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({winner:winner})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Resolved: "+winner+" wins.",false);loadAdminEscrow();}
    async function addNum(){var n=document.getElementById("an").value.trim();var p=Number(document.getElementById("ap").value);var r=await fetch("/admin/numbers",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({number:n,priceSats:p})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Number saved.",false);loadAdminNums();loadNumbers();}
    async function delNum(id){var r=await fetch("/admin/numbers/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Disabled.",false);loadAdminNums();loadNumbers();}
    async function loadAdminNums(){if(role!=="admin")return;var r=await fetch("/admin/numbers",{headers:authH()});if(!r.ok)return;var data=await r.json();var h="";data.forEach(function(i){h+="<div class='box row'><span>"+esc(i.phone_number)+" &mdash; <strong class='ln-yellow'>"+esc(i.price_sats)+" sats</strong> <span class='muted'>"+(i.active?"active":"disabled")+"</span></span><span style='display:flex;gap:6px;'><button onclick='editPrice("+i.id+","+i.price_sats+")' class='btn-secondary' style='padding:6px 12px;'>Edit price</button><button onclick='delNum("+i.id+")' class='btn-danger' style='padding:6px 12px;'>Disable</button></span></div>";});document.getElementById("adminList").innerHTML=h||"<p class='muted'>No numbers yet.</p>";}
    async function editPrice(id,current){var p=prompt("New price in sats (current: "+current+"):");if(!p)return;var n=Number(p);if(!Number.isInteger(n)||n<=0)return setStatus("Invalid price.",true);var r=await fetch("/admin/numbers/"+id+"/price",{method:"PUT",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({priceSats:n})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Price updated to "+n+" sats.",false);loadAdminNums();loadNumbers();}
    async function loadAdminP2P(){if(role!=="admin")return;var r=await fetch("/admin/p2p",{headers:authH()});if(!r.ok)return;var data=await r.json();var h="";data.forEach(function(i){var earned=i.owner_earned_sats||0;var paid=i.owner_paid_sats||0;var owed=earned-paid;h+="<div class='box'><div class='row'><span><strong>"+esc(i.phone_number)+"</strong> &mdash; <span class='ln-yellow'>"+esc(i.price_sats)+" sats</span> &mdash; <span style='color:"+(i.approved?"#4ade80":"#fca5a5")+"'>"+(i.approved?"Approved":"Pending")+"</span></span><span style='display:flex;gap:6px;'>"+(i.approved?"":"<button onclick='approveP2P("+i.id+")' style='background:#166534;color:#4ade80;border:1px solid #4ade80;padding:6px 12px;'>Approve</button>")+"<button onclick='deleteP2P("+i.id+")' class='btn-danger' style='padding:6px 12px;'>Remove</button></span></div><div style='margin-top:8px;font-size:0.85em;'><span class='muted'>Owner earned: </span><strong class='ln-yellow'>"+earned+" sats</strong> &nbsp;|&nbsp; <span class='muted'>Paid out: </span><strong>"+paid+" sats</strong> &nbsp;|&nbsp; <span style='color:"+(owed>0?"#fbbf24":"#4ade80")+"'>Owed: "+owed+" sats</span>"+((owed>0)?"&nbsp;<button onclick='payoutP2P("+i.id+","+owed+")' style='padding:4px 10px;font-size:0.85em;'>Mark paid</button>":"")+"</div></div>";});document.getElementById("adminP2PList").innerHTML=h||"<p class='muted'>No P2P listings yet.</p>";}
    async function approveP2P(id){var r=await fetch("/admin/p2p/"+id+"/approve",{method:"PUT",headers:authH()});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Listing approved.",false);loadAdminP2P();loadP2PMarket();}
    async function deleteP2P(id){if(!confirm("Remove this P2P listing?"))return;var r=await fetch("/admin/p2p/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Listing removed.",false);loadAdminP2P();loadP2PMarket();}
    async function escrowBuyP2P(listingId,amountSats){setStatus("Creating escrow invoice...",false);var r=await fetch("/api/buy",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({listingId:listingId})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);_lightningInvoice=d.paymentRequest||"";if(_lightningInvoice&&typeof window.webln!=="undefined"){try{await window.webln.enable();await window.webln.sendPayment(_lightningInvoice);setStatus("Escrow payment sent via wallet! Waiting...",false);loadEscrowTxs();return;}catch(we){setStatus("WebLN cancelled, use QR below.",false);}}var lnHtml=_lightningInvoice?"<textarea readonly style='width:100%;box-sizing:border-box;background:#0d1520;color:#fbbf24;border:1px solid #2a3a50;border-radius:10px;padding:10px;font-size:0.75em;resize:none;margin-top:10px;' rows='3'>"+esc(_lightningInvoice)+"</textarea><br><button onclick='copyLightning()' style='margin-top:6px;'>Copy Invoice</button>":"";document.getElementById("qr").innerHTML="<div class='box'><h3>&#128274; Escrow Payment</h3><p class='muted' style='font-size:0.88em;'>Funds are held safely in escrow. After you pay, the seller sends you the OTP code. Confirm receipt to release payment. Auto-released after 30 min.</p><p>Amount: <strong class='ln-yellow'>"+esc(d.amountSats)+" sats</strong> &nbsp;<span class='muted' style='font-size:0.85em;'>(8% platform fee included)</span></p>"+(d.qr?"<img src='"+esc(d.qr)+"' width='200' alt='QR' style='display:block;margin:10px auto;'>":"")+lnHtml+"<p class='muted' style='font-size:0.8em;margin-top:10px;'>TX: "+esc(d.txId)+"</p><button onclick='clearQR()' class='btn-secondary' style='width:100%;margin-top:8px;'>Cancel</button></div>";document.getElementById("qr").scrollIntoView({behavior:"smooth"});setStatus("Scan QR to pay escrow. Seller will be notified.",false);}
    async function loadEscrowTxs(){if(!token||role==="admin")return;var r=await fetch("/api/my-escrow",{headers:authH()});if(!r.ok)return;var data=await r.json();var box=document.getElementById("escrow-txs-box");if(!data.length){if(box)box.style.display="none";return;}if(box)box.style.display="block";var COLORS={pending:"#94a3b8",paid:"#fbbf24",released:"#4ade80",disputed:"#fc8181",refunded:"#a5b4fc"};var LABELS={pending:"Awaiting Payment",paid:"Paid — Awaiting Confirmation",released:"Complete",disputed:"In Dispute",refunded:"Refunded"};var h="<h4>&#128274; My Escrow Transactions</h4>";var hasSeller=data.some(function(i){return i.my_role==="seller";});if(hasSeller)h+="<button onclick='showWithdrawForm()' class='btn-secondary' style='padding:5px 12px;font-size:0.85em;margin-bottom:10px;'>&#9889; Withdraw Balance to Lightning</button>";data.forEach(function(i){var statusColor=COLORS[i.status]||"#94a3b8";var statusLabel=LABELS[i.status]||i.status;var isBuyer=i.my_role==="buyer";var actions="";if(i.status==="paid"&&isBuyer){actions="<div style='margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;'><button onclick='confirmEscrow("+JSON.stringify(i.id)+")' style='background:#166534;color:#4ade80;border:1px solid #4ade80;padding:6px 12px;font-size:0.85em;'>&#10003; Confirm Receipt</button><button onclick='disputeEscrow("+JSON.stringify(i.id)+")' class='btn-danger' style='padding:6px 12px;font-size:0.85em;'>&#9888; Dispute</button></div>";}h+="<div class='box'><div class='row'><span><strong>"+(isBuyer?"Buying":"Selling")+"</strong> &mdash; <span class='ln-yellow'>"+esc(i.amount_sats)+" sats</span>"+(i.my_role==="seller"?" &bull; <span style='color:#4ade80;font-size:0.85em;'>You receive: "+esc(i.seller_amount)+" sats</span>":"")+" &mdash; <span style='color:"+statusColor+";font-size:0.88em;'>"+esc(statusLabel)+"</span>"+(i.dispute_reason?"<br><span class='muted' style='font-size:0.82em;'>Dispute: "+esc(i.dispute_reason)+"</span>":"")+"<br><span class='muted' style='font-size:0.8em;'>"+esc(new Date(Number(i.created_at)).toLocaleString())+"</span></span></div>"+actions+"</div>";});document.getElementById("escrow-txs").innerHTML=h;}
    async function confirmEscrow(txId){if(!confirm("Confirm receipt? This will release payment to the seller immediately."))return;var r=await fetch("/api/confirm/"+txId,{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Payment released to seller. Transaction complete!",false);loadEscrowTxs();loadWalletBalance();}
    async function disputeEscrow(txId){var reason=prompt("Describe the problem (e.g. wrong code, no response):");if(!reason)return;var r=await fetch("/api/dispute/"+txId,{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({reason:reason})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Dispute opened. Admin will review and resolve.",false);loadEscrowTxs();}
    async function doWithdraw(){var addr=document.getElementById("ln-address").value.trim();if(!addr)return setStatus("Enter Lightning address.",true);if(!confirm("Withdraw all balance to: "+addr+"?"))return;var r=await fetch("/api/withdraw",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({lightningAddress:addr})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Withdrawal sent! "+d.amountSats+" sats → "+addr,false);document.getElementById("withdraw-form").style.display="none";document.getElementById("ln-address").value="";loadWalletBalance();}
    async function payoutP2P(id,amount){if(!confirm("Mark "+amount+" sats as paid out to this owner?"))return;var r=await fetch("/admin/p2p/"+id+"/payout",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({amount:amount})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Payout of "+amount+" sats marked.",false);loadAdminP2P();}
    async function submitP2P(){var phone=document.getElementById("p2p-phone").value.trim();var price=Number(document.getElementById("p2p-price").value);var desc=document.getElementById("p2p-desc").value.trim();if(!phone||!price)return setStatus("Enter phone number and price.",true);var r=await fetch("/p2p/submit",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({phoneNumber:phone,priceSats:price,description:desc})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Listing submitted! Waiting for admin approval.",false);document.getElementById("p2p-phone").value="";document.getElementById("p2p-price").value="";document.getElementById("p2p-desc").value="";loadMyP2PListings();}
    async function loadP2PMarket(){if(!token)return;var r=await fetch("/p2p/market",{headers:authH()});if(!r.ok)return;var data=await r.json();var h="";if(!data.length)h="<p class='muted'>No listings in the marketplace yet. Be the first to list your number!</p>";data.forEach(function(i){h+="<div class='box row'><span><strong>"+esc(i.phone_number)+"</strong> &mdash; <span class='ln-yellow'>"+esc(i.price_sats)+" sats</span>"+(i.description?"<br><span class='muted' style='font-size:0.85em;'>"+esc(i.description)+"</span>":"")+"<br><span class='muted' style='font-size:0.78em;'>&#128274; Escrow protected &bull; 8% fee</span></span><button onclick='escrowBuyP2P("+i.id+","+i.price_sats+")' style='background:linear-gradient(135deg,#1e3a2e,#166534);border:1px solid #4ade80;color:#4ade80;'>&#128274; Escrow Buy</button></div>";});document.getElementById("p2p-market").innerHTML=h;}
    async function loadMyP2PListings(){if(!token)return;var r=await fetch("/p2p/my-listings",{headers:authH()});if(!r.ok)return;var data=await r.json();if(!data.length){document.getElementById("p2p-my-listings").innerHTML="";document.getElementById("p2p-submit-box").style.display="block";return;}document.getElementById("p2p-submit-box").style.display="block";var h="<div class='box'><h4>My listings</h4>";data.forEach(function(i){var earned=i.owner_earned_sats||0;var paid=i.owner_paid_sats||0;h+="<div class='box' style='margin:8px 0;'><strong>"+esc(i.phone_number)+"</strong> &mdash; "+esc(i.price_sats)+" sats &mdash; <span style='color:"+(i.approved?"#4ade80":"#fca5a5")+"'>"+(i.approved?"Active":"Pending approval")+"</span><br><span class='muted' style='font-size:0.85em;'>Earned: "+earned+" sats | Paid out: "+paid+" sats | Owed: "+(earned-paid)+" sats</span></div>";});h+="</div>";document.getElementById("p2p-my-listings").innerHTML=h;}
    function renderSendTab(){if(!token){document.getElementById("send-login-box").style.display="block";document.getElementById("send-admin-panel").style.display="none";document.getElementById("send-client-panel").style.display="none";return;}document.getElementById("send-login-box").style.display="none";if(role==="admin"){document.getElementById("send-admin-panel").style.display="block";document.getElementById("send-client-panel").style.display="none";var base=location.origin;document.getElementById("poll-url").textContent=base+"/api/pending-sms";document.getElementById("ack-url").textContent=base+"/api/sms-sent/[id]";var td=document.getElementById("macro-token-display");if(td)td.textContent=token;loadSendNumbersAdmin();loadOutbox();}else{document.getElementById("send-admin-panel").style.display="none";document.getElementById("send-client-panel").style.display="block";loadSendNumbers();checkSendCredit();loadMySent();}}
    async function addSendNumber(){var phone=document.getElementById("sn-phone").value.trim();var price=Number(document.getElementById("sn-price").value);if(!phone||!price)return setStatus("Enter phone and price.",true);var r=await fetch("/admin/send-numbers",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({phoneNumber:phone,priceSats:price})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Send number added.",false);document.getElementById("sn-phone").value="";document.getElementById("sn-price").value="";loadSendNumbersAdmin();}
    async function loadSendNumbersAdmin(){if(role!=="admin")return;var r=await fetch("/admin/send-numbers",{headers:authH()});if(!r.ok)return;var data=await r.json();var h="";data.forEach(function(i){h+="<div class='box row'><span><strong>"+esc(i.phone_number)+"</strong> &mdash; <span class='ln-yellow'>"+esc(i.price_sats)+" sats</span> <span class='muted'>"+(i.active?"active":"disabled")+"</span></span><button onclick='disableSendNumber("+i.id+")' class='btn-danger' style='padding:6px 12px;'>Disable</button></div>";});document.getElementById("send-numbers-admin-list").innerHTML=h||"<p class='muted'>No send numbers yet.</p>";}
    async function disableSendNumber(id){var r=await fetch("/admin/send-numbers/"+id,{method:"DELETE",headers:authH()});if(!r.ok)return setStatus("Error.",true);setStatus("Disabled.",false);loadSendNumbersAdmin();}
    async function loadOutbox(){if(role!=="admin")return;var r=await fetch("/admin/outbox",{headers:authH()});if(!r.ok)return;var data=await r.json();var h="";if(!data.length)h="<p class='muted'>No messages yet.</p>";data.forEach(function(i){var col=i.status==="sent"?"#4ade80":i.status==="failed"?"#fca5a5":"#facc15";h+="<div class='box row'><span><strong>"+esc(i.recipient)+"</strong><br><span class='muted' style='font-size:0.85em;'>"+esc(i.message)+"</span></span><span style='color:"+col+";font-weight:bold;font-size:0.88em;'>"+esc(i.status)+"<br><span style='color:#555;font-size:0.8em;'>"+esc(new Date(i.created_at).toLocaleString())+"</span></span></div>";});document.getElementById("outbox-list").innerHTML=h;}
    var _sendNums={};
    async function loadSendNumbers(){if(!token||role==="admin")return;var r=await fetch("/send-numbers",{headers:authH()});if(!r.ok)return;var data=await r.json();_sendNums={};var h="";if(!data.length)h="<p class='muted'>No send numbers available yet.</p>";data.forEach(function(i){_sendNums[i.id]=i;h+="<div class='box row'><span><strong>"+esc(i.phone_number)+"</strong><br><span class='muted' style='font-size:0.85em;'>Send 1 SMS from this number &mdash; <span class='ln-yellow'>"+esc(i.price_sats)+" sats</span></span></span><button onclick='buySendCredit("+i.id+")'>&#9889; Buy</button></div>";});document.getElementById("send-numbers-list").innerHTML=h;}
    var _sendPollTimer=null;
    async function buySendCredit(id){setStatus("Creating invoice...",false);var r=await fetch("/create-invoice",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({sendNumberId:id})});var inv=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(inv.error||"Error.",true);setStatus("Scan QR to pay.",false);_lightningInvoice=inv.lightning_invoice||"";var lnHtml=_lightningInvoice?"<textarea style='width:100%;box-sizing:border-box;background:#111;color:#facc15;border:1px solid #444;border-radius:8px;padding:8px;font-size:0.75em;margin-top:8px;resize:none;' rows='3' readonly>"+esc(_lightningInvoice)+"</textarea><br><button onclick='copyLightning()' style='margin-top:4px;'>Copy Invoice</button>":"";var chkHtml=inv.checkout_url?"<br><a href='"+esc(inv.checkout_url)+"' target='_blank'>Open in Browser</a>":"";document.getElementById("send-qr").innerHTML="<div class='box'><h3>Scan Lightning QR</h3><p>Amount: "+esc(inv.amount_sats)+" sats</p><img src='"+esc(inv.qr)+"' width='220' alt='QR'>"+lnHtml+chkHtml+"</div>";if(_sendPollTimer)clearInterval(_sendPollTimer);_sendPollTimer=setInterval(async function(){var cr=await fetch("/my-send-credit",{headers:authH()});if(!cr.ok)return;var cd=await cr.json();if(cd&&cd.id){clearInterval(_sendPollTimer);_sendPollTimer=null;document.getElementById("send-qr").innerHTML="";setStatus("Payment confirmed! Compose your message.",false);checkSendCredit();}},5000);}
    async function checkSendCredit(){if(!token||role==="admin")return;var r=await fetch("/my-send-credit",{headers:authH()});if(!r.ok)return;var credit=await r.json();var composeBox=document.getElementById("send-compose-box");if(credit&&credit.id){composeBox.style.display="block";composeBox.dataset.creditId=credit.id;}else{composeBox.style.display="none";}}
    async function submitMessage(){var creditId=document.getElementById("send-compose-box").dataset.creditId;var recipient=document.getElementById("send-recipient").value.trim();var message=document.getElementById("send-message").value.trim();if(!recipient||!message)return setStatus("Enter recipient and message.",true);var r=await fetch("/send-message",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({creditId:creditId,recipient:recipient,message:message})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Error.",true);setStatus("Message queued! Will be sent shortly.",false);document.getElementById("send-recipient").value="";document.getElementById("send-message").value="";document.getElementById("send-compose-box").style.display="none";loadMySent();}
    async function loadMySent(){if(!token||role==="admin")return;var r=await fetch("/my-sent",{headers:authH()});if(!r.ok)return;var data=await r.json();var box=document.getElementById("my-sent-box");if(!data.length){box.style.display="none";return;}box.style.display="block";var h="";data.forEach(function(i){var col=i.status==="sent"?"#4ade80":"#facc15";h+="<div class='box row'><span><strong>"+esc(i.recipient)+"</strong><br><span class='muted' style='font-size:0.85em;'>"+esc(i.message)+"</span></span><span style='color:"+col+";font-weight:bold;font-size:0.88em;'>"+esc(i.status)+"</span></div>";});document.getElementById("my-sent-list").innerHTML=h;}
    var _p2pData={};
    /* buyP2P() removed — all P2P purchases now go through escrowBuyP2P() → /api/buy */
    var COUNTRIES=["Albania","Argentina","Australia","Austria","Bangladesh","Belarus","Belgium","Bosnia","Brazil","Bulgaria","Canada","Chile","China","Colombia","Croatia","Czech Republic","Denmark","Egypt","Estonia","Finland","France","Germany","Greece","Hong Kong","Hungary","India","Indonesia","Ireland","Israel","Italy","Japan","Kazakhstan","Kenya","Kosovo","Latvia","Lithuania","Malaysia","Mexico","Montenegro","Morocco","Netherlands","New Zealand","Nigeria","North Macedonia","Norway","Pakistan","Peru","Philippines","Poland","Portugal","Romania","Russia","Saudi Arabia","Serbia","Singapore","Slovakia","Slovenia","South Africa","South Korea","Spain","Sweden","Switzerland","Taiwan","Thailand","Turkey","UAE","UK","Ukraine","USA","Vietnam","Other"];
    var SERVICES=["Telegram","WhatsApp","Viber","Signal","Instagram","Facebook","Messenger","Twitter / X","TikTok","Snapchat","YouTube","Twitch","Discord","LinkedIn","Pinterest","Reddit","Clubhouse","BeReal","Threads","Google","Apple","Microsoft","Amazon","Netflix","Spotify","Disney+","HBO Max","Hulu","Prime Video","Steam","Twitch","Uber","Uber Eats","Airbnb","Booking.com","Fiverr","Upwork","Etsy","eBay","Shopify","Tinder","Bumble","Hinge","Badoo","OkCupid","PayPal","Cash App","Venmo","Wise","Revolut","Skrill","Neteller","N26","Monzo","Coinbase","Binance","Bybit","OKX","KuCoin","Kraken","Bitget","MEXC","Gate.io","Nexo","Crypto.com","Dropbox","GitHub","Slack","Zoom","Teams","Notion","Trello","Figma","ChatGPT","Other"];
    var _numsData={};
    var _providerCatalog=null;
    var _providerBuyState={country:"",service:"",priceSats:0};
    async function loadProviderCatalog(){if(!token)return;try{var r=await fetch("/api/provider/catalog",{headers:authH()});if(!r.ok)return;var cat=await r.json();_providerCatalog=cat;renderProviderUI();}catch(e){console.error("Provider catalog err:",e);}}
    function renderProviderUI(){var box=document.getElementById("provider-box");if(!box)return;var cat=_providerCatalog;if(!cat||!cat.active){box.style.display="none";return;}box.style.display="block";var cOpts=cat.countries.map(function(c){return"<option value='"+esc(c.id)+"'>"+esc(c.name)+"</option>";}).join("");box.innerHTML="<h3>&#127760; "+t("get_num")+"</h3><p class='muted' style='font-size:0.85em;margin-bottom:14px;'>Powered by "+esc(cat.type)+". Number assigned instantly after payment.</p><div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;'><div><label class='muted' style='font-size:0.85em;'>"+t("select_country")+"</label><br><select id='prov-country' onchange='onProviderCountryChange()' style='width:100%;margin-top:4px;'><option value=''>-- "+t("select_country")+" --</option>"+cOpts+"</select></div><div><label class='muted' style='font-size:0.85em;'>"+t("select_service")+"</label><br><select id='prov-service' onchange='onProviderServiceChange()' style='width:100%;margin-top:4px;'><option value=''>-- "+t("select_service")+" --</option></select></div></div><div id='prov-price-box' style='display:none;margin-bottom:12px;padding:10px;background:#0d1520;border-radius:10px;border:1px solid #1e2d40;'><span class='muted' style='font-size:0.85em;'>"+t("price")+": </span><strong class='ln-yellow' id='prov-price-val'>-- sats</strong><span class='muted' id='prov-avail' style='font-size:0.82em;margin-left:10px;'></span></div><button id='prov-buy-btn' onclick='buyProviderNum()' style='width:100%;padding:14px;font-size:1.05em;display:none;'>&#9889; "+t("get_num")+" via Lightning</button><div id='prov-status' class='muted' style='font-size:0.85em;margin-top:8px;'></div>";}
    async function onProviderCountryChange(){var country=document.getElementById("prov-country")?document.getElementById("prov-country").value:"";var svcSel=document.getElementById("prov-service");if(!svcSel||!country)return;svcSel.innerHTML="<option>Loading...</option>";var pb=document.getElementById("prov-price-box");var bb=document.getElementById("prov-buy-btn");if(pb)pb.style.display="none";if(bb)bb.style.display="none";try{var r=await fetch("/api/provider/catalog?country="+encodeURIComponent(country),{headers:authH()});var cat=await r.json();var sOpts=(cat.services||[]).map(function(s){return"<option value='"+esc(s.id)+"'>"+esc(s.name)+(s.available?" ("+s.available+")":"")+"</option>";}).join("");svcSel.innerHTML="<option value=''>-- Select service --</option>"+sOpts;}catch(e){svcSel.innerHTML="<option value=''>Error loading</option>";}  _providerBuyState.country=country;_providerBuyState.service="";_providerBuyState.priceSats=0;}
    async function onProviderServiceChange(){var country=document.getElementById("prov-country")?document.getElementById("prov-country").value:"";var service=document.getElementById("prov-service")?document.getElementById("prov-service").value:"";if(!country||!service)return;_providerBuyState.country=country;_providerBuyState.service=service;_providerBuyState.priceSats=0;var priceBox=document.getElementById("prov-price-box");var priceVal=document.getElementById("prov-price-val");var availEl=document.getElementById("prov-avail");var buyBtn=document.getElementById("prov-buy-btn");if(priceBox)priceBox.style.display="block";if(priceVal)priceVal.textContent="Loading...";if(buyBtn)buyBtn.style.display="none";try{var r=await fetch("/api/provider/price?country="+encodeURIComponent(country)+"&service="+encodeURIComponent(service),{headers:authH()});var pd=await r.json();_providerBuyState.priceSats=pd.sats||0;if(priceVal)priceVal.textContent=esc(String(pd.sats))+" sats";if(availEl)availEl.textContent=pd.available?"("+pd.available+" available)":"";if(buyBtn&&pd.sats>0)buyBtn.style.display="block";}catch(e){if(priceVal)priceVal.textContent="Error";}}
    async function buyProviderNum(){var country=_providerBuyState.country;var service=_providerBuyState.service;var priceSats=_providerBuyState.priceSats;if(!country||!service||!priceSats)return setStatus("Select country, service and wait for price.",true);setStatus("Creating invoice...",false);var btn=document.getElementById("prov-buy-btn");if(btn)btn.disabled=true;var r=await fetch("/create-invoice",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({mode:"provider",country:country,service:service,priceSats:priceSats})});var inv=await r.json().catch(function(){return{error:"Error"};});if(btn)btn.disabled=false;if(!r.ok)return setStatus(inv.error||"Error.",true);if(inv.paid_from_wallet){setStatus("Paid from wallet! Assigning your number...",false);loadWalletBalance();setTimeout(function(){loadSessions();document.getElementById("sessions").scrollIntoView({behavior:"smooth"});},2000);return;}setStatus("Scan QR to pay. Number assigned after payment.",false);_lightningInvoice=inv.lightning_invoice||"";if(_lightningInvoice&&typeof window.webln!=="undefined"){try{await window.webln.enable();await window.webln.sendPayment(_lightningInvoice);setStatus("Payment sent! Assigning your number...",false);clearQR();startPolling();return;}catch(we){setStatus("WebLN cancelled, use QR below.",false);}}var lnHtml=_lightningInvoice?"<textarea style='width:100%;box-sizing:border-box;background:#0d1520;color:#fbbf24;border:1px solid #2a3a50;border-radius:10px;padding:10px;font-size:0.75em;margin-top:10px;resize:none;' rows='3' readonly>"+esc(_lightningInvoice)+"</textarea><br><button onclick='copyLightning()' style='margin-top:6px;'>Copy Invoice</button>":"";var chkHtml=inv.checkout_url?"<br><a href='"+esc(inv.checkout_url)+"' target='_blank' style='display:inline-block;margin-top:8px;color:#ff8040;'>Open in Wallet App</a>":"";document.getElementById("qr").innerHTML="<div class='box'><h3>&#9889; Scan to Pay</h3><p class='muted' style='font-size:0.9em;'>"+esc(service)+" &bull; "+esc(country)+"</p><p>Amount: <strong class='ln-yellow'>"+esc(String(priceSats))+" sats</strong></p><img src='"+esc(inv.qr)+"' width='220' alt='QR'>"+lnHtml+chkHtml+"<p class='muted' style='font-size:0.85em;margin-top:10px;'>Number will be assigned after payment confirmation.</p><button onclick='clearQR()' class='btn-secondary' style='width:100%;margin-top:8px;padding:10px;'>Cancel</button></div>";document.getElementById("qr").scrollIntoView({behavior:"smooth"});startPolling();}
    async function loadNumbers(){if(!token)return;loadProviderCatalog();var r=await fetch("/numbers",{headers:authH()});if(!r.ok)return setStatus("Login again.",true);var data=await r.json();_numsData={};if(!data.length){document.getElementById("numbers").innerHTML="<p class='muted' style='font-size:0.9em;'>"+t("no_nums")+"</p>";return;}var h="<h3>"+t("avail_nums")+"</h3>";data.forEach(function(i){_numsData[i.id]={phone:i.phone_number,sats:i.price_sats};h+="<div class='box row'><span><strong>"+esc(i.phone_number)+"</strong><br><span class='ln-yellow' style='font-size:0.9em;'>&#9889; "+esc(i.price_sats)+" sats</span></span><button onclick='showBuyPanel("+i.id+")'>&#9889; Buy</button></div>";});document.getElementById("numbers").innerHTML=h;}
    function showBuyPanel(id){var num=_numsData[id]||{};var phone=num.phone||"";var sats=num.sats||"";var cOpts=COUNTRIES.map(function(c){return"<option>"+esc(c)+"</option>";}).join("");var sOpts=SERVICES.map(function(s){return"<option>"+esc(s)+"</option>";}).join("");document.getElementById("qr").innerHTML="<div class='box'><h3>&#9889; "+esc(phone)+"</h3><div class='row' style='gap:12px;margin-bottom:14px;'><div style='flex:1'><label class='muted' style='font-size:0.85em;'>Country</label><br><select id='selCountry' style='width:100%;margin-top:4px;'>"+cOpts+"</select></div><div style='flex:1'><label class='muted' style='font-size:0.85em;'>Service</label><br><select id='selService' style='width:100%;margin-top:4px;'>"+sOpts+"</select></div></div><p style='font-size:1em;margin:0 0 14px;'>Price: <strong class='ln-yellow'>&#9889; "+esc(sats)+" sats</strong></p><button onclick='buyNum("+id+")' style='width:100%;padding:13px;font-size:1.05em;'>&#9889; Pay via Lightning</button><br><button onclick='clearQR()' class='btn-secondary' style='width:100%;margin-top:6px;padding:10px;'>Cancel</button></div>";document.getElementById("qr").scrollIntoView({behavior:"smooth"});}
    var _lightningInvoice = "";
    var _pollTimer = null;
    function copyLightning(){if(!_lightningInvoice)return;navigator.clipboard.writeText(_lightningInvoice).then(function(){setStatus("Copied!",false);}).catch(function(){setStatus("Copy failed.",true);});}
    function clearQR(){document.getElementById("qr").innerHTML="";if(_pollTimer){clearInterval(_pollTimer);_pollTimer=null;}}
    function startPolling(){if(_pollTimer)clearInterval(_pollTimer);_pollTimer=setInterval(async function(){if(!token)return;var r=await fetch("/my-numbers",{headers:authH()});if(!r.ok)return;var data=await r.json();if(data.length){clearQR();setStatus("Payment confirmed! Your number is active.",false);loadSessions();document.getElementById("sessions").scrollIntoView({behavior:"smooth"});}},5000);}
    async function buyNum(id){setStatus("Creating invoice...",false);var country=document.getElementById("selCountry")?document.getElementById("selCountry").value:"";var service=document.getElementById("selService")?document.getElementById("selService").value:"";var r=await fetch("/create-invoice",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({numberId:id,country:country,service:service})});var inv=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(inv.error||"Error.",true);if(inv.paid_from_wallet){clearQR();setStatus("Paid from wallet! "+inv.amount_sats+" sats deducted. Number is active.",false);loadWalletBalance();loadSessions();document.getElementById("sessions").scrollIntoView({behavior:"smooth"});return;}setStatus("Scan QR to pay. Waiting for confirmation...",false);_lightningInvoice=inv.lightning_invoice||"";if(_lightningInvoice&&typeof window.webln!=="undefined"){try{await window.webln.enable();await window.webln.sendPayment(_lightningInvoice);setStatus("Payment sent via wallet! Waiting for confirmation...",false);clearQR();startPolling();return;}catch(we){setStatus("WebLN cancelled, use QR below.",false);}}var lnHtml="";if(_lightningInvoice){lnHtml="<textarea id='lnTxt' style='width:100%;box-sizing:border-box;background:#0d1520;color:#fbbf24;border:1px solid #2a3a50;border-radius:10px;padding:10px;font-size:0.75em;margin-top:10px;resize:none;' rows='3' readonly>"+esc(_lightningInvoice)+"</textarea><br><button onclick='copyLightning()' style='margin-top:6px;'>Copy Invoice</button>";}var chkHtml=inv.checkout_url?"<br><a href='"+esc(inv.checkout_url)+"' target='_blank' style='display:inline-block;margin-top:8px;color:#ff8040;'>Open in Wallet App</a>":"";document.getElementById("qr").innerHTML="<div class='box'><h3>&#9889; Scan to Pay</h3><p>Amount: <strong class='ln-yellow'>"+esc(inv.amount_sats)+" sats</strong></p><img src='"+esc(inv.qr)+"' width='220' alt='QR'>"+lnHtml+chkHtml+"<p class='muted' style='font-size:0.85em;margin-top:10px;'>Auto-refreshes every 5s. Scroll down after payment to see your number.</p></div>";startPolling();}
    var _sessionsData={};
    async function loadSessions(){if(!token||role==="admin")return;var r=await fetch("/my-numbers",{headers:authH()});if(!r.ok)return;var data=await r.json();_sessionsData={};var h="<h3>"+t("my_nums")+"</h3>";if(!data.length)h+="<p class='muted'>No active numbers yet.</p>";data.forEach(function(i){_sessionsData[i.id]=i;var tags="";if(i.country)tags+="<span style='background:#1e2d40;border:1px solid #2a3a50;border-radius:6px;padding:2px 8px;font-size:0.8em;margin-right:6px;color:#94a3b8;'>"+esc(i.country)+"</span>";if(i.service)tags+="<span style='background:#1a1500;border:1px solid #fbbf24;border-radius:6px;padding:2px 8px;font-size:0.8em;color:#fbbf24;'>"+esc(i.service)+"</span>";var cd=countdown(i.expires_at);var cdColor=new Date(i.expires_at)-Date.now()<1800000?"#fc8181":"#4ade80";h+="<div class='box' style='display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap;'><div><strong style='font-size:1.05em;'>"+esc(i.phone_number)+"</strong>"+(tags?" &nbsp;"+tags:"")+"<br><span style='color:"+cdColor+";font-size:0.85em;margin-top:4px;display:inline-block;'>&#9201; "+esc(cd)+"</span><span class='muted' style='font-size:0.8em;'> &mdash; "+esc(new Date(i.expires_at).toLocaleString())+"</span></div><button onclick='requestRefund("+i.id+")' class='btn-danger' style='padding:6px 12px;font-size:0.85em;flex-shrink:0;'>&#8592; Refund</button></div>";});document.getElementById("sessions").innerHTML=h;}
    async function requestRefund(id){var sess=_sessionsData[id];if(!sess)return;if(!confirm("Refund for "+sess.phone_number+"? Only possible if NO OTP was received. Sats go back to your wallet."))return;var r=await fetch("/refund-session",{method:"POST",headers:authH({"Content-Type":"application/json"}),body:JSON.stringify({sessionId:id})});var d=await r.json().catch(function(){return{error:"Error"};});if(!r.ok)return setStatus(d.error||"Refund failed.",true);setStatus("Refund successful! "+d.refunded_sats+" sats returned to your wallet.",false);loadSessions();loadWalletBalance();}
    async function loadMessages(){if(!token)return;var r=await fetch("/messages",{headers:authH()});if(!r.ok)return;var data=await r.json();var h="<h3>"+t("otp_inbox")+"</h3>";if(!data.length)h+="<p class='muted'>No messages yet.</p>";data.forEach(function(i){h+="<div class='box'><span class='muted'>"+esc(i.phone_number)+"</span><br>"+esc(i.text)+(i.otp?" <strong style='color:#facc15;font-size:1.2em'>"+esc(i.otp)+"</strong>":"")+"<br><span class='muted' style='font-size:0.85em'>"+esc(new Date(i.created_at).toLocaleString())+"</span></div>";});document.getElementById("otp").innerHTML=h;}
    function refreshAll(){renderAdmin();loadNumbers();loadSessions();loadMessages();loadWalletBalance();}
    var wsP=location.protocol==="https:"?"wss://":"ws://";
    var ws=new WebSocket(wsP+location.host);
    ws.onopen=function(){console.log("WS connected");};
    ws.onmessage=function(e){try{var m=JSON.parse(e.data);if(m.type==="session_activated"){clearQR();setStatus("Payment confirmed! Your number is active.",false);loadSessions();loadMessages();loadWalletBalance();setTimeout(function(){var el=document.getElementById("sessions");if(el)el.scrollIntoView({behavior:"smooth"});},300);}else if(m.type==="message"){loadMessages();if(m.otp){showNotif("SMSNero: New OTP arrived","Code: "+m.otp);}}else if(m.type==="wallet_topped_up"){loadWalletBalance();setStatus("Wallet topped up!",false);document.getElementById("deposit-form").style.display="none";document.getElementById("deposit-qr").innerHTML="";}else if(m.type==="send_credit_activated"){checkSendCredit();setStatus("Send credit activated!",false);}else if(m.type==="escrow_paid"){loadEscrowTxs();if(_myUserId&&m.sellerId===_myUserId){playSaleAlert();playSaleAlert();setStatus("&#128176; Nova prodaja! Neko je platio escrow. Cekaj potvrdu.",false);showNotif("SMSNero: Nova prodaja!","Kupac platio "+m.amountSats+" sats. Cekaj potvrdu primanja.");}else{setStatus("Escrow payment confirmed! Waiting for buyer confirmation.",false);showNotif("SMSNero: Escrow Paid","Funds held. Confirm receipt to release to seller.");}}else if(m.type==="escrow_released"){setStatus("Escrow released! Seller received payment.",false);loadEscrowTxs();loadWalletBalance();if(role==="admin")loadAdminEscrow();}else if(m.type==="escrow_disputed"){playDisputeAlert();setStatus("&#9888; Escrow dispute opened. Admin will review.",false);loadEscrowTxs();if(role==="admin"){loadAdminEscrow();showNotif("SMSNero Admin: DISPUTE","Nova zaba! Kupac otvorio spor. Treba rucno resiti.");}}else if(m.type==="escrow_refunded"){setStatus("Escrow refunded by admin.",false);loadEscrowTxs();loadWalletBalance();}else if(m.type==="provider_buy_error"){setStatus("Provider error: "+m.error,true);}}catch(err){}};
    ws.onerror=function(){console.warn("WS error");};
    setInterval(function(){if(token&&role!=="admin")loadSessions();},60000);
    applyTheme(_themeIdx);
    applyLang();
    (function(){var btn=document.getElementById("admin-login-btn");var inp=document.getElementById("adminPass");if(btn)btn.addEventListener("click",adminLogin);if(inp)inp.addEventListener("keydown",function(e){if(e.key==="Enter")adminLogin();});})();
    if(token)refreshAll();
    loadAnnouncements();loadPromoAds();loadCryptoNews();
    if("serviceWorker" in navigator){navigator.serviceWorker.register("/sw.js").catch(function(){});}
  </script>
</body>
</html>`;

app.use(rateLimit);

app.get("/healthz", function(req, res) { res.json({ status: "ok" }); });
app.get("/favicon.ico", function(req, res) { res.status(204).end(); });
app.get("/", function(req, res) { res.send(HTML); });

const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff6600"/><stop offset="100%" stop-color="#cc2200"/></linearGradient></defs><rect width="192" height="192" rx="40" fill="url(#bg)"/><polygon points="108,18 58,106 96,106 82,174 142,82 104,82" fill="#ffffff" opacity="0.95"/></svg>`;

app.get("/icon-192.svg", function(req, res) {
  res.setHeader("Content-Type", "image/svg+xml");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.send(ICON_SVG);
});
app.get("/icon-512.svg", function(req, res) {
  res.setHeader("Content-Type", "image/svg+xml");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.send(ICON_SVG.replace('viewBox="0 0 192 192"', 'viewBox="0 0 512 512"').replace('width="192" height="192"', 'width="512" height="512"').replace('rx="40"', 'rx="80"'));
});
app.get("/manifest.json", function(req, res) {
  res.setHeader("Content-Type", "application/manifest+json");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.json({
    name: "SMSNero",
    short_name: "SMSNero",
    description: "Rent phone numbers and receive SMS/OTP via Bitcoin Lightning",
    start_url: "/",
    display: "standalone",
    background_color: "#0c0f14",
    theme_color: "#0c0f14",
    orientation: "portrait-primary",
    icons: [
      { src: "/icon-192.svg", sizes: "192x192", type: "image/svg+xml", purpose: "any maskable" },
      { src: "/icon-512.svg", sizes: "512x512", type: "image/svg+xml", purpose: "any maskable" }
    ]
  });
});
app.get("/sw.js", function(req, res) {
  res.setHeader("Content-Type", "application/javascript");
  res.setHeader("Cache-Control", "no-cache");
  res.send(`
const CACHE="smsnero-v1";
self.addEventListener("install",function(e){
  e.waitUntil(caches.open(CACHE).then(function(c){return c.add("/");}));
  self.skipWaiting();
});
self.addEventListener("activate",function(e){
  e.waitUntil(caches.keys().then(function(keys){return Promise.all(keys.filter(function(k){return k!==CACHE;}).map(function(k){return caches.delete(k);}));}));
  self.clients.claim();
});
self.addEventListener("fetch",function(e){
  if(e.request.method!=="GET")return;
  e.respondWith(fetch(e.request).catch(function(){return caches.match("/");}));
});
  `.trim());
});

app.post("/register", wrap(async function(req, res) {
  const username = "user" + Date.now();
  const result = await pool.query("INSERT INTO users (username, role) VALUES ($1, 'user') RETURNING id, username, role", [username]);
  const user = result.rows[0];
  res.json({ token: signToken(user), user: user });
}));

app.post("/admin/login", function(req, res) {
  if (String(req.body.password || "") !== ADMIN_PASSWORD) {
    return res.status(403).json({ error: "Wrong admin password" });
  }
  const user = { id: 0, username: "admin", role: "admin" };
  return res.json({ token: signToken(user), user: user });
});

app.get("/numbers", auth, wrap(async function(req, res) {
  const result = await pool.query("SELECT id, phone_number, price_sats FROM numbers WHERE active = TRUE ORDER BY id DESC");
  res.json(result.rows);
}));

app.get("/my-numbers", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.json([]);
  const result = await pool.query(
    "SELECT s.id, s.expires_at, s.country, s.service, n.phone_number FROM sessions s JOIN numbers n ON n.id = s.number_id WHERE s.user_id = $1 AND s.expires_at > NOW() ORDER BY s.created_at DESC",
    [req.user.id]
  );
  res.json(result.rows);
}));

app.get("/messages", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") {
    const result = await pool.query("SELECT id, phone_number, text, otp, created_at FROM messages WHERE phone_number NOT LIKE '\\%%' AND phone_number NOT LIKE '[%' ORDER BY created_at DESC LIMIT 200");
    return res.json(result.rows);
  }
  const sessResult = await pool.query("SELECT number_id FROM sessions WHERE user_id = $1 AND expires_at > NOW() ORDER BY created_at DESC", [req.user.id]);
  if (!sessResult.rows.length) return res.json([]);
  const ids = sessResult.rows.map(function(r) { return r.number_id; });
  const result = await pool.query(
    "SELECT id, phone_number, text, otp, created_at FROM messages WHERE number_id = ANY($1) AND phone_number NOT LIKE '\\%%' AND phone_number NOT LIKE '[%' AND otp IS NOT NULL ORDER BY created_at DESC LIMIT 200",
    [ids]
  );
  res.json(result.rows);
}));

app.get("/admin/numbers", auth, adminOnly, wrap(async function(req, res) {
  const result = await pool.query("SELECT id, phone_number, price_sats, active, created_at FROM numbers ORDER BY id DESC");
  res.json(result.rows);
}));

app.post("/admin/numbers", auth, adminOnly, wrap(async function(req, res) {
  const number = String(req.body.number || "").trim();
  const priceSats = Number(req.body.priceSats);
  if (!number || !/^\+[1-9]\d{7,14}$/.test(number)) {
    return res.status(400).json({ error: "Use international format, e.g. +46700000001" });
  }
  if (!Number.isInteger(priceSats) || priceSats <= 0) {
    return res.status(400).json({ error: "Price must be a positive whole number of satoshis" });
  }
  const result = await pool.query(
    "INSERT INTO numbers (phone_number, price_sats, active) VALUES ($1, $2, TRUE) ON CONFLICT (phone_number) DO UPDATE SET price_sats = EXCLUDED.price_sats, active = TRUE RETURNING id, phone_number, price_sats, active",
    [number, priceSats]
  );
  return res.json(result.rows[0]);
}));

app.delete("/admin/numbers/:id", auth, adminOnly, wrap(async function(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid number ID" });
  await pool.query("UPDATE numbers SET active = FALSE WHERE id = $1", [id]);
  res.json({ ok: true });
}));

app.put("/admin/numbers/:id/price", auth, adminOnly, wrap(async function(req, res) {
  const id = Number(req.params.id);
  const priceSats = Number(req.body.priceSats);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid number ID" });
  if (!Number.isInteger(priceSats) || priceSats <= 0) return res.status(400).json({ error: "Price must be a positive whole number of satoshis" });
  const result = await pool.query("UPDATE numbers SET price_sats = $1 WHERE id = $2 RETURNING id, phone_number, price_sats, active", [priceSats, id]);
  if (!result.rows.length) return res.status(404).json({ error: "Number not found" });
  res.json(result.rows[0]);
}));

app.post("/create-invoice", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.status(400).json({ error: "Admin cannot buy numbers" });
  if (!SWISS_API_KEY || !SWISS_SECRET_KEY) {
    return res.status(503).json({ error: "Payment not configured. Set SWISS_API_KEY and SWISS_SECRET_KEY." });
  }

  // PROVIDER MODE: buy number dynamically from SMSPool/5sim
  if (req.body.mode === "provider") {
    const provider = await getActiveProvider();
    if (!provider) return res.status(503).json({ error: "No SMS provider configured. Contact admin." });
    const country = String(req.body.country || "").trim();
    const service = String(req.body.service || "").trim();
    const priceSats = Number(req.body.priceSats);
    if (!country || !service) return res.status(400).json({ error: "Country and service are required" });
    if (!Number.isInteger(priceSats) || priceSats <= 0) return res.status(400).json({ error: "Invalid price" });
    const appUrl = process.env.APP_URL || ("https://" + (process.env.RENDER_EXTERNAL_HOSTNAME || "smsnero.onrender.com"));
    // Create invoice WITHOUT number_id (provider mode: number assigned on payment)
    const invResult = await pool.query(
      "INSERT INTO invoices (user_id, number_id, amount_sats, country, service, provider) VALUES ($1, NULL, $2, $3, $4, $5) RETURNING id",
      [req.user.id, priceSats, country, service, provider.provider_type]
    );
    const invoiceId = invResult.rows[0].id;
    const payload = { title: "SMSNero", description: service + " - " + country, amount: priceSats, unit: "sat", onChain: false, delay: 10, webhook: { url: appUrl + "/webhook" } };
    const response = await fetch(SWISS_API_URL + "/checkout", { method: "POST", headers: { "Content-Type": "application/json", "api-key": SWISS_API_KEY }, body: JSON.stringify(payload) });
    const rawText = await response.text().catch(function() { return ""; });
    let data = {};
    try { data = JSON.parse(rawText); } catch(e) {}
    if (!response.ok) return res.status(502).json({ error: "Payment error: " + (data.message || data.error || rawText.slice(0, 200)) });
    await pool.query("UPDATE invoices SET provider_payment_id=$1, checkout_url=$2 WHERE id=$3", [data.id || null, data.checkoutUrl || data.url || null, invoiceId]);
    const lightningInvoice = data.pr || data.paymentRequest || null;
    const qrSource = lightningInvoice || data.checkoutUrl || data.url;
    if (!qrSource) return res.status(502).json({ error: "No payment URL returned" });
    const qr = await QRCode.toDataURL(qrSource);
    // Try wallet payment (atomic balance check prevents TOCTOU race)
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const deductResult = await client.query(
        "UPDATE wallets SET balance_sats = balance_sats - $1 WHERE user_id = $2 AND balance_sats >= $1 RETURNING balance_sats",
        [priceSats, req.user.id]
      );
      if (deductResult.rowCount > 0) {
        await client.query("UPDATE invoices SET status='paid' WHERE id=$1", [invoiceId]);
        await client.query("COMMIT");
        // Buy number from provider immediately
        let phone, orderId;
        try {
          const bought = await providerBuyNumber(provider, country, service);
          phone = bought.phone; orderId = bought.orderId;
        } catch(be) {
          const client2 = await pool.connect();
          await client2.query("UPDATE wallets SET balance_sats = balance_sats + $1 WHERE user_id = $2", [priceSats, req.user.id]).catch(function(){});
          client2.release();
          return res.status(502).json({ error: "Provider error: " + be.message });
        }
        const nr = await pool.query("INSERT INTO numbers (phone_number, price_sats, active) VALUES ($1, $2, TRUE) ON CONFLICT (phone_number) DO UPDATE SET active=TRUE, price_sats=EXCLUDED.price_sats RETURNING id", [phone, priceSats]);
        const numberId = nr.rows[0].id;
        await pool.query("UPDATE invoices SET number_id=$1 WHERE id=$2", [numberId, invoiceId]);
        const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600000);
        await pool.query("INSERT INTO sessions (user_id, number_id, invoice_id, expires_at, country, service, provider, provider_order_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING", [req.user.id, numberId, invoiceId, expiresAt, country, service, provider.provider_type, orderId]);
        broadcast({ type: "session_activated", userId: req.user.id, numberId, phoneNumber: phone });
        return res.json({ paid_from_wallet: true, amount_sats: priceSats, phone_number: phone });
      }
      // Insufficient wallet balance: roll back and fall through to Lightning payment
      await client.query("ROLLBACK");
    } catch(e) { await client.query("ROLLBACK").catch(function(){}); throw e; } finally { client.release(); }
    return res.json({ invoice_id: invoiceId, amount_sats: priceSats, qr: qr, lightning_invoice: lightningInvoice, checkout_url: data.checkoutUrl || data.url, mode: "provider" });
  }

  // P2P purchases must go through POST /api/buy (escrow flow), not this endpoint.
  if (req.body.p2pListingId) {
    return res.status(410).json({ error: "P2P purchases must use POST /api/buy (escrow flow). This path has been removed." });
  }

  let number, p2pListingId = null, sendNumberId = null;
  if (req.body.sendNumberId) {
    const sid = Number(req.body.sendNumberId);
    if (!Number.isInteger(sid) || sid <= 0) return res.status(400).json({ error: "Invalid send number ID" });
    const sr = await pool.query("SELECT id, phone_number, price_sats FROM send_numbers WHERE id = $1 AND active = TRUE", [sid]);
    if (!sr.rows[0]) return res.status(400).json({ error: "Send number not available" });
    number = { id: sr.rows[0].id, phone_number: sr.rows[0].phone_number, price_sats: sr.rows[0].price_sats, _isSend: true };
    sendNumberId = sid;
  } else {
    const numberId = Number(req.body.numberId);
    if (!Number.isInteger(numberId) || numberId <= 0) return res.status(400).json({ error: "Invalid number ID" });
    const numberResult = await pool.query("SELECT id, phone_number, price_sats FROM numbers WHERE id = $1 AND active = TRUE", [numberId]);
    number = numberResult.rows[0];
    if (!number) return res.status(400).json({ error: "Number not available" });
  }
  const appUrl = process.env.APP_URL || ("https://" + (process.env.RENDER_EXTERNAL_HOSTNAME || "smsnero.onrender.com"));
  const payload = {
    title: "SMSNero",
    description: "Phone number: " + number.phone_number,
    amount: number.price_sats,
    unit: "sat",
    onChain: false,
    delay: 10,
    webhook: { url: appUrl + "/webhook" }
  };
  const response = await fetch(SWISS_API_URL + "/checkout", {
    method: "POST",
    headers: { "Content-Type": "application/json", "api-key": SWISS_API_KEY },
    body: JSON.stringify(payload),
  });
  const rawText = await response.text().catch(function() { return ""; });
  let data = {};
  try { data = JSON.parse(rawText); } catch(e) {}
  if (!response.ok) {
    console.error("Swiss Bitcoin Pay HTTP status:", response.status, "body:", rawText.slice(0, 500));
    return res.status(502).json({ error: "Payment error HTTP " + response.status + ": " + (data.message || data.error || data.detail || rawText.slice(0, 200) || "empty response") });
  }
  const checkoutUrl = data.checkoutUrl || data.url || data.paymentUrl || data.payment_url;
  const lightningInvoice = data.pr || data.paymentRequest || null;
  if (!checkoutUrl && !lightningInvoice) {
    console.error("Swiss Bitcoin Pay no URL:", JSON.stringify(data));
    return res.status(502).json({ error: "No checkout URL returned. Response: " + JSON.stringify(data) });
  }
  const qrSource = lightningInvoice || checkoutUrl;
  const qr = await QRCode.toDataURL(qrSource);
  const country = String(req.body.country || "").trim().slice(0, 100) || null;
  const service = String(req.body.service || "").trim().slice(0, 100) || null;
  // Try wallet payment first (only for regular number and send-credit purchases)
  if (!sendNumberId && !number._isSend) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const deductResult = await client.query(
        "UPDATE wallets SET balance_sats = balance_sats - $1 WHERE user_id = $2 AND balance_sats >= $1 RETURNING balance_sats",
        [number.price_sats, req.user.id]
      );
      if (deductResult.rowCount > 0) {
        const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600000);
        await client.query("INSERT INTO sessions (user_id, number_id, expires_at, country, service) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING", [req.user.id, number.id, expiresAt, country, service]);
        await client.query("COMMIT");
        broadcast({ type: "session_activated", userId: req.user.id, numberId: number.id });
        return res.json({ paid_from_wallet: true, amount_sats: number.price_sats, phone_number: number.phone_number });
      }
      // Insufficient balance: roll back and fall through to Lightning invoice
      await client.query("ROLLBACK");
    } catch(e) { await client.query("ROLLBACK").catch(function(){}); throw e; }
    finally { client.release(); }
  }
  const numIdForInvoice = number._isSend ? null : number.id;
  const result = await pool.query(
    "INSERT INTO invoices (provider_payment_id, user_id, number_id, amount_sats, status, checkout_url, qr, country, service, send_number_id) VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9) RETURNING *",
    [data.id || null, req.user.id, numIdForInvoice, number.price_sats, checkoutUrl || qrSource, qr, country, service, sendNumberId]
  );
  const row = result.rows[0];
  row.lightning_invoice = lightningInvoice;
  return res.json(row);
}));

app.post("/webhook", wrap(async function(req, res) {
  if (!verifyWebhookSignature(req)) {
    console.warn("Webhook signature mismatch — ignoring request from", req.ip);
    return res.status(401).json({ error: "Invalid webhook signature" });
  }
  const event = req.body || {};
  console.log("Webhook received from Swiss Bitcoin Pay:", JSON.stringify(event));
  const eventId = event.invoiceId || event.paymentId || event.id;
  const status = String(event.status || "").toLowerCase();
  if (!eventId) return res.sendStatus(400);
  const invoiceResult = await pool.query("SELECT * FROM invoices WHERE id::text = $1 OR provider_payment_id = $1 LIMIT 1", [String(eventId)]);
  const invoice = invoiceResult.rows[0];
  if (!invoice) return res.sendStatus(404);
  if (status === "paid" || status === "settled" || status === "confirmed") {
    await pool.query("UPDATE invoices SET status = 'paid' WHERE id = $1", [invoice.id]);
    if (invoice.is_deposit) {
      await pool.query("INSERT INTO wallets (user_id, balance_sats) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET balance_sats = wallets.balance_sats + EXCLUDED.balance_sats", [invoice.user_id, invoice.amount_sats]);
      broadcast({ type: "wallet_topped_up", userId: invoice.user_id, amount: invoice.amount_sats });
      return res.sendStatus(200);
    }
    if (invoice.send_number_id) {
      await pool.query("INSERT INTO send_credits (user_id, send_number_id, invoice_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [invoice.user_id, invoice.send_number_id, invoice.id]);
      broadcast({ type: "send_credit_activated", userId: invoice.user_id });
    } else if (invoice.provider && !invoice.number_id) {
      // PROVIDER MODE: buy number from provider on payment
      const provider = await getActiveProvider();
      if (provider) {
        try {
          const bought = await providerBuyNumber(provider, invoice.country, invoice.service);
          const nr = await pool.query("INSERT INTO numbers (phone_number, price_sats, active) VALUES ($1, $2, TRUE) ON CONFLICT (phone_number) DO UPDATE SET active=TRUE, price_sats=EXCLUDED.price_sats RETURNING id", [bought.phone, invoice.amount_sats]);
          const numberId = nr.rows[0].id;
          await pool.query("UPDATE invoices SET number_id=$1 WHERE id=$2", [numberId, invoice.id]);
          const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600000);
          await pool.query("INSERT INTO sessions (user_id, number_id, invoice_id, expires_at, country, service, provider, provider_order_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            [invoice.user_id, numberId, invoice.id, expiresAt, invoice.country || null, invoice.service || null, provider.provider_type, bought.orderId]);
          broadcast({ type: "session_activated", userId: invoice.user_id, numberId, phoneNumber: bought.phone });
          console.log("Provider number bought on payment:", bought.phone, "orderId:", bought.orderId);
        } catch(pe) {
          console.error("Provider buy error on webhook payment:", pe.message);
          broadcast({ type: "provider_buy_error", userId: invoice.user_id, error: pe.message });
        }
      }
    } else {
      const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600000);
      await pool.query("INSERT INTO sessions (user_id, number_id, invoice_id, expires_at, country, service) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING", [invoice.user_id, invoice.number_id, invoice.id, expiresAt, invoice.country || null, invoice.service || null]);
      broadcast({ type: "session_activated", userId: invoice.user_id, numberId: invoice.number_id });
    }
    return res.sendStatus(200);
  }
  if (status === "expired" || status === "cancelled" || status === "failed") {
    await pool.query("UPDATE invoices SET status = $1 WHERE id = $2", [status, invoice.id]);
  }
  return res.sendStatus(200);
}));

app.post("/test-sms", auth, adminOnly, wrap(async function(req, res) {
  const { number, text } = req.body || {};
  if (!text) return res.status(400).json({ error: "Need text" });
  let numberId = null;
  if (number) {
    const numRes = await pool.query("SELECT id FROM numbers WHERE phone_number = $1 LIMIT 1", [number]);
    if (numRes.rows.length) numberId = numRes.rows[0].id;
  }
  if (!numberId) {
    const activeRes = await pool.query("SELECT number_id FROM sessions WHERE expires_at > NOW() ORDER BY created_at DESC LIMIT 1");
    if (activeRes.rows.length) numberId = activeRes.rows[0].number_id;
  }
  const otp = extractOTP(text);
  await pool.query("INSERT INTO messages (number_id, phone_number, text, otp) VALUES ($1, $2, $3, $4)", [numberId, "+000test", text, otp]);
  broadcast({ type: "message", phoneNumber: "+000test", text: text, otp: otp });
  console.log("Test SMS injected: text:", text, "otp:", otp, "number_id:", numberId);
  return res.json({ ok: true, otp: otp, number_id: numberId });
}));

async function handleSmsWebhook(req, res) {
  const body = req.body || {};
  console.log("=== SMS WEBHOOK ===");
  console.log("Method:", req.method, "Query:", JSON.stringify(req.query));
  console.log("Body:", JSON.stringify(body));
  console.log("Headers content-type:", req.headers["content-type"]);
  const sender = String(req.query.from || req.query.sender || req.query.originator || req.query.msisdn || body.from || body.phone || body.sender || body.originator || body.msisdn || "").trim();
  const text = String(req.query.text || req.query.body || req.query.message || req.query.sms || req.query.msg || body.text || body.message || body.body || body.sms || body.content || body.msg || "").trim();
  const toField = String(req.query.to || req.query.number || req.query.inbound_number || body.to || body.recipient || body.number || body.inbound_number || "").trim();
  console.log("Parsed sender:", sender, "text:", text, "to:", toField);
  if (!sender || !text) {
    console.log("SMS webhook missing fields");
    return res.status(400).json({ error: "Missing sender and text fields", received: { query: req.query, body: body } });
  }
  let numberId = null;
  if (toField) {
    const toResult = await pool.query("SELECT id FROM numbers WHERE phone_number = $1 LIMIT 1", [toField]);
    if (toResult.rows.length) numberId = toResult.rows[0].id;
  }
  if (!numberId) {
    const activeResult = await pool.query("SELECT number_id FROM sessions WHERE expires_at > NOW() ORDER BY created_at DESC LIMIT 1");
    if (activeResult.rows.length) numberId = activeResult.rows[0].number_id;
  }
  console.log("SMS assigned to number_id:", numberId, "from:", sender);
  const otp = extractOTP(text);
  await pool.query("INSERT INTO messages (number_id, phone_number, text, otp) VALUES ($1, $2, $3, $4)", [numberId, sender, text, otp]);
  broadcast({ type: "message", phoneNumber: sender, text: text, otp: otp });
  return res.sendStatus(200);
}
app.post("/sms-webhook", wrap(handleSmsWebhook));
app.get("/sms-webhook", wrap(handleSmsWebhook));

// Admin: test SMS delivery (simulate incoming SMS)
app.post("/admin/test-sms", auth, adminOnly, wrap(async function(req, res) {
  const text = String(req.body.text || "Your OTP code is 999888. Valid for 5 minutes.").trim();
  const from = String(req.body.from || "+10000000000").trim();
  const to = String(req.body.to || "").trim();
  let numberId = null;
  if (to) {
    const r = await pool.query("SELECT id FROM numbers WHERE phone_number=$1 LIMIT 1", [to]);
    if (r.rows.length) numberId = r.rows[0].id;
  }
  if (!numberId) {
    const r = await pool.query("SELECT number_id FROM sessions WHERE expires_at > NOW() ORDER BY created_at DESC LIMIT 1");
    if (r.rows.length) numberId = r.rows[0].number_id;
  }
  const otp = extractOTP(text);
  await pool.query("INSERT INTO messages (number_id, phone_number, text, otp) VALUES ($1, $2, $3, $4)", [numberId, from, text, otp]);
  broadcast({ type: "message", phoneNumber: from, text: text, otp: otp });
  console.log("TEST SMS injected: from", from, "text:", text, "otp:", otp, "number_id:", numberId);
  return res.json({ ok: true, otp: otp, number_id: numberId, message: "Test SMS injected and broadcast to all connected clients." });
}));

// P2P: submit a listing
app.post("/p2p/submit", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.status(400).json({ error: "Admin cannot submit P2P listings" });
  const phone = String(req.body.phoneNumber || "").trim();
  const price = Number(req.body.priceSats);
  const desc = String(req.body.description || "").trim().slice(0, 300) || null;
  if (!phone || !phone.startsWith("+")) return res.status(400).json({ error: "Phone number must start with +" });
  if (!Number.isInteger(price) || price <= 0) return res.status(400).json({ error: "Price must be a positive integer in sats" });
  const r = await pool.query(
    "INSERT INTO p2p_listings (user_id, phone_number, price_sats, description) VALUES ($1, $2, $3, $4) RETURNING id",
    [req.user.id, phone, price, desc]
  );
  res.json({ ok: true, id: r.rows[0].id });
}));

// P2P: get marketplace (approved & active listings, not owned by self)
app.get("/p2p/market", auth, wrap(async function(req, res) {
  const r = await pool.query(
    "SELECT id, phone_number, price_sats, description FROM p2p_listings WHERE approved = TRUE AND active = TRUE AND user_id <> $1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(r.rows);
}));

// P2P: get own listings with earnings
app.get("/p2p/my-listings", auth, wrap(async function(req, res) {
  const r = await pool.query(
    "SELECT id, phone_number, price_sats, description, approved, active, owner_earned_sats, owner_paid_sats FROM p2p_listings WHERE user_id = $1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(r.rows);
}));

// ADMIN: view all P2P listings
app.get("/admin/p2p", auth, adminOnly, wrap(async function(req, res) {
  const r = await pool.query(
    "SELECT p.*, u.username FROM p2p_listings p LEFT JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC"
  );
  res.json(r.rows);
}));

// ADMIN: approve a P2P listing (adds number to numbers table)
app.put("/admin/p2p/:id/approve", auth, adminOnly, wrap(async function(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid ID" });
  const lr = await pool.query("SELECT * FROM p2p_listings WHERE id = $1", [id]);
  const listing = lr.rows[0];
  if (!listing) return res.status(404).json({ error: "Listing not found" });
  // Upsert the number into the numbers table
  const nr = await pool.query(
    "INSERT INTO numbers (phone_number, price_sats) VALUES ($1, $2) ON CONFLICT (phone_number) DO UPDATE SET active = TRUE, price_sats = EXCLUDED.price_sats RETURNING id",
    [listing.phone_number, listing.price_sats]
  );
  const numberId = nr.rows[0].id;
  await pool.query("UPDATE p2p_listings SET approved = TRUE, active = TRUE, number_id = $1 WHERE id = $2", [numberId, id]);
  res.json({ ok: true });
}));

// ADMIN: remove/deactivate a P2P listing
app.delete("/admin/p2p/:id", auth, adminOnly, wrap(async function(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid ID" });
  await pool.query("UPDATE p2p_listings SET active = FALSE WHERE id = $1", [id]);
  res.json({ ok: true });
}));

// ADMIN: mark a payout as done
app.post("/admin/p2p/:id/payout", auth, adminOnly, wrap(async function(req, res) {
  const id = Number(req.params.id);
  const amount = Number(req.body.amount);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid ID" });
  if (!Number.isInteger(amount) || amount <= 0) return res.status(400).json({ error: "Invalid amount" });
  await pool.query("UPDATE p2p_listings SET owner_paid_sats = owner_paid_sats + $1 WHERE id = $2", [amount, id]);
  res.json({ ok: true });
}));

// REFUND: request refund if no OTP received
app.post("/refund-session", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.status(400).json({ error: "Admin cannot refund" });
  const sessionId = Number(req.body.sessionId);
  if (!sessionId) return res.status(400).json({ error: "Missing sessionId" });
  const sRow = await pool.query(
    "SELECT s.id, s.user_id, s.number_id, s.created_at, s.provider, s.provider_order_id, n.price_sats FROM sessions s JOIN numbers n ON n.id = s.number_id WHERE s.id = $1 AND s.user_id = $2",
    [sessionId, req.user.id]
  );
  if (!sRow.rows.length) return res.status(404).json({ error: "Session not found" });
  const sess = sRow.rows[0];
  const msgCheck = await pool.query(
    "SELECT id FROM messages WHERE number_id = $1 AND created_at >= $2 LIMIT 1",
    [sess.number_id, sess.created_at]
  );
  if (msgCheck.rows.length) return res.status(403).json({ error: "OTP/SMS already received — no refund possible" });
  const inv = await pool.query(
    "SELECT amount_sats FROM invoices WHERE user_id = $1 AND number_id = $2 AND status = 'paid' AND is_deposit = FALSE ORDER BY id DESC LIMIT 1",
    [req.user.id, sess.number_id]
  );
  const refundSats = inv.rows.length ? Number(inv.rows[0].amount_sats) : Number(sess.price_sats);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM sessions WHERE id = $1", [sess.id]);
    await client.query("INSERT INTO wallets (user_id, balance_sats) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET balance_sats = wallets.balance_sats + EXCLUDED.balance_sats", [req.user.id, refundSats]);
    await client.query("COMMIT");
    broadcast({ type: "wallet_topped_up", userId: req.user.id, amount: refundSats });
    // Cancel with provider if applicable
    if (sess.provider && sess.provider_order_id) {
      const provider = await getActiveProvider();
      if (provider) {
        providerRefund(provider, sess.provider_order_id).then(function(r) {
          console.log("Provider refund result for", sess.provider_order_id, ":", JSON.stringify(r));
        });
      }
    }
    res.json({ refunded_sats: refundSats });
  } catch(e) { await client.query("ROLLBACK"); throw e; }
  finally { client.release(); }
}));

// WALLET: get balance
app.get("/wallet/balance", auth, wrap(async function(req, res) {
  const r = await pool.query("SELECT balance_sats FROM wallets WHERE user_id = $1", [req.user.id]);
  res.json({ balance_sats: r.rows[0]?.balance_sats || 0 });
}));

// WALLET: deposit (create Lightning invoice)
app.post("/wallet/deposit", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.status(400).json({ error: "Admin cannot deposit to wallet" });
  if (!SWISS_API_KEY || !SWISS_SECRET_KEY) return res.status(503).json({ error: "Payment not configured" });
  const amount = Number(req.body.amountSats);
  if (!Number.isInteger(amount) || amount < 100) return res.status(400).json({ error: "Minimum deposit is 100 sats" });
  const appUrl = process.env.APP_URL || ("https://" + (process.env.RENDER_EXTERNAL_HOSTNAME || "smsnero.onrender.com"));
  const payload = { title: "SMSNero Wallet", description: "Deposit " + amount + " sats", amount: amount, unit: "sat", onChain: false, delay: 10, webhook: { url: appUrl + "/webhook" } };
  const response = await fetch(SWISS_API_URL + "/checkout", { method: "POST", headers: { "Content-Type": "application/json", "api-key": SWISS_API_KEY }, body: JSON.stringify(payload) });
  const rawText = await response.text().catch(function() { return ""; });
  let data = {}; try { data = JSON.parse(rawText); } catch(e) {}
  if (!response.ok) return res.status(502).json({ error: "Payment error: " + (data.message || rawText.slice(0, 100)) });
  const checkoutUrl = data.checkoutUrl || data.url || data.paymentUrl;
  const lightningInvoice = data.pr || data.paymentRequest || null;
  if (!checkoutUrl && !lightningInvoice) return res.status(502).json({ error: "No checkout URL returned" });
  const qrSource = lightningInvoice || checkoutUrl;
  const qr = await QRCode.toDataURL(qrSource);
  const r = await pool.query("INSERT INTO invoices (provider_payment_id, user_id, amount_sats, status, checkout_url, qr, is_deposit) VALUES ($1, $2, $3, 'pending', $4, $5, TRUE) RETURNING id, amount_sats, checkout_url, qr", [data.id || null, req.user.id, amount, checkoutUrl || qrSource, qr]);
  const row = r.rows[0]; row.lightning_invoice = lightningInvoice;
  res.json(row);
}));

// ADMIN: stats dashboard
app.get("/admin/stats", auth, adminOnly, wrap(async function(req, res) {
  const rev = await pool.query("SELECT COALESCE(SUM(amount_sats),0) as total, COUNT(*) as count FROM invoices WHERE status='paid' AND is_deposit=FALSE AND send_number_id IS NULL");
  const active = await pool.query("SELECT COUNT(*) as count FROM sessions WHERE expires_at > NOW()");
  const p2p = await pool.query("SELECT COALESCE(SUM(amount_sats),0) as total, COUNT(*) as count FROM invoices WHERE status='paid' AND p2p_listing_id IS NOT NULL");
  const sends = await pool.query("SELECT COUNT(*) as count FROM outbox WHERE status='sent'");
  const services = await pool.query("SELECT service, COUNT(*) as cnt FROM sessions WHERE service IS NOT NULL GROUP BY service ORDER BY cnt DESC LIMIT 5");
  const today = await pool.query("SELECT COALESCE(SUM(amount_sats),0) as total FROM invoices WHERE status='paid' AND is_deposit=FALSE AND created_at > NOW() - INTERVAL '24 hours'");
  res.json({ total_revenue: Number(rev.rows[0].total), total_invoices: Number(rev.rows[0].count), active_sessions: Number(active.rows[0].count), p2p_revenue: Number(p2p.rows[0].total), p2p_count: Number(p2p.rows[0].count), sms_sent: Number(sends.rows[0].count), today_revenue: Number(today.rows[0].total), top_services: services.rows });
}));

// ADMIN: add a send number
app.post("/admin/send-numbers", auth, adminOnly, wrap(async function(req, res) {
  const phone = String(req.body.phoneNumber || "").trim();
  const price = Number(req.body.priceSats);
  if (!phone || !phone.startsWith("+")) return res.status(400).json({ error: "Phone must start with +" });
  if (!Number.isInteger(price) || price <= 0) return res.status(400).json({ error: "Price must be positive sats" });
  const r = await pool.query("INSERT INTO send_numbers (phone_number, price_sats) VALUES ($1, $2) ON CONFLICT (phone_number) DO UPDATE SET active = TRUE, price_sats = EXCLUDED.price_sats RETURNING *", [phone, price]);
  res.json(r.rows[0]);
}));

// ADMIN: list send numbers
app.get("/admin/send-numbers", auth, adminOnly, wrap(async function(req, res) {
  const r = await pool.query("SELECT * FROM send_numbers ORDER BY created_at DESC");
  res.json(r.rows);
}));

// ADMIN: disable a send number
app.delete("/admin/send-numbers/:id", auth, adminOnly, wrap(async function(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid ID" });
  await pool.query("UPDATE send_numbers SET active = FALSE WHERE id = $1", [id]);
  res.json({ ok: true });
}));

// ADMIN: view outbox
app.get("/admin/outbox", auth, adminOnly, wrap(async function(req, res) {
  const r = await pool.query("SELECT * FROM outbox ORDER BY created_at DESC LIMIT 100");
  res.json(r.rows);
}));

// CLIENT: list active send numbers
app.get("/send-numbers", auth, wrap(async function(req, res) {
  const r = await pool.query("SELECT id, phone_number, price_sats FROM send_numbers WHERE active = TRUE ORDER BY created_at DESC");
  res.json(r.rows);
}));

// CLIENT: check for unused send credit
app.get("/my-send-credit", auth, wrap(async function(req, res) {
  const r = await pool.query("SELECT id, send_number_id FROM send_credits WHERE user_id = $1 AND used = FALSE ORDER BY created_at DESC LIMIT 1", [req.user.id]);
  if (!r.rows.length) return res.status(204).send("");
  res.json(r.rows[0]);
}));

// CLIENT: submit a message using a send credit
app.post("/send-message", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.status(400).json({ error: "Admin cannot use send credits" });
  const creditId = Number(req.body.creditId);
  const recipient = String(req.body.recipient || "").trim();
  const message = String(req.body.message || "").trim().slice(0, 500);
  if (!Number.isInteger(creditId) || creditId <= 0) return res.status(400).json({ error: "Invalid credit ID" });
  if (!recipient || !message) return res.status(400).json({ error: "recipient and message required" });
  const cr = await pool.query("SELECT * FROM send_credits WHERE id = $1 AND user_id = $2 AND used = FALSE", [creditId, req.user.id]);
  if (!cr.rows[0]) return res.status(400).json({ error: "No valid send credit found" });
  const credit = cr.rows[0];
  await pool.query("UPDATE send_credits SET used = TRUE WHERE id = $1", [creditId]);
  await pool.query("INSERT INTO outbox (user_id, send_number_id, recipient, message) VALUES ($1, $2, $3, $4)", [req.user.id, credit.send_number_id, recipient, message]);
  res.json({ ok: true });
}));

// CLIENT: view own sent messages
app.get("/my-sent", auth, wrap(async function(req, res) {
  const r = await pool.query("SELECT recipient, message, status, created_at FROM outbox WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50", [req.user.id]);
  res.json(r.rows);
}));

// Extract the admin JWT for MacroDroid endpoints.
// Primary: Authorization: Bearer <token> header.
// Fallback: ?key=<token> query param (deprecated — avoid; token leaks into logs).
function macrodroidAuth(req, res) {
  const authHeader = req.headers.authorization || "";
  let key = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (!key) {
    key = String(req.query.key || "").trim();
    if (key) console.warn("MacroDroid: token supplied via query param — switch to Authorization: Bearer header");
  }
  if (!key) { res.status(401).json({ error: "Missing Authorization header (Bearer token required)" }); return null; }
  let user;
  try { user = verifyToken(key); } catch(e) { res.status(403).json({ error: "Invalid or expired token" }); return null; }
  if (user.role !== "admin") { res.status(403).json({ error: "Admin only" }); return null; }
  return user;
}

// MacroDroid polling: returns next pending SMS
app.get("/api/pending-sms", wrap(async function(req, res) {
  if (!macrodroidAuth(req, res)) return;
  const r = await pool.query("SELECT id, recipient, message FROM outbox WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1");
  if (!r.rows.length) return res.status(204).send("");
  res.json(r.rows[0]);
}));

// MacroDroid confirm: marks SMS as sent
app.get("/api/sms-sent/:id", wrap(async function(req, res) {
  if (!macrodroidAuth(req, res)) return;
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid ID" });
  await pool.query("UPDATE outbox SET status = 'sent' WHERE id = $1", [id]);
  res.json({ ok: true });
}));

// PUBLIC: announcements (no auth)
app.get("/public/announcements", wrap(async function(req, res) {
  const r = await pool.query("SELECT id, title, body, created_at FROM announcements WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 10");
  res.json(r.rows);
}));

// PUBLIC: promo ads (no auth)
app.get("/public/promo-ads", wrap(async function(req, res) {
  const r = await pool.query("SELECT id, title, url, description FROM promo_ads WHERE is_active = TRUE ORDER BY sort_order ASC, created_at DESC LIMIT 20");
  res.json(r.rows);
}));

// PUBLIC: crypto news (no auth, cached)
app.get("/public/news", wrap(async function(req, res) {
  const items = await fetchNews();
  res.json(items);
}));

// PUBLIC: show active referral codes so clients know what's available
app.get("/public/referral-codes", wrap(async function(req, res) {
  const r = await pool.query("SELECT code, bonus_sats, description FROM referral_codes WHERE is_active = TRUE AND uses_count < max_uses ORDER BY created_at DESC LIMIT 20");
  res.json(r.rows);
}));

// USER: use referral code
app.post("/use-referral", auth, wrap(async function(req, res) {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Code is required" });
  const codeRow = await pool.query("SELECT * FROM referral_codes WHERE code = $1 AND is_active = TRUE", [String(code).toUpperCase()]);
  if (!codeRow.rows.length) return res.status(404).json({ error: "Invalid or expired referral code" });
  const rc = codeRow.rows[0];
  if (rc.uses_count >= rc.max_uses) return res.status(400).json({ error: "This code has reached its usage limit" });
  const already = await pool.query("SELECT id FROM user_referrals WHERE user_id = $1 AND referral_code_id = $2", [req.user.id, rc.id]);
  if (already.rows.length) return res.status(400).json({ error: "You already used this referral code" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO user_referrals (user_id, referral_code_id) VALUES ($1, $2)", [req.user.id, rc.id]);
    await client.query("INSERT INTO wallets (user_id, balance_sats) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET balance_sats = wallets.balance_sats + $2", [req.user.id, rc.bonus_sats]);
    await client.query("UPDATE referral_codes SET uses_count = uses_count + 1 WHERE id = $1", [rc.id]);
    await client.query("COMMIT");
    res.json({ bonus_sats: rc.bonus_sats });
  } catch(e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}));

// ADMIN: referral codes CRUD
app.get("/admin/referral-codes", auth, adminOnly, wrap(async function(req, res) {
  const r = await pool.query("SELECT * FROM referral_codes ORDER BY created_at DESC");
  res.json(r.rows);
}));
app.post("/admin/referral-codes", auth, adminOnly, wrap(async function(req, res) {
  const { code, bonusSats, description } = req.body;
  if (!code || !bonusSats) return res.status(400).json({ error: "Code and bonusSats required" });
  const r = await pool.query("INSERT INTO referral_codes (code, bonus_sats, description) VALUES ($1, $2, $3) RETURNING *", [String(code).toUpperCase(), Number(bonusSats), description || null]);
  res.json(r.rows[0]);
}));
app.delete("/admin/referral-codes/:id", auth, adminOnly, wrap(async function(req, res) {
  await pool.query("UPDATE referral_codes SET is_active = FALSE WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
}));

// ADMIN: announcements CRUD
app.get("/admin/announcements", auth, adminOnly, wrap(async function(req, res) {
  const r = await pool.query("SELECT * FROM announcements ORDER BY created_at DESC LIMIT 20");
  res.json(r.rows);
}));
app.post("/admin/announcements", auth, adminOnly, wrap(async function(req, res) {
  const { title, body } = req.body;
  if (!title) return res.status(400).json({ error: "Title required" });
  const r = await pool.query("INSERT INTO announcements (title, body) VALUES ($1, $2) RETURNING *", [title, body || null]);
  res.json(r.rows[0]);
}));
app.delete("/admin/announcements/:id", auth, adminOnly, wrap(async function(req, res) {
  await pool.query("DELETE FROM announcements WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
}));

// ADMIN: promo ads CRUD
app.get("/admin/promo-ads", auth, adminOnly, wrap(async function(req, res) {
  const r = await pool.query("SELECT * FROM promo_ads ORDER BY sort_order ASC, created_at DESC");
  res.json(r.rows);
}));
app.post("/admin/promo-ads", auth, adminOnly, wrap(async function(req, res) {
  const { title, url, description } = req.body;
  if (!title || !url) return res.status(400).json({ error: "Title and URL required" });
  const r = await pool.query("INSERT INTO promo_ads (title, url, description) VALUES ($1, $2, $3) RETURNING *", [title, url, description || null]);
  res.json(r.rows[0]);
}));
app.delete("/admin/promo-ads/:id", auth, adminOnly, wrap(async function(req, res) {
  await pool.query("DELETE FROM promo_ads WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
}));

async function releaseFunds(tx) {
  await pool.query("INSERT INTO wallets (user_id, balance_sats) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET balance_sats = wallets.balance_sats + EXCLUDED.balance_sats", [tx.seller_id, tx.seller_amount]);
  await pool.query("UPDATE escrow_transactions SET status='released', released_at=$1 WHERE id=$2", [Date.now(), tx.id]);
  if (tx.listing_id) await pool.query("UPDATE p2p_listings SET owner_earned_sats = owner_earned_sats + $1 WHERE id = $2", [tx.seller_amount, tx.listing_id]);
  broadcast({ type: "escrow_released", txId: tx.id, sellerId: tx.seller_id });
}

app.post("/api/buy", auth, wrap(async function(req, res) {
  if (!SWISS_API_KEY) return res.status(503).json({ error: "Payment not configured" });
  const { listingId } = req.body;
  const buyerId = req.user.id;
  if (!listingId) return res.status(400).json({ error: "listingId required" });
  const listing = await pool.query("SELECT * FROM p2p_listings WHERE id=$1 AND active=TRUE AND approved=TRUE", [listingId]);
  if (!listing.rows.length) return res.status(404).json({ error: "Listing not found or not approved" });
  const item = listing.rows[0];
  if (buyerId === item.user_id) return res.status(400).json({ error: "Cannot buy your own listing" });
  const sats = item.price_sats;
  const commission = Math.ceil(sats * 0.08);
  const sellerAmount = sats - commission;
  const txId = crypto.randomBytes(16).toString("hex");
  const baseUrl = process.env.BASE_URL || "https://smsnero.onrender.com";
  const webhookUrl = baseUrl + "/api/webhook/" + txId;
  const payload = { amount: sats, unit: "sat", description: "SMSNero Escrow #" + txId.slice(0, 8), webhook: webhookUrl, delay: 1800 };
  const response = await fetch(SWISS_API_URL + "/checkout", { method: "POST", headers: { "Content-Type": "application/json", "api-key": SWISS_API_KEY }, body: JSON.stringify(payload) });
  if (!response.ok) {
    const err = await response.text();
    return res.status(502).json({ error: "Invoice creation failed: " + err });
  }
  const invoice = await response.json();
  const paymentRequest = invoice.payment_request || invoice.paymentRequest || invoice.lightning_invoice || "";
  const invoiceId = String(invoice.id || invoice.payment_id || "");
  await pool.query("INSERT INTO escrow_transactions (id, listing_id, buyer_id, seller_id, amount_sats, seller_amount, commission, invoice_id, payment_request, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10)", [txId, listingId, buyerId, item.user_id, sats, sellerAmount, commission, invoiceId, paymentRequest, Date.now()]);
  res.json({ txId, paymentRequest, amountSats: sats, qr: invoice.qr || "" });
}));

app.post("/api/webhook/:txId", wrap(async function(req, res) {
  if (!verifyWebhookSignature(req)) {
    console.warn("Escrow webhook signature mismatch — ignoring request from", req.ip);
    return res.status(401).json({ error: "Invalid webhook signature" });
  }
  const { txId } = req.params;
  const tx = await pool.query("SELECT * FROM escrow_transactions WHERE id=$1", [txId]);
  if (!tx.rows.length) return res.status(404).json({ error: "Transaction not found" });
  if (tx.rows[0].status !== "pending") return res.json({ ok: true });
  const body = req.body;
  if (body && (body.paid === true || body.status === "paid" || body.status === "PAID" || body.status === "settled")) {
    await pool.query("UPDATE escrow_transactions SET status='paid', paid_at=$1 WHERE id=$2", [Date.now(), txId]);
    broadcast({ type: "escrow_paid", txId, listingId: tx.rows[0].listing_id, sellerId: tx.rows[0].seller_id, amountSats: tx.rows[0].seller_amount });
    console.log("Escrow paid:", txId);
  }
  res.json({ ok: true });
}));

app.post("/api/confirm/:txId", auth, wrap(async function(req, res) {
  const { txId } = req.params;
  const tx = await pool.query("SELECT * FROM escrow_transactions WHERE id=$1", [txId]);
  if (!tx.rows.length) return res.status(404).json({ error: "Transaction not found" });
  const item = tx.rows[0];
  if (item.buyer_id !== req.user.id && req.user.role !== "admin") return res.status(403).json({ error: "Not your transaction" });
  if (!["paid", "disputed"].includes(item.status)) return res.status(400).json({ error: "Transaction not in confirmable state. Status: " + item.status });
  await releaseFunds(item);
  res.json({ ok: true, sellerAmount: item.seller_amount });
}));

app.post("/api/dispute/:txId", auth, wrap(async function(req, res) {
  const { txId } = req.params;
  const { reason } = req.body;
  const tx = await pool.query("SELECT * FROM escrow_transactions WHERE id=$1", [txId]);
  if (!tx.rows.length) return res.status(404).json({ error: "Transaction not found" });
  const item = tx.rows[0];
  if (item.buyer_id !== req.user.id) return res.status(403).json({ error: "Only the buyer can open a dispute" });
  if (item.status !== "paid") return res.status(400).json({ error: "Can only dispute paid transactions" });
  await pool.query("UPDATE escrow_transactions SET status='disputed', dispute_reason=$1 WHERE id=$2", [reason || "No reason provided", txId]);
  broadcast({ type: "escrow_disputed", txId });
  res.json({ ok: true });
}));

app.post("/api/admin/resolve/:txId", auth, adminOnly, wrap(async function(req, res) {
  const { txId } = req.params;
  const { winner } = req.body;
  if (!["buyer", "seller"].includes(winner)) return res.status(400).json({ error: "winner must be 'buyer' or 'seller'" });
  const tx = await pool.query("SELECT * FROM escrow_transactions WHERE id=$1", [txId]);
  if (!tx.rows.length) return res.status(404).json({ error: "Transaction not found" });
  const item = tx.rows[0];
  if (!["disputed", "paid"].includes(item.status)) return res.status(400).json({ error: "Can only resolve disputed or paid transactions" });
  if (winner === "seller") {
    await releaseFunds(item);
    res.json({ ok: true, resolution: "seller_wins" });
  } else {
    // Credit the full amount back to the buyer's wallet
    await pool.query(
      "INSERT INTO wallets (user_id, balance_sats) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET balance_sats = wallets.balance_sats + EXCLUDED.balance_sats",
      [item.buyer_id, item.amount_sats]
    );
    await pool.query("UPDATE escrow_transactions SET status='refunded', released_at=$1 WHERE id=$2", [Date.now(), txId]);
    broadcast({ type: "escrow_refunded", txId, buyerId: item.buyer_id, amountSats: item.amount_sats });
    res.json({ ok: true, resolution: "buyer_refunded", refundedSats: item.amount_sats });
  }
}));

app.get("/api/tx/:txId", auth, wrap(async function(req, res) {
  const tx = await pool.query("SELECT id, listing_id, buyer_id, seller_id, amount_sats, seller_amount, commission, status, dispute_reason, created_at, paid_at, released_at FROM escrow_transactions WHERE id=$1", [req.params.txId]);
  if (!tx.rows.length) return res.status(404).json({ error: "Not found" });
  const item = tx.rows[0];
  if (item.buyer_id !== req.user.id && item.seller_id !== req.user.id && req.user.role !== "admin") return res.status(403).json({ error: "Access denied" });
  res.json({ ...item, my_role: item.buyer_id === req.user.id ? "buyer" : "seller" });
}));

app.get("/api/my-escrow", auth, wrap(async function(req, res) {
  if (req.user.role === "admin") return res.json([]);
  const uid = req.user.id;
  const result = await pool.query("SELECT id, listing_id, buyer_id, seller_id, amount_sats, seller_amount, commission, status, dispute_reason, created_at, paid_at, released_at FROM escrow_transactions WHERE (buyer_id=$1 OR seller_id=$1) AND status NOT IN ('released','refunded') ORDER BY created_at DESC LIMIT 30", [uid]);
  const rows = result.rows.map(function(r) { return Object.assign({}, r, { my_role: r.buyer_id === uid ? "buyer" : "seller" }); });
  res.json(rows);
}));

app.get("/api/admin/escrow", auth, adminOnly, wrap(async function(req, res) {
  const result = await pool.query("SELECT e.*, ub.username AS buyer_name, us.username AS seller_name FROM escrow_transactions e LEFT JOIN users ub ON ub.id=e.buyer_id LEFT JOIN users us ON us.id=e.seller_id ORDER BY e.created_at DESC LIMIT 100");
  res.json(result.rows);
}));

app.post("/api/withdraw", auth, wrap(async function(req, res) {
  if (!SWISS_API_KEY) return res.status(503).json({ error: "Payment not configured" });
  const { lightningAddress } = req.body;
  if (!lightningAddress || !lightningAddress.trim()) return res.status(400).json({ error: "lightningAddress required" });
  const wallet = await pool.query("SELECT balance_sats FROM wallets WHERE user_id=$1", [req.user.id]);
  const balance = wallet.rows.length ? wallet.rows[0].balance_sats : 0;
  if (balance < 100) return res.status(400).json({ error: "Minimum withdrawal is 100 sats. Your balance: " + balance + " sats" });
  await pool.query("UPDATE wallets SET balance_sats=0 WHERE user_id=$1", [req.user.id]);
  try {
    const response = await fetch(SWISS_API_URL + "/payout", { method: "POST", headers: { "Content-Type": "application/json", "api-key": SWISS_API_KEY }, body: JSON.stringify({ amount: balance, unit: "sat", address: lightningAddress.trim() }) });
    if (!response.ok) {
      await pool.query("UPDATE wallets SET balance_sats=balance_sats+$1 WHERE user_id=$2", [balance, req.user.id]);
      const err = await response.text();
      return res.status(502).json({ error: "Payout failed: " + err });
    }
    const result = await response.json();
    res.json({ ok: true, amountSats: balance, result });
  } catch(e) {
    await pool.query("UPDATE wallets SET balance_sats=balance_sats+$1 WHERE user_id=$2", [balance, req.user.id]);
    res.status(502).json({ error: "Payout error: " + e.message });
  }
}));

// PROVIDER CATALOG: countries, services, price (public for logged-in users)
app.get("/api/provider/catalog", auth, wrap(async function(req, res) {
  const provider = await getActiveProvider();
  if (!provider) return res.json({ active: false, type: null, countries: [], services: [] });
  try {
    const countries = await providerGetCountries(provider);
    const country = req.query.country || null;
    const services = country ? await providerGetServices(provider, country) : [];
    return res.json({ active: true, type: provider.provider_type, btcRate: _btcRate, countries: countries.slice(0, 300), services: services.slice(0, 500) });
  } catch(e) {
    console.error("Provider catalog error:", e.message);
    return res.status(502).json({ active: false, type: provider.provider_type, error: e.message, countries: [], services: [] });
  }
}));

app.get("/api/provider/price", auth, wrap(async function(req, res) {
  const provider = await getActiveProvider();
  if (!provider) return res.json({ sats: 0, usd_cents: 0 });
  const { country, service } = req.query;
  if (!country || !service) return res.json({ sats: 0, usd_cents: 0 });
  try {
    const services = await providerGetServices(provider, country);
    const svc = services.find(function(s) { return s.id === service || s.name.toLowerCase() === String(service).toLowerCase(); });
    const cents = svc ? (svc.price_cents || 50) : 50;
    const markup = 1.3;
    const finalCents = Math.ceil(cents * markup);
    const sats = usdCentsToSats(finalCents);
    return res.json({ sats: sats, usd_cents: finalCents, raw_cents: cents, btcRate: _btcRate, available: svc ? (svc.available || 0) : 0 });
  } catch(e) {
    console.error("Provider price error:", e.message);
    return res.json({ sats: usdCentsToSats(65), usd_cents: 65, btcRate: _btcRate });
  }
}));

app.get("/admin/sms-providers", auth, adminOnly, wrap(async function(req, res) {
  const result = await pool.query("SELECT id, name, provider_type, api_url, is_active, notes, created_at FROM sms_providers ORDER BY id DESC");
  res.json(result.rows);
}));

app.post("/admin/sms-providers", auth, adminOnly, wrap(async function(req, res) {
  const { name, provider_type, api_key, api_secret, api_url, notes } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "Provider name required" });
  const result = await pool.query(
    "INSERT INTO sms_providers (name, provider_type, api_key, api_secret, api_url, notes) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, provider_type, api_url, is_active, notes, created_at",
    [name.trim(), (provider_type || "other").trim(), api_key || null, api_secret || null, api_url || null, notes || null]
  );
  res.json(result.rows[0]);
}));

app.patch("/admin/sms-providers/:id", auth, adminOnly, wrap(async function(req, res) {
  const { is_active } = req.body;
  await pool.query("UPDATE sms_providers SET is_active = $1 WHERE id = $2", [!!is_active, req.params.id]);
  res.json({ ok: true });
}));

app.delete("/admin/sms-providers/:id", auth, adminOnly, wrap(async function(req, res) {
  await pool.query("DELETE FROM sms_providers WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
}));

wss.on("connection", function(socket) {
  sockets.add(socket);
  socket.on("close", function() { sockets.delete(socket); });
  socket.on("error", function() { sockets.delete(socket); });
});

initDb().then(function() {
  setInterval(pollProviderSessions, 12000);
  server.listen(PORT, function() {
    console.log("SMSNero running on port " + PORT);
  });
}).catch(function(err) {
  console.error("Failed to initialize database:", err);
  process.exit(1);
});
