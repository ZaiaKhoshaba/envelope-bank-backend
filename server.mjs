// bank-backend/server.mjs

import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

// ── Env config ────────────────────────────────────────────────────────────────

const PORT = Number(process.env.PORT || 4000);

// MongoDB
const MONGODB_URI = process.env.MONGODB_URI || "";

// Fiskil
const FISKIL_API_BASE      = (process.env.FISKIL_API_BASE || "https://api.fiskil.com").replace(/\/+$/, "");
const FISKIL_V1_BASE       = FISKIL_API_BASE.endsWith("/v1") ? FISKIL_API_BASE : `${FISKIL_API_BASE}/v1`;
const FISKIL_CLIENT_ID     = process.env.FISKIL_CLIENT_ID     || "";
const FISKIL_CLIENT_SECRET = process.env.FISKIL_CLIENT_SECRET || "";
const FISKIL_END_USER_ID   = process.env.FISKIL_END_USER_ID   || "";

// Auth
const AUTH_JWT_SECRET  = process.env.AUTH_JWT_SECRET  || "change-me-in-.env";
const AUTH_JWT_EXPIRES = process.env.AUTH_JWT_EXPIRES || "7d";

// Webhook
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";

// ── MongoDB connection ────────────────────────────────────────────────────────
// Single client instance, lazily connected on first use.
// Includes a ping-based health check so that connections dropped during
// Render's free-tier sleep are automatically re-established on wake-up.

let _client = null;
let _db     = null;

async function getDb() {
  // If we already have a connection, verify it is still alive.
  // Render's free-tier server sleeps and drops the TCP socket, which leaves
  // the MongoClient in a "Topology is closed" state. The ping detects this
  // and forces a fresh connection before any real DB work is attempted.
  if (_client && _db) {
    try {
      await _client.db("admin").command({ ping: 1 });
      return _db; // connection is healthy — reuse it
    } catch {
      console.warn("⚠️  MongoDB connection lost (server woke from sleep?) — reconnecting…");
      try { await _client.close(); } catch { /* ignore */ }
      _client = null;
      _db     = null;
    }
  }

  if (!MONGODB_URI) {
    throw new Error(
      "MONGODB_URI is not set. Add it to your .env file (local) " +
      "or Render environment variables (production)."
    );
  }

  _client = new MongoClient(MONGODB_URI, {
    serverSelectionTimeoutMS: 10_000,  // fail fast if Atlas is unreachable
    connectTimeoutMS:         10_000,
    socketTimeoutMS:          45_000,
  });
  await _client.connect();
  console.log("✅ MongoDB connected");
  _db = _client.db("envelopes"); // database name inside Atlas
  return _db;
}

// ── User helpers ──────────────────────────────────────────────────────────────

async function findUserByEmail(email) {
  const db = await getDb();
  return db.collection("users").findOne({ email });
}

async function insertUser(user) {
  const db = await getDb();
  await db.collection("users").insertOne(user);
}

function publicUser(u) {
  const { _id, passwordHash, ...rest } = u;
  return rest;
}

// ── Push token helpers ────────────────────────────────────────────────────────

async function getPushTokens(filter = {}) {
  const db = await getDb();
  return db.collection("push_tokens").find(filter).toArray();
}

async function upsertPushToken(userId, token) {
  const db = await getDb();
  // replaceOne with upsert = insert if not found, replace if found
  await db.collection("push_tokens").replaceOne(
    { userId, token },
    { userId, token, createdAt: new Date().toISOString() },
    { upsert: true }
  );
}

async function removePushTokens(filter) {
  const db = await getDb();
  await db.collection("push_tokens").deleteMany(filter);
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json());

// ── Fiskil token cache ────────────────────────────────────────────────────────

let TOKEN_CACHE = { token: null, expiresAt: 0 };

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

async function getAccessToken() {
  if (TOKEN_CACHE.token && TOKEN_CACHE.expiresAt - nowSec() > 60) {
    return TOKEN_CACHE.token;
  }
  if (!FISKIL_CLIENT_ID || !FISKIL_CLIENT_SECRET) {
    throw new Error("Missing FISKIL_CLIENT_ID / FISKIL_CLIENT_SECRET in .env");
  }
  const resp = await fetch(`${FISKIL_V1_BASE}/token`, {
    method:  "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body:    JSON.stringify({ client_id: FISKIL_CLIENT_ID, client_secret: FISKIL_CLIENT_SECRET }),
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`token ${resp.status}: ${text}`);
  let json;
  try { json = text ? JSON.parse(text) : {}; }
  catch { throw new Error(`token parse error: ${text}`); }
  const accessToken = json.access_token || json.token;
  const ttl = Number(json.expires_in || 1800);
  if (!accessToken) throw new Error(`No access_token in response: ${text}`);
  TOKEN_CACHE = { token: accessToken, expiresAt: nowSec() + ttl };
  return accessToken;
}

async function fiskilFetch(pathPart, { method = "GET", qs, json } = {}) {
  const token = await getAccessToken();
  const p   = pathPart.startsWith("/") ? pathPart : `/${pathPart}`;
  const url = new URL(`${FISKIL_V1_BASE}${p}`);
  if (qs) Object.entries(qs).forEach(([k, v]) => url.searchParams.set(k, v));
  const resp = await fetch(url.toString(), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept:        "application/json",
      ...(json ? { "Content-Type": "application/json" } : {}),
    },
    body: json ? JSON.stringify(json) : undefined,
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`${method} ${url.pathname} ${resp.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// ── Expo push helper ──────────────────────────────────────────────────────────

async function sendExpoPush({ to, title, body, data = {} }) {
  if (!to || !to.startsWith("ExponentPushToken[")) {
    console.log(`[push] Skipping invalid token: ${to}`);
    return { ok: false, reason: "invalid token" };
  }
  try {
    const resp = await fetch("https://exp.host/--/api/v2/push/send", {
      method:  "POST",
      headers: {
        "Content-Type":   "application/json",
        Accept:           "application/json",
        "accept-encoding": "gzip, deflate",
      },
      body: JSON.stringify({
        to, title, body, data,
        sound:     "default",
        priority:  "high",
        channelId: "transactions",
      }),
    });
    const json = await resp.json();
    console.log(`[push] Sent to ${to.slice(0, 30)}...:`, JSON.stringify(json));
    return { ok: true, result: json };
  } catch (e) {
    console.error("[push] Error:", e.message);
    return { ok: false, reason: e.message };
  }
}

async function notifyUser(userId, { title, body, data }) {
  const targets = await getPushTokens(userId ? { userId } : {});
  if (targets.length === 0) {
    console.log("[push] No tokens for user:", userId ?? "all");
    return;
  }
  for (const t of targets) {
    await sendExpoPush({ to: t.token, title, body, data });
  }
}

// ── Auth middleware ───────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.toLowerCase().startsWith("bearer "))
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  try {
    req.user = jwt.verify(header.slice(7).trim(), AUTH_JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ── Routes: health ────────────────────────────────────────────────────────────

app.get("/", (_req, res) => res.send("bank-backend OK"));

app.get("/diag", async (_req, res) => {
  const out = { ok: true, mongo: !!MONGODB_URI };
  try {
    const token = await getAccessToken();
    out.fiskilToken = token ? "ok" : "missing";
  } catch (e) {
    out.ok = false;
    out.error = String(e?.message || e);
  }
  res.json(out);
});

// ── Routes: Fiskil ────────────────────────────────────────────────────────────

app.get("/fiskil/accounts", async (_req, res) => {
  try {
    const json = await fiskilFetch(`/banking/accounts?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}`);
    const accounts =
      Array.isArray(json?.accounts)       ? json.accounts :
      Array.isArray(json?.data?.accounts) ? json.data.accounts :
      Array.isArray(json?.data)           ? json.data :
      Array.isArray(json)                 ? json : [];
    res.json({ ok: true, accounts });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

app.post("/fiskil/transactions", async (req, res) => {
  try {
    if (!FISKIL_END_USER_ID) throw new Error("Missing FISKIL_END_USER_ID in .env");
    const limit = Number(req.body?.limit || 50);

    function buildMock() {
      const iso = new Date().toISOString().slice(0, 10);
      return [
        { id: "mock_tx_1", amount: -75.23,   description: "Coles Supermarket", postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_2", amount: -42.50,   description: "Shell Petrol",       postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_3", amount: -120.00,  description: "Kmart",              postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_4", amount: -950.00,  description: "Rent / Mortgage",    postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_5", amount: 2200.00,  description: "Salary",             postedAt: iso, source: "mock", imported: false },
      ];
    }

    const accJson = await fiskilFetch(`/banking/accounts?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}`);
    const accounts =
      Array.isArray(accJson?.accounts)       ? accJson.accounts :
      Array.isArray(accJson?.data?.accounts) ? accJson.data.accounts :
      Array.isArray(accJson?.data)           ? accJson.data :
      Array.isArray(accJson)                 ? accJson : [];

    if (accounts.length === 0) {
      return res.json({ txs: buildMock(), info: "No Fiskil accounts; returning mock." });
    }

    const allTx = [];
    for (const acc of accounts) {
      const accId = acc.id || acc.account_id || acc.accountId;
      if (!accId) continue;
      const txJson = await fiskilFetch(
        `/banking/transactions?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}&account_id=${encodeURIComponent(accId)}&limit=${limit}`
      );
      const list =
        Array.isArray(txJson?.transactions)       ? txJson.transactions :
        Array.isArray(txJson?.data?.transactions) ? txJson.data.transactions :
        Array.isArray(txJson?.data)               ? txJson.data :
        Array.isArray(txJson)                     ? txJson : [];

      for (const t of list) {
        const rawAmt = Number(t.amount ?? (t.amountInCents ? t.amountInCents / 100 : 0)) || 0;
        const desc   = t.description || t.merchantName || t.merchant?.name || t.remitter || "Transaction";
        const posted = t.postedAt || t.postDate || t.bookedDate || t.transactionDate || t.createdAt || null;
        allTx.push({
          id:       String(t.id ?? t.transactionId ?? `${accId}_${posted}_${rawAmt}`),
          amount:   rawAmt,
          description: desc,
          postedAt: posted,
          source:   "fiskil",
          imported: true,
        });
      }
    }

    if (allTx.length === 0) {
      return res.json({ txs: buildMock(), info: "No Fiskil transactions; returning mock." });
    }
    res.json({ txs: allTx });
  } catch (e) {
    res.status(400).json({ error: String(e?.message || e) });
  }
});

app.post("/fiskil/connect/start", async (req, res) => {
  try {
    const { endUserId, redirectUri } = req.body || {};
    res.json({ ok: true, endUserId: endUserId || FISKIL_END_USER_ID });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

// ── Routes: Auth ──────────────────────────────────────────────────────────────

app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, firstName, surname, dateOfBirth, gender,
            // legacy fallback: older clients send "name" as a single field
            name } = req.body || {};

    const trimmedEmail     = (email     || "").trim().toLowerCase();
    const trimmedFirst     = (firstName || name || "").trim();
    const trimmedSurname   = (surname   || "").trim();
    const trimmedDob       = (dateOfBirth || "").trim();
    const trimmedGender    = (gender    || "").trim();

    if (!trimmedEmail || !password)
      return res.status(400).json({ error: "email and password are required" });
    if (password.length < 8)
      return res.status(400).json({ error: "password must be at least 8 characters" });
    if (!trimmedFirst)
      return res.status(400).json({ error: "first name is required" });

    const existing = await findUserByEmail(trimmedEmail);
    if (existing)
      return res.status(409).json({ error: "email already registered" });

    const now = new Date().toISOString();
    const displayName = trimmedSurname
      ? `${trimmedFirst} ${trimmedSurname}`
      : trimmedFirst;

    const newUser = {
      id:           `u_${Date.now()}_${Math.floor(Math.random() * 1e6)}`,
      email:        trimmedEmail,
      name:         displayName,
      firstName:    trimmedFirst,
      surname:      trimmedSurname || null,
      dateOfBirth:  trimmedDob    || null,
      gender:       trimmedGender || null,
      passwordHash: bcrypt.hashSync(password, 10),
      createdAt:    now,
      updatedAt:    now,
    };

    await insertUser(newUser);

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      AUTH_JWT_SECRET,
      { expiresIn: AUTH_JWT_EXPIRES }
    );
    res.status(201).json({ user: publicUser(newUser), token });
  } catch (e) {
    console.error("/auth/register error:", e.message);
    res.status(500).json({ error: "Registration failed. Please try again." });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const trimmedEmail = (email || "").trim().toLowerCase();

    if (!trimmedEmail || !password)
      return res.status(400).json({ error: "email and password are required" });

    const user = await findUserByEmail(trimmedEmail);
    if (!user || !bcrypt.compareSync(password, user.passwordHash || ""))
      return res.status(401).json({ error: "invalid email or password" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      AUTH_JWT_SECRET,
      { expiresIn: AUTH_JWT_EXPIRES }
    );
    res.json({ user: publicUser(user), token });
  } catch (e) {
    console.error("/auth/login error:", e.message);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});

app.get("/me", authMiddleware, (req, res) => res.json({ user: req.user }));

// ── Routes: Push tokens ───────────────────────────────────────────────────────

app.post("/push/register", authMiddleware, async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token || !token.startsWith("ExponentPushToken["))
      return res.status(400).json({ error: "Invalid Expo push token" });

    await upsertPushToken(req.user.id, token);
    console.log(`[push] Registered token for user ${req.user.id}: ${token.slice(0, 35)}...`);
    res.json({ ok: true });
  } catch (e) {
    console.error("/push/register error:", e.message);
    res.status(500).json({ error: "Failed to register push token" });
  }
});

app.delete("/push/unregister", authMiddleware, async (req, res) => {
  try {
    const { token } = req.body || {};
    const filter = token
      ? { userId: req.user.id, token }
      : { userId: req.user.id };
    await removePushTokens(filter);
    res.json({ ok: true });
  } catch (e) {
    console.error("/push/unregister error:", e.message);
    res.status(500).json({ error: "Failed to unregister push token" });
  }
});

// ── Routes: Webhook ───────────────────────────────────────────────────────────

app.post("/webhook/transaction", async (req, res) => {
  if (WEBHOOK_SECRET && req.body?.secret !== WEBHOOK_SECRET)
    return res.status(401).json({ error: "Invalid webhook secret" });

  const tx = req.body?.transaction;
  if (!tx) return res.status(400).json({ error: "Missing transaction object" });

  const amount   = Number(tx.amount || 0);
  const isSpend  = amount < 0;
  const absAmt   = Math.abs(amount).toFixed(2);
  const merchant = tx.merchant || tx.description || "Transaction";
  const userId   = req.body?.userId || null;

  console.log(`[webhook] ${merchant} $${absAmt} (${isSpend ? "spend" : "income"})`);

  await notifyUser(userId, {
    title: isSpend ? `💸 New spend: $${absAmt}` : `💰 Money received: $${absAmt}`,
    body:  isSpend
      ? `${merchant} — tap to allocate to an envelope`
      : `${merchant} — tap to add to your envelopes`,
    data: {
      type:     isSpend ? "spend" : "income",
      amount,
      merchant,
      txId:     tx.id || `webhook_${Date.now()}`,
      screen:   "transactions",
    },
  });

  res.json({ ok: true, notified: true });
});

app.post("/webhook/test", async (req, res) => {
  const merchant = req.body?.merchant || "Test Merchant";
  const amount   = Number(req.body?.amount ?? -49.99);
  const userId   = req.body?.userId || null;
  const txId     = `test_${Date.now()}`;

  console.log(`[webhook/test] ${merchant} $${Math.abs(amount)}`);

  await notifyUser(userId, {
    title: amount < 0 ? `💸 New spend: $${Math.abs(amount).toFixed(2)}` : `💰 Money received: $${Math.abs(amount).toFixed(2)}`,
    body:  amount < 0
      ? `${merchant} — tap to allocate to an envelope`
      : `${merchant} — tap to add to your envelopes`,
    data: {
      type:     amount < 0 ? "spend" : "income",
      amount,
      merchant,
      txId,
      screen:   "transactions",
    },
  });

  res.json({ ok: true, txId, merchant, amount });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ bank-backend listening on http://0.0.0.0:${PORT}`);
  if (!MONGODB_URI) {
    console.warn("⚠️  MONGODB_URI not set — database calls will fail until you add it.");
  }
});
