// bank-backend/server.mjs

// ----- .env loader & core imports -----
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Resolve __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env next to this file
dotenv.config({ path: path.join(__dirname, ".env") });

// ----- Env config -----
const PORT = Number(process.env.PORT || 4000);

// Fiskil
const FISKIL_API_BASE = (process.env.FISKIL_API_BASE || "https://api.fiskil.com").replace(/\/+$/, "");
const FISKIL_V1_BASE = FISKIL_API_BASE.endsWith("/v1")
  ? FISKIL_API_BASE
  : `${FISKIL_API_BASE}/v1`;

const FISKIL_CLIENT_ID     = process.env.FISKIL_CLIENT_ID || "";
const FISKIL_CLIENT_SECRET = process.env.FISKIL_CLIENT_SECRET || "";
const FISKIL_END_USER_ID   = process.env.FISKIL_END_USER_ID || "";

// Auth
const AUTH_JWT_SECRET  = process.env.AUTH_JWT_SECRET || "change-me-in-.env";
const AUTH_JWT_EXPIRES = process.env.AUTH_JWT_EXPIRES || "7d";

// Webhook secret — add WEBHOOK_SECRET=anything to your .env for basic security
// Leave blank to skip verification (fine for dev/demo)
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";

// ----- Express app -----
const app = express();
app.use(cors());
app.use(express.json());

function envStatus() {
  return {
    FISKIL_API_BASE,
    hasClientId:    !!FISKIL_CLIENT_ID,
    hasClientSecret:!!FISKIL_CLIENT_SECRET,
    endUserId:      FISKIL_END_USER_ID || null,
  };
}

// ======================= FISKIL TOKEN & HELPERS =======================

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
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ client_id: FISKIL_CLIENT_ID, client_secret: FISKIL_CLIENT_SECRET }),
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`token ${resp.status}: ${text}`);
  let json;
  try { json = text ? JSON.parse(text) : {}; }
  catch { throw new Error(`token parse error: ${text}`); }
  const accessToken = json.access_token || json.token;
  const ttl = Number(json.expires_in || 1800);
  if (!accessToken) throw new Error(`No access_token/token in response: ${text}`);
  TOKEN_CACHE = { token: accessToken, expiresAt: nowSec() + ttl };
  return accessToken;
}

async function fiskilFetch(pathPart, { method = "GET", qs, json } = {}) {
  const token = await getAccessToken();
  const p = pathPart.startsWith("/") ? pathPart : `/${pathPart}`;
  const url = new URL(`${FISKIL_V1_BASE}${p}`);
  if (qs) Object.entries(qs).forEach(([k, v]) => url.searchParams.set(k, v));
  const resp = await fetch(url.toString(), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(json ? { "Content-Type": "application/json" } : {}),
    },
    body: json ? JSON.stringify(json) : undefined,
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`${method} ${url.pathname}${url.search} ${resp.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// ======================= PUSH TOKEN STORE =======================
// Stored in push-tokens.json next to this file.
// Format: [ { userId, token, createdAt } ]
// Multiple tokens per user = multiple devices supported automatically.

const pushTokensFile = path.join(__dirname, "push-tokens.json");

function readPushTokens() {
  try {
    const raw = fs.readFileSync(pushTokensFile, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function writePushTokens(tokens) {
  fs.writeFileSync(pushTokensFile, JSON.stringify(tokens, null, 2), "utf8");
}

// ======================= EXPO PUSH HELPER =======================
// Sends a push notification via Expo's free push service.
// Docs: https://docs.expo.dev/push-notifications/sending-notifications/

async function sendExpoPush({ to, title, body, data = {} }) {
  if (!to || !to.startsWith("ExponentPushToken[")) {
    console.log(`[push] Skipping invalid token: ${to}`);
    return { ok: false, reason: "invalid token" };
  }

  const message = {
    to,
    sound: "default",
    title,
    body,
    data,
    priority: "high",
    channelId: "transactions", // Android notification channel
  };

  try {
    const resp = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "accept-encoding": "gzip, deflate",
      },
      body: JSON.stringify(message),
    });
    const json = await resp.json();
    console.log(`[push] Sent to ${to.slice(0, 30)}...:`, JSON.stringify(json));
    return { ok: true, result: json };
  } catch (e) {
    console.error("[push] Error:", e.message);
    return { ok: false, reason: e.message };
  }
}

// Send to ALL tokens for a given userId (or all tokens if userId is null)
async function notifyUser(userId, { title, body, data }) {
  const allTokens = readPushTokens();
  const targets = userId
    ? allTokens.filter(t => t.userId === userId)
    : allTokens; // null = broadcast to all (useful for single-user demo)

  if (targets.length === 0) {
    console.log("[push] No tokens registered for user:", userId ?? "all");
    return;
  }

  for (const t of targets) {
    await sendExpoPush({ to: t.token, title, body, data });
  }
}

// ======================= FISKIL ROUTES =======================

app.get("/", (_req, res) => res.send("bank-backend OK"));

app.get("/diag", async (_req, res) => {
  const out = { ok: true, env: envStatus() };
  try {
    const token = await getAccessToken();
    out.token = token ? "ok" : "missing";
    try {
      const h = await fetch(`${FISKIL_V1_BASE}/health`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      out.health = { status: h.status, body: await h.text() };
    } catch (e) {
      out.health = { error: String(e?.message || e) };
    }
  } catch (e) {
    out.ok = false;
    out.error = String(e?.message || e);
  }
  res.json(out);
});

app.get("/fiskil/accounts", async (_req, res) => {
  try {
    const json = await fiskilFetch(
      `/banking/accounts?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}`
    );
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

    function buildMockTransactions() {
      const iso = new Date().toISOString().slice(0, 10);
      return [
        { id: "mock_tx_1", amount: -75.23,  description: "Coles Supermarket", postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_2", amount: -42.50,  description: "Shell Petrol",       postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_3", amount: -120.00, description: "Kmart",              postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_4", amount: -950.00, description: "Rent / Mortgage",    postedAt: iso, source: "mock", imported: false },
        { id: "mock_tx_5", amount: 2200.00, description: "Salary",             postedAt: iso, source: "mock", imported: false },
      ];
    }

    const accJson = await fiskilFetch(
      `/banking/accounts?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}`
    );
    const accounts =
      Array.isArray(accJson?.accounts)       ? accJson.accounts :
      Array.isArray(accJson?.data?.accounts) ? accJson.data.accounts :
      Array.isArray(accJson?.data)           ? accJson.data :
      Array.isArray(accJson)                 ? accJson : [];

    if (accounts.length === 0) {
      return res.json({ txs: buildMockTransactions(), info: "No Fiskil accounts; returning mock." });
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
      return res.json({ txs: buildMockTransactions(), info: "No Fiskil transactions; returning mock." });
    }
    res.json({ txs: allTx });
  } catch (e) {
    res.status(400).json({ error: String(e?.message || e), note: "Check /diag if this keeps failing." });
  }
});

app.post("/basiq/connect/start", (_req, res) => {
  res.json({ connectUrl: null });
});

// ======================= AUTH =======================

const usersFile = path.join(__dirname, "users.json");

function readUsers() {
  try {
    const raw = fs.readFileSync(usersFile, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}

function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), "utf8");
}

function publicUser(u) {
  const { passwordHash, ...rest } = u;
  return rest;
}

app.post("/auth/register", (req, res) => {
  const { email, password, name } = req.body || {};
  const trimmedEmail = (email || "").trim().toLowerCase();
  const trimmedName  = (name  || "").trim();

  if (!trimmedEmail || !password)
    return res.status(400).json({ error: "email and password are required" });
  if (password.length < 8)
    return res.status(400).json({ error: "password must be at least 8 characters" });

  const users = readUsers();
  if (users.find(u => u.email === trimmedEmail))
    return res.status(409).json({ error: "email already registered" });

  const nowIso = new Date().toISOString();
  const newUser = {
    id:           `u_${Date.now()}_${Math.floor(Math.random() * 1e6)}`,
    email:        trimmedEmail,
    name:         trimmedName || trimmedEmail,
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt:    nowIso,
    updatedAt:    nowIso,
  };
  users.push(newUser);
  writeUsers(users);

  const token = jwt.sign({ id: newUser.id, email: newUser.email }, AUTH_JWT_SECRET, { expiresIn: AUTH_JWT_EXPIRES });
  res.status(201).json({ user: publicUser(newUser), token });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const trimmedEmail = (email || "").trim().toLowerCase();

  if (!trimmedEmail || !password)
    return res.status(400).json({ error: "email and password are required" });

  const users = readUsers();
  const user  = users.find(u => u.email === trimmedEmail);
  if (!user || !bcrypt.compareSync(password, user.passwordHash || ""))
    return res.status(401).json({ error: "invalid email or password" });

  const token = jwt.sign({ id: user.id, email: user.email }, AUTH_JWT_SECRET, { expiresIn: AUTH_JWT_EXPIRES });
  res.json({ user: publicUser(user), token });
});

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

app.get("/me", authMiddleware, (req, res) => res.json({ user: req.user }));

// ======================= PUSH TOKEN ROUTES =======================

// POST /push/register
// Body: { token: "ExponentPushToken[...]" }
// Header: Authorization: Bearer <jwt>
// Registers (or updates) the push token for the authenticated user.

app.post("/push/register", authMiddleware, (req, res) => {
  const { token } = req.body || {};
  if (!token || !token.startsWith("ExponentPushToken[")) {
    return res.status(400).json({ error: "Invalid Expo push token" });
  }

  const userId = req.user.id;
  const tokens = readPushTokens();

  // Remove any existing entry for this exact token (avoid duplicates)
  const filtered = tokens.filter(t => !(t.userId === userId && t.token === token));
  filtered.push({ userId, token, createdAt: new Date().toISOString() });
  writePushTokens(filtered);

  console.log(`[push] Registered token for user ${userId}: ${token.slice(0, 35)}...`);
  res.json({ ok: true });
});

// DELETE /push/unregister
// Removes the token for this user (called on logout)

app.delete("/push/unregister", authMiddleware, (req, res) => {
  const { token } = req.body || {};
  const userId = req.user.id;
  const tokens = readPushTokens();
  const filtered = token
    ? tokens.filter(t => !(t.userId === userId && t.token === token))
    : tokens.filter(t => t.userId !== userId); // remove all for this user
  writePushTokens(filtered);
  res.json({ ok: true });
});

// GET /push/tokens — dev only, lists all registered tokens
app.get("/push/tokens", (_req, res) => {
  res.json({ tokens: readPushTokens() });
});

// ======================= WEBHOOK: INCOMING TRANSACTION =======================
//
// This endpoint is what gets called when a new bank transaction occurs.
// In production: Fiskil calls this URL when a transaction is posted.
// In development: you call it manually via /webhook/test below.
//
// POST /webhook/transaction
// Body: {
//   secret: "your-webhook-secret",   // optional security check
//   transaction: {
//     id, amount, description, merchant, postedAt
//   },
//   userId: "u_xxx"   // optional — if omitted, notifies ALL registered devices
// }

app.post("/webhook/transaction", async (req, res) => {
  // Optional secret check
  if (WEBHOOK_SECRET && req.body?.secret !== WEBHOOK_SECRET) {
    return res.status(401).json({ error: "Invalid webhook secret" });
  }

  const tx = req.body?.transaction;
  if (!tx) {
    return res.status(400).json({ error: "Missing transaction object" });
  }

  const amount  = Number(tx.amount || 0);
  const isSpend = amount < 0;
  const absAmt  = Math.abs(amount).toFixed(2);
  const merchant = tx.merchant || tx.description || "Transaction";
  const userId  = req.body?.userId || null; // null = notify all

  console.log(`[webhook] Incoming transaction: ${merchant} $${absAmt} (${isSpend ? "spend" : "income"})`);

  // Build notification content
  const title = isSpend
    ? `💸 New spend: $${absAmt}`
    : `💰 Money received: $${absAmt}`;

  const body = isSpend
    ? `${merchant} — tap to allocate to an envelope`
    : `${merchant} — tap to allocate to your envelopes`;

  // Fire push notification to user's device(s)
  await notifyUser(userId, {
    title,
    body,
    data: {
      type:     isSpend ? "spend" : "income",
      amount:   amount,
      merchant: merchant,
      txId:     tx.id || `webhook_${Date.now()}`,
      screen:   "transactions", // hint to the app which screen to open
    },
  });

  res.json({ ok: true, notified: true, merchant, amount });
});

// ======================= TEST WEBHOOK TRIGGER =======================
//
// POST /webhook/test
// Fires a fake transaction notification to all registered devices.
// Use this to test the full pipeline without needing a real bank transaction.
// Body: { merchant?: string, amount?: number, userId?: string }

app.post("/webhook/test", async (req, res) => {
  const merchant = req.body?.merchant || "Test Merchant";
  const amount   = Number(req.body?.amount ?? -49.99);
  const userId   = req.body?.userId || null;

  const fakeTx = {
    id:          `test_${Date.now()}`,
    amount,
    merchant,
    description: merchant,
    postedAt:    new Date().toISOString(),
  };

  console.log(`[webhook/test] Firing test notification: ${merchant} $${Math.abs(amount)}`);

  // Reuse the same webhook logic
  await notifyUser(userId, {
    title:  amount < 0 ? `💸 New spend: $${Math.abs(amount).toFixed(2)}` : `💰 Money received: $${Math.abs(amount).toFixed(2)}`,
    body:   amount < 0
      ? `${merchant} — tap to allocate to an envelope`
      : `${merchant} — tap to allocate to your envelopes`,
    data: {
      type:     amount < 0 ? "spend" : "income",
      amount,
      merchant,
      txId:     fakeTx.id,
      screen:   "transactions",
    },
  });

  res.json({ ok: true, fired: fakeTx });
});

// ======================= START SERVER =======================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ bank-backend (Fiskil + auth + push) on http://0.0.0.0:${PORT}`);
});
