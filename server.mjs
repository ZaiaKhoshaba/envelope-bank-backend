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

// Normalise so we ALWAYS have a correct v1 base:
// - If .env already has .../v1, we keep it
// - If not, we add /v1
const FISKIL_V1_BASE = FISKIL_API_BASE.endsWith("/v1")
  ? FISKIL_API_BASE
  : `${FISKIL_API_BASE}/v1`;

const FISKIL_CLIENT_ID = process.env.FISKIL_CLIENT_ID || "";
const FISKIL_CLIENT_SECRET = process.env.FISKIL_CLIENT_SECRET || "";
const FISKIL_END_USER_ID = process.env.FISKIL_END_USER_ID || "";


// Auth
const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET || "change-me-in-.env";
const AUTH_JWT_EXPIRES = process.env.AUTH_JWT_EXPIRES || "7d";

// ----- Express app -----
const app = express();
app.use(cors());
app.use(express.json());

// Small helper just to see env status if needed
function envStatus() {
  return {
    FISKIL_API_BASE,
    hasClientId: !!FISKIL_CLIENT_ID,
    hasClientSecret: !!FISKIL_CLIENT_SECRET,
    endUserId: FISKIL_END_USER_ID || null,
  };
}

// ======================= FISKIL TOKEN & HELPERS =======================

let TOKEN_CACHE = { token: null, expiresAt: 0 };

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

async function getAccessToken() {
  // reuse token if still valid for 60s
  if (TOKEN_CACHE.token && TOKEN_CACHE.expiresAt - nowSec() > 60) {
    return TOKEN_CACHE.token;
  }

  if (!FISKIL_CLIENT_ID || !FISKIL_CLIENT_SECRET) {
    throw new Error("Missing FISKIL_CLIENT_ID / FISKIL_CLIENT_SECRET in .env");
  }

  const url = `${FISKIL_V1_BASE}/token`;
  const body = {
    client_id: FISKIL_CLIENT_ID,
    client_secret: FISKIL_CLIENT_SECRET,
  };

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });

    const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`token ${resp.status}: ${text}`);
  }

  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`token parse error: ${text}`);
  }

  // Fiskil may return either "access_token" or "token"
  const accessToken = json.access_token || json.token;
  const ttl = Number(json.expires_in || 1800);

  if (!accessToken) {
    throw new Error(`No access_token/token in response: ${text}`);
  }

  TOKEN_CACHE = {
    token: accessToken,
    expiresAt: nowSec() + ttl,
  };

  return accessToken;
}

async function fiskilFetch(pathPart, { method = "GET", qs, json } = {}) {
  const token = await getAccessToken();

  const path = pathPart.startsWith("/") ? pathPart : `/${pathPart}`;
  const url = new URL(`${FISKIL_V1_BASE}${path}`);


  if (qs) {
    Object.entries(qs).forEach(([k, v]) => url.searchParams.set(k, v));
  }

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
  if (!resp.ok) {
    throw new Error(`${method} ${url.pathname}${url.search} ${resp.status}: ${text}`);
  }

  return text ? JSON.parse(text) : null;
}

// ======================= FISKIL ROUTES =======================

app.get("/", (_req, res) => {
  res.send("bank-backend OK");
});

// Diagnostics
app.get("/diag", async (_req, res) => {
  const out = { ok: true, env: envStatus() };
  try {
    const token = await getAccessToken();
    out.token = token ? "ok" : "missing";

    // light health probe (some tenants may not expose /health; that's fine)
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
    // Fiskil banking accounts for this end user
    const json = await fiskilFetch(
      `/banking/accounts?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}`,
      { method: "GET" }
    );

    // Fiskil banking API usually returns { accounts: [...] }
    const accounts =
      Array.isArray(json?.accounts) ? json.accounts :
      Array.isArray(json?.data?.accounts) ? json.data.accounts :
      Array.isArray(json?.data) ? json.data :
      Array.isArray(json) ? json :
      [];

    res.json({ ok: true, accounts });
  } catch (e2) {
    res.status(400).json({ ok: false, error: String(e2.message || e2) });
  }
});

// Import latest transactions across all accounts
app.post("/fiskil/transactions", async (req, res) => {
  try {
    if (!FISKIL_END_USER_ID) {
      throw new Error("Missing FISKIL_END_USER_ID in .env");
    }

    const limit = Number(req.body?.limit || 50);

    // Helper to build some mock transactions when Fiskil has nothing
    function buildMockTransactions() {
      const today = new Date();
      const iso = today.toISOString().slice(0, 10); // YYYY-MM-DD

      return [
        {
          id: "mock_tx_1",
          amount: -75.23,
          description: "Coles Supermarket",
          postedAt: iso,
          source: "mock",
          imported: false,
        },
        {
          id: "mock_tx_2",
          amount: -42.5,
          description: "Shell Petrol",
          postedAt: iso,
          source: "mock",
          imported: false,
        },
        {
          id: "mock_tx_3",
          amount: -120.0,
          description: "Kmart",
          postedAt: iso,
          source: "mock",
          imported: false,
        },
        {
          id: "mock_tx_4",
          amount: -950.0,
          description: "Rent / Mortgage",
          postedAt: iso,
          source: "mock",
          imported: false,
        },
        {
          id: "mock_tx_5",
          amount: 2200.0,
          description: "Salary",
          postedAt: iso,
          source: "mock",
          imported: false,
        },
      ];
    }

    // 1) Accounts via Fiskil banking API
    const accJson = await fiskilFetch(
      `/banking/accounts?end_user_id=${encodeURIComponent(FISKIL_END_USER_ID)}`,
      { method: "GET" }
    );
    const accounts =
      Array.isArray(accJson?.accounts) ? accJson.accounts :
      Array.isArray(accJson?.data?.accounts) ? accJson.data.accounts :
      Array.isArray(accJson?.data) ? accJson.data :
      Array.isArray(accJson) ? accJson :
      [];

    if (accounts.length === 0) {
      // No real accounts -> return mock data
      return res.json({
        txs: buildMockTransactions(),
        info: "No Fiskil accounts for this end user; returning mock transactions.",
      });
    }

    // 2) Pull tx per account
    const allTx = [];
    for (const acc of accounts) {
      const accId = acc.id || acc.account_id || acc.accountId;
      if (!accId) continue;

      const txJson = await fiskilFetch(
        `/banking/transactions?end_user_id=${encodeURIComponent(
          FISKIL_END_USER_ID
        )}&account_id=${encodeURIComponent(accId)}&limit=${encodeURIComponent(
          limit
        )}`,
        { method: "GET" }
      );

      const list =
        Array.isArray(txJson?.transactions) ? txJson.transactions :
        Array.isArray(txJson?.data?.transactions) ? txJson.data.transactions :
        Array.isArray(txJson?.data) ? txJson.data :
        Array.isArray(txJson) ? txJson :
        [];

      for (const t of list) {
        const rawAmt =
          Number(
            t.amount ??
              (t.amountInCents ? t.amountInCents / 100 : 0)
          ) || 0;

        const desc =
          t.description ||
          t.merchantName ||
          t.merchant?.name ||
          t.remitter ||
          "Transaction";

        const posted =
          t.postedAt ||
          t.postDate ||
          t.bookedDate ||
          t.transactionDate ||
          t.createdAt ||
          null;

        allTx.push({
          id: String(
            t.id ??
              t.transactionId ??
              `${accId}_${posted}_${rawAmt}`
          ),
          amount: rawAmt,
          description: desc,
          postedAt: posted,
          source: "fiskil",
          imported: true,
        });
      }
    }

    // If Fiskil returned no transactions at all, fall back to mock
    if (allTx.length === 0) {
      return res.json({
        txs: buildMockTransactions(),
        info: "No Fiskil transactions found; returning mock transactions.",
      });
    }

    // Normal case: return real data
    res.json({ txs: allTx });
  } catch (e) {
    res.status(400).json({
      error: String(e?.message || e),
      note: "Check /diag if this keeps failing.",
    });
  }
});

// Stub so “Connect Bank” button doesn’t explode
app.post("/basiq/connect/start", (_req, res) => {
  res.json({ connectUrl: null }); // app already knows how to handle null
});

// ======================= AUTH: JSON "DATABASE" =======================

// We'll keep users in a small JSON file next to this script.
// Not for production, but perfect for a free MVP.

const usersFile = path.join(__dirname, "users.json");

function readUsers() {
  try {
    const raw = fs.readFileSync(usersFile, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), "utf8");
}

function publicUser(u) {
  const { passwordHash, ...rest } = u;
  return rest;
}

// ----- /auth/register -----
app.post("/auth/register", (req, res) => {
  const { email, password, name } = req.body || {};

  const trimmedEmail = (email || "").trim().toLowerCase();
  const trimmedName = (name || "").trim();

  if (!trimmedEmail || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  const users = readUsers();
  const existing = users.find((u) => u.email === trimmedEmail);
  if (existing) {
    return res.status(409).json({ error: "email already registered" });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const nowIso = new Date().toISOString();

  const newUser = {
    id: `u_${Date.now()}_${Math.floor(Math.random() * 1e6)}`,
    email: trimmedEmail,
    name: trimmedName || trimmedEmail,
    passwordHash,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  users.push(newUser);
  writeUsers(users);

  const token = jwt.sign(
    { id: newUser.id, email: newUser.email },
    AUTH_JWT_SECRET,
    { expiresIn: AUTH_JWT_EXPIRES }
  );

  res.status(201).json({
    user: publicUser(newUser),
    token,
  });
});

// ----- /auth/login -----
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const trimmedEmail = (email || "").trim().toLowerCase();

  if (!trimmedEmail || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const users = readUsers();
  const user = users.find((u) => u.email === trimmedEmail);
  if (!user) {
    return res.status(401).json({ error: "invalid email or password" });
  }

  const ok = bcrypt.compareSync(password, user.passwordHash || "");
  if (!ok) {
    return res.status(401).json({ error: "invalid email or password" });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    AUTH_JWT_SECRET,
    { expiresIn: AUTH_JWT_EXPIRES }
  );

  res.json({
    user: publicUser(user),
    token,
  });
});

// ----- auth middleware & example protected route -----
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }
  const token = header.slice(7).trim();
  try {
    const payload = jwt.verify(token, AUTH_JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Simple example you can hit later from the app
app.get("/me", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ======================= START SERVER =======================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ bank-backend (Fiskil + auth) on http://0.0.0.0:${PORT}`);
});
