// Kept Vault: the customer's own private store for the Kept trading journal.
// It runs in the customer's Cloudflare account. Their journal, share links, replay
// data and API keys live here and nowhere else. The Kept app (the website) talks to
// this vault straight from the customer's browser; the Kept company never sees it.
//
//   GET    /api/health                    public: is the vault set up?
//   POST   /api/login    {password}       -> {token}   (lockout after repeated misses)
//   GET    /api/journal                   -> {data, updated_at}
//   PUT    /api/journal  {data}           -> {ok}
//   GET    /api/media?id=ID               -> {data}   one screenshot or voice note
//   PUT    /api/media?id=ID  {data}       -> {ok}
//   POST   /api/share    {data, days}     -> {id, expires_at}
//   GET    /api/share?id=ID               public: one shared day (410 once expired)
//   GET    /api/share?mine=1              -> {shares}
//   DELETE /api/share?id=ID               -> {ok}
//   GET    /api/bars?sym&start&end        -> {bars, sym, source}   (Databento, cached here)
//   POST   /api/ai       {system, prompt, key?} -> {text, model}   (Anthropic)
//
// Secrets (set when you deploy, or later in Cloudflare > Workers > kept-vault > Settings):
//   VAULT_PASSWORD  required. The password you type into Kept to open your vault.
//   DATABENTO_KEY   optional. Turns on trade replay.
//   ANTHROPIC_KEY   optional. Turns on AI review.
// Variable:
//   APP_ORIGINS     the Kept website address(es) allowed to talk to this vault.

const VERSION = "1.0.0";
const TOKEN_MAX_AGE = 90 * 864e5;
const MAX_FAILS = 8;
const WINDOW_MS = 15 * 60 * 1000;
const MAX_SHARE_BYTES = 100000;
const MAX_MEDIA_BYTES = 25e6;
const MAX_SHARES = 200;
const MAX_WINDOW_S = 6 * 3600;
const AI_MODEL = "claude-opus-5-5";
const AI_MAX_PROMPT = 120000;

// ---------- small helpers ----------
const enc = (s) => new TextEncoder().encode(s);
function b64url(bytes) {
  let s = "";
  bytes.forEach((x) => (s += String.fromCharCode(x)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urldec(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
// a secret value counts as "not set" when blank or a placeholder like "none"
function secret(v) {
  const s = String(v || "").trim();
  return s && !/^(none|skip|n\/a|-)$/i.test(s) ? s : "";
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = String(env.APP_ORIGINS || "")
    .split(",")
    .map((x) => x.trim().replace(/\/+$/, ""))
    .filter(Boolean);
  const ok = origin && (allowed.includes(origin) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin));
  return ok
    ? {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Max-Age": "86400",
        Vary: "Origin",
      }
    : { Vary: "Origin" };
}
function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}

// ---------- password + tokens ----------
// The signing key is derived from VAULT_PASSWORD, so changing the password signs everyone out.
async function hmacKey(env) {
  return crypto.subtle.importKey("raw", enc("kept-vault-v1|" + secret(env.VAULT_PASSWORD)), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify",
  ]);
}
async function sign(payload, env) {
  const p = b64url(enc(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), enc(p));
  return p + "." + b64url(new Uint8Array(sig));
}
async function verify(token, env) {
  if (!token || token.indexOf(".") < 0) return null;
  const [p, s] = token.split(".");
  let ok = false;
  try {
    ok = await crypto.subtle.verify("HMAC", await hmacKey(env), b64urldec(s), enc(p));
  } catch (e) {
    return null;
  }
  if (!ok) return null;
  try {
    const c = JSON.parse(new TextDecoder().decode(b64urldec(p)));
    return c && c.iat && Date.now() - c.iat < TOKEN_MAX_AGE ? c : null;
  } catch (e) {
    return null;
  }
}
// compare two strings without leaking where they differ
async function sameText(a, b) {
  const k = await crypto.subtle.importKey("raw", enc("cmp"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const x = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc(a)));
  const y = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc(b)));
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}
async function signedIn(request, env) {
  const t = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  return !!(await verify(t, env));
}

// ---------- database ----------
let schemaReady = false;
async function ensureSchema(DB) {
  if (schemaReady) return;
  await DB.batch([
    DB.prepare("CREATE TABLE IF NOT EXISTS journal (id TEXT PRIMARY KEY, data TEXT, updated_at INTEGER)"),
    DB.prepare("CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, data TEXT, updated_at INTEGER)"),
    DB.prepare("CREATE TABLE IF NOT EXISTS shares (id TEXT PRIMARY KEY, day TEXT, data TEXT, created_at INTEGER, expires_at INTEGER)"),
    DB.prepare("CREATE TABLE IF NOT EXISTS bars_cache (key TEXT PRIMARY KEY, data TEXT, created_at INTEGER)"),
    DB.prepare("CREATE TABLE IF NOT EXISTS login_fails (key TEXT PRIMARY KEY, n INTEGER, first_at INTEGER)"),
  ]);
  schemaReady = true;
}

// ---------- routes ----------
async function health(env) {
  return json({
    ok: true,
    app: "kept-vault",
    version: VERSION,
    ready: !!env.DB && secret(env.VAULT_PASSWORD).length >= 8,
    replay: !!secret(env.DATABENTO_KEY),
    ai: !!secret(env.ANTHROPIC_KEY),
  });
}

async function login(request, env) {
  const pw = secret(env.VAULT_PASSWORD);
  if (pw.length < 8) return json({ code: "no_password", error: "This vault has no password yet. Set VAULT_PASSWORD (8+ characters) in Cloudflare." }, 500);
  let body = {};
  try {
    body = await request.json();
  } catch (e) {}
  const keys = ["ip:" + (request.headers.get("CF-Connecting-IP") || "?"), "all"];
  const now = Date.now();
  for (const k of keys) {
    const r = await env.DB.prepare("SELECT n, first_at FROM login_fails WHERE key=?").bind(k).first();
    const limit = k === "all" ? MAX_FAILS * 3 : MAX_FAILS;
    if (r && now - r.first_at < WINDOW_MS && r.n >= limit) return json({ code: "locked", error: "Too many tries. Wait 15 minutes, then try again." }, 429);
  }
  if (!(await sameText(String(body.password || ""), pw))) {
    for (const k of keys) {
      const r = await env.DB.prepare("SELECT n, first_at FROM login_fails WHERE key=?").bind(k).first();
      const fresh = !r || now - r.first_at >= WINDOW_MS;
      await env.DB.prepare("INSERT OR REPLACE INTO login_fails (key, n, first_at) VALUES (?,?,?)")
        .bind(k, fresh ? 1 : r.n + 1, fresh ? now : r.first_at)
        .run();
    }
    return json({ code: "bad_password", error: "That vault password did not match." }, 401);
  }
  await env.DB.prepare("DELETE FROM login_fails").run();
  return json({ token: await sign({ v: 1, iat: now }, env) });
}

// Screenshots and voice notes live one per row, so the journal itself stays small and fast.
async function media(request, env) {
  if (!(await signedIn(request, env))) return json({ error: "Not signed in." }, 401);
  const id = new URL(request.url).searchParams.get("id") || "";
  if (!/^m[a-z0-9_]{4,40}$/.test(id)) return json({ error: "Bad request." }, 400);
  if (request.method === "GET") {
    const row = await env.DB.prepare("SELECT data FROM media WHERE id=?").bind(id).first();
    return row ? json({ data: row.data }) : json({ error: "Not found." }, 404);
  }
  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ error: "Bad request." }, 400);
    }
    const data = String((body && body.data) || "");
    if (!data.startsWith("data:")) return json({ error: "Bad request." }, 400);
    if (data.length > MAX_MEDIA_BYTES) return json({ error: "That file is too large." }, 413);
    await env.DB.prepare("INSERT OR REPLACE INTO media (id, data, updated_at) VALUES (?,?,?)").bind(id, data, Date.now()).run();
    return json({ ok: true });
  }
  return json({ error: "Method not allowed." }, 405);
}

async function journal(request, env) {
  if (!(await signedIn(request, env))) return json({ error: "Not signed in." }, 401);
  if (request.method === "GET") {
    const row = await env.DB.prepare("SELECT data, updated_at FROM journal WHERE id='me'").first();
    if (!row) return json({ data: null });
    let data = null;
    try {
      data = JSON.parse(row.data);
    } catch (e) {}
    return json({ data, updated_at: row.updated_at });
  }
  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ error: "Bad request." }, 400);
    }
    await env.DB.prepare(
      "INSERT INTO journal (id, data, updated_at) VALUES ('me',?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at"
    )
      .bind(JSON.stringify(body.data || {}), Date.now())
      .run();
    return json({ ok: true });
  }
  return json({ error: "Method not allowed." }, 405);
}

function newId() {
  return b64url(crypto.getRandomValues(new Uint8Array(16)));
}
async function share(request, env) {
  const url = new URL(request.url);
  const pub = (obj, status = 200) => json(obj, status, { "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer" });
  if (request.method === "GET" && !url.searchParams.get("mine")) {
    const id = String(url.searchParams.get("id") || "");
    if (!/^[A-Za-z0-9_-]{16,40}$/.test(id)) return pub({ error: "Not found." }, 404);
    const row = await env.DB.prepare("SELECT data, created_at, expires_at FROM shares WHERE id=?").bind(id).first();
    if (!row) return pub({ error: "Not found." }, 404);
    if (row.expires_at && row.expires_at < Date.now()) {
      await env.DB.prepare("DELETE FROM shares WHERE id=?").bind(id).run();
      return pub({ error: "This link has ended." }, 410);
    }
    let data = null;
    try {
      data = JSON.parse(row.data);
    } catch (e) {}
    return pub({ data, created_at: row.created_at });
  }
  if (!(await signedIn(request, env))) return json({ error: "Not signed in." }, 401);
  if (request.method === "GET") {
    await env.DB.prepare("DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at<?").bind(Date.now()).run();
    const rows = await env.DB.prepare("SELECT id, day, created_at, expires_at FROM shares ORDER BY created_at DESC").all();
    return json({ shares: rows.results || [] });
  }
  if (request.method === "POST") {
    const raw = await request.text();
    if (raw.length > MAX_SHARE_BYTES) return json({ error: "That day is too large to share." }, 413);
    let body;
    try {
      body = JSON.parse(raw);
    } catch (e) {
      return json({ error: "Bad request." }, 400);
    }
    const data = body && body.data;
    if (!data || typeof data !== "object" || !/^\d{4}-\d{2}-\d{2}$/.test(String(data.day || ""))) return json({ error: "Bad request." }, 400);
    const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM shares").first();
    if (c && c.n >= MAX_SHARES) return json({ error: "You have a lot of links. Turn some off first." }, 429);
    const id = newId();
    const days = [7, 30].includes(Number(body.days)) ? Number(body.days) : 0;
    const expires_at = days ? Date.now() + days * 864e5 : null;
    await env.DB.prepare("INSERT INTO shares (id, day, data, created_at, expires_at) VALUES (?,?,?,?,?)")
      .bind(id, data.day, JSON.stringify(data), Date.now(), expires_at)
      .run();
    return json({ id, expires_at });
  }
  if (request.method === "DELETE") {
    await env.DB.prepare("DELETE FROM shares WHERE id=?").bind(String(url.searchParams.get("id") || "")).run();
    return json({ ok: true });
  }
  return json({ error: "Method not allowed." }, 405);
}

// "NQZ6" = an exact contract; "NQ" = a root, replayed on the volume front month
function symbolPlan(sym) {
  if (/^[A-Z0-9]{1,4}[FGHJKMNQUVXZ]\d{1,2}$/.test(sym))
    return [
      { symbols: sym, stype_in: "raw_symbol" },
      { symbols: sym.replace(/[FGHJKMNQUVXZ]\d{1,2}$/, "") + ".v.0", stype_in: "continuous" },
    ];
  return [{ symbols: sym + ".v.0", stype_in: "continuous" }];
}
async function fetchBars(env, plan, start, end) {
  const body = new URLSearchParams({
    dataset: "GLBX.MDP3", symbols: plan.symbols, stype_in: plan.stype_in, schema: "ohlcv-1s",
    start, end, encoding: "json", pretty_px: "true", map_symbols: "true",
  });
  const r = await fetch((env.DATABENTO_URL || "https://hist.databento.com") + "/v0/timeseries.get_range", {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(secret(env.DATABENTO_KEY) + ":"), "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const text = await r.text();
  if (!r.ok) {
    let detail = "";
    try {
      const d = JSON.parse(text).detail;
      detail = typeof d === "string" ? d : (d && d.case + " " + (d.message || "")) || "";
    } catch (e) {}
    return { status: r.status, detail };
  }
  const bars = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let o;
    try {
      o = JSON.parse(line);
    } catch (e) {
      continue;
    }
    const ts = o.hd && o.hd.ts_event;
    if (ts == null) continue;
    bars.push([Number(BigInt(ts) / 1000000000n), Number(o.open), Number(o.high), Number(o.low), Number(o.close), Number(o.volume) || 0]);
  }
  return { status: 200, bars };
}
async function bars(request, env) {
  if (!(await signedIn(request, env))) return json({ error: "Not signed in." }, 401);
  if (!secret(env.DATABENTO_KEY)) return json({ code: "not_set_up", error: "Add your Databento key to your vault to turn on replay." }, 503);
  const url = new URL(request.url);
  const sym = String(url.searchParams.get("sym") || "").toUpperCase();
  const s = Date.parse(url.searchParams.get("start") || ""), e = Date.parse(url.searchParams.get("end") || "");
  if (!/^[A-Z0-9]{1,8}$/.test(sym) || !isFinite(s) || !isFinite(e) || e <= s) return json({ code: "error", error: "Bad request." }, 400);
  const start = Math.floor(s / 60000) * 60, end = Math.min(Math.ceil(e / 60000) * 60, start + MAX_WINDOW_S);
  const key = ["v1", sym, start, end].join("|");
  const hit = await env.DB.prepare("SELECT data FROM bars_cache WHERE key=?").bind(key).first();
  if (hit) return json(JSON.parse(hit.data));
  const iso = (sec) => new Date(sec * 1000).toISOString();
  let res, used;
  for (const plan of symbolPlan(sym)) {
    res = await fetchBars(env, plan, iso(start), iso(end));
    used = plan.symbols;
    if (res.status === 200 && res.bars.length) break;
    if ([401, 402, 403, 429].includes(res.status)) break;
  }
  if (res.status === 401) return json({ code: "bad_key", error: "Databento did not accept the key in your vault." }, 502);
  if (res.status === 402) return json({ code: "payment", error: "Your Databento account needs payment details or credits." }, 502);
  if (res.status === 403) return json({ code: "error", error: "Your Databento account does not include CME (GLBX.MDP3) data." }, 502);
  if (res.status === 429) return json({ code: "error", error: "Databento is busy. Try again in a moment." }, 503);
  if (res.status === 422 && /available_end|after/i.test(res.detail || "")) return json({ code: "not_available_yet", error: "Not available yet." }, 409);
  if (res.status !== 200) return json({ code: "error", error: "Databento: " + (res.detail || "request failed (" + res.status + ")") }, 502);
  const out = { bars: res.bars, sym: used, source: "Databento" };
  if (res.bars.length)
    await env.DB.prepare("INSERT OR REPLACE INTO bars_cache (key, data, created_at) VALUES (?,?,?)").bind(key, JSON.stringify(out), Date.now()).run();
  return json(out);
}

async function ai(request, env) {
  if (!(await signedIn(request, env))) return json({ error: "Not signed in." }, 401);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ code: "error", error: "Bad request." }, 400);
  }
  const key = secret(body && body.key) || secret(env.ANTHROPIC_KEY);
  const system = String((body && body.system) || ""), prompt = String((body && body.prompt) || "");
  if (!key) return json({ code: "no_key", error: "Add your Anthropic key to your vault (or in Kept's Settings) to turn on AI review." }, 400);
  if (!prompt || prompt.length + system.length > AI_MAX_PROMPT) return json({ code: "error", error: "That is too much to review at once. Pick fewer days." }, 400);
  let r, data;
  try {
    r = await fetch((env.ANTHROPIC_URL || "https://api.anthropic.com") + "/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "server-side-fallback-2026-07-01",
      },
      body: JSON.stringify({
        model: AI_MODEL,
        max_tokens: 16000,
        output_config: { effort: "medium" },
        fallbacks: "default",
        system,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    data = await r.json().catch(() => ({}));
  } catch (e) {
    return json({ code: "error", error: "Could not reach Anthropic. Try again in a moment." }, 502);
  }
  if (!r.ok) {
    const msg = (data && data.error && data.error.message) || "";
    if (r.status === 401) return json({ code: "bad_key", error: "Anthropic did not accept that API key." }, 502);
    if (r.status === 402 || /credit|billing|balance/i.test(msg)) return json({ code: "payment", error: "Your Anthropic account needs credits or billing set up." }, 502);
    if (r.status === 429 || r.status >= 500) return json({ code: "busy", error: "Anthropic is busy right now. Try again in a moment." }, 503);
    return json({ code: "error", error: "Anthropic: " + (msg || "request failed (" + r.status + ")") }, 502);
  }
  if (data.stop_reason === "refusal") return json({ code: "refusal", error: "The model declined to review this. Try a different set of trades." }, 200);
  const text = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
  if (!text) return json({ code: "error", error: "The review came back empty. Try again." }, 502);
  return json({ text, model: data.model || AI_MODEL, stop_reason: data.stop_reason, usage: data.usage || null });
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    const path = new URL(request.url).pathname.replace(/\/+$/, "");
    let res;
    try {
      if (path === "" || path === "/api/health") res = await health(env);
      else {
        if (!env.DB) res = json({ error: "This vault has no database. Redeploy it with the Deploy to Cloudflare button." }, 500);
        else {
          await ensureSchema(env.DB);
          if (path === "/api/login" && request.method === "POST") res = await login(request, env);
          else if (path === "/api/journal") res = await journal(request, env);
          else if (path === "/api/media") res = await media(request, env);
          else if (path === "/api/share") res = await share(request, env);
          else if (path === "/api/bars" && request.method === "GET") res = await bars(request, env);
          else if (path === "/api/ai" && request.method === "POST") res = await ai(request, env);
          else res = json({ error: "Not found." }, 404);
        }
      }
    } catch (e) {
      res = json({ error: "Something went wrong in your vault." }, 500);
    }
    for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
    return res;
  },
};
