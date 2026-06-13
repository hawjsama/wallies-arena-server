// Wallies Arena — Colyseus authoritative game server (external host, e.g. Railway).
//
// ⚠️ This is NODE.JS server code for EXTERNAL deployment, NOT part of the
//    Base44 frontend build. It is stored as .txt so the frontend linter
//    ignores it. When deploying, save it as `index.js` in your server repo.
//
// This is the OTHER bookend of the PvP bridge. Base44 mints a signed join
// ticket (issueGameServerToken); this server VERIFIES that ticket locally using
// the shared GAME_SERVER_JOIN_SECRET, seats the player on the correct team,
// runs the 30Hz authoritative tick loop, and on match end POSTs the result back
// to Base44's submitGameServerResult.
//
// === DEPLOY ===
// See README.md in this folder for the copy-paste Railway deploy guide.
//
// === ENV REQUIRED ===
//   GAME_SERVER_JOIN_SECRET   — MUST match the secret set in Base44.
//   BASE44_RESULT_URL         — full URL of the submitGameServerResult function.
//   INTERNAL_FUNCTION_SECRET  — MUST match Base44's, to authorize the writeback.
//   PORT                      — provided by Railway automatically.

import http from 'http';
import express from 'express';
import pkg from 'colyseus';
const { Server, Room } = pkg;
import { WebSocketTransport } from '@colyseus/ws-transport';
import crypto from 'crypto';
import BlocklesRoom from './blocklesRoom.js';

const PORT = Number(process.env.PORT || 2567);
const JOIN_SECRET = process.env.GAME_SERVER_JOIN_SECRET || '';
const RESULT_URL = process.env.BASE44_RESULT_URL || '';
const INTERNAL_SECRET = process.env.INTERNAL_FUNCTION_SECRET || '';
const TICK_HZ = 30;
// Hard ceiling on a single match. Backstops any combat-logic bug that fails to
// reach an end condition so a room can never run (and bill) forever.
const MAX_MATCH_MS = 15 * 60 * 1000; // 15 minutes

// Fail fast & loud at boot if the shared secrets are missing — otherwise every
// ticket verification and writeback would silently fail in production.
if (!JOIN_SECRET) console.error('[arena] FATAL: GAME_SERVER_JOIN_SECRET is not set — all joins will be rejected.');
if (!INTERNAL_SECRET) console.error('[arena] FATAL: INTERNAL_FUNCTION_SECRET is not set — result writebacks will be rejected.');
if (!RESULT_URL) console.error('[arena] WARN: BASE44_RESULT_URL is not set — match results will NOT be written back.');

// ── Ticket verification (mirrors issueGameServerToken's HMAC) ────────────────
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}
function hmacB64url(secret, message) {
  return crypto.createHmac('sha256', secret).update(message)
    .digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function verifyTicket(token) {
  if (!token || typeof token !== 'string' || !JOIN_SECRET) return null;
  const [payloadB64, sig] = token.split('.');
  if (!payloadB64 || !sig) return null;
  const expected = hmacB64url(JOIN_SECRET, payloadB64);
  // Constant-time compare.
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(payloadB64)); } catch { return null; }
  if (!payload?.exp || payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
  // payload = { sid, pid, handle, team, mode, ... }. NOTE: there is NO email in
  // the token by design (see docs/IDENTITY_AND_PII_RULE.md). We seat/track by
  // the opaque pid hash + public handle; the email lives only inside Base44.
  return payload;
}

// ── Result writeback to Base44 ───────────────────────────────────────────────
// Base44's submitGameServerResult is fully idempotent (atomic result_applied
// claim), so retrying a writeback can NEVER double-pay ILY or double-apply MMR.
// That makes a bounded retry loop safe AND important: if the single POST failed
// (transient network blip), the match result would be lost forever and the
// session would later be swept to 'abandoned' with no payout. We retry with
// exponential backoff so a real result reliably lands.
async function writeResult(sessionId, winnerTeam, resultStats) {
  if (!RESULT_URL) return false;
  const body = JSON.stringify({
    internal_secret: INTERNAL_SECRET,
    session_id: sessionId,
    winner_team: winnerTeam,
    result_stats: resultStats,
  });
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const res = await fetch(RESULT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (res.ok) return true;
      // 4xx (bad secret, invalid winner) won't fix itself — stop retrying.
      if (res.status >= 400 && res.status < 500) {
        console.error(`[arena] writeback rejected ${res.status} — not retrying`);
        return false;
      }
    } catch (e) {
      console.error(`[arena] writeback attempt ${attempt} failed`, e);
    }
    await new Promise((r) => setTimeout(r, Math.min(1000 * 2 ** (attempt - 1), 8000)));
  }
  console.error('[arena] writeback gave up after 5 attempts for', sessionId);
  return false;
}

// ── Authoritative Arena room ─────────────────────────────────────────────────
class ArenaRoom extends Room {
  onCreate() {
    this.maxClients = 8;
    this.players = new Map(); // sessionId(socket) -> { email, handle, team }
    this.tickHandle = this.clock.setInterval(() => this.tick(), 1000 / TICK_HZ);
    this.startedAt = Date.now();
  }

  // Validate the Base44 ticket BEFORE allowing the socket to join.
  onAuth(client, options) {
    const payload = verifyTicket(options?.token);
    if (!payload) throw new Error('invalid_or_expired_ticket');

    // ANTI-REPLAY / ROOM BINDING: the FIRST validated ticket pins this room to
    // its Base44 session id. Every later joiner MUST carry a ticket for the
    // SAME session — otherwise a valid ticket minted for session A could be
    // replayed to slip into session B's live room. A mismatch is rejected.
    if (!this.base44SessionId) {
      this.base44SessionId = payload.sid;
    } else if (payload.sid !== this.base44SessionId) {
      throw new Error('ticket_session_mismatch');
    }
    return payload; // becomes client.auth
  }

  onJoin(client) {
    // NO email here — we only ever receive pid (opaque hash) + handle from the
    // signed token. Seating/scoreboard use these; Base44 resolves the real
    // email server-side at writeback time.
    const { pid, handle, team } = client.auth;
    this.players.set(client.sessionId, { pid, handle, team });
    console.log(`[arena] ${handle || pid} joined team ${team}`);
  }

  // 30Hz authoritative simulation — replace with your real combat logic.
  tick() {
    if (this.ended) return;
    // HARD SAFETY CEILING: no match may run longer than MAX_MATCH_MS. Even if
    // your real combat logic has a bug that never reaches an end condition, the
    // room self-finalizes (as a draw) and disposes — so a wedged room can't
    // leak memory/CPU forever or hold players hostage.
    const elapsed = Date.now() - this.startedAt;
    const timedOut = elapsed > MAX_MATCH_MS;

    // Example end condition: stop after 90s and pick a winner. Swap with real rules.
    if (elapsed > 90_000 || timedOut) {
      this.ended = true;
      const winner = timedOut ? 'draw' : (Math.random() < 0.5 ? 'one' : 'two');
      // Scoreboard is keyed by HANDLE (public) — never email. Base44's
      // submitGameServerResult applies ILY/MMR off the server-side roster, not
      // off keys in result_stats, so handles here are purely descriptive.
      const stats = {};
      for (const p of this.players.values()) stats[p.handle || p.pid] = { team: p.team };
      // Fire-and-forget the (idempotent, retrying) writeback, then dispose.
      writeResult(this.base44SessionId, winner, stats).finally(() => this.disconnect());
    }
  }

  onLeave(client) { this.players.delete(client.sessionId); }
  onDispose() { this.clock.clear(); }
}

// ── Boot ─────────────────────────────────────────────────────────────────────
// CRITICAL: We bind the Express HTTP server OURSELVES (server.listen) and hand
// the SAME server to Colyseus's WebSocketTransport. We do NOT call
// gameServer.listen() — in Colyseus 0.15 that spins up its own internal HTTP
// server and ignores our Express routes, so /health would never respond and
// Railway would kill the container as "unhealthy". Sharing one server means
// HTTP (/, /health) and WebSocket (Colyseus) both live on the same bound port.
console.log('[arena] booting...');

const app = express();
app.get('/', (_req, res) => res.send('Wallies Arena server is running.'));
app.get('/health', (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const gameServer = new Server({ transport: new WebSocketTransport({ server }) });
gameServer.define('arena',    ArenaRoom);
gameServer.define('blockles', BlocklesRoom);

// Bind the shared server. This is the ONLY listen() call.
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[arena] HTTP + Colyseus listening on 0.0.0.0:${PORT}`);
});

// Surface any boot-time failures that would otherwise be silent.
process.on('uncaughtException', (e) => console.error('[arena] uncaughtException', e));
process.on('unhandledRejection', (e) => console.error('[arena] unhandledRejection', e));
