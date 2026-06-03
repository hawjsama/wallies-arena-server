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

const PORT = Number(process.env.PORT || 2567);
const JOIN_SECRET = process.env.GAME_SERVER_JOIN_SECRET || '';
const RESULT_URL = process.env.BASE44_RESULT_URL || '';
const INTERNAL_SECRET = process.env.INTERNAL_FUNCTION_SECRET || '';
const TICK_HZ = 30;

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
  return payload; // { sid, email, handle, team, mode, ... }
}

// ── Result writeback to Base44 ───────────────────────────────────────────────
async function writeResult(sessionId, winnerTeam, resultStats) {
  if (!RESULT_URL) return;
  try {
    await fetch(RESULT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        internal_secret: INTERNAL_SECRET,
        session_id: sessionId,
        winner_team: winnerTeam,
        result_stats: resultStats,
      }),
    });
  } catch (e) {
    console.error('[arena] result writeback failed', e);
  }
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
    return payload; // becomes client.auth
  }

  onJoin(client) {
    const { email, handle, team, sid } = client.auth;
    this.base44SessionId = sid;
    this.players.set(client.sessionId, { email, handle, team });
    console.log(`[arena] ${handle || email} joined team ${team}`);
  }

  // 30Hz authoritative simulation — replace with your real combat logic.
  tick() {
    // Example end condition: stop after 90s and pick a winner. Swap with real rules.
    if (Date.now() - this.startedAt > 90_000 && !this.ended) {
      this.ended = true;
      const winner = Math.random() < 0.5 ? 'one' : 'two';
      const stats = {};
      for (const p of this.players.values()) stats[p.email] = { team: p.team };
      writeResult(this.base44SessionId, winner, stats);
      this.disconnect();
    }
  }

  onLeave(client) { this.players.delete(client.sessionId); }
  onDispose() { this.clock.clear(); }
}

// ── Boot ─────────────────────────────────────────────────────────────────────
const app = express();
app.get('/health', (_req, res) => res.json({ ok: true }));
const server = http.createServer(app);
const gameServer = new Server({ transport: new WebSocketTransport({ server }) });
gameServer.define('arena', ArenaRoom);
gameServer.listen(PORT);
console.log(`[arena] Colyseus listening on :${PORT}`);
