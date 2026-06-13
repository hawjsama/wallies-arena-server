// Wallies Blockles — Colyseus MATCHMAKING LOBBY room (external host, same Railway
// server as Arena + the Blockles world room).
//
// ⚠️ NODE.JS server code for EXTERNAL deployment — NOT part of the Base44 build.
//    Stored as .txt so the frontend linter ignores it. When deploying, save it
//    as `blocklesLobbyRoom.js` in your server repo and register it (see DEPLOY).
//
// === WHAT THIS IS — THE ENTERPRISE MATCHMAKER (Riot / Valve / Open Match) ===
// The queue lives IN MEMORY here, fed by socket EVENTS — never by polling a DB.
// A player opens a WebSocket, sends one { type:'queue', mode } message, and the
// ticket sits in this room's RAM. A tick loop pairs same-mode tickets and the
// instant it pairs you it PUSHES 'match_found' down your socket. There is ZERO
// database read in the hot path; Base44 is touched ONLY at the moment of a match
// (createBlocklesSessionFromLobby) to persist the GameSession + BlocklesMatch.
//
// === DEPLOY (add to the EXISTING Arena server's index.js) ===
//   import BlocklesLobbyRoom from './blocklesLobbyRoom.js';
//   gameServer.define('blockles_lobby', BlocklesLobbyRoom);
// Clients connect to `wss://<railway-domain>/blockles_lobby` with { token }
// minted by issueBlocklesLobbyToken. Reuses the SAME GAME_SERVER_JOIN_SECRET.
//
// === ENV REQUIRED (already set for Arena) ===
//   GAME_SERVER_JOIN_SECRET   — verifies lobby join tickets (same as Arena).
//   INTERNAL_FUNCTION_SECRET  — authorizes createBlocklesSessionFromLobby.
//   BASE44_BLOCKLES_ALLOC_URL — full URL of createBlocklesSessionFromLobby.
//
// === WIRE PROTOCOL (client ⇄ this room) ===
//   Inbound  (client → room):
//     send('queue',   { mode })   — enter the queue for a game mode
//     send('dequeue', {})         — leave the queue
//   Outbound (room → client):
//     on('queued',      { mode, position })
//     on('match_found', { session_id, match_id, mode })   ← PUSHED, no polling
//
// === IDENTITY / PII ===
// Players are seated by the OPAQUE pid hash + public handle from the signed
// token (mode === 'blockles_lobby'). No email ever reaches this server;
// createBlocklesSessionFromLobby resolves pid → party server-side in Base44.

import pkg from 'colyseus';
const { Room } = pkg;
import crypto from 'crypto';

const JOIN_SECRET = process.env.GAME_SERVER_JOIN_SECRET || '';
const INTERNAL_SECRET = process.env.INTERNAL_FUNCTION_SECRET || '';
const ALLOC_URL = process.env.BASE44_BLOCKLES_ALLOC_URL || '';
const TICK_MS = 1000;                 // pair pass cadence
const VALID_MODES = ['king_of_hill', 'build_battle', 'speed_mine'];

if (!JOIN_SECRET) console.error('[blockles-lobby] FATAL: GAME_SERVER_JOIN_SECRET not set — joins rejected.');
if (!INTERNAL_SECRET) console.error('[blockles-lobby] FATAL: INTERNAL_FUNCTION_SECRET not set — allocation rejected.');
if (!ALLOC_URL) console.error('[blockles-lobby] FATAL: BASE44_BLOCKLES_ALLOC_URL not set — cannot create matches.');

// ── Ticket verification (identical HMAC to issueBlocklesLobbyToken) ──────────
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
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(payloadB64)); } catch { return null; }
  if (!payload?.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
  if (payload.room !== 'blockles_lobby') return null; // only lobby tickets here
  return payload; // { sid:'blockles_lobby', pid, handle, mode }
}

// Ask Base44 to atomically claim both pids' tickets + build the match/session.
async function allocate(pidA, pidB, mode) {
  if (!ALLOC_URL) return null;
  try {
    const res = await fetch(ALLOC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ internal_secret: INTERNAL_SECRET, pid_a: pidA, pid_b: pidB, mode }),
    });
    if (res.ok) return await res.json().catch(() => null);
    console.warn(`[blockles-lobby] allocate rejected ${res.status} for ${pidA}/${pidB}`);
    return null;
  } catch (e) {
    console.error('[blockles-lobby] allocate error', e?.message || e);
    return null;
  }
}

export default class BlocklesLobbyRoom extends Room {
  onCreate() {
    this.autoDispose = false;          // the lobby is a long-lived singleton
    this.maxClients = 1000;
    // queued: sessionId(socket) -> { pid, handle, mode, queuedAt }
    this.queued = new Map();
    this.pairing = false;

    this.onMessage('queue', (client, msg) => {
      const mode = msg && VALID_MODES.includes(msg.mode) ? msg.mode : null;
      if (!mode) return;
      // Defense-in-depth: the queue message mode MUST match the token's mode
      // (the durable ticket). Prevents a player from accidentally queuing for
      // a different mode than their ticket, which would strand them forever.
      if (mode !== client.auth.mode) return;
      const { pid, handle } = client.auth;
      this.queued.set(client.sessionId, { pid, handle, mode, queuedAt: Date.now() });
      const position = [...this.queued.values()].filter((q) => q.mode === mode).length;
      client.send('queued', { mode, position });
    });

    this.onMessage('dequeue', (client) => {
      this.queued.delete(client.sessionId);
    });

    this.tickHandle = this.clock.setInterval(() => this.pairTick(), TICK_MS);
  }

  onAuth(client, options) {
    const payload = verifyTicket(options && options.token);
    if (!payload) throw new Error('invalid_or_expired_ticket');
    return payload;
  }

  onJoin() { /* player is in the lobby; they queue via the 'queue' message */ }

  // ── In-memory pair pass: same mode, oldest first, never the same pid ─────────
  async pairTick() {
    if (this.pairing) return;          // never overlap a slow allocate() call
    this.pairing = true;
    try {
      // Bucket queued sockets by mode.
      const byMode = new Map();
      for (const [sid, q] of this.queued.entries()) {
        if (!byMode.has(q.mode)) byMode.set(q.mode, []);
        byMode.get(q.mode).push({ sid, ...q });
      }
      for (const [mode, list] of byMode.entries()) {
        list.sort((a, b) => a.queuedAt - b.queuedAt);
        for (let i = 0; i + 1 < list.length; i += 2) {
          const a = list[i], b = list[i + 1];
          if (a.pid === b.pid) continue; // never self-pair
          // Remove from queue BEFORE the async allocate so a slow call can't
          // double-pair them on the next tick.
          this.queued.delete(a.sid);
          this.queued.delete(b.sid);
          const result = await allocate(a.pid, b.pid, mode);
          if (!result || !result.match_id) {
            // Allocation failed — both go back into the queue for the next pass.
            this.queued.set(a.sid, { pid: a.pid, handle: a.handle, mode, queuedAt: a.queuedAt });
            this.queued.set(b.sid, { pid: b.pid, handle: b.handle, mode, queuedAt: b.queuedAt });
            continue;
          }
          // PUSH match_found to both sockets (if still connected).
          const payload = {
            session_id: result.session_id || '',
            match_id: result.match_id,
            world_id: result.world_id || '',
            world_join_code: result.world_join_code || '',
            mode,
          };
          for (const sid of [a.sid, b.sid]) {
            const c = this.clients.find((cl) => cl.sessionId === sid);
            if (c) { try { c.send('match_found', payload); } catch { /* gone */ } }
          }
          console.log(`[blockles-lobby] matched ${a.handle} vs ${b.handle} (${mode})`);
        }
      }
    } finally {
      this.pairing = false;
    }
  }

  onLeave(client) { this.queued.delete(client.sessionId); }
  onDispose() { this.clock.clear(); }
}
