// Wallies Blockles — Colyseus realtime room (external host, same Railway server as Arena).
//
// ⚠️ NODE.JS server code for EXTERNAL deployment — NOT part of the Base44 build.
//    Stored as .txt so the frontend linter ignores it. When deploying, save it
//    as `blocklesRoom.js` in your server repo and register it (see DEPLOY below).
//
// ⚠️ CANONICAL COPY. Byte-for-byte identical to
//    docs/blockles/colyseus-server/blocklesRoom.js.txt — deploy EITHER one.
//    The client hook components/blockles/useBlocklesRealtime.js speaks exactly
//    this protocol.
//
// === DEPLOY (add to the EXISTING Arena server's index.js) ===
//   import BlocklesRoom from './blocklesRoom.js';   // default import (no braces)
//   gameServer.define('arena',    ArenaRoom);
//   gameServer.define('blockles', BlocklesRoom);
// Clients connect to `wss://<railway-domain>/blockles` with { token }.
// Reuses the SAME GAME_SERVER_JOIN_SECRET — verifyTicket is identical to Arena.
//
// === WIRE PROTOCOL (client ⇄ this room) ===
//   Inbound  (client → room):
//     send('pos',  { x, y, z, ry })                         — throttled ~12Hz
//     send('edit', { action:'place'|'remove', x, y, z, block_type })
//   Outbound (room → client):
//     on('joined',  { self_id })                            — your own roster id
//     on('players', { players:[{id,handle,avatar_url,avatar_style,x,y,z,ry}] })
//     on('edit',    { id, action, x, y, z, block_type })
//
// === WHAT THIS ROOM IS ===
// A lightweight, NON-authoritative realtime relay for a single Blockles world.
// Unlike ArenaRoom (authoritative 30Hz combat sim with MMR/ILY writeback), this
// room has NO game logic, NO winner, NO writeback. Block persistence + anti-
// cheat live in Base44 (placeBlocklesBlock / removeBlocklesBlock). This room
// only BROADCASTS each player's position and each block place/break, instantly.
//
// === ANTI-EXPLOIT ===
// Non-authoritative: a malicious client can at MOST make OTHER players briefly
// SEE a ghost block/position — it can never grant blocks, ILY, or alter
// persisted state (only Base44 writes the DB, with auth + double-spend guards).
// To stop a flood degrading the room we rate-limit BOTH inbound channels per
// socket (token-bucket) and clamp edit coords to world bounds. Over-budget
// messages are silently dropped.
//
// === IDENTITY / PII ===
// Players are seated by the OPAQUE pid hash + public handle carried in the
// signed token (mode === 'blockles'). No email ever reaches this server.

import pkg from 'colyseus';
const { Room } = pkg;
import crypto from 'crypto';

const JOIN_SECRET = process.env.GAME_SERVER_JOIN_SECRET || '';
const BROADCAST_HZ = 12;            // roster fan-out rate (matches client throttle)
const IDLE_KICK_MS = 30000;         // drop a socket silent for 30s (closed tab)
const MAX_PLAYERS = 16;             // matches Base44 upsertBlocklesPresence cap
const WORLD_MIN = -64, WORLD_MAX = 64, WORLD_MAX_HEIGHT = 64;
const POS_BUCKET_MAX = 20, POS_REFILL_PER_SEC = 15;
const EDIT_BUCKET_MAX = 30, EDIT_REFILL_PER_SEC = 12;

// ── Ticket verification (identical HMAC to issueBlocklesRealtimeToken) ─────────
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
  if (!payload?.exp || payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
  if (payload.mode !== 'blockles') return null; // only Blockles tickets here
  return payload; // { sid(=worldId), room(=worldId), pid, handle, mode }
}

function num(n, d = 0) { const v = Number(n); return Number.isFinite(v) ? v : d; }
function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

function takeToken(bucket, max, refillPerSec) {
  const now = Date.now();
  const elapsed = (now - bucket.ts) / 1000;
  bucket.ts = now;
  bucket.tokens = Math.min(max, bucket.tokens + elapsed * refillPerSec);
  if (bucket.tokens < 1) return false;
  bucket.tokens -= 1;
  return true;
}

export default class BlocklesRoom extends Room {
  onCreate(options) {
    this.maxClients = MAX_PLAYERS;
    this.worldId = (options && options.world_id) ? String(options.world_id) : null;
    this.players = new Map();
    this.broadcastHandle = this.clock.setInterval(() => this.broadcastRoster(), 1000 / BROADCAST_HZ);
    this.reaperHandle = this.clock.setInterval(() => this.reapIdle(), 5000);

    this.onMessage('pos', (client, msg) => {
      const p = this.players.get(client.sessionId);
      if (!p || !msg) return;
      p.lastSeen = Date.now();
      if (!takeToken(p.posBucket, POS_BUCKET_MAX, POS_REFILL_PER_SEC)) return;
      p.x = num(msg.x); p.y = num(msg.y); p.z = num(msg.z); p.ry = num(msg.ry);
    });

    this.onMessage('edit', (client, msg) => {
      const p = this.players.get(client.sessionId);
      if (!p || !msg) return;
      p.lastSeen = Date.now();
      if (!takeToken(p.editBucket, EDIT_BUCKET_MAX, EDIT_REFILL_PER_SEC)) return;
      const x = clamp(Math.round(num(msg.x)), WORLD_MIN, WORLD_MAX);
      const y = clamp(Math.round(num(msg.y)), 0, WORLD_MAX_HEIGHT);
      const z = clamp(Math.round(num(msg.z)), WORLD_MIN, WORLD_MAX);
      const action = msg.action === 'remove' ? 'remove' : 'place';
      this.broadcast('edit', {
        id: client.sessionId,
        action, x, y, z,
        block_type: action === 'place' ? String(msg.block_type || '').slice(0, 32) : null,
      }, { except: client });
    });
  }

  onAuth(client, options) {
    const payload = verifyTicket(options && options.token);
    if (!payload) throw new Error('invalid_or_expired_ticket');
    if (!this.worldId) {
      this.worldId = payload.sid;
    } else if (payload.sid !== this.worldId) {
      throw new Error('ticket_world_mismatch');
    }
    return payload;
  }

  onJoin(client, options) {
    const { pid, handle } = client.auth;
    this.players.set(client.sessionId, {
      pid,
      handle: handle || 'Builder',
      avatar_url: (options?.avatar_url || '').toString().slice(0, 512) || null,
      avatar_style: (options?.avatar_style || '').toString().slice(0, 64) || null,
      x: 0, y: 0, z: 0, ry: 0,
      lastSeen: Date.now(),
      posBucket: { tokens: POS_BUCKET_MAX, ts: Date.now() },
      editBucket: { tokens: EDIT_BUCKET_MAX, ts: Date.now() },
    });
    client.send('joined', { self_id: client.sessionId });
  }

  broadcastRoster() {
    if (this.players.size === 0) return;
    const players = [];
    for (const [id, p] of this.players.entries()) {
      players.push({
        id,
        handle: p.handle,
        avatar_url: p.avatar_url,
        avatar_style: p.avatar_style,
        x: p.x, y: p.y, z: p.z, ry: p.ry,
      });
    }
    this.broadcast('players', { players });
  }

  reapIdle() {
    const now = Date.now();
    for (const [id, p] of this.players.entries()) {
      if (now - p.lastSeen > IDLE_KICK_MS) {
        this.players.delete(id);
        const c = this.clients.find((cl) => cl.sessionId === id);
        if (c) { try { c.leave(); } catch { /* ignore */ } }
      }
    }
  }

  onLeave(client) { this.players.delete(client.sessionId); }
  onDispose() { this.clock.clear(); }
}
