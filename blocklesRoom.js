// Wallies Blockles — Colyseus realtime room (external host, same Railway server as Arena).
//
// ⚠️ NODE.JS server code for EXTERNAL deployment — NOT part of the Base44 build.
//    Stored as .txt so the frontend linter ignores it. When deploying, save it
//    as `blocklesRoom.js` in your server repo and register it (see DEPLOY below).
//
// === WHAT THIS ROOM IS ===
// A lightweight, NON-authoritative realtime relay for a single Blockles world.
// Unlike ArenaRoom (which runs an authoritative 30Hz combat sim and writes
// results/MMR/ILY back to Base44), this room has NO game logic, NO winner, and
// NO writeback. Block persistence + anti-cheat already live in Base44
// (placeBlocklesBlock / removeBlocklesBlock). This room only BROADCASTS:
//   - each player's live position to everyone else in the world,
//   - each block place/break event to everyone else, instantly.
//
// === IDENTITY / PII ===
// Players are seated by the OPAQUE pid hash + public handle carried in the
// signed token (mode === 'blockles'). No email ever reaches this server.
//
// === DEPLOY (add to the EXISTING Arena server's index.js) ===
//   import BlocklesRoom from './blocklesRoom.js';
//   ...
//   gameServer.define('blockles', BlocklesRoom);
// Clients connect to `wss://<railway-domain>/blockles` with { token }.
// Reuses the SAME GAME_SERVER_JOIN_SECRET — verifyTicket is identical to Arena.

import pkg from 'colyseus';
const { Room } = pkg;
import crypto from 'crypto';

const JOIN_SECRET = process.env.GAME_SERVER_JOIN_SECRET || '';
const BROADCAST_HZ = 12;              // how often we fan out the player roster
const IDLE_KICK_MS = 30000;           // drop a socket that hasn't sent anything
const MAX_PLAYERS_PER_WORLD = 32;     // safety ceiling per world room

// ── Ticket verification (identical HMAC to Arena's verifyTicket) ─────────────
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

export default class BlocklesRoom extends Room {
  onCreate() {
    this.maxClients = MAX_PLAYERS_PER_WORLD;
    // socketSessionId -> { pid, handle, avatar_url, avatar_style, x,y,z, ry, lastSeen }
    this.players = new Map();
    this.broadcastHandle = this.clock.setInterval(() => this.broadcastRoster(), 1000 / BROADCAST_HZ);
    this.reaperHandle = this.clock.setInterval(() => this.reapIdle(), 5000);
  }

  // Validate the Base44 ticket BEFORE the socket may join, and bind this room to
  // its world id (anti-replay: every joiner must carry a ticket for the SAME world).
  onAuth(client, options) {
    const payload = verifyTicket(options?.token);
    if (!payload) throw new Error('invalid_or_expired_ticket');
    if (!this.worldId) {
      this.worldId = payload.sid;
    } else if (payload.sid !== this.worldId) {
      throw new Error('ticket_world_mismatch');
    }
    return payload; // becomes client.auth
  }

  onJoin(client, options) {
    const { pid, handle } = client.auth;
    this.players.set(client.sessionId, {
      pid,
      handle: handle || 'Builder',
      avatar_url: (options?.avatar_url || '').toString() || null,
      avatar_style: (options?.avatar_style || '').toString() || null,
      x: 0, y: 0, z: 0, ry: 0,
      lastSeen: Date.now(),
    });
    // Tell the client it's in, and which roster id is "self" so it can exclude itself.
    client.send('joined', { self_id: client.sessionId });
  }

  onMessage(client, type, message) {
    const p = this.players.get(client.sessionId);
    if (!p) return;
    p.lastSeen = Date.now();

    if (type === 'pos' && message) {
      p.x = Number(message.x) || 0;
      p.y = Number(message.y) || 0;
      p.z = Number(message.z) || 0;
      p.ry = Number(message.ry) || 0;
      return;
    }
    if (type === 'edit' && message) {
      // Relay the edit to everyone else. We do NOT persist here — Base44 already
      // did (or will) authoritatively; this is purely the instant visual echo.
      const action = message.action === 'remove' ? 'remove' : 'place';
      this.broadcast('edit', {
        id: client.sessionId,
        action,
        x: Number(message.x) || 0,
        y: Number(message.y) || 0,
        z: Number(message.z) || 0,
        block_type: message.block_type || null,
      }, { except: client });
    }
  }

  // Fan out the live player roster (positions) to everyone.
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

  // Drop sockets that have gone silent (closed tab without a clean leave).
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
