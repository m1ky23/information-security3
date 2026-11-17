const c = require('crypto'), fs = require('fs'), path = require('path');
const PEPPER = process.env.PEPPER || 'dev-pepper-change-me';           // secret kept OUTSIDE the database
const ON_VERCEL = !!process.env.VERCEL;
const USERS = ON_VERCEL ? '/tmp/users.json' : path.join(__dirname, '../data/users.json');
const LOCAL_CLOUD = path.join(__dirname, '../data/cloud-backup.json'); // local stand-in for the cloud
const KEY = c.createHash('sha256').update(PEPPER).digest();

// ---------- password hashing: HMAC(pepper, password) -> scrypt with per-user salt ----------
const hashPw = (pw, salt) =>
  c.scryptSync(c.createHmac('sha256', PEPPER).update(pw).digest(), salt, 64).toString('hex');
const newSalt = () => c.randomBytes(16).toString('hex');
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && c.timingSafeEqual(x, y); };

// ---------- TOTP (RFC 6238): HMAC-SHA1, 30 s step, 6 digits ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = buf => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
const b32dec = s => { let bits = ''; for (const ch of s) bits += B32.indexOf(ch).toString(2).padStart(5, '0');
  const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totp = (secret, t = Date.now()) => {
  const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = c.createHmac('sha1', b32dec(secret)).update(ctr).digest(), o = h[19] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0'); };
const checkTotp = (secret, code) => [-30000, 0, 30000].some(d => safeEq(totp(secret, Date.now() + d), String(code)));
const newSecret = () => b32enc(c.randomBytes(20));

// ---------- encrypt the TOTP secret at rest (AES-256-GCM, key derived from pepper) ----------
const enc = txt => { const iv = c.randomBytes(12), k = c.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([k.update(txt, 'utf8'), k.final()]); return [iv, k.getAuthTag(), ct].map(b => b.toString('hex')).join('.'); };
const dec = s => { const [iv, tag, ct] = s.split('.').map(h => Buffer.from(h, 'hex'));
  const d = c.createDecipheriv('aes-256-gcm', KEY, iv); d.setAuthTag(tag); return Buffer.concat([d.update(ct), d.final()]).toString('utf8'); };

// ---------- signed, expiring tokens (stateless, works on serverless) ----------
const sign = (p, mins) => { const b = Buffer.from(JSON.stringify({ ...p, exp: Date.now() + mins * 60000 })).toString('base64url');
  return b + '.' + c.createHmac('sha256', KEY).update(b).digest('base64url'); };
const verify = (t, kind) => { try { const [b, s] = String(t).split('.');
  if (!safeEq(s, c.createHmac('sha256', KEY).update(b).digest('base64url'))) return null;
  const p = JSON.parse(Buffer.from(b, 'base64url')); return p.exp > Date.now() && p.kind === kind ? p : null; } catch { return null; } };

// ---------- storage + cloud backup ----------
const cloudCfg = () => process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN;
async function cloud(cmd) {                          // Upstash Redis REST API (free cloud database)
  if (cloudCfg()) { const r = await fetch(process.env.UPSTASH_REDIS_REST_URL, { method: 'POST',
      headers: { Authorization: 'Bearer ' + process.env.UPSTASH_REDIS_REST_TOKEN }, body: JSON.stringify(cmd) });
    return (await r.json()).result; }
  if (ON_VERCEL) throw new Error('Cloud storage not configured');
  fs.mkdirSync(path.dirname(LOCAL_CLOUD), { recursive: true });   // local demo only
  if (cmd[0] === 'SET') { fs.writeFileSync(LOCAL_CLOUD, cmd[2]); return 'OK'; }
  return fs.existsSync(LOCAL_CLOUD) ? fs.readFileSync(LOCAL_CLOUD, 'utf8') : null; }
const readLocal = () => { try { return JSON.parse(fs.readFileSync(USERS, 'utf8')); } catch { return null; } };
const writeUsers = u => { fs.mkdirSync(path.dirname(USERS), { recursive: true }); fs.writeFileSync(USERS, JSON.stringify(u, null, 2)); };
async function loadUsers() {                         // auto-restore from the cloud if local data is gone
  let u = readLocal(); if (u) return u;
  try { const j = await cloud(['GET', 'pu:backup']); u = j ? JSON.parse(j) : {}; } catch { u = {}; }
  writeUsers(u); return u; }
const backup = async () => { const u = await loadUsers(); await cloud(['SET', 'pu:backup', JSON.stringify(u)]); return Object.keys(u).length; };
const restore = async () => { const j = await cloud(['GET', 'pu:backup']); if (!j) throw new Error('No backup found');
  const u = JSON.parse(j); writeUsers(u); return Object.keys(u).length; };

module.exports = { hashPw, newSalt, safeEq, checkTotp, totp, newSecret, enc, dec, sign, verify, loadUsers, writeUsers, backup, restore };
