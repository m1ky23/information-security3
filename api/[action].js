const k = require('../lib/core');
const fails = {};                                    // simple lock-out: 5 wrong attempts -> 5 minutes
const locked = u => fails[u] && fails[u].n >= 5 && Date.now() < fails[u].until;
const bad = u => { const f = fails[u] = fails[u] || { n: 0 }; f.n++; f.until = Date.now() + 300000; };

module.exports = async (req, res) => {
  const send = (code, obj) => res.status(code).json(obj);
  const b = req.body || {}, action = req.query.action;
  try {
    const users = await k.loadUsers();
    if (action === 'register') {
      const u = String(b.username || '').toLowerCase(), pw = String(b.password || '');
      if (!/^[a-z0-9_]{3,32}$/.test(u)) return send(400, { error: 'Username: 3-32 letters, numbers or _' });
      if (pw.length < 8 || !/[a-z]/i.test(pw) || !/\d/.test(pw)) return send(400, { error: 'Password: min 8 chars with a letter and a number' });
      if (users[u]) return send(409, { error: 'Username already taken' });
      const salt = k.newSalt(), secret = k.newSecret();
      users[u] = { salt, hash: k.hashPw(pw, salt), totp: k.enc(secret), created: new Date().toISOString() };
      k.writeUsers(users);
      return send(201, { secret, otpauth: `otpauth://totp/SecureLogin:${u}?secret=${secret}&issuer=SecureLogin` });
    }
    if (action === 'login') {                        // STEP 1: password
      const u = String(b.username || '').toLowerCase(), rec = users[u];
      if (locked(u)) return send(429, { error: 'Too many attempts. Try again in 5 minutes.' });
      const ok = !!rec && k.safeEq(k.hashPw(String(b.password || ''), rec.salt), rec.hash);
      if (!rec) k.hashPw(String(b.password || ''), '00');          // equalise timing for unknown users
      if (!ok) { bad(u); return send(401, { error: 'Invalid username or password' }); }
      return send(200, { pending: k.sign({ kind: 'otp', u }, 5) });
    }
    if (action === 'verify') {                       // STEP 2: authenticator code
      const p = k.verify(b.pending, 'otp'); if (!p) return send(401, { error: 'Step 1 expired. Log in again.' });
      if (locked(p.u)) return send(429, { error: 'Too many attempts. Try again in 5 minutes.' });
      if (!k.checkTotp(k.dec(users[p.u].totp), b.code)) { bad(p.u); return send(401, { error: 'Wrong or expired code' }); }
      delete fails[p.u]; return send(200, { session: k.sign({ kind: 'session', u: p.u }, 15), user: p.u });
    }
    const s = k.verify((req.headers.authorization || '').replace('Bearer ', ''), 'session');
    if (!s) return send(401, { error: 'Please log in with both steps' });
    if (action === 'me') return send(200, { user: s.u, users: Object.keys(users).length });
    if (action === 'backup') return send(200, { ok: true, count: await k.backup(), at: new Date().toISOString() });
    if (action === 'restore') return send(200, { ok: true, count: await k.restore() });
    send(404, { error: 'Unknown action' });
  } catch (e) { send(500, { error: e.message }); }
};
