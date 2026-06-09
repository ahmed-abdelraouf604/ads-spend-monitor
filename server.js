// WebSocket polyfill for Node.js 20 + Supabase
const WebSocket = require('ws');
global.WebSocket = WebSocket;

require('dotenv').config();
const express          = require('express');
const session          = require('express-session');
const cors             = require('cors');
const { google }       = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const path             = require('path');
const crypto           = require('crypto');
const bcrypt           = require('bcrypt');
const dns              = require('dns').promises;

const app  = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(session({
  secret:            process.env.SESSION_SECRET || 'change-this-secret',
  resave:            false,
  saveUninitialized: false,
  cookie:            { secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// ============================================================
// AUTH  +  DEVICE / SESSION MANAGER
// ============================================================

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress || req.ip || '';
}

const authCache     = {};
const lastSeenCache = {};
const AUTH_CACHE_TTL  = 60_000;
const LAST_SEEN_TTL   = 5 * 60_000;

async function isSessionValid(sessionId) {
  if (!sessionId) return false;
  const c = authCache[sessionId];
  if (c && Date.now() - c.ts < AUTH_CACHE_TTL) return c.valid;
  const { data } = await supabase.from('sessions').select('id')
    .eq('session_id', sessionId).maybeSingle();
  const valid = !!data;
  authCache[sessionId] = { valid, ts: Date.now() };
  return valid;
}

async function upsertDeviceSession(req) {
  const now   = new Date().toISOString();
  const ua    = req.headers['user-agent'] || '';
  const uid   = req.session.userId   || null;
  const uname = req.session.username || null;

  // One device == same user + same browser (user_agent). This key is stable
  // across logout/login and needs no cookie, so a device is never duplicated.
  const base = {
    session_id:   req.sessionID,
    ip_address:   getClientIp(req),
    user_agent:   ua,
    user_id:      uid,
    username:     uname,
    device_name:  req.session.deviceName || null,
    last_seen_at: now
  };

  try {
    let q = supabase.from('sessions').select('id, session_id, created_at').eq('user_agent', ua);
    q = uid ? q.eq('user_id', uid) : q.eq('username', uname);
    const { data: rows, error: selErr } = await q.order('created_at', { ascending: true });
    if (selErr) throw selErr;

    if (rows && rows.length) {
      // Reuse the oldest matching row — its created_at stays as the first sign-in date
      const keep = rows[0];
      if (keep.session_id) delete authCache[keep.session_id];
      const { error: updErr } = await supabase.from('sessions').update(base).eq('id', keep.id);
      if (updErr) throw updErr;

      // Collapse any leftover duplicates for this device into the row we kept
      const dupes = rows.slice(1);
      if (dupes.length) {
        dupes.forEach(r => r.session_id && delete authCache[r.session_id]);
        await supabase.from('sessions').delete().in('id', dupes.map(r => r.id));
      }
    } else {
      const { error: insErr } = await supabase.from('sessions').insert({ ...base, created_at: now });
      if (insErr) throw insErr;
    }
  } catch (e) {
    // Dedup write failed — fall back to a plain upsert so a row ALWAYS exists
    // (auth checks and the Device Manager both read from this table).
    console.error('[upsertDeviceSession] failed, using fallback:', e.message);
    await supabase.from('sessions').upsert({ ...base, created_at: now }, { onConflict: 'session_id' });
  }
  authCache[req.sessionID] = { valid: true, ts: Date.now() };
}

async function requireAuth(req, res, next) {
  try {
    if (await isSessionValid(req.sessionID)) {
      if (!req.session.userId || req.session.isAdmin === undefined) {
        const { data: sess } = await supabase.from('sessions')
          .select('user_id, username').eq('session_id', req.sessionID).maybeSingle();
        const lookupId = sess?.user_id;
        if (lookupId) {
          const { data: user } = await supabase.from('users')
            .select('id, username, is_admin').eq('id', lookupId).maybeSingle();
          if (user) {
            req.session.userId   = user.id;
            req.session.username = user.username;
            req.session.isAdmin  = user.is_admin === true;
            console.log('[requireAuth] re-hydrated session for', user.username, '(isAdmin:', req.session.isAdmin, ')');
          }
        } else if (sess?.username) {
          const { data: user } = await supabase.from('users')
            .select('id, username, is_admin').eq('username', sess.username).maybeSingle();
          if (user) {
            req.session.userId   = user.id;
            req.session.username = user.username;
            req.session.isAdmin  = user.is_admin === true;
            console.log('[requireAuth] re-hydrated by username for', user.username, '(isAdmin:', req.session.isAdmin, ')');
          }
        }
      }
      if (req.session.isAdmin === undefined) req.session.isAdmin = false;
      return next();
    }
  } catch(e) { console.error('requireAuth:', e.message); }
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(403).json({ error: 'Admin access required' });
}

async function getUserAllowedAccounts(req) {
  if (req.session.isAdmin === true) return null;
  if (!req.session.userId) return new Set();
  const { data } = await supabase.from('user_accounts')
    .select('account_id').eq('user_id', req.session.userId);
  return new Set((data || []).map(r => r.account_id));
}

async function bootstrapAdmin() {
  const adminPw = process.env.ADMIN_PASSWORD;
  if (!adminPw) {
    console.log('⚠️  ADMIN_PASSWORD not set — skipping admin bootstrap');
    return;
  }
  try {
    const { data: users } = await supabase.from('users').select('id').limit(1);
    if (users && users.length > 0) return;
    const hash = await bcrypt.hash(adminPw, 10);
    const { error } = await supabase.from('users')
      .insert({ username: 'admin', password_hash: hash, is_admin: true });
    if (error) console.error('Bootstrap admin error:', error.message);
    else console.log('✅ Admin user "admin" created');
  } catch(e) { console.error('bootstrapAdmin:', e.message); }
}

// ── Device name helpers ──
// osHint: accurate OS name sent by the client via User-Agent Client Hints API
function buildUAName(ua, osHint) {
  if (!ua) return osHint || 'Unknown Device';
  let m, browser = '', os = osHint || '';
  if      ((m = ua.match(/Edg\/([\d]+)/)))            browser = 'Edge '    + m[1];
  else if ((m = ua.match(/OPR\/([\d]+)/)))             browser = 'Opera '   + m[1];
  else if ((m = ua.match(/Chrome\/([\d]+)/)))          browser = 'Chrome '  + m[1];
  else if ((m = ua.match(/Firefox\/([\d]+)/)))         browser = 'Firefox ' + m[1];
  else if ((m = ua.match(/Version\/([\d]+).*Safari/))) browser = 'Safari '  + m[1];
  else if (/Safari/.test(ua))                          browser = 'Safari';
  if (!os) {
    if      ((m = ua.match(/Windows NT ([\d.]+)/)))    os = ({'10.0':'Windows 10','6.3':'Windows 8.1','6.2':'Windows 8','6.1':'Windows 7'}[m[1]] || 'Windows');
    else if (/Mac OS X/.test(ua))    os = 'macOS';
    else if (/Android/.test(ua))     os = 'Android';
    else if (/iPhone|iPad/.test(ua)) os = 'iOS';
    else if (/CrOS/.test(ua))        os = 'ChromeOS';
    else if (/Linux/.test(ua))       os = 'Linux';
  }
  return [browser, os].filter(Boolean).join(' · ') || 'Unknown Device';
}

async function resolveDeviceName(ip, ua, osHint) {
  const loopback = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
  if (ip && !loopback.includes(ip)) {
    try {
      // Race DNS reverse lookup against a 1.5 s timeout so login stays fast
      const lookup  = dns.reverse(ip).then(hosts => hosts[0]?.split('.')[0] || null);
      const timeout = new Promise(r => setTimeout(() => r(null), 1500));
      const host    = await Promise.race([lookup, timeout]);
      if (host) return host;
    } catch(e) { /* not resolvable — fall through */ }
  }
  return buildUAName(ua, osHint);
}

// ── Login / Logout ──
app.post('/auth/login', async (req, res) => {
  const { username, password, osHint } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const { data: user } = await supabase.from('users').select('*')
    .eq('username', username).maybeSingle();
  if (!user)
    return res.status(401).json({ error: 'Invalid username or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match)
    return res.status(401).json({ error: 'Invalid username or password' });

  req.session.userId     = user.id;
  req.session.username   = user.username;
  req.session.isAdmin    = user.is_admin;
  req.session.deviceName = await resolveDeviceName(getClientIp(req), req.headers['user-agent'] || '', osHint || null);
  await upsertDeviceSession(req);
  res.json({ success: true, isAdmin: user.is_admin });
});

app.post('/auth/logout', async (req, res) => {
  if (req.sessionID) {
    await supabase.from('sessions').delete().eq('session_id', req.sessionID);
    delete authCache[req.sessionID];
    delete lastSeenCache[req.sessionID];
  }
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/auth/check', async (req, res) => {
  try {
    if (await isSessionValid(req.sessionID)) return res.json({ authenticated: true });
  } catch(e) {}
  res.json({ authenticated: false });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ username: req.session.username || '', isAdmin: !!req.session.isAdmin });
});

app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ============================================================
// PACING CALCULATION
// ============================================================
function calcPacing(mtdSpend, monthlyBudget, rangePercent) {
  if (!monthlyBudget || monthlyBudget <= 0) return null;
  const currentDay = new Date().getDate();
  const range      = rangePercent || 10;
  const expected   = (currentDay / 30.4) * monthlyBudget;
  const variance   = ((mtdSpend / expected) - 1) * 100;
  let status;
  if (variance > range)       status = 'overspending';
  else if (variance < -range) status = 'underspending';
  else                        status = 'on_track';
  return {
    currentDay,
    expected:    Math.round(expected * 100) / 100,
    variance:    Math.round(variance * 10) / 10,
    absVariance: Math.round(Math.abs(variance) * 10) / 10,
    status,
    range
  };
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api', requireAuth);

// Debug endpoints
app.get('/debug/session', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    userId:    req.session.userId   || null,
    username:  req.session.username || null,
    isAdmin:   req.session.isAdmin,
    authenticated: req.session.authenticated || null
  });
});

app.get('/debug/users', async (req, res) => {
  const { data, error } = await supabase.from('users')
    .select('id, username, is_admin, created_at');
  res.json({ users: data || [], error: error?.message || null });
});

// ── Debug: test token + account discovery for a single login ──
app.get('/debug/accounts/:email', async (req, res) => {
  const email = decodeURIComponent(req.params.email);
  try {
    const { data: login } = await supabase.from('google_logins')
      .select('*').eq('email', email).maybeSingle();
    if (!login) return res.json({ error: 'Login not found', email });

    const info = {
      email,
      has_access_token:  !!login.access_token,
      has_refresh_token: !!login.refresh_token,
      token_expiry:      login.token_expiry,
      token_expired:     login.token_expiry
        ? Date.now() > Number(login.token_expiry)
        : 'unknown (null expiry stored)',
    };

    let authClient;
    try {
      authClient = await getAuthClient(login);
      info.auth_status = 'ok — token refreshed/valid';
    } catch(e) {
      info.auth_status = 'FAILED: ' + e.message;
      return res.json(info);
    }

    try {
      const token    = (await authClient.getAccessToken()).token;
      const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
      const r = await fetch(`${ADS_BASE}/customers:listAccessibleCustomers`, {
        headers: { 'Authorization': 'Bearer ' + token, 'developer-token': devToken }
      });
      const d = await r.json();
      info.listAccessibleCustomers_http_status = r.status;
      info.listAccessibleCustomers_response    = d;

      if (r.ok && d.resourceNames?.length) {
        info.mcc_ids_found = d.resourceNames.map(n => n.replace('customers/', ''));
      }
    } catch(e) {
      info.listAccessibleCustomers_error = e.message;
    }

    res.json(info);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.use('/api', (req, res, next) => {
  next();
  const id = req.sessionID;
  if (!id) return;
  const now = Date.now();
  if (!lastSeenCache[id] || now - lastSeenCache[id] > LAST_SEEN_TTL) {
    lastSeenCache[id] = now;
    supabase.from('sessions').update({ last_seen_at: new Date().toISOString() })
      .eq('session_id', id).then(() => {}).catch(() => {});
  }
});

// ─────────────────────────────────────────────
// DEVICE MANAGER
// ─────────────────────────────────────────────
app.get('/api/sessions', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('sessions').select('*')
    .order('last_seen_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const current = req.sessionID;
  res.json({
    sessions: (data || []).map(s => ({
      id:           s.id,
      isCurrent:    s.session_id === current,
      ipAddress:    s.ip_address,
      userAgent:    s.user_agent,
      deviceName:   s.device_name || null,
      username:     s.username || 'Unknown',
      firstLoginAt: s.first_login_at || s.created_at,
      lastSeenAt:   s.last_seen_at
    }))
  });
});

app.delete('/api/sessions', requireAdmin, async (req, res) => {
  const current = req.sessionID;
  if (!current) return res.status(400).json({ error: 'Cannot identify current session' });
  const { data: others } = await supabase.from('sessions').select('session_id')
    .neq('session_id', current);
  const { error } = await supabase.from('sessions').delete().neq('session_id', current);
  if (error) return res.status(500).json({ error: error.message });
  (others || []).forEach(s => {
    req.sessionStore.destroy(s.session_id, () => {});
    delete authCache[s.session_id];
    delete lastSeenCache[s.session_id];
  });
  res.json({ success: true });
});

app.delete('/api/sessions/:id', requireAdmin, async (req, res) => {
  const { data: sess } = await supabase.from('sessions').select('session_id')
    .eq('id', req.params.id).maybeSingle();
  const { error } = await supabase.from('sessions').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  if (sess?.session_id) {
    req.sessionStore.destroy(sess.session_id, err => {
      if (err) console.error('sessionStore.destroy:', err.message);
    });
    delete authCache[sess.session_id];
    delete lastSeenCache[sess.session_id];
  }
  res.json({ success: true });
});

// ─────────────────────────────────────────────
// USER MANAGEMENT
// ─────────────────────────────────────────────
app.get('/api/users', requireAdmin, async (req, res) => {
  const { data: users, error } = await supabase
    .from('users').select('id,username,is_admin,created_at')
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  const { data: assignments } = await supabase.from('user_accounts').select('user_id');
  const counts = {};
  (assignments || []).forEach(r => { counts[r.user_id] = (counts[r.user_id] || 0) + 1; });
  res.json({ users: (users || []).map(u => ({ ...u, accountCount: counts[u.id] || 0 })) });
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, password, isAdmin } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  const hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('users')
    .insert({ username, password_hash: hash, is_admin: !!isAdmin })
    .select('id,username,is_admin').single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ user: data });
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  if (req.params.id === req.session.userId)
    return res.status(400).json({ error: 'Cannot delete your own account' });
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/users/:id/password', requireAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const hash = await bcrypt.hash(password, 10);
  const { error } = await supabase.from('users')
    .update({ password_hash: hash }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.get('/api/users/:id/accounts', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('user_accounts')
    .select('account_id').eq('user_id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ accountIds: (data || []).map(r => r.account_id) });
});

app.put('/api/users/:id/accounts', requireAdmin, async (req, res) => {
  const { accountIds } = req.body;
  if (!Array.isArray(accountIds))
    return res.status(400).json({ error: 'accountIds must be array' });
  await supabase.from('user_accounts').delete().eq('user_id', req.params.id);
  if (accountIds.length > 0) {
    const rows = accountIds.map(id => ({
      user_id:    req.params.id,
      account_id: String(id).replace(/-/g, '')
    }));
    const { error } = await supabase.from('user_accounts').insert(rows);
    if (error) return res.status(500).json({ error: error.message });
  }
  res.json({ success: true });
});

app.get('/api/me/accounts', requireAuth, async (req, res) => {
  if (req.session.isAdmin) {
    const { data } = await supabase.from('whitelist').select('account_id');
    return res.json({ accountIds: (data || []).map(r => r.account_id) });
  }
  const { data, error } = await supabase.from('user_accounts')
    .select('account_id').eq('user_id', req.session.userId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ accountIds: (data || []).map(r => r.account_id) });
});

// AUTH — Google OAuth
app.get('/auth/url', (req, res) => {
  const oauth2Client = makeOAuth2Client();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline', prompt: 'consent select_account',
    scope: [
      'https://www.googleapis.com/auth/adwords',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ]
  });
  res.json({ url });
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`<script>window.opener.postMessage({type:'AUTH_ERROR',error:'${error}'},'*');window.close();</script>`);
  try {
    const oauth2Client = makeOAuth2Client();
    const { tokens }   = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: u } = await oauth2.userinfo.get();
    const { error: dbErr } = await supabase.from('google_logins').upsert({
      email: u.email, name: u.name, picture: u.picture,
      access_token: tokens.access_token, refresh_token: tokens.refresh_token,
      token_expiry: tokens.expiry_date, updated_at: new Date().toISOString()
    }, { onConflict: 'email' });
    if (dbErr) throw new Error('DB error: ' + dbErr.message);
    res.send(`<script>window.opener.postMessage({type:'AUTH_SUCCESS',email:'${u.email}',name:'${u.name}',picture:'${u.picture||''}'},'*');window.close();</script>`);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.send(`<script>window.opener.postMessage({type:'AUTH_ERROR',error:'${err.message}'},'*');window.close();</script>`);
  }
});

// LOGINS
app.get('/api/logins', async (req, res) => {
  const { data, error } = await supabase.from('google_logins')
    .select('email,name,picture,updated_at').order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ logins: data || [] });
});

app.delete('/api/logins/:email', async (req, res) => {
  const { error } = await supabase.from('google_logins')
    .delete().eq('email', decodeURIComponent(req.params.email));
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ============================================================
// ACCOUNTS DISCOVERY
// ============================================================
app.get('/api/accounts', async (req, res) => {
  console.log('[/api/accounts] session:', {
    userId:   req.session.userId,
    isAdmin:  req.session.isAdmin,
    username: req.session.username
  });
  try {
    const allowedAccounts = await getUserAllowedAccounts(req);
    console.log('[/api/accounts] allowedAccounts:',
      allowedAccounts === null ? 'null (admin)' : `Set(${allowedAccounts.size})`);

    const logins  = await getAllLogins();
    const results = [];

    for (const login of logins) {
      try {
        const authClient = await getAuthClient(login);
        const mccs = await listAccessibleCustomers(authClient);
        console.log(`[/api/accounts] ${login.email} → ${mccs.length} MCCs:`, mccs);
        for (const mccId of mccs) {
          const mccName  = await getMccName(authClient, mccId);
          const accounts = await listSubAccounts(authClient, mccId);
          console.log(`[/api/accounts] MCC ${mccId} (${mccName}) → ${accounts.length} accounts`);
          results.push(...accounts.map(a => ({ ...a, loginEmail: login.email, mccId, mccName })));
        }
      } catch(e) {
        console.error('[/api/accounts] error for', login.email, ':', e.message);
      }
    }

    const filtered = allowedAccounts !== null
      ? results.filter(a => allowedAccounts.has(a.accountId))
      : results;

    console.log('[/api/accounts] returning', filtered.length, 'of', results.length, 'accounts');
    res.json({ accounts: filtered });
  } catch (err) {
    console.error('[/api/accounts] fatal:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SPEND + PACING
// ============================================================
app.get('/api/spend', async (req, res) => {
  try {
    const logins          = await getAllLogins();
    const whitelist       = await getWhitelist();
    const allowedAccounts = await getUserAllowedAccounts(req);
    const results         = [];

    for (const login of logins) {
      let myAccounts = whitelist.filter(w => w.login_email === login.email);
      if (allowedAccounts !== null)
        myAccounts = myAccounts.filter(w => allowedAccounts.has(w.account_id));
      if (!myAccounts.length) continue;
      try {
        const authClient = await getAuthClient(login);
        for (const acc of myAccounts) {
          try {
            const spend  = await getAccountSpend(authClient, acc.account_id, acc.mcc_id);
            const pacing = calcPacing(spend.mtd, acc.monthly_budget, acc.range_percent);
            results.push({
              accountId:     formatId(acc.account_id),
              accountName:   acc.account_name,
              currency:      spend.currency,
              dailySpend:    spend.daily,
              mtdSpend:      spend.mtd,
              monthlyBudget: acc.monthly_budget,
              rangePercent:  acc.range_percent || 10,
              pacing,
              loginEmail:    login.email,
              mccId:         formatId(acc.mcc_id),
              mccName:       acc.mcc_name || ('MCC ' + acc.mcc_id)
            });
          } catch(e) { console.error('Spend error for', acc.account_id, e.message); }
        }
      } catch(e) { console.error('Auth error for', login.email, e.message); }
    }

    const order = { overspending: 0, underspending: 1, on_track: 2 };
    results.sort((a, b) => {
      const aO = a.pacing ? (order[a.pacing.status] ?? 3) : 4;
      const bO = b.pacing ? (order[b.pacing.status] ?? 3) : 4;
      return aO - bO;
    });
    res.json({ accounts: results, generatedAt: new Date().toISOString() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// WHITELIST
// ============================================================
app.get('/api/whitelist', async (req, res) => {
  const { data, error } = await supabase.from('whitelist').select('*');
  if (error) return res.status(500).json({ error: error.message });
  const accounts = (data || []).map(r => ({
    accountId:     r.account_id,
    accountName:   r.account_name,
    mccId:         r.mcc_id,
    mccName:       r.mcc_name,
    loginEmail:    r.login_email,
    monthlyBudget: r.monthly_budget,
    rangePercent:  r.range_percent
  }));
  res.json({ accounts });
});

app.post('/api/whitelist', async (req, res) => {
  const { accounts, removed } = req.body;
  if (!Array.isArray(accounts)) return res.status(400).json({ error: 'accounts must be array' });

  if (Array.isArray(removed) && removed.length > 0) {
    const ids = removed.map(id => String(id).replace(/-/g,''));
    await supabase.from('whitelist').delete().in('account_id', ids);
  }

  const { data: existing } = await supabase.from('whitelist')
    .select('account_id,monthly_budget,range_percent');
  const existingMap = {};
  (existing || []).forEach(r => { existingMap[r.account_id] = r; });

  for (const a of accounts) {
    const accountId = String(a.accountId).replace(/-/g,'');
    const prev = existingMap[accountId];
    const row = {
      account_id:     accountId,
      account_name:   a.accountName,
      mcc_id:         String(a.mccId).replace(/-/g,''),
      mcc_name:       a.mccName || null,
      login_email:    a.loginEmail,
      monthly_budget: a.monthlyBudget != null ? a.monthlyBudget : (prev?.monthly_budget ?? null),
      range_percent:  a.rangePercent  != null ? a.rangePercent  : (prev?.range_percent  ?? 10)
    };
    const { error } = await supabase.from('whitelist').upsert(row, { onConflict: 'account_id' });
    if (error) console.error('Upsert error for', accountId, error.message);
  }

  res.json({ success: true, saved: accounts.length });
});

app.delete('/api/whitelist/:accountId', async (req, res) => {
  const accountId = req.params.accountId.replace(/-/g,'');
  const { error } = await supabase.from('whitelist').delete().eq('account_id', accountId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/whitelist/:accountId', async (req, res) => {
  const { monthlyBudget, rangePercent } = req.body;
  const accountId = req.params.accountId.replace(/-/g,'');
  const { error } = await supabase.from('whitelist')
    .update({ monthly_budget: monthlyBudget, range_percent: rangePercent || 10 })
    .eq('account_id', accountId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ============================================================
// GOOGLE ADS API HELPERS
// ============================================================
const ADS_VERSION = 'v23';
const ADS_BASE    = `https://googleads.googleapis.com/${ADS_VERSION}`;

async function listAccessibleCustomers(authClient) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
  const res = await fetch(`${ADS_BASE}/customers:listAccessibleCustomers`, {
    headers: { 'Authorization': 'Bearer ' + token, 'developer-token': devToken }
  });
  const data = await res.json();
  if (!res.ok) {
    const msg = data?.error?.message || JSON.stringify(data).substring(0, 300);
    console.error('[listAccessibleCustomers] API error:', msg);
    throw new Error('listAccessibleCustomers failed: ' + msg);
  }
  return (data.resourceNames || []).map(r => r.replace('customers/', ''));
}

async function getMccName(authClient, mccId) {
  try {
    const token    = (await authClient.getAccessToken()).token;
    const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
    const res = await fetch(`${ADS_BASE}/customers/${mccId}/googleAds:search`, {
      method: 'POST',
      headers: {
        'Authorization':    'Bearer ' + token,
        'developer-token':  devToken,
        'login-customer-id': mccId,
        'Content-Type':     'application/json'
      },
      body: JSON.stringify({ query: 'SELECT customer.descriptive_name FROM customer LIMIT 1' })
    });
    const data = await res.json();
    return data.results?.[0]?.customer?.descriptiveName || ('MCC ' + mccId);
  } catch(e) { return 'MCC ' + mccId; }
}

async function listSubAccounts(authClient, mccId) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
  const query    = `SELECT customer_client.id, customer_client.descriptive_name, customer_client.currency_code FROM customer_client WHERE customer_client.level = 1 AND customer_client.status = 'ENABLED'`;
  const res = await fetch(`${ADS_BASE}/customers/${mccId}/googleAds:search`, {
    method: 'POST',
    headers: {
      'Authorization':    'Bearer ' + token,
      'developer-token':  devToken,
      'login-customer-id': mccId,
      'Content-Type':     'application/json'
    },
    body: JSON.stringify({ query })
  });
  const data = await res.json();
  if (!res.ok) {
    console.error('[listSubAccounts] error for MCC', mccId, JSON.stringify(data).substring(0, 200));
    return [];
  }
  return (data.results || []).map(r => ({
    accountId:   String(r.customerClient.id),
    accountName: r.customerClient.descriptiveName || 'Account ' + r.customerClient.id,
    currency:    r.customerClient.currencyCode || ''
  }));
}

async function getAccountSpend(authClient, accountId, mccId) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
  const headers  = {
    'Authorization':    'Bearer ' + token,
    'developer-token':  devToken,
    'login-customer-id': mccId,
    'Content-Type':     'application/json'
  };
  const [dRes, mRes] = await Promise.all([
    fetch(`${ADS_BASE}/customers/${accountId}/googleAds:search`, {
      method: 'POST', headers,
      body: JSON.stringify({ query: 'SELECT metrics.cost_micros, customer.currency_code FROM customer WHERE segments.date DURING TODAY' })
    }),
    fetch(`${ADS_BASE}/customers/${accountId}/googleAds:search`, {
      method: 'POST', headers,
      body: JSON.stringify({ query: 'SELECT metrics.cost_micros FROM customer WHERE segments.date DURING THIS_MONTH' })
    })
  ]);
  const dData = await dRes.json();
  const mData = await mRes.json();
  return {
    daily:    sumMicros(dData),
    mtd:      sumMicros(mData),
    currency: dData.results?.[0]?.customer?.currencyCode || ''
  };
}

function sumMicros(data) {
  if (!data.results) return 0;
  return Math.round(
    (data.results.reduce((s, r) => s + parseInt(r.metrics?.costMicros || 0, 10), 0) / 1e6) * 100
  ) / 100;
}

async function getAllLogins() {
  const { data, error } = await supabase.from('google_logins').select('*');
  if (error) throw new Error(error.message);
  return data || [];
}

async function getWhitelist() {
  const { data, error } = await supabase.from('whitelist').select('*');
  if (error) throw new Error(error.message);
  return data || [];
}

// ── FIXED: always refresh when token_expiry is null or expired ──
async function getAuthClient(login) {
  const oauth2Client = makeOAuth2Client();
  oauth2Client.setCredentials({
    access_token:  login.access_token,
    refresh_token: login.refresh_token,
    expiry_date:   login.token_expiry
  });

  // Refresh if: token_expiry is null/missing, OR token is expired/within 60s of expiry
  const needsRefresh = !login.token_expiry || Date.now() > Number(login.token_expiry) - 60000;

  if (needsRefresh && login.refresh_token) {
    try {
      const { credentials } = await oauth2Client.refreshAccessToken();
      await supabase.from('google_logins').update({
        access_token: credentials.access_token,
        token_expiry: credentials.expiry_date,
        updated_at:   new Date().toISOString()
      }).eq('email', login.email);
      oauth2Client.setCredentials(credentials);
      console.log('[getAuthClient] refreshed token for', login.email,
        '— new expiry:', new Date(credentials.expiry_date).toISOString());
    } catch(e) {
      console.error('[getAuthClient] token refresh FAILED for', login.email, ':', e.message);
      throw new Error('Token refresh failed for ' + login.email + '. Please reconnect the Google account. (' + e.message + ')');
    }
  }

  return oauth2Client;
}

function formatId(id) {
  const s = String(id).replace(/-/g, '');
  return s.length === 10 ? `${s.slice(0,3)}-${s.slice(3,6)}-${s.slice(6)}` : s;
}

// ============================================================
// PERFORMANCE METRICS API
// ============================================================
app.post('/api/performance', async (req, res) => {
  try {
    const { accountIds, dateRange } = req.body;
    if (!Array.isArray(accountIds) || accountIds.length === 0)
      return res.status(400).json({ error: 'accountIds required' });

    const allowedAccounts = await getUserAllowedAccounts(req);

    let cleanIds = accountIds.map(id => String(id).replace(/-/g, ''));
    if (allowedAccounts !== null)
      cleanIds = cleanIds.filter(id => allowedAccounts.has(id));

    if (!cleanIds.length)
      return res.json({ accounts: [], generatedAt: new Date().toISOString() });

    const logins    = await getAllLogins();
    const whitelist = await getWhitelist();
    const results   = [];
    const dateClause = buildDateClause(dateRange);

    const whitelistMap = {};
    whitelist.forEach(w => { whitelistMap[w.account_id] = w; });

    const authClients        = {};
    const accessibleIdsCache = {};

    for (const cleanId of cleanIds) {
      const acc = whitelistMap[cleanId];
      if (!acc) {
        let found = false;
        for (const login of logins) {
          try {
            if (!authClients[login.email]) {
              authClients[login.email]        = await getAuthClient(login);
              accessibleIdsCache[login.email] = await listAccessibleCustomers(authClients[login.email]);
            }
            const authClient = authClients[login.email];
            if (!authClient) continue;
            const accessibleIds = accessibleIdsCache[login.email] || [];
            const metrics = await getAccountMetrics(authClient, cleanId, '', dateClause, accessibleIds);
            if (!metrics.hasError) {
              results.push({
                accountId:   formatId(cleanId),
                accountName: metrics.descriptiveName || formatId(cleanId),
                mccId: '', loginEmail: login.email, currency: metrics.currency || '',
                impressions: metrics.impressions, clicks: metrics.clicks,
                ctr: metrics.ctr, avgCpc: metrics.avgCpc, cost: metrics.cost,
                conversions: metrics.conversions, costPerConv: metrics.costPerConv,
                convRate: metrics.convRate, hasError: false
              });
              found = true;
              break;
            }
          } catch(e) { /* try next login */ }
        }
        if (!found) {
          results.push({
            accountId: formatId(cleanId), accountName: formatId(cleanId),
            mccId: '', loginEmail: '', currency: '',
            impressions:0, clicks:0, ctr:0, avgCpc:0,
            cost:0, conversions:0, costPerConv:0, convRate:0,
            hasError:true, errorMsg:'Account not accessible by any connected login'
          });
        }
        continue;
      }

      if (!authClients[acc.login_email]) {
        const login = logins.find(l => l.email === acc.login_email);
        if (login) {
          try {
            authClients[acc.login_email]        = await getAuthClient(login);
            accessibleIdsCache[acc.login_email] = await listAccessibleCustomers(authClients[acc.login_email]);
          } catch(e) { authClients[acc.login_email] = null; }
        }
      }
      const authClient = authClients[acc.login_email];

      if (!authClient) {
        results.push({
          accountId: formatId(acc.account_id), accountName: acc.account_name,
          mccId: formatId(acc.mcc_id), loginEmail: acc.login_email, currency: acc.currency || '',
          impressions:0, clicks:0, ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0,
          hasError:true, errorMsg:'Authentication failed'
        });
        continue;
      }

      try {
        const accessibleIds = accessibleIdsCache[acc.login_email] || [];
        const metrics = await getAccountMetrics(authClient, acc.account_id, acc.mcc_id, dateClause, accessibleIds);
        results.push({
          accountId:   formatId(acc.account_id),
          accountName: metrics.descriptiveName || acc.account_name || formatId(acc.account_id),
          mccId:       formatId(acc.mcc_id),
          loginEmail:  acc.login_email,
          currency:    metrics.currency || acc.currency || '',
          impressions: metrics.impressions,
          clicks:      metrics.clicks,
          ctr:         metrics.ctr,
          avgCpc:      metrics.avgCpc,
          cost:        metrics.cost,
          conversions: metrics.conversions,
          costPerConv: metrics.costPerConv,
          convRate:    metrics.convRate,
          hasError:    metrics.hasError || false
        });
      } catch(e) {
        console.error('Metrics error for', acc.account_id, e.message);
        results.push({
          accountId:   formatId(acc.account_id),
          accountName: acc.account_name,
          mccId:       formatId(acc.mcc_id),
          loginEmail:  acc.login_email,
          currency:    acc.currency || '',
          impressions:0, clicks:0, ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0,
          hasError:true, errorMsg:e.message
        });
      }
    }

    results.sort((a, b) => (b.cost || 0) - (a.cost || 0));
    res.json({ accounts: results, generatedAt: new Date().toISOString() });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

function buildDateClause(dateRange) {
  if (!dateRange || dateRange === 'TODAY')   return 'DURING TODAY';
  if (dateRange === 'YESTERDAY')             return 'DURING YESTERDAY';
  if (dateRange === 'LAST_7_DAYS')           return 'DURING LAST_7_DAYS';
  if (dateRange === 'LAST_30_DAYS')          return 'DURING LAST_30_DAYS';
  if (dateRange === 'THIS_MONTH')            return 'DURING THIS_MONTH';
  if (dateRange === 'LAST_MONTH')            return 'DURING LAST_MONTH';
  if (dateRange && dateRange.from && dateRange.to)
    return `BETWEEN '${dateRange.from}' AND '${dateRange.to}'`;
  return 'DURING LAST_30_DAYS';
}

async function getAccountMetrics(authClient, accountId, mccId, dateClause, accessibleIds = []) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;

  const cleanAccountId = String(accountId).replace(/-/g, '');
  const cleanMccId     = String(mccId).replace(/-/g, '');

  const query = `
    SELECT
      customer.descriptive_name,
      customer.currency_code,
      metrics.impressions,
      metrics.clicks,
      metrics.ctr,
      metrics.average_cpc,
      metrics.cost_micros,
      metrics.conversions,
      metrics.cost_per_conversion,
      metrics.conversions_from_interactions_rate
    FROM customer
    WHERE segments.date ${dateClause}
  `;

  async function tryFetch(loginId) {
    const headers = {
      'Authorization':    'Bearer ' + token,
      'developer-token':  devToken,
      'login-customer-id': loginId,
      'Content-Type':     'application/json'
    };
    const r = await fetch(`${ADS_BASE}/customers/${cleanAccountId}/googleAds:search`, {
      method: 'POST', headers, body: JSON.stringify({ query })
    });
    const d = await r.json();
    return { ok: r.ok, data: d };
  }

  let result = null;

  if (cleanMccId && cleanMccId !== cleanAccountId) {
    const { ok, data } = await tryFetch(cleanMccId);
    if (ok) result = data;
    else console.error(`Metrics error for ${cleanAccountId} (login: ${cleanMccId}):`,
      JSON.stringify(data).substring(0, 200));
  }

  if (!result) {
    for (const loginId of accessibleIds) {
      if (loginId === cleanMccId || loginId === cleanAccountId) continue;
      const { ok, data } = await tryFetch(loginId);
      if (ok) { result = data; break; }
    }
  }

  if (!result) {
    const { ok, data } = await tryFetch(cleanAccountId);
    if (ok) result = data;
    else {
      const errMsg = data?.error?.message || JSON.stringify(data).substring(0, 100);
      return {
        currency:'', descriptiveName:'', impressions:0, clicks:0,
        ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0,
        hasError:true, errorMsg:errMsg
      };
    }
  }

  if (!result.results || !result.results.length) {
    return {
      currency:'', descriptiveName:'', impressions:0, clicks:0,
      ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0,
      hasError:false
    };
  }

  let impressions = 0, clicks = 0, costMicros = 0, conversions = 0;
  let currency = '', descriptiveName = '';
  result.results.forEach(r => {
    impressions    += parseInt(r.metrics?.impressions || 0);
    clicks         += parseInt(r.metrics?.clicks || 0);
    costMicros     += parseInt(r.metrics?.costMicros || 0);
    conversions    += parseFloat(r.metrics?.conversions || 0);
    if (!currency)        currency        = r.customer?.currencyCode    || '';
    if (!descriptiveName) descriptiveName = r.customer?.descriptiveName || '';
  });

  const cost        = Math.round((costMicros / 1e6) * 100) / 100;
  const ctr         = impressions > 0 ? (clicks / impressions) * 100 : 0;
  const avgCpc      = clicks > 0 ? (costMicros / 1e6) / clicks : 0;
  const costPerConv = conversions > 0 ? cost / conversions : 0;
  const convRate    = clicks > 0 ? (conversions / clicks) * 100 : 0;

  return {
    currency,
    descriptiveName,
    impressions,
    clicks,
    ctr:         Math.round(ctr * 100) / 100,
    avgCpc:      Math.round(avgCpc * 100) / 100,
    cost,
    conversions: Math.round(conversions * 100) / 100,
    costPerConv: Math.round(costPerConv * 100) / 100,
    convRate:    Math.round(convRate * 100) / 100
  };
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Ads Monitor running on port ${PORT}`);
  bootstrapAdmin();
});
