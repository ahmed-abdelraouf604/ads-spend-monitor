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
// PASSWORD GATE  +  DEVICE / SESSION MANAGER
//
// Each login creates a row in the "sessions" Supabase table
// keyed by the express session ID.  requireAuth checks the DB
// (cached 60 s in memory) so revocation takes effect quickly
// and server restarts don't log anyone out.
// ============================================================
const REMEMBER_COOKIE  = 'ads_auth';
const REMEMBER_MAX_AGE = 365 * 24 * 60 * 60 * 1000; // 1 year

function makeAuthToken() {
  const secret = process.env.SESSION_SECRET || 'change-this-secret';
  const pw     = process.env.APP_PASSWORD   || '';
  return crypto.createHmac('sha256', secret).update(pw).digest('hex');
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const [k, ...rest] = part.trim().split('=');
    if (k) out[k.trim()] = decodeURIComponent(rest.join('=').trim());
  });
  return out;
}

function isRemembered(req) {
  const cookies = parseCookies(req);
  const token   = cookies[REMEMBER_COOKIE];
  if (!token) return false;
  const expected = makeAuthToken();
  if (token.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress || req.ip || '';
}

// In-memory caches — avoids a DB hit on every request
const authCache     = {}; // sessionId → { valid: bool, ts: number }
const lastSeenCache = {}; // sessionId → timestamp of last DB write
const AUTH_CACHE_TTL  = 60_000;      // re-check DB every 60 s
const LAST_SEEN_TTL   = 5 * 60_000; // write last_seen_at every 5 min

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

async function upsertDbSession(req) {
  const now = new Date().toISOString();
  const { error } = await supabase.from('sessions').upsert({
    session_id:   req.sessionID,
    ip_address:   getClientIp(req),
    user_agent:   req.headers['user-agent'] || '',
    created_at:   now,
    last_seen_at: now
  }, { onConflict: 'session_id' });
  if (!error) authCache[req.sessionID] = { valid: true, ts: Date.now() };
}

async function requireAuth(req, res, next) {
  try {
    if (await isSessionValid(req.sessionID)) return next();
    // Fallback: in-memory session or HMAC cookie (pre-device-manager logins)
    if (req.session.authenticated || isRemembered(req)) {
      req.session.authenticated = true;
      upsertDbSession(req).catch(() => {}); // register/migrate — fire & forget
      return next();
    }
  } catch(e) { console.error('requireAuth:', e.message); }
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(403).json({ error: 'Admin access required' });
}

app.post('/auth/password', async (req, res) => {
  const { password } = req.body;
  const appPw   = process.env.APP_PASSWORD;
  const adminPw = process.env.ADMIN_PASSWORD;
  if (!appPw) return res.status(500).json({ error: 'APP_PASSWORD not set on server' });

  const isAdmin = adminPw && password === adminPw;
  const isUser  = password === appPw;
  if (!isAdmin && !isUser) return res.status(401).json({ error: 'Incorrect password' });

  req.session.authenticated = true;
  req.session.isAdmin       = isAdmin;
  await upsertDbSession(req);
  res.cookie(REMEMBER_COOKIE, makeAuthToken(), { httpOnly: true, maxAge: REMEMBER_MAX_AGE, sameSite: 'lax' });
  res.json({ success: true, isAdmin });
});

app.post('/auth/logout', async (req, res) => {
  if (req.sessionID) {
    await supabase.from('sessions').delete().eq('session_id', req.sessionID);
    delete authCache[req.sessionID];
    delete lastSeenCache[req.sessionID];
  }
  res.clearCookie(REMEMBER_COOKIE);
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/auth/check', async (req, res) => {
  try {
    if (await isSessionValid(req.sessionID)) return res.json({ authenticated: true });
    if (req.session.authenticated || isRemembered(req)) {
      req.session.authenticated = true;
      await upsertDbSession(req); // await so next API call finds the row
      return res.json({ authenticated: true });
    }
  } catch(e) {}
  res.json({ authenticated: false });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ isAdmin: !!req.session.isAdmin });
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
// expected = (currentDay / 30.4) * monthlyBudget
// variance = (actualMtd / expected - 1) * 100
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

// Protect all /api/* routes
app.use('/api', requireAuth);

// Update last_seen_at on every authenticated API request (throttled to once per 5 min)
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
// DEVICE MANAGER  — session CRUD
// ─────────────────────────────────────────────
app.get('/api/sessions', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('sessions').select('*')
    .order('last_seen_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const current = req.sessionID;
  res.json({
    sessions: (data || []).map(s => ({
      id:         s.id,
      isCurrent:  s.session_id === current,
      ipAddress:  s.ip_address,
      userAgent:  s.user_agent,
      createdAt:  s.created_at,
      lastSeenAt: s.last_seen_at
    }))
  });
});

app.delete('/api/sessions', requireAdmin, async (req, res) => {
  const current = req.sessionID;
  if (!current) return res.status(400).json({ error: 'Cannot identify current session' });
  const { error } = await supabase.from('sessions').delete().neq('session_id', current);
  if (error) return res.status(500).json({ error: error.message });
  Object.keys(authCache).forEach(k => { if (k !== current) { delete authCache[k]; delete lastSeenCache[k]; } });
  res.json({ success: true });
});

app.delete('/api/sessions/:id', requireAdmin, async (req, res) => {
  const { data: sess } = await supabase.from('sessions').select('session_id')
    .eq('id', req.params.id).maybeSingle();
  const { error } = await supabase.from('sessions').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  if (sess?.session_id) { delete authCache[sess.session_id]; delete lastSeenCache[sess.session_id]; }
  res.json({ success: true });
});

// AUTH
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
  const { data, error } = await supabase.from('google_logins').select('email,name,picture,updated_at').order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ logins: data || [] });
});

app.delete('/api/logins/:email', async (req, res) => {
  const { error } = await supabase.from('google_logins').delete().eq('email', decodeURIComponent(req.params.email));
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ACCOUNTS DISCOVERY
app.get('/api/accounts', async (req, res) => {
  try {
    const logins = await getAllLogins();
    const results = [];
    for (const login of logins) {
      try {
        const authClient = await getAuthClient(login);
        const mccs = await listAccessibleCustomers(authClient);
        for (const mccId of mccs) {
          const mccName = await getMccName(authClient, mccId);
          const accounts = await listSubAccounts(authClient, mccId);
          results.push(...accounts.map(a => ({ ...a, loginEmail: login.email, mccId, mccName })));
        }
      } catch(e) { console.error('Account error for', login.email, e.message); }
    }
    res.json({ accounts: results });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// SPEND + PACING
app.get('/api/spend', async (req, res) => {
  try {
    const logins    = await getAllLogins();
    const whitelist = await getWhitelist();
    const results   = [];
    for (const login of logins) {
      const myAccounts = whitelist.filter(w => w.login_email === login.email);
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

// WHITELIST — GET current list
app.get('/api/whitelist', async (req, res) => {
  const { data, error } = await supabase.from('whitelist').select('*');
  if (error) return res.status(500).json({ error: error.message });
  const accounts = (data || []).map(r => ({
    accountId:     r.account_id,
    accountName:   r.account_name,
    mccId:         r.mcc_id,
    loginEmail:    r.login_email,
    monthlyBudget: r.monthly_budget,
    rangePercent:  r.range_percent
  }));
  res.json({ accounts });
});

// WHITELIST — upsert only, never deletes existing accounts or their budgets
app.post('/api/whitelist', async (req, res) => {
  const { accounts, removed } = req.body;
  if (!Array.isArray(accounts)) return res.status(400).json({ error: 'accounts must be array' });

  // 1. Delete explicitly removed accounts
  if (Array.isArray(removed) && removed.length > 0) {
    const ids = removed.map(id => String(id).replace(/-/g,''));
    await supabase.from('whitelist').delete().in('account_id', ids);
  }

  // 2. Fetch existing budgets so we preserve them
  const { data: existing } = await supabase.from('whitelist').select('account_id,monthly_budget,range_percent');
  const existingMap = {};
  (existing || []).forEach(r => { existingMap[r.account_id] = r; });

  // 3. Upsert new/updated accounts — preserve existing budget if not provided
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

// DELETE single account from whitelist
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

// GOOGLE ADS API
const ADS_VERSION = 'v23';
const ADS_BASE    = `https://googleads.googleapis.com/${ADS_VERSION}`;

async function listAccessibleCustomers(authClient) {
  const token = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
  const res = await fetch(`${ADS_BASE}/customers:listAccessibleCustomers`, {
    headers: { 'Authorization': 'Bearer ' + token, 'developer-token': devToken }
  });
  const data = await res.json();
  if (!res.ok) { console.error('listAccessibleCustomers:', JSON.stringify(data)); return []; }
  return (data.resourceNames || []).map(r => r.replace('customers/', ''));
}

async function getMccName(authClient, mccId) {
  try {
    const token    = (await authClient.getAccessToken()).token;
    const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
    const res = await fetch(`${ADS_BASE}/customers/${mccId}/googleAds:search`, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'developer-token': devToken, 'login-customer-id': mccId, 'Content-Type': 'application/json' },
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
  const res  = await fetch(`${ADS_BASE}/customers/${mccId}/googleAds:search`, {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token, 'developer-token': devToken, 'login-customer-id': mccId, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query })
  });
  const data = await res.json();
  if (!res.ok) return [];
  return (data.results || []).map(r => ({
    accountId:   String(r.customerClient.id),
    accountName: r.customerClient.descriptiveName || 'Account ' + r.customerClient.id,
    currency:    r.customerClient.currencyCode || ''
  }));
}

async function getAccountSpend(authClient, accountId, mccId) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
  const headers  = { 'Authorization': 'Bearer ' + token, 'developer-token': devToken, 'login-customer-id': mccId, 'Content-Type': 'application/json' };
  const [dRes, mRes] = await Promise.all([
    fetch(`${ADS_BASE}/customers/${accountId}/googleAds:search`, { method: 'POST', headers, body: JSON.stringify({ query: 'SELECT metrics.cost_micros, customer.currency_code FROM customer WHERE segments.date DURING TODAY' }) }),
    fetch(`${ADS_BASE}/customers/${accountId}/googleAds:search`, { method: 'POST', headers, body: JSON.stringify({ query: 'SELECT metrics.cost_micros FROM customer WHERE segments.date DURING THIS_MONTH' }) })
  ]);
  const dData = await dRes.json();
  const mData = await mRes.json();
  return { daily: sumMicros(dData), mtd: sumMicros(mData), currency: dData.results?.[0]?.customer?.currencyCode || '' };
}

function sumMicros(data) {
  if (!data.results) return 0;
  return Math.round((data.results.reduce((s, r) => s + parseInt(r.metrics?.costMicros || 0, 10), 0) / 1e6) * 100) / 100;
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

async function getAuthClient(login) {
  const oauth2Client = makeOAuth2Client();
  oauth2Client.setCredentials({ access_token: login.access_token, refresh_token: login.refresh_token, expiry_date: login.token_expiry });
  if (login.token_expiry && Date.now() > login.token_expiry - 60000) {
    const { credentials } = await oauth2Client.refreshAccessToken();
    await supabase.from('google_logins').update({ access_token: credentials.access_token, token_expiry: credentials.expiry_date, updated_at: new Date().toISOString() }).eq('email', login.email);
    oauth2Client.setCredentials(credentials);
  }
  return oauth2Client;
}

function formatId(id) {
  const s = String(id).replace(/-/g, '');
  return s.length === 10 ? `${s.slice(0,3)}-${s.slice(3,6)}-${s.slice(6)}` : s;
}

// ============================================================
// PERFORMANCE METRICS API
// POST /api/performance
// Body: { accountIds: ['123','456'], dateRange: 'LAST_7_DAYS'|'LAST_30_DAYS'|'THIS_MONTH'|'LAST_MONTH'|'TODAY'|'YESTERDAY'|{from:'2024-01-01',to:'2024-01-31'} }
// ============================================================
app.post('/api/performance', async (req, res) => {
  try {
    const { accountIds, dateRange } = req.body;
    if (!Array.isArray(accountIds) || accountIds.length === 0)
      return res.status(400).json({ error: 'accountIds required' });

    // Normalize all accountIds to no-dashes format
    const cleanIds = accountIds.map(id => String(id).replace(/-/g, ''));

    const logins    = await getAllLogins();
    const whitelist = await getWhitelist();
    const results   = [];

    // Build GAQL date condition
    const dateClause = buildDateClause(dateRange);

    // Build a map of accountId → whitelist entry for fast lookup
    const whitelistMap = {};
    whitelist.forEach(w => { whitelistMap[w.account_id] = w; });

    // Also build maps of loginEmail → authClient and → accessible customer IDs (lazy)
    const authClients        = {};
    const accessibleIdsCache = {};

    for (const cleanId of cleanIds) {
      const acc = whitelistMap[cleanId];
      if (!acc) {
        // Account not in whitelist — try all available logins to fetch metrics
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

      // Get or create authClient + accessible customers for this login
      if (!authClients[acc.login_email]) {
        const login = logins.find(l => l.email === acc.login_email);
        if (login) {
          try {
            authClients[acc.login_email]        = await getAuthClient(login);
            accessibleIdsCache[acc.login_email] = await listAccessibleCustomers(authClients[acc.login_email]);
          }
          catch(e) { authClients[acc.login_email] = null; }
        }
      }
      const authClient = authClients[acc.login_email];

      if (!authClient) {
        // Could not authenticate for this login
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

    // Sort by cost descending
    results.sort((a, b) => (b.cost || 0) - (a.cost || 0));
    res.json({ accounts: results, generatedAt: new Date().toISOString() });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

function buildDateClause(dateRange) {
  if (!dateRange || dateRange === 'TODAY')       return 'DURING TODAY';
  if (dateRange === 'YESTERDAY')                 return 'DURING YESTERDAY';
  if (dateRange === 'LAST_7_DAYS')               return 'DURING LAST_7_DAYS';
  if (dateRange === 'LAST_30_DAYS')              return 'DURING LAST_30_DAYS';
  if (dateRange === 'THIS_MONTH')                return 'DURING THIS_MONTH';
  if (dateRange === 'LAST_MONTH')                return 'DURING LAST_MONTH';
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
      'Authorization': 'Bearer ' + token,
      'developer-token': devToken,
      'login-customer-id': loginId,
      'Content-Type': 'application/json'
    };
    const r = await fetch(`${ADS_BASE}/customers/${cleanAccountId}/googleAds:search`, {
      method: 'POST', headers, body: JSON.stringify({ query })
    });
    const d = await r.json();
    return { ok: r.ok, data: d };
  }

  let result = null;

  // 1. Try the stored MCC first
  if (cleanMccId && cleanMccId !== cleanAccountId) {
    const { ok, data } = await tryFetch(cleanMccId);
    if (ok) result = data;
    else console.error(`Metrics error for ${cleanAccountId} (login: ${cleanMccId}):`, JSON.stringify(data).substring(0, 200));
  }

  // 2. Stored MCC failed — try every accessible customer ID as login-customer-id
  if (!result) {
    for (const loginId of accessibleIds) {
      if (loginId === cleanMccId || loginId === cleanAccountId) continue;
      const { ok, data } = await tryFetch(loginId);
      if (ok) { result = data; break; }
    }
  }

  // 3. Last resort: use the account itself as login-customer-id
  if (!result) {
    const { ok, data } = await tryFetch(cleanAccountId);
    if (ok) result = data;
    else {
      const errMsg = data?.error?.message || JSON.stringify(data).substring(0, 100);
      return { currency:'', descriptiveName:'', impressions:0, clicks:0, ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0, hasError:true, errorMsg:errMsg };
    }
  }

  if (!result.results || !result.results.length) {
    return { currency:'', descriptiveName:'', impressions:0, clicks:0, ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0, hasError:false };
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

app.listen(PORT, '0.0.0.0', () => console.log(`✅ Ads Monitor running on port ${PORT}`));
