// ============================================================
// ADS SPEND MONITOR — Backend Server
// Express + Google OAuth2 + Google Ads API v23
// ============================================================
const WebSocket = require('ws');
global.WebSocket = WebSocket;
require('dotenv').config();
const express        = require('express');
const session        = require('express-session');
const cors           = require('cors');
const { google }     = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const path           = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Middleware ──
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(session({
  secret:            process.env.SESSION_SECRET || 'change-this-secret',
  resave:            false,
  saveUninitialized: false,
  cookie:            { secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));

// Serve frontend
app.use(express.static(path.join(__dirname)));

// ── OAuth2 Client factory ──
function makeOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ============================================================
// AUTH ROUTES
// ============================================================

// GET /auth/url?email=hint@email.com
// Returns a Google OAuth URL — opens in popup
app.get('/auth/url', (req, res) => {
  const oauth2Client = makeOAuth2Client();
  const url = oauth2Client.generateAuthUrl({
    access_type:  'offline',
    prompt:       'consent select_account',
    scope: [
      'https://www.googleapis.com/auth/adwords',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ],
    login_hint: req.query.email || ''
  });
  res.json({ url });
});

// GET /auth/callback — Google redirects here after login
app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`<script>window.opener.postMessage({type:'AUTH_ERROR',error:'${error}'},'*');window.close();</script>`);

  try {
    const oauth2Client = makeOAuth2Client();
    const { tokens }   = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get user info
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: userInfo } = await oauth2.userinfo.get();

    // Save/update login in Supabase
    const { error: dbErr } = await supabase.from('google_logins').upsert({
      email:         userInfo.email,
      name:          userInfo.name,
      picture:       userInfo.picture,
      access_token:  tokens.access_token,
      refresh_token: tokens.refresh_token,
      token_expiry:  tokens.expiry_date,
      updated_at:    new Date().toISOString()
    }, { onConflict: 'email' });

    if (dbErr) throw new Error('DB error: ' + dbErr.message);

    // Send success back to opener window
    res.send(`
      <script>
        window.opener.postMessage({
          type:  'AUTH_SUCCESS',
          email: '${userInfo.email}',
          name:  '${userInfo.name}',
          picture: '${userInfo.picture}'
        }, '*');
        window.close();
      </script>
    `);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.send(`<script>window.opener.postMessage({type:'AUTH_ERROR',error:'${err.message}'},'*');window.close();</script>`);
  }
});

// ============================================================
// LOGINS API
// ============================================================

// GET /api/logins — list all connected Google accounts
app.get('/api/logins', async (req, res) => {
  const { data, error } = await supabase
    .from('google_logins')
    .select('email, name, picture, updated_at')
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ logins: data || [] });
});

// DELETE /api/logins/:email — remove a Google account
app.delete('/api/logins/:email', async (req, res) => {
  const { error } = await supabase
    .from('google_logins')
    .delete()
    .eq('email', req.params.email);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ============================================================
// ACCOUNTS API
// ============================================================

// GET /api/accounts — list all sub-accounts across all logins
app.get('/api/accounts', async (req, res) => {
  try {
    const logins = await getAllLogins();
    const results = [];

    for (const login of logins) {
      const authClient = await getAuthClient(login);
      const accounts   = await listSubAccounts(authClient, login.email);
      results.push(...accounts);
    }

    res.json({ accounts: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SPEND DATA API
// ============================================================

// GET /api/spend — get spend for whitelisted accounts
app.get('/api/spend', async (req, res) => {
  try {
    const logins     = await getAllLogins();
    const whitelist  = await getWhitelist();
    const results    = [];

    for (const login of logins) {
      const authClient  = await getAuthClient(login);
      // Only fetch accounts that belong to this login and are whitelisted
      const myAccounts  = whitelist.filter(w => w.login_email === login.email);

      for (const acc of myAccounts) {
        try {
          const spend = await getAccountSpend(authClient, acc.account_id, acc.mcc_id);
          results.push({
            accountId:      formatId(acc.account_id),
            accountName:    acc.account_name,
            currency:       spend.currency,
            dailySpend:     spend.daily,
            mtdSpend:       spend.mtd,
            dailyThreshold: acc.daily_threshold,
            mtdThreshold:   acc.mtd_threshold,
            dailyOver:      acc.daily_threshold != null ? spend.daily > acc.daily_threshold : false,
            mtdOver:        acc.mtd_threshold   != null ? spend.mtd   > acc.mtd_threshold   : false,
            loginEmail:     login.email,
            mccId:          formatId(acc.mcc_id)
          });
        } catch (e) {
          console.error('Spend error for', acc.account_id, e.message);
        }
      }
    }

    // Sort: over threshold first
    results.sort((a, b) =>
      ((b.dailyOver||b.mtdOver)?1:0) - ((a.dailyOver||a.mtdOver)?1:0));

    res.json({ accounts: results, generatedAt: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/spend/all-accounts — discover + fetch all accounts across all logins (no whitelist)
app.get('/api/spend/discover', async (req, res) => {
  try {
    const logins  = await getAllLogins();
    const results = [];

    for (const login of logins) {
      const authClient = await getAuthClient(login);
      const mccs       = await listMCCs(authClient, login.email);

      for (const mcc of mccs) {
        const accounts = await listSubAccounts(authClient, login.email, mcc.id);
        for (const acc of accounts) {
          results.push({ ...acc, loginEmail: login.email, mccId: mcc.id, mccName: mcc.name });
        }
      }
    }

    res.json({ accounts: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/whitelist — save account selection
app.post('/api/whitelist', async (req, res) => {
  const { accounts } = req.body; // [{accountId, accountName, mccId, loginEmail, dailyThreshold, mtdThreshold}]
  if (!Array.isArray(accounts)) return res.status(400).json({ error: 'accounts must be array' });

  // Delete existing and re-insert
  await supabase.from('whitelist').delete().neq('id', 0);

  if (accounts.length > 0) {
    const rows = accounts.map(a => ({
      account_id:      String(a.accountId).replace(/-/g,''),
      account_name:    a.accountName,
      mcc_id:          String(a.mccId).replace(/-/g,''),
      login_email:     a.loginEmail,
      daily_threshold: a.dailyThreshold || null,
      mtd_threshold:   a.mtdThreshold   || null
    }));

    const { error } = await supabase.from('whitelist').insert(rows);
    if (error) return res.status(500).json({ error: error.message });
  }

  res.json({ success: true, saved: accounts.length });
});

// PATCH /api/whitelist/:accountId — update thresholds
app.patch('/api/whitelist/:accountId', async (req, res) => {
  const { dailyThreshold, mtdThreshold } = req.body;
  const accountId = req.params.accountId.replace(/-/g,'');

  const { error } = await supabase.from('whitelist')
    .update({ daily_threshold: dailyThreshold, mtd_threshold: mtdThreshold })
    .eq('account_id', accountId);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ============================================================
// GOOGLE ADS API HELPERS
// ============================================================
const ADS_API_VERSION = 'v23';
const ADS_BASE        = `https://googleads.googleapis.com/${ADS_API_VERSION}`;

async function listMCCs(authClient, loginEmail) {
  // The top-level accessible customers for this login
  const token    = await authClient.getAccessToken();
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;

  const res = await fetch(`${ADS_BASE}/customers:listAccessibleCustomers`, {
    headers: {
      'Authorization':   'Bearer ' + token.token,
      'developer-token': devToken
    }
  });

  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data));

  const resourceNames = data.resourceNames || [];
  return resourceNames.map(r => ({ id: r.replace('customers/', ''), name: '' }));
}

async function listSubAccounts(authClient, loginEmail, mccId) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;

  const query = `SELECT customer_client.id, customer_client.descriptive_name,
    customer_client.currency_code, customer_client.level
    FROM customer_client
    WHERE customer_client.level = 1 AND customer_client.status = 'ENABLED'`;

  const res = await fetch(`${ADS_BASE}/customers/${mccId}/googleAds:search`, {
    method:  'POST',
    headers: {
      'Authorization':      'Bearer ' + token,
      'developer-token':    devToken,
      'login-customer-id':  mccId,
      'Content-Type':       'application/json'
    },
    body: JSON.stringify({ query })
  });

  const data = await res.json();
  if (!res.ok) return [];

  return (data.results || []).map(r => ({
    accountId:   String(r.customerClient.id),
    accountName: r.customerClient.descriptiveName || 'Account ' + r.customerClient.id,
    currency:    r.customerClient.currencyCode || '',
    loginEmail,
    mccId
  }));
}

async function getAccountSpend(authClient, accountId, mccId) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;

  const headers = {
    'Authorization':      'Bearer ' + token,
    'developer-token':    devToken,
    'login-customer-id':  mccId,
    'Content-Type':       'application/json'
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

  const currency = dData.results?.[0]?.customer?.currencyCode || '';

  return {
    daily:    sumMicros(dData),
    mtd:      sumMicros(mData),
    currency
  };
}

function sumMicros(data) {
  if (!data.results) return 0;
  const total = data.results.reduce((s, r) => s + parseInt(r.metrics?.costMicros || 0, 10), 0);
  return Math.round((total / 1e6) * 100) / 100;
}

// ============================================================
// DATABASE HELPERS
// ============================================================
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
  oauth2Client.setCredentials({
    access_token:  login.access_token,
    refresh_token: login.refresh_token,
    expiry_date:   login.token_expiry
  });

  // Auto-refresh if expired
  if (login.token_expiry && Date.now() > login.token_expiry - 60000) {
    const { credentials } = await oauth2Client.refreshAccessToken();
    // Save refreshed token
    await supabase.from('google_logins').update({
      access_token: credentials.access_token,
      token_expiry: credentials.expiry_date,
      updated_at:   new Date().toISOString()
    }).eq('email', login.email);
    oauth2Client.setCredentials(credentials);
  }

  return oauth2Client;
}

// ── Helper ──
function formatId(id) {
  const s = String(id).replace(/-/g, '');
  return s.length === 10 ? `${s.slice(0,3)}-${s.slice(3,6)}-${s.slice(6)}` : s;
}

// ── Start ──
app.listen(PORT, () => console.log(`✅ Ads Monitor running on port ${PORT}`));
