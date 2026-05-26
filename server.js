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

    const logins    = await getAllLogins();
    const whitelist = await getWhitelist();
    const results   = [];

    // Build GAQL date condition
    const dateClause = buildDateClause(dateRange);

    for (const login of logins) {
      const myAccounts = whitelist.filter(w =>
        accountIds.includes(w.account_id) && w.login_email === login.email
      );
      if (!myAccounts.length) continue;

      try {
        const authClient = await getAuthClient(login);
        for (const acc of myAccounts) {
          try {
            const metrics = await getAccountMetrics(authClient, acc.account_id, acc.mcc_id, dateClause);
            results.push({
              accountId:   formatId(acc.account_id),
              accountName: acc.account_name,
              mccId:       formatId(acc.mcc_id),
              loginEmail:  login.email,
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
            // Still include the account with zeros so it shows in the table
            results.push({
              accountId:   formatId(acc.account_id),
              accountName: acc.account_name,
              mccId:       formatId(acc.mcc_id),
              loginEmail:  login.email,
              currency:    acc.currency || '',
              impressions: 0, clicks: 0, ctr: 0, avgCpc: 0,
              cost: 0, conversions: 0, costPerConv: 0, convRate: 0,
              hasError: true, errorMsg: e.message
            });
          }
        }
      } catch(e) { console.error('Auth error for', login.email, e.message); }
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

async function getAccountMetrics(authClient, accountId, mccId, dateClause) {
  const token    = (await authClient.getAccessToken()).token;
  const devToken = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
  const headers  = {
    'Authorization': 'Bearer ' + token,
    'developer-token': devToken,
    'login-customer-id': mccId,
    'Content-Type': 'application/json'
  };

  const query = `
    SELECT
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

  const res  = await fetch(`${ADS_BASE}/customers/${accountId}/googleAds:search`, {
    method: 'POST', headers, body: JSON.stringify({ query })
  });
  const data = await res.json();

  if (!res.ok) {
    console.error('Metrics API error for', accountId, JSON.stringify(data).substring(0, 200));
    return { currency:'', impressions:0, clicks:0, ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0, hasError:true };
  }
  if (!data.results || !data.results.length) {
    // Account has no data for this period — still return zeros (not an error)
    return { currency:'', impressions:0, clicks:0, ctr:0, avgCpc:0, cost:0, conversions:0, costPerConv:0, convRate:0, hasError:false };
  }

  // Aggregate across all rows (date segments)
  let impressions = 0, clicks = 0, costMicros = 0, conversions = 0;
  let currency = '';
  data.results.forEach(r => {
    impressions += parseInt(r.metrics?.impressions || 0);
    clicks      += parseInt(r.metrics?.clicks || 0);
    costMicros  += parseInt(r.metrics?.costMicros || 0);
    conversions += parseFloat(r.metrics?.conversions || 0);
    if (!currency) currency = r.customer?.currencyCode || '';
  });

  const cost      = Math.round((costMicros / 1e6) * 100) / 100;
  const ctr       = clicks > 0 && impressions > 0 ? (clicks / impressions) * 100 : 0;
  const avgCpc    = clicks > 0 ? (costMicros / 1e6) / clicks : 0;
  const costPerConv = conversions > 0 ? cost / conversions : 0;
  const convRate  = clicks > 0 ? (conversions / clicks) * 100 : 0;

  return {
    currency,
    impressions,
    clicks,
    ctr:        Math.round(ctr * 100) / 100,
    avgCpc:     Math.round(avgCpc * 100) / 100,
    cost,
    conversions: Math.round(conversions * 100) / 100,
    costPerConv: Math.round(costPerConv * 100) / 100,
    convRate:   Math.round(convRate * 100) / 100
  };
}

app.listen(PORT, '0.0.0.0', () => console.log(`✅ Ads Monitor running on port ${PORT}`));
