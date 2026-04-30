// Railway injects env vars automatically
const express      = require('express');
const path         = require('path');
const { Pool }     = require('pg');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const compression  = require('compression');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET  = process.env.JWT_SECRET || 'tc-dev-secret-change-in-prod';
const IS_PROD     = process.env.NODE_ENV === 'production';
const COOKIE_NAME = 'tc_session';
const COOKIE_OPTS = {
  httpOnly: true,
  secure:   IS_PROD,
  sameSite: 'lax',
  maxAge:   12 * 3600000,
  path:     '/',
};

const app = express();
app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// ── DB INIT ──────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS employees    (id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS locations    (id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS departments  (id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS time_records (id TEXT PRIMARY KEY, emp_id TEXT, record_date DATE, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS payroll_cuts (id TEXT PRIMARY KEY, status TEXT DEFAULT 'pendiente', data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS system_users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS tax_ytd      (emp_id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS company_cfg  (id TEXT PRIMARY KEY DEFAULT 'main', data JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMPTZ DEFAULT NOW());
    CREATE INDEX IF NOT EXISTS idx_tr_emp  ON time_records(emp_id);
    CREATE INDEX IF NOT EXISTS idx_tr_date ON time_records(record_date);
    CREATE INDEX IF NOT EXISTS idx_emp_pin ON employees((data->>'pin')) WHERE data->>'status' = 'active';
  `);
  console.log('✅ DB ready');
}

// ── JWT HELPERS ───────────────────────────────────────────────────────
function sign(payload, hours = 12) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: hours + 'h' });
}
function readSession(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (cookie) try { return jwt.verify(cookie, JWT_SECRET); } catch {}
  const hdr = req.headers.authorization;
  if (hdr?.startsWith('Bearer ')) try { return jwt.verify(hdr.slice(7), JWT_SECRET); } catch {}
  return null;
}
function requireAuth(req, res, next) {
  req.session = readSession(req);
  if (!req.session) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── AUTH: ADMIN LOGIN ─────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  console.log('[login] attempt:', username);
  try {
    const r = await pool.query(
      "SELECT id, data FROM system_users WHERE username = $1",
      [username.toLowerCase().trim()]
    );
    if (!r.rows.length) {
      console.log('[login] user not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const { id, data } = r.rows[0];
    console.log('[login] found user:', data.username, 'status:', data.status, 'hasHash:', !!data.passwordHash);
    if (data.status === 'inactive') return res.status(401).json({ error: 'Account inactive' });
    // Try plain text first, then bcrypt hash
    let valid = false;
    if (data.password && data.password === password) {
      valid = true;
      console.log('[login] plain text match');
    } else if (data.passwordHash) {
      valid = await bcrypt.compare(password, data.passwordHash);
      console.log('[login] bcrypt result:', valid);
    }
    if (!valid) {
      console.log('[login] invalid password for:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = { id, username: data.username, name: data.name, role: data.role, type: 'admin' };
    res.cookie(COOKIE_NAME, sign(user), COOKIE_OPTS);
    console.log('[login] success:', data.name);
    res.json({ ok: true, user });
  } catch (e) { console.error('[login]', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── AUTH: EMPLOYEE PIN LOGIN ──────────────────────────────────────────
app.post('/api/auth/pin', async (req, res) => {
  const { pin } = req.body || {};
  if (!pin) return res.status(400).json({ error: 'Missing PIN' });
  const pinStr = String(pin).trim();
  try {
    // Search by PIN in active employees
    const r = await pool.query(
      "SELECT id, data FROM employees WHERE data->>'pin' = $1 AND data->>'status' = 'active'",
      [pinStr]
    );
    if (!r.rows.length) {
      console.log('[pin] Not found for PIN:', pinStr);
      return res.status(401).json({ error: 'PIN incorrecto' });
    }
    const { id, data } = r.rows[0];
    const employee = { id, ...data };
    const payload  = { id, name: data.name, type: 'employee', isEmployee: true };
    res.cookie(COOKIE_NAME, sign(payload, 12), COOKIE_OPTS);
    console.log('[pin] Login OK:', data.name);
    res.json({ ok: true, employee });
  } catch (e) { console.error('[pin]', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── AUTH: LOGOUT ──────────────────────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

// ── AUTH: WHOAMI ──────────────────────────────────────────────────────
app.get('/api/auth/me', (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user: session });
});

// ── EMPLOYEES: ACTIVE LIST (public — no auth needed for PIN screen) ───
app.get('/api/employees/active', async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, data->>'name' as name, data->>'avatar' as avatar, data->>'dept' as dept " +
      "FROM employees WHERE data->>'status' = 'active' ORDER BY data->>'name'"
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── FULL DB (auth required) ───────────────────────────────────────────
app.get('/api/db', requireAuth, async (req, res) => {
  try {
    const isEmployee = req.session.type === 'employee' || req.session.isEmployee;
    const empId = req.session.id;

    const [emps, locs, depts, trs, cuts, users, ytd, co] = await Promise.all([
      pool.query("SELECT id, data FROM employees ORDER BY data->>'name'"),
      pool.query("SELECT id, data FROM locations ORDER BY data->>'name'"),
      pool.query("SELECT id, data FROM departments ORDER BY data->>'name'"),
      // Employees only see their own time records
      isEmployee
        ? pool.query("SELECT id, data FROM time_records WHERE emp_id=$1 ORDER BY record_date DESC, updated_at DESC", [empId])
        : pool.query("SELECT id, data FROM time_records ORDER BY record_date DESC, updated_at DESC"),
      isEmployee
        ? pool.query("SELECT id, data FROM payroll_cuts WHERE data @> $1 ORDER BY updated_at DESC", [JSON.stringify({ empSnapshot: [{ id: empId }] })])
        : pool.query("SELECT id, data FROM payroll_cuts ORDER BY updated_at DESC"),
      isEmployee
        ? pool.query("SELECT id, data FROM system_users WHERE id='none'") // empty
        : pool.query("SELECT id, data FROM system_users ORDER BY data->>'name'"),
      pool.query("SELECT emp_id, data FROM tax_ytd"),
      pool.query("SELECT data FROM company_cfg WHERE id = 'main'"),
    ]);
    const ytdMap = {};
    ytd.rows.forEach(r => { ytdMap[r.emp_id] = r.data; });
    res.json({
      employees:   emps.rows.map(r => ({ id: r.id, ...r.data })),
      locations:   locs.rows.map(r => ({ id: r.id, ...r.data })),
      departments: depts.rows.map(r => ({ id: r.id, ...r.data })),
      timeRecords: trs.rows.map(r => ({ id: r.id, ...r.data })),
      payrollCuts: cuts.rows.map(r => ({ id: r.id, ...r.data })),
      systemUsers: users.rows.map(r => ({ id: r.id, ...r.data })),
      taxYtd: ytdMap,
      company: co.rows[0]?.data || {},
    });
  } catch (e) { console.error('[db]', e.message); res.status(500).json({ error: e.message }); }
});

// ── CRUD HELPERS ──────────────────────────────────────────────────────
app.put('/api/employees/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const data = { ...req.body }; delete data.id;
  await pool.query(
    'INSERT INTO employees(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2,updated_at=NOW()',
    [id, JSON.stringify(data)]
  );
  res.json({ id, ...data });
});
app.delete('/api/employees/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM employees WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.put('/api/locations/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  await pool.query('INSERT INTO locations(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2,updated_at=NOW()', [id, JSON.stringify(data)]);
  res.json({ id, ...data });
});
app.delete('/api/locations/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM locations WHERE id=$1', [req.params.id]); res.json({ ok: true });
});

app.put('/api/departments/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  await pool.query('INSERT INTO departments(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2,updated_at=NOW()', [id, JSON.stringify(data)]);
  res.json({ id, ...data });
});
app.delete('/api/departments/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM departments WHERE id=$1', [req.params.id]); res.json({ ok: true });
});

app.put('/api/time-records/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  await pool.query(
    'INSERT INTO time_records(id,emp_id,record_date,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=$4,emp_id=$2,record_date=$3,updated_at=NOW()',
    [id, data.empId || '', data.date || new Date().toISOString().slice(0,10), JSON.stringify(data)]
  );
  res.json({ id, ...data });
});
app.delete('/api/time-records/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM time_records WHERE id=$1', [req.params.id]); res.json({ ok: true });
});

app.put('/api/payroll-cuts/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  await pool.query(
    'INSERT INTO payroll_cuts(id,status,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=$3,status=$2,updated_at=NOW()',
    [id, data.status || 'pendiente', JSON.stringify(data)]
  );
  res.json({ id, ...data });
});

app.put('/api/system-users/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  if (data.password && !data.passwordHash) {
    data.passwordHash = await bcrypt.hash(data.password, 10);
    delete data.password;
  }
  await pool.query(
    'INSERT INTO system_users(id,username,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=$3,username=$2,updated_at=NOW()',
    [id, data.username, JSON.stringify(data)]
  );
  res.json({ id, ...data });
});

app.put('/api/tax-ytd', requireAuth, async (req, res) => {
  for (const [empId, data] of Object.entries(req.body)) {
    await pool.query(
      'INSERT INTO tax_ytd(emp_id,data) VALUES($1,$2) ON CONFLICT(emp_id) DO UPDATE SET data=$2,updated_at=NOW()',
      [empId, JSON.stringify(data)]
    );
  }
  res.json({ ok: true });
});

app.put('/api/company', requireAuth, async (req, res) => {
  await pool.query(
    "INSERT INTO company_cfg(id,data) VALUES('main',$1) ON CONFLICT(id) DO UPDATE SET data=$1,updated_at=NOW()",
    [JSON.stringify(req.body)]
  );
  res.json({ ok: true });
});

// ── DEBUG: check users (only in dev) ─────────────────────────────────
app.get('/api/debug/users', async (req, res) => {
  if (IS_PROD) return res.status(404).end();
  const r = await pool.query("SELECT id, data->>'username' as u, data->>'password' as p, data->>'passwordHash' as h, data->>'status' as s FROM system_users");
  res.json(r.rows);
});

// ── EMERGENCY: reset admin password (remove after use!) ───────────────
app.post('/api/debug/reset-admin', async (req, res) => {
  if (IS_PROD) return res.status(404).end();
  const hash = await bcrypt.hash('admin2025', 10);
  await pool.query("UPDATE system_users SET data = data || $1 WHERE data->>'username' = 'admin'",
    [JSON.stringify({ passwordHash: hash, password: 'admin2025', status: 'active' })]);
  res.json({ ok: true, msg: 'admin password reset to admin2025' });
});

// ── HEALTH ────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, ts: new Date().toISOString() });
  } catch { res.status(503).json({ ok: false }); }
});

// ── SPA FALLBACK ──────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── START ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 TimeClock on :${PORT} (${IS_PROD ? 'prod' : 'dev'})`)))
  .catch(e => { console.error('Startup failed:', e); process.exit(1); });
