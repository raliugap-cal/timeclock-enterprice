require('dotenv').config();
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
app.use(express.json({ limit: '50mb' }));  // Large limit for empSnapshot with 500 employees
app.use(express.static(path.join(__dirname, '../public')));

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
    CREATE TABLE IF NOT EXISTS fiscal_periods (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        date_start DATE NOT NULL,
        date_end DATE NOT NULL,
        status TEXT DEFAULT 'abierto',
        closed_by TEXT,
        closed_at TIMESTAMPTZ,
        data JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS job_applications (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        candidate_name TEXT NOT NULL,
        candidate_email TEXT,
        status TEXT DEFAULT 'nuevo',
        cv_data TEXT,
        ai_score INTEGER,
        ai_analysis JSONB,
        interview_slot TEXT,
        data JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS interview_slots (
        id TEXT PRIMARY KEY,
        date DATE NOT NULL,
        time TEXT NOT NULL,
        duration_min INTEGER DEFAULT 60,
        status TEXT DEFAULT 'disponible',
        job_id TEXT,
        application_id TEXT,
        recruiter_note TEXT,
        data JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_slots_date ON interview_slots(date);
    CREATE INDEX IF NOT EXISTS idx_apps_job   ON job_applications(job_id);
    CREATE INDEX IF NOT EXISTS idx_tr_emp  ON time_records(emp_id);
    CREATE INDEX IF NOT EXISTS idx_tr_date ON time_records(record_date);
  `);
  console.log('✅ DB ready');
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

// ── ADMIN LOGIN ──────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  console.log('[login] attempt:', username);
  try {
    const r = await pool.query("SELECT id, data FROM system_users WHERE username = $1", [username.toLowerCase().trim()]);
    if (!r.rows.length) { console.log('[login] not found:', username); return res.status(401).json({ error: 'Invalid credentials' }); }
    const { id, data } = r.rows[0];
    if (data.status === 'inactive') return res.status(401).json({ error: 'Account inactive' });
    const valid = data.passwordHash ? await bcrypt.compare(password, data.passwordHash) : data.password === password;
    if (!valid) { console.log('[login] wrong password:', username); return res.status(401).json({ error: 'Invalid credentials' }); }
    const user = { id, username: data.username, name: data.name, role: data.role, type: 'admin' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '8h' });
    res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
    console.log('[login] OK:', data.name);
    res.json({ ok: true, user });
  } catch (e) { console.error('[login]', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── EMPLOYEE PIN LOGIN ───────────────────────────────────────────────
app.post('/api/auth/pin', async (req, res) => {
  const { pin, empId } = req.body || {};
  if (!pin) return res.status(400).json({ error: 'Missing PIN' });
  const pinStr = String(pin).trim();
  console.log('[pin] attempt - empId:', empId, 'pin:', pinStr);
  try {
    let r;
    if (empId) {
      r = await pool.query("SELECT id, data FROM employees WHERE id = $1 AND data->>'status' = 'active'", [empId]);
      if (!r.rows.length) { console.log('[pin] empId not found:', empId); return res.status(401).json({ error: 'Empleado no encontrado' }); }
      const storedPin = r.rows[0].data.pin;
      if (storedPin !== pinStr) { console.log('[pin] PIN mismatch for:', r.rows[0].data.name); return res.status(401).json({ error: 'PIN incorrecto' }); }
    } else {
      r = await pool.query("SELECT id, data FROM employees WHERE data->>'pin' = $1 AND data->>'status' = 'active' LIMIT 1", [pinStr]);
      if (!r.rows.length) return res.status(401).json({ error: 'PIN incorrecto' });
    }
    const { id, data } = r.rows[0];
    const employee = { id, ...data };
    const token = jwt.sign({ id, name: data.name, type: 'employee', isEmployee: true }, JWT_SECRET, { expiresIn: '12h' });
    res.cookie(COOKIE_NAME, token, { ...COOKIE_OPTS, maxAge: 12 * 3600000 });
    console.log('[pin] Login OK:', data.name, id);
    res.json({ ok: true, employee });
  } catch (e) { console.error('[pin]', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── LOGOUT ───────────────────────────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

// ── WHOAMI ────────────────────────────────────────────────────────────
app.get('/api/auth/me', (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user: session });
});

// ── ACTIVE EMPLOYEES (public) ─────────────────────────────────────────
app.get('/api/employees/active', async (req, res) => {
  try {
    const r = await pool.query("SELECT id, data->>'name' as name, data->>'avatar' as avatar, data->>'dept' as dept, data->>'role' as role FROM employees WHERE data->>'status' = 'active' ORDER BY data->>'name'");
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── FULL DB ───────────────────────────────────────────────────────────
app.get('/api/db', requireAuth, async (req, res) => {
  try {
    const isEmployee = req.session.type === 'employee' || req.session.isEmployee;
    const empId = req.session.id;
    const [emps, locs, depts, trs, cuts, users, ytd, co] = await Promise.all([
      pool.query("SELECT id, data FROM employees ORDER BY data->>'name'"),
      pool.query("SELECT id, data FROM locations ORDER BY data->>'name'"),
      pool.query("SELECT id, data FROM departments ORDER BY data->>'name'"),
      isEmployee
        ? pool.query("SELECT id, data FROM time_records WHERE emp_id=$1 ORDER BY record_date DESC, updated_at DESC", [empId])
        : pool.query("SELECT id, data FROM time_records ORDER BY record_date DESC, updated_at DESC"),
      isEmployee
        ? pool.query("SELECT id, data FROM payroll_cuts ORDER BY updated_at DESC LIMIT 10")
        : pool.query("SELECT id, data FROM payroll_cuts ORDER BY updated_at DESC"),
      isEmployee
        ? pool.query("SELECT id, data FROM system_users WHERE id='__none__'")
        : pool.query("SELECT id, data FROM system_users ORDER BY data->>'name'"),
      pool.query("SELECT emp_id, data FROM tax_ytd"),
      pool.query("SELECT data FROM company_cfg WHERE id='main'"),
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

// ── CRUD ──────────────────────────────────────────────────────────────
app.put('/api/employees/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  await pool.query('INSERT INTO employees(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2,updated_at=NOW()', [id, JSON.stringify(data)]);
  res.json({ id, ...data });
});
app.delete('/api/employees/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM employees WHERE id=$1', [req.params.id]); res.json({ ok: true });
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
  await pool.query('INSERT INTO time_records(id,emp_id,record_date,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=$4,emp_id=$2,record_date=$3,updated_at=NOW()',
    [id, data.empId || '', data.date || new Date().toISOString().slice(0,10), JSON.stringify(data)]);
  res.json({ id, ...data });
});
app.delete('/api/time-records/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM time_records WHERE id=$1', [req.params.id]); res.json({ ok: true });
});
app.put('/api/payroll-cuts/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const data = { ...req.body }; delete data.id;
  const snapLen = data.empSnapshot?.length || 0;
  console.log('[payroll-cut] saving:', id, 'snap:', snapLen, 'employees', 'status:', data.status);
  try {
    await pool.query('INSERT INTO payroll_cuts(id,status,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=$3,status=$2,updated_at=NOW()',
      [id, data.status || 'pendiente', JSON.stringify(data)]);
    console.log('[payroll-cut] saved OK:', id);
    res.json({ id, ...data });
  } catch(e) { console.error('[payroll-cut] ERROR:', e.message); res.status(500).json({ error: e.message }); }
});
app.put('/api/system-users/:id', requireAuth, async (req, res) => {
  const { id } = req.params; const data = { ...req.body }; delete data.id;
  if (data.password && !data.passwordHash) {
    data.passwordHash = await bcrypt.hash(data.password, 10);
    delete data.password;
  }
  await pool.query('INSERT INTO system_users(id,username,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=$3,username=$2,updated_at=NOW()',
    [id, data.username, JSON.stringify(data)]);
  res.json({ id, ...data });
});
app.put('/api/tax-ytd', requireAuth, async (req, res) => {
  for (const [empId, data] of Object.entries(req.body))
    await pool.query('INSERT INTO tax_ytd(emp_id,data) VALUES($1,$2) ON CONFLICT(emp_id) DO UPDATE SET data=$2,updated_at=NOW()', [empId, JSON.stringify(data)]);
  res.json({ ok: true });
});
app.put('/api/company', requireAuth, async (req, res) => {
  await pool.query("INSERT INTO company_cfg(id,data) VALUES('main',$1) ON CONFLICT(id) DO UPDATE SET data=$1,updated_at=NOW()", [JSON.stringify(req.body)]);
  res.json({ ok: true });
});
app.get('/api/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, ts: new Date().toISOString() }); }
  catch { res.status(503).json({ ok: false }); }
});

// ── INTERVIEW SLOTS ───────────────────────────────────────────────────
// Public: get available slots
app.get('/api/slots/available', async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM interview_slots WHERE status='disponible' AND date >= CURRENT_DATE ORDER BY date, time"
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: get all slots
app.get('/api/slots', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM interview_slots ORDER BY date, time');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/slots/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { date, time, duration_min, status, job_id, application_id, recruiter_note, data } = req.body;
  try {
    await pool.query(`INSERT INTO interview_slots(id,date,time,duration_min,status,job_id,application_id,recruiter_note,data)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT(id) DO UPDATE SET date=$2,time=$3,duration_min=$4,status=$5,job_id=$6,application_id=$7,recruiter_note=$8,data=$9,updated_at=NOW()`,
      [id, date, time, duration_min||60, status||'disponible', job_id||null, application_id||null, recruiter_note||null, JSON.stringify(data||{})]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/slots/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM interview_slots WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ── JOB APPLICATIONS ─────────────────────────────────────────────────
// Public: submit application
app.post('/api/applications', async (req, res) => {
  const { id, job_id, candidate_name, candidate_email, interview_slot, cv_data, data } = req.body;
  if (!job_id || !candidate_name) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const appId = id || ('app' + Date.now());
    await pool.query(`INSERT INTO job_applications(id,job_id,candidate_name,candidate_email,status,cv_data,interview_slot,data)
      VALUES($1,$2,$3,$4,'nuevo',$5,$6,$7)`,
      [appId, job_id, candidate_name, candidate_email||'', cv_data||null, interview_slot||null, JSON.stringify(data||{})]);
    // Block the slot
    if (interview_slot) {
      await pool.query("UPDATE interview_slots SET status='ocupado', application_id=$1 WHERE id=$2",
        [appId, interview_slot]);
    }
    console.log('[application] new:', candidate_name, 'for job:', job_id);
    res.json({ ok: true, id: appId });
  } catch(e) { console.error('[application]', e.message); res.status(500).json({ error: e.message }); }
});

// Admin: get all applications
app.get('/api/applications', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM job_applications ORDER BY created_at DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: get applications for a job
app.get('/api/applications/job/:jobId', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM job_applications WHERE job_id=$1 ORDER BY created_at DESC', [req.params.jobId]);
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: update application (status, ai_score, ai_analysis)
app.put('/api/applications/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { status, ai_score, ai_analysis, data } = req.body;
  try {
    await pool.query(`UPDATE job_applications SET status=COALESCE($2,status),
      ai_score=COALESCE($3,ai_score), ai_analysis=COALESCE($4,ai_analysis),
      data=COALESCE($5,data), updated_at=NOW() WHERE id=$1`,
      [id, status||null, ai_score||null, ai_analysis ? JSON.stringify(ai_analysis) : null,
       data ? JSON.stringify(data) : null]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: AI analysis proxy — calls Anthropic API server-side (keeps API key secure)
app.post('/api/applications/:id/analyze', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { cv_data, job_description, job_title } = req.body;
  if (!cv_data) return res.status(400).json({ error: 'CV data required' });
  try {
    const prompt = `Eres un experto en recursos humanos. Analiza el siguiente CV para el puesto de "${job_title||'No especificado'}".

DESCRIPCIÓN DEL PUESTO:
${job_description||'No especificada'}

Analiza el CV adjunto y responde ÚNICAMENTE con JSON válido (sin markdown, sin texto extra):
{
  "score": 75,
  "resumen": "Breve resumen del candidato en 2-3 oraciones",
  "escolaridad": { "nivel": "Licenciatura", "area": "Ingeniería", "score": 80, "notas": "..." },
  "experiencia": { "anios": 5, "relevancia": "alta", "score": 85, "notas": "..." },
  "habilidades": { "tecnicas": ["skill1","skill2"], "blandas": ["skill3"], "score": 70, "notas": "..." },
  "referencias": { "tiene": true, "score": 60, "notas": "..." },
  "fortalezas": ["fortaleza1","fortaleza2","fortaleza3"],
  "areas_mejora": ["area1","area2"],
  "recomendacion": "contratar|considerar|rechazar",
  "justificacion": "Razón de la recomendación en 2-3 oraciones"
}`;

    // Send CV as PDF document to Claude (base64)
    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY || '',
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        messages: [{
          role: 'user',
          content: [
            {
              type: 'document',
              source: {
                type: 'base64',
                media_type: 'application/pdf',
                data: cv_data,
              }
            },
            {
              type: 'text',
              text: prompt
            }
          ]
        }],
      }),
    });

    if (!aiRes.ok) {
      const errBody = await aiRes.text();
      console.error('[ai-analysis] Anthropic error:', aiRes.status, errBody.slice(0,200));
      throw new Error('AI API error: ' + aiRes.status);
    }
    const aiData = await aiRes.json();
    const text = (aiData.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('');
    console.log('[ai-analysis] raw response:', text.slice(0,300));
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in AI response: ' + text.slice(0,100));
    const analysis = JSON.parse(jsonMatch[0]);

    // Save to DB
    await pool.query('UPDATE job_applications SET ai_score=$2, ai_analysis=$3, updated_at=NOW() WHERE id=$1',
      [id, analysis.score||0, JSON.stringify(analysis)]);

    console.log('[ai-analysis]', id, 'score:', analysis.score, 'rec:', analysis.recomendacion);
    res.json({ ok: true, analysis });
  } catch(e) {
    console.error('[ai-analysis]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── FISCAL PERIODS ────────────────────────────────────────────────────
app.get('/api/fiscal-periods', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM fiscal_periods ORDER BY date_start DESC');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/fiscal-periods/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, date_start, date_end, status, closed_by, data } = req.body;
  try {
    await pool.query(`INSERT INTO fiscal_periods(id,name,date_start,date_end,status,closed_by,closed_at,data)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT(id) DO UPDATE SET name=$2,date_start=$3,date_end=$4,status=$5,
        closed_by=$6,closed_at=$7,data=$8,updated_at=NOW()`,
      [id, name, date_start, date_end, status||'abierto', closed_by||null,
       status==='cerrado' ? new Date().toISOString() : null,
       JSON.stringify(data||{})]);
    console.log('[fiscal-period]', status==='cerrado'?'CLOSED':'saved', id, name);
    res.json({ ok: true });
  } catch(e) { console.error('[fiscal-period]', e.message); res.status(500).json({ error: e.message }); }
});

// ── CLOSE FISCAL PERIOD — freeze all payroll cuts in range ────────────
app.post('/api/fiscal-periods/:id/close', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    // Get the period
    const p = await pool.query('SELECT * FROM fiscal_periods WHERE id=$1', [id]);
    if (!p.rows.length) return res.status(404).json({ error: 'Period not found' });
    const period = p.rows[0];
    if (period.status === 'cerrado') return res.status(400).json({ error: 'Period already closed' });

    // Get ALL payroll cuts within the period date range (any status except already frozen)
    const cuts = await pool.query(
      `SELECT id, data, status FROM payroll_cuts 
       WHERE status != 'congelado'
       AND (
         (data->>'date' >= $1 AND data->>'date' <= $2)
         OR (data->>'dateFrom' >= $1 AND data->>'dateFrom' <= $2)
         OR (data->>'from' >= $1 AND data->>'from' <= $2)
       )`,
      [period.date_start, period.date_end]
    );
    console.log('[fiscal-period/close] cuts found in range:', cuts.rows.length, 
      cuts.rows.map(c => c.id + ':' + c.status).join(', '));

    // Compute accumulated totals per employee
    const empAccum = {};
    for (const cut of cuts.rows) {
      const snap = cut.data.empSnapshot || [];
      for (const s of snap) {
        if (!empAccum[s.id]) empAccum[s.id] = {
          id: s.id, name: s.name, country: s.country,
          grossTotal: 0, isrTotal: 0, imssObrTotal: 0, imssPatTotal: 0,
          netTotal: 0, cutsCount: 0,
          perceptions: {}, deductions: {},
          cuts: []
        };
        const acc = empAccum[s.id];
        acc.grossTotal  += (s.base||0);
        acc.netTotal    += (s.net||0);
        acc.isrTotal    += (s.deds&&s.deds['ISR Art. 96 LISR']||0);
        acc.imssObrTotal+= (s.deds&&s.deds['IMSS Invalidez y Vida']||0)+(s.deds&&s.deds['IMSS Cesantía y Vejez']||0)+(s.deds&&s.deds['IMSS Enf. y Maternidad']||0);
        acc.cutsCount++;
        // Accumulate each deduction line
        if (s.deds) {
          for (const [k,v] of Object.entries(s.deds)) {
            acc.deductions[k] = (acc.deductions[k]||0) + (v||0);
          }
        }
        acc.cuts.push({ cutId: cut.id, date: cut.data.date||cut.data.period, base: s.base, net: s.net });
      }
    }

    // Save accumulated data into the period
    const periodData = {
      ...period.data,
      cutIds: cuts.rows.map(c=>c.id),
      employeeAccum: empAccum,
      closedAt: new Date().toISOString(),
      closedBy: req.session.name || req.session.id,
      totalCuts: cuts.rows.length,
      totalEmployees: Object.keys(empAccum).length,
      grandGross: Object.values(empAccum).reduce((a,e)=>a+e.grossTotal,0),
      grandISR:   Object.values(empAccum).reduce((a,e)=>a+e.isrTotal,0),
      grandNet:   Object.values(empAccum).reduce((a,e)=>a+e.netTotal,0),
    };

    // Freeze all cuts in this period
    for (const cut of cuts.rows) {
      await pool.query(
        "UPDATE payroll_cuts SET status='congelado', data=data||$1, updated_at=NOW() WHERE id=$2",
        [JSON.stringify({fiscalPeriodId: id, frozen: true}), cut.id]
      );
    }

    // Close the period
    await pool.query(
      `UPDATE fiscal_periods SET status='cerrado', closed_by=$1, closed_at=NOW(), data=$2, updated_at=NOW() WHERE id=$3`,
      [req.session.name||req.session.id, JSON.stringify(periodData), id]
    );

    console.log('[fiscal-period] CLOSED:', id, '- cuts frozen:', cuts.rows.length, '- employees:', Object.keys(empAccum).length);
    res.json({ ok: true, summary: { cuts: cuts.rows.length, employees: Object.keys(empAccum).length, grandGross: periodData.grandGross } });
  } catch(e) { console.error('[fiscal-period/close]', e.message); res.status(500).json({ error: e.message }); }
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

const PORT = process.env.PORT || 3000;
initDB().then(() => app.listen(PORT, () => console.log(`🚀 TimeClock on :${PORT} (${IS_PROD?'prod':'dev'})`)))
  .catch(e => { console.error(e); process.exit(1); });
