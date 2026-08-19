// ═══════════════════════════════════════════════════════════════════════
// TimeClock Enterprise — Master Server
// Gestiona el registro de clientes, provisión de DBs en Railway,
// generación de credenciales y resolución de tenants en el login
// ═══════════════════════════════════════════════════════════════════════
require('dotenv').config();
const express    = require('express');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const path       = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(require('cookie-parser')());
app.use(require('compression')());

// ── Configuración ────────────────────────────────────────────────────────
const PORT            = process.env.PORT           || 4000;
const MASTER_DB_URL   = process.env.MASTER_DATABASE_URL || process.env.DATABASE_URL;
const JWT_SECRET      = process.env.MASTER_JWT_SECRET   || 'master-dev-secret-change-in-prod';
const DB_ENCRYPT_KEY  = process.env.DB_ENCRYPT_KEY      || 'timeclock-encrypt-key-32-chars!!'; // debe ser 32 chars
const RAILWAY_TOKEN   = process.env.RAILWAY_API_TOKEN;
const RAILWAY_GQL     = 'https://backboard.railway.app/graphql/v2';
const RAILWAY_TEAM_ID = process.env.RAILWAY_TEAM_ID;    // opcional: para proyectos de equipo
const COOKIE_NAME     = 'tc_master_session';
const COOKIE_OPTS     = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge:   8 * 3600000,
};

// Schema TimeClock que se aplica a cada nueva DB de cliente
// (igual al initDB() del server principal pero como SQL puro)
const TIMECLOCK_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,data JSONB NOT NULL,status TEXT DEFAULT 'active',created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS user_tenants(user_id TEXT NOT NULL,tenant_id TEXT NOT NULL,role TEXT DEFAULT 'member',is_default BOOLEAN DEFAULT false,created_at TIMESTAMPTZ DEFAULT NOW(),PRIMARY KEY(user_id,tenant_id));
CREATE TABLE IF NOT EXISTS employees(id TEXT PRIMARY KEY,data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS locations(id TEXT PRIMARY KEY,data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS departments(id TEXT PRIMARY KEY,data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS time_records(id TEXT PRIMARY KEY,emp_id TEXT,record_date DATE,data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS payroll_cuts(id TEXT PRIMARY KEY,status TEXT DEFAULT 'pendiente',data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS system_users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS tax_ytd(emp_id TEXT PRIMARY KEY,data JSONB NOT NULL,tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS company_cfg(id TEXT PRIMARY KEY DEFAULT 'main',data JSONB NOT NULL DEFAULT '{}',tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS fiscal_periods(id TEXT PRIMARY KEY,name TEXT NOT NULL,date_start DATE NOT NULL,date_end DATE NOT NULL,status TEXT DEFAULT 'abierto',closed_by TEXT,closed_at TIMESTAMPTZ,data JSONB NOT NULL DEFAULT '{}',tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS session_logs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,user_name TEXT,user_type TEXT DEFAULT 'admin',view_name TEXT NOT NULL,entered_at TIMESTAMPTZ NOT NULL,exited_at TIMESTAMPTZ,duration_sec INTEGER,ip_address TEXT,user_agent TEXT,session_id TEXT,tenant_id TEXT,data JSONB DEFAULT '{}');
CREATE TABLE IF NOT EXISTS job_applications(id TEXT PRIMARY KEY,job_id TEXT NOT NULL,candidate_name TEXT NOT NULL,candidate_email TEXT,status TEXT DEFAULT 'nuevo',cv_data TEXT,ai_score INTEGER,ai_analysis JSONB,interview_slot TEXT,data JSONB NOT NULL DEFAULT '{}',tenant_id TEXT,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS interview_slots(id TEXT PRIMARY KEY,date DATE NOT NULL,time TEXT NOT NULL,duration_min INTEGER DEFAULT 60,status TEXT DEFAULT 'disponible',job_id TEXT,application_id TEXT,recruiter_note TEXT,data JSONB NOT NULL DEFAULT '{}',tenant_id TEXT,updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_emp_tenant ON employees(tenant_id);
CREATE INDEX IF NOT EXISTS idx_loc_tenant ON locations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dept_tenant ON departments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tr_tenant ON time_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cuts_tenant ON payroll_cuts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_su_tenant ON system_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fp_tenant ON fiscal_periods(tenant_id);
CREATE INDEX IF NOT EXISTS idx_logs_tenant ON session_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_apps_tenant ON job_applications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_slots_tenant ON interview_slots(tenant_id);
`;

// ── Pool de conexión a la DB maestra ─────────────────────────────────────
const masterPool = new Pool({ connectionString: MASTER_DB_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });

// ── Utilidades de cifrado ─────────────────────────────────────────────────
const ALGO = 'aes-256-cbc';
function encrypt(text) {
  const iv  = crypto.randomBytes(16);
  const key = Buffer.from(DB_ENCRYPT_KEY.padEnd(32).slice(0, 32));
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  return iv.toString('hex') + ':' + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
function decrypt(enc) {
  if (!enc || !enc.includes(':')) return null;
  const [ivHex, data] = enc.split(':');
  const key = Buffer.from(DB_ENCRYPT_KEY.padEnd(32).slice(0, 32));
  const decipher = crypto.createDecipheriv(ALGO, key, Buffer.from(ivHex, 'hex'));
  return decipher.update(data, 'hex', 'utf8') + decipher.final('utf8');
}

// ── Generador de password seguro ──────────────────────────────────────────
function generatePassword(length = 16) {
  const upper   = 'ABCDEFGHJKMNPQRSTUVWXYZ';
  const lower   = 'abcdefghjkmnpqrstuvwxyz';
  const digits  = '23456789';
  const symbols = '!@#$%^&*';
  const all     = upper + lower + digits + symbols;
  let pwd = '';
  // Garantizar al menos uno de cada tipo
  pwd += upper[Math.floor(Math.random() * upper.length)];
  pwd += lower[Math.floor(Math.random() * lower.length)];
  pwd += digits[Math.floor(Math.random() * digits.length)];
  pwd += symbols[Math.floor(Math.random() * symbols.length)];
  for (let i = 4; i < length; i++)
    pwd += all[Math.floor(Math.random() * all.length)];
  // Mezclar
  return pwd.split('').sort(() => Math.random() - 0.5).join('');
}

// ── Slugify ───────────────────────────────────────────────────────────────
function slugify(text) {
  return text.toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
}

// ── Railway GraphQL helper ─────────────────────────────────────────────────
async function railwayGQL(query, variables = {}) {
  if (!RAILWAY_TOKEN) throw new Error('RAILWAY_API_TOKEN no configurado');
  const res = await fetch(RAILWAY_GQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RAILWAY_TOKEN}` },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors?.length) throw new Error(json.errors[0].message);
  return json.data;
}

// Crea proyecto + servicio PostgreSQL en Railway y devuelve { projectId, serviceId, envId }
async function railwayCreateProject(slug) {
  // 1. Crear proyecto
  const proj = await railwayGQL(`
    mutation projectCreate($input: ProjectCreateInput!) {
      projectCreate(input: $input) { id name }
    }`,
    { input: { name: `timeclock-${slug}`, ...(RAILWAY_TEAM_ID ? { teamId: RAILWAY_TEAM_ID } : {}) } }
  );
  const projectId = proj.projectCreate.id;

  // 2. Obtener el environment "production" del proyecto
  const envData = await railwayGQL(`
    query getEnv($projectId: String!) {
      project(id: $projectId) { environments { edges { node { id name } } } }
    }`, { projectId });
  const envId = envData.project.environments.edges.find(e => e.node.name === 'production')?.node.id
    || envData.project.environments.edges[0]?.node.id;

  // 3. Crear servicio PostgreSQL (plugin nativo de Railway)
  const svc = await railwayGQL(`
    mutation serviceCreate($input: ServiceCreateInput!) {
      serviceCreate(input: $input) { id name }
    }`,
    { input: { projectId, name: 'postgres', source: { repo: '' } } }
  );
  const serviceId = svc.serviceCreate.id;

  // 4. Conectar con template de Postgres (Railway Database plugin)
  await railwayGQL(`
    mutation serviceDatabaseDeploy($serviceId: String!, $environmentId: String!) {
      serviceDatabaseDeploy(serviceId: $serviceId, environmentId: $environmentId, databaseType: postgresql)
    }`,
    { serviceId, environmentId: envId }
  );

  return { projectId, serviceId, envId };
}

// Espera a que la variable DATABASE_URL esté disponible (polling hasta 90s)
async function waitForDatabaseUrl(projectId, serviceId, envId, maxWaitMs = 90000) {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    await new Promise(r => setTimeout(r, 4000));
    try {
      const vars = await railwayGQL(`
        query getVars($projectId: String!, $serviceId: String!, $environmentId: String!) {
          variables(projectId: $projectId, serviceId: $serviceId, environmentId: $environmentId)
        }`,
        { projectId, serviceId, environmentId: envId }
      );
      const url = vars.variables?.DATABASE_URL || vars.variables?.DATABASE_PRIVATE_URL;
      if (url) return url;
    } catch (e) { console.warn('[railway] poll error:', e.message); }
  }
  throw new Error('Timeout esperando DATABASE_URL de Railway (90s)');
}

// Aplica el schema de TimeClock a la nueva DB del cliente
async function applyTimeclockSchema(databaseUrl) {
  const clientPool = new Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: false } });
  try {
    const stmts = TIMECLOCK_SCHEMA_SQL.split(';').map(s => s.trim()).filter(Boolean);
    for (const sql of stmts) {
      try { await clientPool.query(sql + ';'); }
      catch(e) { console.warn('[schema] warning:', e.message.slice(0, 80)); }
    }
    console.log('[schema] TimeClock schema aplicado OK');
  } finally { await clientPool.end(); }
}

// Crea el sistema_user inicial del cliente en su propia DB
async function createInitialAdminInClientDB(databaseUrl, { username, passwordHash, tenantId, clientData }) {
  const clientPool = new Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: false } });
  try {
    // Crear el tenant principal del cliente
    await clientPool.query(
      `INSERT INTO tenants(id, data, status) VALUES($1, $2, 'active') ON CONFLICT(id) DO NOTHING`,
      [tenantId, JSON.stringify({
        name:           clientData.company?.name    || '',
        rfc:            clientData.fiscal?.MX?.rfc  || clientData.fiscal?.US?.ein || '',
        countries:      clientData.countries        || ['MX'],
        plan:           clientData.plan             || 'profesional',
      })]
    );
    // Crear el usuario admin en system_users de la DB del cliente
    const userId = 'su_' + crypto.randomBytes(8).toString('hex');
    await clientPool.query(
      `INSERT INTO system_users(id, username, data, tenant_id) VALUES($1, $2, $3, $4) ON CONFLICT(username) DO NOTHING`,
      [userId, username, JSON.stringify({
        username,
        name:    clientData.contact?.adminName  || 'Administrador',
        email:   clientData.contact?.adminEmail || '',
        role:    'superadmin',
        status:  'active',
        passwordHash,
        createdAt: new Date().toISOString(),
      }), tenantId]
    );
    // Vincular usuario al tenant
    await clientPool.query(
      `INSERT INTO user_tenants(user_id, tenant_id, role, is_default) VALUES($1, $2, 'owner', true) ON CONFLICT DO NOTHING`,
      [userId, tenantId]
    );
    console.log('[admin] Usuario inicial creado en DB del cliente:', username);
    return userId;
  } finally { await clientPool.end(); }
}

// ── Auth de operadores (tu equipo) ────────────────────────────────────────
function readOp(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (cookie) try { return jwt.verify(cookie, JWT_SECRET); } catch {}
  return null;
}
function requireOp(req, res, next) {
  req.operator = readOp(req);
  if (!req.operator) return res.status(401).json({ error: 'No autorizado' });
  next();
}
function requireSuperAdmin(req, res, next) {
  if (req.operator?.role !== 'superadmin') return res.status(403).json({ error: 'Solo superadmin' });
  next();
}

// ── LOG de auditoría ──────────────────────────────────────────────────────
async function auditLog(clientId, operator, action, detail = {}, ip = null) {
  try {
    await masterPool.query(
      `INSERT INTO client_audit_log(client_id, operator, action, detail, ip_address)
       VALUES($1, $2, $3, $4, $5)`,
      [clientId, operator, action, JSON.stringify(detail), ip]
    );
  } catch(e) { console.warn('[audit]', e.message); }
}

// ── RUTAS DE AUTH ─────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });
  try {
    const r = await masterPool.query('SELECT * FROM operators WHERE username=$1 AND status=$2', [username, 'active']);
    if (!r.rows.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const op = r.rows[0];
    const valid = await bcrypt.compare(password, op.password_hash);
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });
    await masterPool.query('UPDATE operators SET last_login=NOW() WHERE id=$1', [op.id]);
    const token = jwt.sign({ id: op.id, username: op.username, name: op.name, role: op.role }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
    res.json({ ok: true, operator: { id: op.id, username: op.username, name: op.name, role: op.role } });
  } catch(e) { console.error('[login]', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireOp, (req, res) => res.json({ operator: req.operator }));

// ── LISTADO DE CLIENTES ───────────────────────────────────────────────────
app.get('/api/clients', requireOp, async (req, res) => {
  try {
    const r = await masterPool.query('SELECT * FROM v_clients_summary');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/clients/:id', requireOp, async (req, res) => {
  try {
    const r = await masterPool.query('SELECT * FROM clients WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    // También traer db info y admin
    const db  = await masterPool.query('SELECT * FROM client_dbs   WHERE client_id=$1', [req.params.id]);
    const adm = await masterPool.query('SELECT id,username,email,name,role,created_at,last_login FROM client_admins WHERE client_id=$1', [req.params.id]);
    const sub = await masterPool.query('SELECT * FROM subscriptions WHERE client_id=$1', [req.params.id]);
    res.json({ ...r.rows[0], db: db.rows[0] || null, admins: adm.rows, subscription: sub.rows[0] || null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CREAR CLIENTE (wizard → guarda datos, NO provisiona aún) ─────────────
app.post('/api/clients', requireOp, async (req, res) => {
  const { data, plan = 'profesional' } = req.body || {};
  if (!data?.company?.name) return res.status(400).json({ error: 'Nombre de empresa requerido' });
  const slug = slugify(data.company.name);
  try {
    // Verificar slug único
    const exists = await masterPool.query('SELECT id FROM clients WHERE slug=$1', [slug]);
    if (exists.rows.length) return res.status(409).json({ error: `El slug '${slug}' ya existe. Modifica el nombre de empresa.` });

    const r = await masterPool.query(
      `INSERT INTO clients(slug, status, plan, data) VALUES($1, 'draft', $2, $3) RETURNING *`,
      [slug, plan, JSON.stringify(data)]
    );
    const client = r.rows[0];

    // Crear suscripción inicial
    await masterPool.query(
      `INSERT INTO subscriptions(client_id, plan, status) VALUES($1, $2, 'trialing')`,
      [client.id, plan]
    );

    await auditLog(client.id, req.operator.username, 'created', { plan, slug }, req.ip);
    console.log('[client] Creado:', slug, client.id);
    res.json({ ok: true, client });
  } catch(e) { console.error('[client/create]', e.message); res.status(500).json({ error: e.message }); }
});

// ── ACTUALIZAR DATOS DEL CLIENTE ──────────────────────────────────────────
app.put('/api/clients/:id', requireOp, async (req, res) => {
  const { data, plan, status } = req.body || {};
  try {
    const updates = [];
    const params  = [req.params.id];
    if (data)   { params.push(JSON.stringify(data)); updates.push(`data=$${params.length}`); }
    if (plan)   { params.push(plan);                 updates.push(`plan=$${params.length}`); }
    if (status) { params.push(status);               updates.push(`status=$${params.length}`); }
    if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar' });
    await masterPool.query(`UPDATE clients SET ${updates.join(',')} WHERE id=$1`, params);
    await auditLog(req.params.id, req.operator.username, 'updated', { fields: updates }, req.ip);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PROVISIONAR DB EN RAILWAY ─────────────────────────────────────────────
// Este endpoint hace el trabajo pesado: Railway API → schema → admin user
app.post('/api/clients/:id/provision', requireOp, async (req, res) => {
  const clientId = req.params.id;
  try {
    // Verificar que el cliente existe y no tiene DB todavía
    const cr = await masterPool.query('SELECT * FROM clients WHERE id=$1', [clientId]);
    if (!cr.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = cr.rows[0];

    const existing = await masterPool.query("SELECT id, status FROM client_dbs WHERE client_id=$1", [clientId]);
    if (existing.rows.length && existing.rows[0].status === 'ready')
      return res.status(409).json({ error: 'Este cliente ya tiene una DB provisionada' });

    // Marcar como "creando" en la DB maestra
    let dbRow;
    if (existing.rows.length) {
      await masterPool.query("UPDATE client_dbs SET status='creating', error_msg=NULL WHERE client_id=$1", [clientId]);
      dbRow = existing.rows[0];
    } else {
      const ins = await masterPool.query(
        `INSERT INTO client_dbs(client_id, region, status) VALUES($1,'us-west-2','creating') RETURNING *`,
        [clientId]
      );
      dbRow = ins.rows[0];
    }

    // Actualizar status del cliente
    await masterPool.query("UPDATE clients SET status='provisioning' WHERE id=$1", [clientId]);

    // Responder inmediatamente — la provisión es async
    res.json({ ok: true, status: 'provisioning', message: 'DB en proceso de creación. Sondea /api/clients/:id/db-status' });

    // ── Proceso async ─────────────────────────────────────────────────
    ;(async () => {
      try {
        console.log('[provision] Iniciando Railway API para:', client.slug);
        const { projectId, serviceId, envId } = await railwayCreateProject(client.slug);

        // Guardar IDs de Railway inmediatamente
        await masterPool.query(
          `UPDATE client_dbs SET railway_project_id=$1, railway_service_id=$2, railway_env_id=$3 WHERE client_id=$4`,
          [projectId, serviceId, envId, clientId]
        );

        // Esperar DATABASE_URL
        console.log('[provision] Esperando DATABASE_URL de Railway...');
        const databaseUrl = await waitForDatabaseUrl(projectId, serviceId, envId);

        // Guardar cifrado en DB maestra
        const encUrl = encrypt(databaseUrl);
        await masterPool.query(
          `UPDATE client_dbs SET database_url_enc=$1, db_name=$2, status='ready', ready_at=NOW(), schema_version=1 WHERE client_id=$3`,
          [encUrl, `timeclock-${client.slug}`, clientId]
        );

        // Aplicar schema TimeClock
        console.log('[provision] Aplicando schema TimeClock...');
        await applyTimeclockSchema(databaseUrl);

        // Marcar cliente como listo
        await masterPool.query("UPDATE clients SET status='db_ready' WHERE id=$1", [clientId]);
        await auditLog(clientId, req.operator?.username || 'system', 'db_provisioned',
          { projectId, serviceId, region: 'us-west-2' });

        console.log('[provision] ✅ DB lista para:', client.slug);
      } catch(e) {
        console.error('[provision] ❌', e.message);
        await masterPool.query(
          `UPDATE client_dbs SET status='error', error_msg=$1 WHERE client_id=$2`,
          [e.message.slice(0, 500), clientId]
        );
        await masterPool.query("UPDATE clients SET status='error' WHERE id=$1", [clientId]);
        await auditLog(clientId, 'system', 'db_provision_error', { error: e.message });
      }
    })();

  } catch(e) { console.error('[provision/init]', e.message); res.status(500).json({ error: e.message }); }
});

// ── SONDEO DE ESTADO DE DB ────────────────────────────────────────────────
app.get('/api/clients/:id/db-status', requireOp, async (req, res) => {
  try {
    const r = await masterPool.query(
      'SELECT status, error_msg, ready_at, railway_project_id, region FROM client_dbs WHERE client_id=$1',
      [req.params.id]
    );
    if (!r.rows.length) return res.json({ status: 'not_started' });
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SETUP INICIAL: generar credenciales del admin ─────────────────────────
app.post('/api/clients/:id/setup', requireOp, async (req, res) => {
  const clientId = req.params.id;
  try {
    const cr = await masterPool.query('SELECT * FROM clients WHERE id=$1', [clientId]);
    if (!cr.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const client = cr.rows[0];

    const dbr = await masterPool.query(
      "SELECT * FROM client_dbs WHERE client_id=$1 AND status='ready'", [clientId]
    );
    if (!dbr.rows.length)
      return res.status(409).json({ error: 'La DB del cliente aún no está lista (status != ready)' });

    const dbRow    = dbr.rows[0];
    const dbUrl    = decrypt(dbRow.database_url_enc);
    if (!dbUrl) return res.status(500).json({ error: 'No se pudo descifrar DATABASE_URL' });

    // Generar credenciales
    const slug       = client.slug;
    const username   = `admin.${slug}`;
    const password   = generatePassword(16);
    const pwdHash    = await bcrypt.hash(password, 12);
    const pwdEnc     = encrypt(password);          // para recuperación por superadmin
    const tenantId   = `tn_${slug}`;

    // Crear en la DB del cliente
    await createInitialAdminInClientDB(dbUrl, {
      username, passwordHash: pwdHash, tenantId, clientData: client.data,
    });

    // Guardar en DB maestra (para recuperación)
    const admExists = await masterPool.query(
      'SELECT id FROM client_admins WHERE client_id=$1 AND username=$2', [clientId, username]
    );
    if (admExists.rows.length) {
      // Regenerar: actualizar hash y enc
      await masterPool.query(
        `UPDATE client_admins SET password_hash=$1, password_enc=$2, updated_at=NOW() WHERE client_id=$3 AND username=$4`,
        [pwdHash, pwdEnc, clientId, username]
      );
    } else {
      await masterPool.query(
        `INSERT INTO client_admins(client_id, username, password_hash, password_enc, email, name, role, is_initial)
         VALUES($1,$2,$3,$4,$5,$6,'superadmin',true)`,
        [clientId, username, pwdHash, pwdEnc,
         client.data?.contact?.adminEmail || '',
         client.data?.contact?.adminName  || 'Administrador']
      );
    }

    // Marcar cliente como activo
    await masterPool.query("UPDATE clients SET status='active', activated_at=COALESCE(activated_at, NOW()) WHERE id=$1", [clientId]);
    await auditLog(clientId, req.operator.username, 'admin_created', { username }, req.ip);

    console.log('[setup] ✅ Admin creado:', username, 'para', slug);
    res.json({
      ok: true,
      credentials: { username, password, tenantId },
      client: { slug, name: client.data?.company?.name },
    });
  } catch(e) { console.error('[setup]', e.message); res.status(500).json({ error: e.message }); }
});

// ── RECUPERAR CREDENCIALES (solo superadmin) ──────────────────────────────
app.get('/api/clients/:id/credentials', requireOp, requireSuperAdmin, async (req, res) => {
  const clientId = req.params.id;
  try {
    const r = await masterPool.query(
      'SELECT username, password_enc, email, name FROM client_admins WHERE client_id=$1 AND is_initial=true',
      [clientId]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Credenciales no encontradas' });
    const adm = r.rows[0];
    const password = decrypt(adm.password_enc);
    await auditLog(clientId, req.operator.username, 'credentials_viewed', {}, req.ip);
    res.json({ username: adm.username, password, email: adm.email, name: adm.name });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SUSPENDER / REACTIVAR CLIENTE ─────────────────────────────────────────
app.post('/api/clients/:id/suspend', requireOp, async (req, res) => {
  try {
    await masterPool.query("UPDATE clients SET status='suspended', suspended_at=NOW() WHERE id=$1", [req.params.id]);
    await masterPool.query("UPDATE subscriptions SET status='cancelled' WHERE client_id=$1", [req.params.id]);
    await auditLog(req.params.id, req.operator.username, 'suspended', {}, req.ip);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clients/:id/reactivate', requireOp, async (req, res) => {
  try {
    await masterPool.query("UPDATE clients SET status='active', suspended_at=NULL WHERE id=$1", [req.params.id]);
    await masterPool.query("UPDATE subscriptions SET status='active' WHERE client_id=$1", [req.params.id]);
    await auditLog(req.params.id, req.operator.username, 'reactivated', {}, req.ip);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── RESOLUCIÓN DE TENANT PARA EL LOGIN DE TIMECLOCK ──────────────────────
// Este endpoint es llamado por el server principal de TimeClock cuando un
// usuario intenta loguearse: recibe el username y devuelve el DATABASE_URL
// del cliente correspondiente, para que el backend conecte a la DB correcta.
app.get('/api/resolve-db', async (req, res) => {
  const { username, clientSlug } = req.query;
  // Verificar que viene de un servidor TimeClock (API key interna)
  const apiKey = req.headers['x-timeclock-key'];
  if (apiKey !== process.env.TIMECLOCK_INTERNAL_KEY)
    return res.status(401).json({ error: 'No autorizado' });

  try {
    let query, params;
    if (clientSlug) {
      query  = `SELECT c.id, c.slug, c.status, db.database_url_enc
                FROM clients c JOIN client_dbs db ON db.client_id=c.id
                WHERE c.slug=$1 AND c.status='active' AND db.status='ready'`;
      params = [clientSlug];
    } else if (username) {
      // Buscar por username del admin → cliente
      query  = `SELECT c.id, c.slug, c.status, db.database_url_enc
                FROM client_admins ca
                JOIN clients c ON c.id=ca.client_id
                JOIN client_dbs db ON db.client_id=c.id
                WHERE ca.username=$1 AND c.status='active' AND db.status='ready'`;
      params = [username];
    } else {
      return res.status(400).json({ error: 'username o clientSlug requerido' });
    }

    const r = await masterPool.query(query, params);
    if (!r.rows.length) return res.status(404).json({ error: 'Cliente no encontrado o inactivo' });

    const row = r.rows[0];
    const databaseUrl = decrypt(row.database_url_enc);
    if (!databaseUrl) return res.status(500).json({ error: 'Error al descifrar DATABASE_URL' });

    res.json({ clientId: row.id, slug: row.slug, databaseUrl });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── LOG DE AUDITORÍA ──────────────────────────────────────────────────────
app.get('/api/audit/:clientId', requireOp, async (req, res) => {
  try {
    const r = await masterPool.query(
      'SELECT * FROM client_audit_log WHERE client_id=$1 ORDER BY created_at DESC LIMIT 100',
      [req.params.clientId]
    );
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await masterPool.query('SELECT 1');
    res.json({ ok: true, railway: !!RAILWAY_TOKEN });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── SERVIR EL FRONTEND ────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-tool.html')));

// ── ARRANQUE ──────────────────────────────────────────────────────────────
masterPool.query('SELECT NOW()').then(() => {
  console.log('✅ Conectado a DB maestra');
  app.listen(PORT, () => console.log(`🚀 Master server en puerto ${PORT}`));
}).catch(e => { console.error('❌ Error DB maestra:', e.message); process.exit(1); });
