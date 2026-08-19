-- ═══════════════════════════════════════════════════════════════════════
-- TimeClock Enterprise — Master Database Schema
-- Base de datos CENTRAL separada en Railway
-- Gestiona el registro de clientes, sus conexiones de DB y credenciales
-- ═══════════════════════════════════════════════════════════════════════

-- ── Extensiones ──────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- para gen_random_uuid() y encrypt

-- ── Tabla principal de clientes ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clients (
  id              TEXT PRIMARY KEY DEFAULT 'cl_' || gen_random_uuid()::text,
  slug            TEXT UNIQUE NOT NULL,          -- 'empresa-roja' → usado en URL y username
  status          TEXT NOT NULL DEFAULT 'provisioning',
                  -- provisioning | active | suspended | cancelled
  plan            TEXT NOT NULL DEFAULT 'profesional',
                  -- basico | profesional | enterprise
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  activated_at    TIMESTAMPTZ,                   -- cuando el cliente hizo su primer login
  suspended_at    TIMESTAMPTZ,
  data            JSONB NOT NULL DEFAULT '{}',   -- todos los datos del wizard
  /*
    data incluye:
    {
      company: { name, legalName, rfc/ein/rnc/nit, logoUrl },
      contact: { adminName, adminEmail, phone },
      countries: ['MX','US','DR','SV'],
      fiscal: { MX: { regimen, pac, imssKey, cfdi }, US: { ein, state } ... },
      billing: { invoices: true, method: 'stripe' },
      branches: [{ name, city, address }],
      startDate: '2026-07-01',
      employeesEstimated: 50,
      notes: ''
    }
  */
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_slug   ON clients(slug);

-- ── Conexiones de base de datos por cliente ───────────────────────────────
-- Cada cliente tiene su propio PostgreSQL en Railway.
-- DATABASE_URL se guarda cifrado con AES-256 usando la clave en env DB_ENCRYPT_KEY
CREATE TABLE IF NOT EXISTS client_dbs (
  id              TEXT PRIMARY KEY DEFAULT 'db_' || gen_random_uuid()::text,
  client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  railway_project_id   TEXT,                     -- ID del proyecto en Railway
  railway_service_id   TEXT,                     -- ID del servicio PostgreSQL
  railway_env_id       TEXT,                     -- ID del environment (production)
  region          TEXT NOT NULL DEFAULT 'us-west-2',
  database_url_enc TEXT,                         -- DATABASE_URL cifrado (AES-256)
  db_name         TEXT,                          -- nombre del DB en Railway
  status          TEXT NOT NULL DEFAULT 'pending',
                  -- pending | creating | ready | error
  error_msg       TEXT,
  schema_version  INTEGER DEFAULT 0,             -- versión del schema TimeClock aplicado
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ready_at        TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cdbs_client   ON client_dbs(client_id);
CREATE INDEX IF NOT EXISTS idx_cdbs_status   ON client_dbs(status);

-- ── Credenciales del administrador inicial ────────────────────────────────
-- Se generan automáticamente al completar el setup inicial.
-- El password se guarda de dos formas:
--   1. bcrypt hash → para verificar el login desde timeclock
--   2. cifrado AES → para recuperación en caso de olvido (solo superadmin puede ver)
CREATE TABLE IF NOT EXISTS client_admins (
  id              TEXT PRIMARY KEY DEFAULT 'adm_' || gen_random_uuid()::text,
  client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  username        TEXT NOT NULL,                 -- 'admin.empresa-roja'
  password_hash   TEXT NOT NULL,                 -- bcrypt para login
  password_enc    TEXT NOT NULL,                 -- AES cifrado para recuperación
  email           TEXT,
  name            TEXT,
  role            TEXT NOT NULL DEFAULT 'superadmin',
  is_initial      BOOLEAN NOT NULL DEFAULT true, -- distingue el admin creado aquí
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login      TIMESTAMPTZ,
  reset_token     TEXT,
  reset_expires   TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cadmins_client   ON client_admins(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cadmins_username ON client_admins(client_id, username);

-- ── Suscripciones y plan ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
  id              TEXT PRIMARY KEY DEFAULT 'sub_' || gen_random_uuid()::text,
  client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  plan            TEXT NOT NULL DEFAULT 'profesional',
  status          TEXT NOT NULL DEFAULT 'active',
                  -- active | past_due | cancelled | trialing
  price_monthly   NUMERIC(10,2),
  currency        TEXT DEFAULT 'MXN',
  billing_day     INTEGER DEFAULT 1,             -- día del mes que se cobra
  trial_ends      TIMESTAMPTZ,
  current_period_start TIMESTAMPTZ,
  current_period_end   TIMESTAMPTZ,
  notes           TEXT,
  data            JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subs_client ON subscriptions(client_id);
CREATE INDEX IF NOT EXISTS idx_subs_status ON subscriptions(status);

-- ── Log de operaciones sobre clientes ────────────────────────────────────
-- Auditoría completa: quién creó, provisionó, suspendió, recuperó credenciales
CREATE TABLE IF NOT EXISTS client_audit_log (
  id              TEXT PRIMARY KEY DEFAULT 'log_' || gen_random_uuid()::text,
  client_id       TEXT REFERENCES clients(id) ON DELETE SET NULL,
  operator        TEXT NOT NULL,                 -- quién hizo la acción (tu equipo)
  action          TEXT NOT NULL,
                  -- created | db_provisioned | admin_created | credentials_viewed
                  -- suspended | reactivated | plan_changed | schema_updated
  detail          JSONB DEFAULT '{}',
  ip_address      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_client ON client_audit_log(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON client_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_date   ON client_audit_log(created_at DESC);

-- ── Tabla de operadores (tu equipo interno) ───────────────────────────────
CREATE TABLE IF NOT EXISTS operators (
  id              TEXT PRIMARY KEY DEFAULT 'op_' || gen_random_uuid()::text,
  username        TEXT UNIQUE NOT NULL,
  password_hash   TEXT NOT NULL,
  name            TEXT NOT NULL,
  email           TEXT,
  role            TEXT NOT NULL DEFAULT 'implementador',
                  -- superadmin | implementador | soporte
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login      TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Operator superadmin por defecto (cambiar en primer login)
INSERT INTO operators(id, username, password_hash, name, role)
VALUES (
  'op_default_super',
  'superadmin',
  -- password: SuperAdmin2026! (cambiar inmediatamente)
  '$2b$10$rOsNmPCGqzqiLFkDpVjOK.8QWz2mNxK1YxGqPkH3V8.I7WqJb2hXi',
  'Super Administrador',
  'superadmin'
) ON CONFLICT(username) DO NOTHING;

-- ── Vista útil: resumen de clientes ──────────────────────────────────────
CREATE OR REPLACE VIEW v_clients_summary AS
SELECT
  c.id,
  c.slug,
  c.status,
  c.plan,
  c.created_at,
  c.activated_at,
  c.data->>'company' as company_json,
  (c.data->'company'->>'name')                  AS company_name,
  (c.data->'contact'->>'adminEmail')             AS admin_email,
  (c.data->'contact'->>'adminName')              AS admin_name,
  c.data->'countries'                            AS countries,
  db.status                                      AS db_status,
  db.region                                      AS db_region,
  db.ready_at                                    AS db_ready_at,
  db.railway_project_id,
  ca.username                                    AS admin_username,
  ca.last_login                                  AS admin_last_login,
  s.plan                                         AS sub_plan,
  s.status                                       AS sub_status,
  s.price_monthly,
  s.currency
FROM clients c
LEFT JOIN client_dbs   db ON db.client_id = c.id
LEFT JOIN client_admins ca ON ca.client_id = c.id AND ca.is_initial = true
LEFT JOIN subscriptions  s ON s.client_id = c.id
ORDER BY c.created_at DESC;

-- ── Función: actualizar updated_at automáticamente ───────────────────────
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE OR REPLACE TRIGGER trg_clients_updated
  BEFORE UPDATE ON clients
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE OR REPLACE TRIGGER trg_client_dbs_updated
  BEFORE UPDATE ON client_dbs
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE OR REPLACE TRIGGER trg_client_admins_updated
  BEFORE UPDATE ON client_admins
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE OR REPLACE TRIGGER trg_subscriptions_updated
  BEFORE UPDATE ON subscriptions
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
