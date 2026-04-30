-- Run this in Railway PostgreSQL Data tab to fix user passwords
-- This REPLACES the entire data field with clean values

INSERT INTO system_users(id, username, data) VALUES
('su1', 'admin',  '{"username":"admin",  "password":"admin2025", "name":"Administrador",  "role":"admin",  "status":"active"}'),
('su2', 'rrhh',   '{"username":"rrhh",   "password":"rh2025",    "name":"Coord. RRHH",    "role":"editor", "status":"active"}'),
('su3', 'nomina', '{"username":"nomina", "password":"nom2025",   "name":"Coord. Nomina",  "role":"editor", "status":"active"}'),
('su4', 'viewer', '{"username":"viewer", "password":"view2025",  "name":"Auditor",        "role":"viewer", "status":"active"}')
ON CONFLICT(id) DO UPDATE SET 
  data = EXCLUDED.data,
  username = EXCLUDED.username,
  updated_at = NOW();

-- Verify
SELECT id, data->>'username' as username, data->>'password' as password, data->>'status' as status 
FROM system_users;
