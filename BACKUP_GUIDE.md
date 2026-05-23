# 📦 Guía de Backup - TimeClock Enterprise

## Opción 1: Backup Automático en Railway (Recomendado)

### Pasos:
1. Ve a: https://railway.com/project/07898d3e-b3f9-4671-83f8-b8cc33baf951
2. Selecciona el servicio **"Postgres"**
3. Pestaña **"Backups"**
4. Haz clic en **"Create Backup"** para uno manual
5. Para automáticos, busca **"Backup Schedule"** en Settings

**Ventajas:**
- ✅ Almacenado en Railway
- ✅ Fácil de restaurar desde el dashboard
- ✅ Automático si lo configuras

---

## Opción 2: Backup Manual con Script

### Usar el script:
```bash
./backup_timeclock.sh
```

Esto crea un archivo SQL en `./backups/timeclock_backup_YYYYMMDD_HHMMSS.sql`

### Restaurar desde backup:
```bash
PGPASSWORD="XESKaZDGhfqGOuyTCzKJSpmusvAukxQS" psql \
  -h switchyard.proxy.rlwy.net \
  -p 29897 \
  -U postgres \
  -d railway \
  < ./backups/timeclock_backup_20260523_214942.sql
```

---

## Opción 3: Backup Manual con Comando

```bash
PGPASSWORD="XESKaZDGhfqGOuyTCzKJSpmusvAukxQS" pg_dump \
  -h switchyard.proxy.rlwy.net \
  -p 29897 \
  -U postgres \
  -d railway \
  > backup_$(date +%Y%m%d).sql
```

---

## Recomendación de Estrategia

| Frecuencia | Método | Ubicación |
|-----------|--------|-----------|
| Diaria | Railway Automático | Railway Cloud |
| Semanal | Script local | Tu máquina |
| Mensual | Descarga manual | Almacenamiento externo |

---

## Credenciales de BD (Guarda en lugar seguro)

```
Host: switchyard.proxy.rlwy.net
Puerto: 29897
Usuario: postgres
Contraseña: XESKaZDGhfqGOuyTCzKJSpmusvAukxQS
Base de datos: railway
```

⚠️ **IMPORTANTE**: Nunca compartas estas credenciales en GitHub o públicamente.

---

## Verificar Backup

```bash
# Ver tamaño
ls -lh ./backups/

# Ver primeras líneas
head -20 ./backups/timeclock_backup_*.sql

# Contar tablas
grep "CREATE TABLE" ./backups/timeclock_backup_*.sql | wc -l
```

