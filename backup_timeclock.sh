#!/bin/bash
DB_HOST="switchyard.proxy.rlwy.net"
DB_PORT="29897"
DB_USER="postgres"
DB_PASSWORD="XESKaZDGhfqGOuyTCzKJSpmusvAukxQS"
DB_NAME="railway"
BACKUP_DIR="./backups"
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/timeclock_backup_$(date +%Y%m%d_%H%M%S).sql"
echo "Creando backup..."
PGPASSWORD="$DB_PASSWORD" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_FILE" 2>&1
if [ -s "$BACKUP_FILE" ]; then
  SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
  echo "Backup exitoso: $BACKUP_FILE ($SIZE)"
else
  echo "Error al crear backup"
  exit 1
fi
