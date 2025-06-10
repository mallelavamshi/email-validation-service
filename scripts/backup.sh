#!/bin/bash

BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)

echo "💾 Creating backup..."

mkdir -p $BACKUP_DIR

# Backup Redis data
echo "Backing up Redis data..."
docker exec email-validation-service-redis-1 redis-cli BGSAVE
sleep 5
docker cp email-validation-service-redis-1:/data/dump.rdb $BACKUP_DIR/redis_backup_$DATE.rdb

# Backup configuration
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz \
    docker-compose.yml \
    docker/ \
    scripts/ \
    .env

echo "✅ Backup completed: $BACKUP_DIR"
echo "📁 Files created:"
ls -la $BACKUP_DIR/*$DATE*

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*backup_*" -mtime +7 -delete