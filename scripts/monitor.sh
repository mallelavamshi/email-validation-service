#!/bin/bash

echo "📊 Email Validation Service Monitor"
echo "=================================="

# Check if service is running
if ! curl -s http://localhost/health >/dev/null; then
    echo "❌ Service is not responding"
    echo ""
    echo "🐳 Container Status:"
    docker-compose ps
    exit 1
fi

echo "✅ Service is healthy"
echo ""

# Get service stats
echo "📈 Service Statistics:"
curl -s http://localhost/stats | python3 -m json.tool

echo ""
echo "🗂️  Disposable Domains Status:"
curl -s http://localhost/disposable-domains/status | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'  Total domains: {data[\"total_domains\"]:,}')
print(f'  Last updated: {data[\"last_updated\"]}')
print(f'  Next update: {data[\"next_update\"]}')
print(f'  Auto-update: {data[\"auto_update_enabled\"]}')
"

echo ""
echo "💾 Resource Usage:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

echo ""
echo "🐳 Container Health:"
docker-compose ps