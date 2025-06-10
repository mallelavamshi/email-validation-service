#!/bin/bash
set -e

echo "🚀 Deploying Email Validation Service..."

# Stop existing services
docker-compose down

# Pull latest images and build
docker-compose pull
docker-compose build --no-cache

# Start services
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 45

# Health check with retry
for i in {1..30}; do
    if curl -s http://localhost/health | grep -q "healthy"; then
        echo "✅ Service is running successfully!"
        
        # Display service information
        echo ""
        echo "📊 Service Status:"
        curl -s http://localhost/disposable-domains/status | python3 -m json.tool
        
        echo ""
        echo "🌐 Service URLs:"
        echo "  - Health: http://$(curl -s ifconfig.me)/health"
        echo "  - API Docs: http://$(curl -s ifconfig.me)/docs"
        echo "  - Validate: http://$(curl -s ifconfig.me)/validate"
        echo ""
        echo "📝 Test Commands:"
        echo "  curl -X POST http://localhost/validate -H 'Content-Type: application/json' -d '{\"email\":\"test@gmail.com\"}'"
        echo "  curl http://localhost/disposable-domains/status"
        exit 0
    fi
    echo "Waiting for health check... ($i/30)"
    sleep 5
done

echo "❌ Health check failed"
echo "📋 Container Status:"
docker-compose ps
echo ""
echo "📋 Logs:"
docker-compose logs --tail=20
exit 1