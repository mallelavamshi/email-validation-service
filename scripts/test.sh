#!/bin/bash

echo "🧪 Running Email Validation Tests..."

# Run unit tests
echo "1. Running unit tests..."
docker-compose -f docker-compose.test.yml run --rm email-validator-test

# Run integration tests if service is running
if curl -s http://localhost/health >/dev/null 2>&1; then
    echo ""
    echo "2. Running integration tests..."
    
    echo "Testing regular email:"
    curl -s -X POST http://localhost/validate \
        -H "Content-Type: application/json" \
        -d '{"email":"test@gmail.com"}' | python3 -m json.tool
    
    echo ""
    echo "Testing disposable email:"
    curl -s -X POST http://localhost/validate \
        -H "Content-Type: application/json" \
        -d '{"email":"test@10minutemail.com"}' | python3 -m json.tool
    
    echo ""
    echo "Testing bulk validation:"
    curl -s -X POST http://localhost/validate/bulk \
        -H "Content-Type: application/json" \
        -d '{"emails":["valid@gmail.com","disposable@tempmail.org"]}' | python3 -m json.tool
    
    echo ""
    echo "Checking disposable domains status:"
    curl -s http://localhost/disposable-domains/status | python3 -m json.tool
else
    echo "⚠️  Service not running, skipping integration tests"
    echo "   Run 'scripts/deploy.sh' first"
fi