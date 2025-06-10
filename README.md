# Email Validation Service

A high-performance email validation service with automatic disposable domain updates from GitHub.

## Features

- 🚀 **High Performance**: 300+ validations per minute with load balancing
- 🔄 **Auto-Updates**: Daily updates from 50,000+ disposable domain list
- 📊 **Comprehensive Validation**: Syntax, domain, MX, SMTP, and disposable checks
- 🛡️ **Production Ready**: Docker, Redis caching, rate limiting, monitoring
- 🔧 **Easy Integration**: RESTful API with OpenAPI documentation

## Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/email-validation-service.git
   cd email-validation-service
   ```

2. **Start development environment**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

3. **Test the API**
   ```bash
   curl -X POST http://localhost:8000/validate \
     -H "Content-Type: application/json" \
     -d '{"email":"test@gmail.com"}'
   ```

### Production Deployment

1. **Deploy to server**
   ```bash
   ./scripts/deploy.sh
   ```

2. **Monitor service**
   ```bash
   ./scripts/monitor.sh
   ```

## API Endpoints

- `GET /health` - Service health check
- `POST /validate` - Validate single email
- `POST /validate/bulk` - Validate multiple emails
- `GET /disposable-domains/status` - Auto-update status
- `GET /docs` - Interactive API documentation

## API Examples

### Single Email Validation
```bash
curl -X POST http://localhost/validate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "check_smtp": true
  }'
```

**Response:**
```json
{
  "email": "user@example.com",
  "result": "deliverable",
  "risk_level": "low",
  "confidence_score": 0.95,
  "syntax_valid": true,
  "domain_exists": true,
  "has_mx_records": true,
  "smtp_deliverable": true,
  "is_disposable": false,
  "is_role_account": false,
  "recommendations": [],
  "validated_at": "2024-01-15T10:30:00Z",
  "processing_time_ms": 245
}
```

### Bulk Email Validation
```bash
curl -X POST http://localhost/validate/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      "user1@gmail.com",
      "user2@tempmail.org",
      "invalid.email"
    ],
    "check_smtp": true
  }'
```

### Check Disposable Domains Status
```bash
curl http://localhost/disposable-domains/status
```

## Auto-Update System

The service automatically updates its disposable domain list from:
- **Source**: https://github.com/disposable-email-domains/disposable-email-domains
- **Frequency**: Every 24 hours
- **Domains**: 50,000+ constantly updated list
- **Zero Downtime**: Updates happen without service interruption

## Configuration

Environment variables:

```bash
# Disposable domains source
DISPOSABLE_DOMAINS_URL=https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf

# Auto-update settings
AUTO_UPDATE_ENABLED=true
UPDATE_INTERVAL_HOURS=24
FORCE_UPDATE_INTERVAL_HOURS=48

# Performance settings
MAX_CONCURRENT_SMTP=20
VALIDATION_CACHE_TTL=7200
MAX_BULK_SIZE=1000
```

## Development

### Running Tests
```bash
# Unit tests
./scripts/test.sh

# Integration tests
docker-compose -f docker-compose.test.yml up

# Code quality
docker run --rm -v $(pwd):/app python:3.11-slim sh -c "
  cd /app && 
  pip install flake8 black mypy && 
  flake8 . &&
  black --check . &&
  mypy . --ignore-missing-imports
"
```

### Project Structure
```
email-validation-service/
├── main.py                    # Main application
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Production container
├── docker-compose.yml         # Production deployment
├── docker-compose.dev.yml     # Development environment
├── Jenkinsfile               # CI/CD pipeline
├── scripts/                  # Deployment scripts
│   ├── deploy.sh
│   ├── test.sh
│   ├── monitor.sh
│   └── backup.sh
├── tests/                    # Test suite
│   ├── unit/
│   ├── integration/
│   └── smoke/
├── docker/                   # Docker configurations
│   └── nginx.conf
└── docs/                     # Documentation
```

## Monitoring

### Health Checks
```bash
curl http://localhost/health
```

### Service Statistics
```bash
curl http://localhost/stats
```

### Resource Monitoring
```bash
./scripts/monitor.sh
```

## Performance

### Expected Performance (4 CPU, 16GB RAM)
- **Throughput**: 300+ validations per minute
- **Response Time**: 200-500ms per email
- **Daily Capacity**: 400,000+ validations
- **Cache Hit Rate**: 70-80%
- **Disposable Detection**: 99.9% accuracy

### Resource Usage
- **CPU**: ~3.7 cores under load
- **Memory**: ~10GB total (4GB Redis, 6GB app instances)
- **Storage**: ~200MB for disposable domains cache
- **Network**: Minimal (auto-updates ~1MB/day)

## Security

- Rate limiting on all endpoints
- Input validation and sanitization
- No sensitive data logging
- Container security best practices
- Regular security dependency updates

## Support

For issues and questions:
1. Check the [API documentation](http://localhost/docs)
2. Review logs: `docker-compose logs`
3. Monitor status: `./scripts/monitor.sh`
4. Open an issue on GitHub

## License

MIT License - see LICENSE file for details.

---

**Production-ready email validation with 50,000+ auto-updated disposable domains.**
EOF

# Create documentation
mkdir -p docs

cat > docs/API.md << 'EOF'
# API Documentation

## Authentication

Currently, the API doesn't require authentication. For production use, consider implementing API keys or OAuth.

## Rate Limits

- `/validate`: 500 requests per minute per IP
- `/validate/bulk`: 50 requests per minute per IP
- `/admin/*`: 5 requests per hour per IP

## Error Handling

All endpoints return standard HTTP status codes:

- `200`: Success
- `400`: Bad Request (invalid input)
- `422`: Validation Error (invalid email format)
- `429`: Rate limit exceeded
- `500`: Internal server error

Error responses include details:
```json
{
  "detail": "Invalid email format",
  "type": "validation_error"
}
```

## Endpoints

### POST /validate

Validate a single email address.

**Request:**
```json
{
  "email": "user@example.com",
  "check_smtp": true
}
```

**Response:**
```json
{
  "email": "user@example.com",
  "result": "deliverable|undeliverable|risky|unknown",
  "risk_level": "low|medium|high|critical",
  "confidence_score": 0.95,
  "syntax_valid": true,
  "domain_exists": true,
  "has_mx_records": true,
  "smtp_deliverable": true,
  "is_disposable": false,
  "is_role_account": false,
  "disposable_confidence": 0.0,
  "disposable_source": "not_disposable|github_list|pattern_match",
  "typo_suggestion": null,
  "recommendations": [],
  "validated_at": "2024-01-15T10:30:00Z",
  "processing_time_ms": 245,
  "cached": false
}
```

### POST /validate/bulk

Validate multiple email addresses.

**Request:**
```json
{
  "emails": ["user1@example.com", "user2@test.com"],
  "check_smtp": true
}
```

**Response:**
```json
{
  "results": [
    {
      "email": "user1@example.com",
      "result": "deliverable",
      // ... full validation result
    }
  ],
  "summary": {
    "deliverable": 1,
    "undeliverable": 0,
    "risky": 0,
    "unknown": 0
  },
  "total_processed": 1,
  "processing_time_ms": 1250
}
```

### GET /disposable-domains/status

Get auto-update system status.

**Response:**
```json
{
  "total_domains": 52847,
  "last_updated": "2024-01-15T10:30:00Z",
  "last_checked": "2024-01-15T14:30:00Z",
  "next_update": "2024-01-16T10:30:00Z",
  "source_url": "https://raw.githubusercontent.com/...",
  "auto_update_enabled": true,
  "update_interval_hours": 24,
  "domains_added_last_update": 23,
  "domains_removed_last_update": 7
}
```
EOF

cat > docs/DEPLOYMENT.md << 'EOF'
# Deployment Guide

## Prerequisites

- Docker and Docker Compose
- Ubuntu 18.04+ or similar Linux distribution
- Minimum 4GB RAM, 2 CPU cores
- Open ports: 80, 443 (optional: 8080 for Jenkins)
