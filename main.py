#!/bin/bash

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Set
import asyncio
import aioredis
import aiohttp
import aiodns
import json
import time
import hashlib
import gzip
import pickle
import re
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import difflib
import smtplib
import socket
from concurrent.futures import ThreadPoolExecutor
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Config:
    """Configuration loaded from environment variables"""
    disposable_domains_url: str = os.getenv(
        'DISPOSABLE_DOMAINS_URL', 
        'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf'
    )
    auto_update_enabled: bool = os.getenv('AUTO_UPDATE_ENABLED', 'true').lower() == 'true'
    update_interval_hours: int = int(os.getenv('UPDATE_INTERVAL_HOURS', '24'))
    force_update_interval_hours: int = int(os.getenv('FORCE_UPDATE_INTERVAL_HOURS', '48'))
    validation_cache_ttl: int = int(os.getenv('VALIDATION_CACHE_TTL', '7200'))
    max_bulk_size: int = int(os.getenv('MAX_BULK_SIZE', '1000'))
    smtp_timeout: int = int(os.getenv('SMTP_TIMEOUT', '25'))
    max_concurrent_smtp: int = int(os.getenv('MAX_CONCURRENT_SMTP', '20'))
    redis_url: str = os.getenv('REDIS_URL', 'redis://redis:6379')

class ValidationResult(str, Enum):
    DELIVERABLE = "deliverable"
    UNDELIVERABLE = "undeliverable"
    RISKY = "risky"
    UNKNOWN = "unknown"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EmailValidationResult(BaseModel):
    email: str
    result: ValidationResult
    risk_level: RiskLevel
    confidence_score: float
    syntax_valid: bool
    domain_exists: bool
    has_mx_records: bool
    smtp_deliverable: Optional[bool] = None
    is_disposable: bool
    is_role_account: bool
    disposable_confidence: float
    disposable_source: str = ""
    typo_suggestion: Optional[str] = None
    recommendations: List[str] = []
    validated_at: datetime
    processing_time_ms: int
    cached: bool = False

class EmailValidationRequest(BaseModel):
    email: EmailStr
    check_smtp: bool = True

class BulkEmailValidationRequest(BaseModel):
    emails: List[EmailStr]
    check_smtp: bool = True

class DisposableDomainsStatus(BaseModel):
    total_domains: int
    last_updated: Optional[str]
    last_checked: Optional[str]
    next_update: Optional[str]
    source_url: str
    auto_update_enabled: bool
    update_interval_hours: int
    domains_added_last_update: int = 0
    domains_removed_last_update: int = 0

class DisposableDomainAutoUpdater:
    def __init__(self, redis_client, config: Config):
        self.redis = redis_client
        self.config = config
        self.domains_key = "disposable_domains:compressed_v2"
        self.metadata_key = "disposable_domains:metadata_v2"
        self.last_check_key = "disposable_domains:last_check_v2"
        self.disposable_domains: Set[str] = set()
        self.update_task = None
        self.running = False
    
    async def start_auto_updates(self):
        if not self.config.auto_update_enabled:
            logger.info("Auto-updates disabled in configuration")
            return
        
        if self.running:
            return
        
        self.running = True
        self.update_task = asyncio.create_task(self._update_loop())
        logger.info(f"Started auto-updater for disposable domains (every {self.config.update_interval_hours}h)")
    
    async def stop_auto_updates(self):
        self.running = False
        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped auto-updater for disposable domains")
    
    async def _update_loop(self):
        while self.running:
            try:
                result = await self.check_and_update()
                if result.get('success'):
                    if result.get('updated'):
                        logger.info(f"Auto-update successful: {result.get('total_domains')} domains loaded")
                    else:
                        logger.debug("Auto-update check: no changes detected")
                else:
                    logger.warning(f"Auto-update failed: {result.get('error')}")
                
                await asyncio.sleep(3600)  # 1 hour
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto-update loop: {e}")
                await asyncio.sleep(1800)  # Wait 30 minutes on error
    
    async def fetch_from_github(self) -> Optional[Set[str]]:
        try:
            logger.info(f"Fetching disposable domains from: {self.config.disposable_domains_url}")
            
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.config.disposable_domains_url) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}: {response.reason}")
                    
                    content = await response.text()
                    domains = set()
                    lines_processed = 0
                    
                    for line in content.strip().split('\n'):
                        lines_processed += 1
                        domain = line.strip().lower()
                        
                        if not domain or domain.startswith('#') or domain.startswith('//'):
                            continue
                        
                        domain = self._clean_domain(domain)
                        
                        if self._is_valid_domain(domain):
                            domains.add(domain)
                    
                    logger.info(f"Processed {lines_processed} lines, extracted {len(domains)} valid domains")
                    
                    if len(domains) < 1000:
                        raise Exception(f"Domain count too low: {len(domains)} (expected > 1000)")
                    
                    return domains
                    
        except Exception as e:
            logger.error(f"Failed to fetch domains from GitHub: {e}")
            return None
    
    def _clean_domain(self, domain: str) -> str:
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        if '/' in domain:
            domain = domain.split('/')[0]
        if ':' in domain and not domain.count(':') > 1:
            domain = domain.split(':')[0]
        return domain.strip().lower()
    
    def _is_valid_domain(self, domain: str) -> bool:
        if not domain or len(domain) < 3 or len(domain) > 253:
            return False
        if '.' not in domain:
            return False
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        if domain.startswith(('.', '-')) or domain.endswith(('.', '-')):
            return False
        parts = domain.split('.')
        if len(parts) < 2 or len(parts[-1]) < 2:
            return False
        return True
    
    async def should_update(self) -> tuple[bool, str]:
        try:
            last_check = await self.redis.get(self.last_check_key)
            
            if not last_check:
                return True, "No previous update found"
            
            last_check_time = datetime.fromisoformat(last_check)
            time_since_check = datetime.utcnow() - last_check_time
            hours_since_check = time_since_check.total_seconds() / 3600
            
            if hours_since_check > self.config.force_update_interval_hours:
                return True, f"Force update after {hours_since_check:.1f} hours"
            
            if hours_since_check > self.config.update_interval_hours:
                return True, f"Regular update after {hours_since_check:.1f} hours"
            
            next_update_hours = self.config.update_interval_hours - hours_since_check
            return False, f"Next update in {next_update_hours:.1f} hours"
            
        except Exception as e:
            logger.error(f"Error checking update schedule: {e}")
            return True, "Error checking schedule - forcing update"
    
    async def check_and_update(self, force: bool = False) -> dict:
        try:
            should_update, reason = await self.should_update()
            
            if not should_update and not force:
                return {
                    'success': True,
                    'updated': False,
                    'reason': reason,
                    'total_domains': len(self.disposable_domains)
                }
            
            logger.info(f"Checking for disposable domain updates: {reason}")
            
            new_domains = await self.fetch_from_github()
            
            if new_domains is None:
                return {
                    'success': False,
                    'error': 'Failed to fetch domains from GitHub'
                }
            
            current_domains = await self.load_from_cache()
            content_changed = new_domains != current_domains
            
            if not content_changed and not force:
                logger.info("No changes detected in disposable domains")
                await self.redis.setex(
                    self.last_check_key,
                    self.config.update_interval_hours * 3600 * 2,
                    datetime.utcnow().isoformat()
                )
                return {
                    'success': True,
                    'updated': False,
                    'reason': 'No changes detected',
                    'total_domains': len(new_domains)
                }
            
            result = await self.update_domains(new_domains, current_domains)
            
            if result['success']:
                self.disposable_domains = new_domains
                logger.info(f"Successfully updated disposable domains: "
                           f"{len(new_domains)} total, "
                           f"+{result['added']} added, "
                           f"-{result['removed']} removed")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in check_and_update: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def update_domains(self, new_domains: Set[str], current_domains: Set[str]) -> dict:
        try:
            added_domains = new_domains - current_domains
            removed_domains = current_domains - new_domains
            
            compressed_data = gzip.compress(pickle.dumps(new_domains))
            await self.redis.setex(
                self.domains_key,
                self.config.update_interval_hours * 3600 * 2,
                compressed_data.decode('latin1')
            )
            
            metadata = {
                'total_domains': len(new_domains),
                'domains_added': len(added_domains),
                'domains_removed': len(removed_domains),
                'updated_at': datetime.utcnow().isoformat(),
                'source_url': self.config.disposable_domains_url,
                'version': '2.0'
            }
            
            await self.redis.setex(
                self.metadata_key,
                self.config.update_interval_hours * 3600 * 2,
                json.dumps(metadata)
            )
            
            await self.redis.setex(
                self.last_check_key,
                self.config.update_interval_hours * 3600 * 2,
                datetime.utcnow().isoformat()
            )
            
            return {
                'success': True,
                'updated': True,
                'total_domains': len(new_domains),
                'added': len(added_domains),
                'removed': len(removed_domains),
                'updated_at': metadata['updated_at']
            }
            
        except Exception as e:
            logger.error(f"Failed to update domains in Redis: {e}")
            return {'success': False, 'error': str(e)}
    
    async def load_from_cache(self) -> Set[str]:
        try:
            cached_data = await self.redis.get(self.domains_key)
            if cached_data:
                domains_bytes = cached_data.encode('latin1')
                return pickle.loads(gzip.decompress(domains_bytes))
            return set()
        except Exception as e:
            logger.error(f"Failed to load domains from cache: {e}")
            return set()
    
    async def initialize(self):
        self.disposable_domains = await self.load_from_cache()
        
        if not self.disposable_domains:
            logger.info("No cached disposable domains found, performing initial update...")
            result = await self.check_and_update(force=True)
            
            if result.get('success'):
                logger.info(f"Initial update successful: {result.get('total_domains')} domains loaded")
            else:
                logger.error(f"Initial update failed: {result.get('error')}")
                self.disposable_domains = self._get_fallback_domains()
        else:
            logger.info(f"Loaded {len(self.disposable_domains)} disposable domains from cache")
        
        await self.start_auto_updates()
    
    def _get_fallback_domains(self) -> Set[str]:
        return {
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'throwaway.email',
            'getnada.com', 'maildrop.cc', 'temp-mail.org'
        }
    
    async def get_status(self) -> DisposableDomainsStatus:
        try:
            metadata_str = await self.redis.get(self.metadata_key)
            metadata = json.loads(metadata_str) if metadata_str else {}
            
            last_check = await self.redis.get(self.last_check_key)
            
            next_update = None
            if last_check:
                last_check_time = datetime.fromisoformat(last_check)
                next_update_time = last_check_time + timedelta(hours=self.config.update_interval_hours)
                next_update = next_update_time.isoformat()
            
            return DisposableDomainsStatus(
                total_domains=len(self.disposable_domains),
                last_updated=metadata.get('updated_at'),
                last_checked=last_check,
                next_update=next_update,
                source_url=self.config.disposable_domains_url,
                auto_update_enabled=self.config.auto_update_enabled,
                update_interval_hours=self.config.update_interval_hours,
                domains_added_last_update=metadata.get('domains_added', 0),
                domains_removed_last_update=metadata.get('domains_removed', 0)
            )
            
        except Exception as e:
            logger.error(f"Error getting disposable domains status: {e}")
            return DisposableDomainsStatus(
                total_domains=len(self.disposable_domains),
                last_updated=None,
                last_checked=None,
                next_update=None,
                source_url=self.config.disposable_domains_url,
                auto_update_enabled=self.config.auto_update_enabled,
                update_interval_hours=self.config.update_interval_hours
            )

class EmailValidatorWithAutoUpdate:
    def __init__(self):
        self.config = Config()
        self.redis = None
        self.domain_updater = None
        self.dns_resolver = aiodns.DNSResolver(timeout=10)
        self.smtp_semaphore = asyncio.Semaphore(self.config.max_concurrent_smtp)
        
        self.typo_map = {
            'gmai.com': 'gmail.com', 'gmail.co': 'gmail.com', 'gmial.com': 'gmail.com',
            'yaho.com': 'yahoo.com', 'yahoo.co': 'yahoo.com',
            'hotmai.com': 'hotmail.com', 'outlook.co': 'outlook.com'
        }
        
        self.role_patterns = {
            'admin', 'support', 'info', 'contact', 'sales', 'marketing',
            'noreply', 'no-reply', 'help', 'service', 'team', 'billing'
        }
    
    async def initialize(self):
        self.redis = aioredis.from_url(self.config.redis_url, decode_responses=True)
        self.domain_updater = DisposableDomainAutoUpdater(self.redis, self.config)
        await self.domain_updater.initialize()
        logger.info("Email validator with auto-update initialized")
    
    async def shutdown(self):
        if self.domain_updater:
            await self.domain_updater.stop_auto_updates()
        if self.redis:
            await self.redis.close()
    
    def validate_syntax(self, email: str) -> bool:
        if '@' not in email or email.count('@') != 1:
            return False
        
        local, domain = email.rsplit('@', 1)
        
        if len(local) == 0 or len(local) > 64 or len(domain) > 253:
            return False
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def suggest_typo_correction(self, domain: str) -> Optional[str]:
        return self.typo_map.get(domain.lower())
    
    def is_role_account(self, email: str) -> bool:
        local_part = email.split('@')[0].lower()
        return any(pattern in local_part for pattern in self.role_patterns)
    
    async def is_disposable_domain(self, domain: str) -> tuple[bool, float, str]:
        domain_lower = domain.lower()
        
        if domain_lower in self.domain_updater.disposable_domains:
            return True, 1.0, "github_list"
        
        patterns = [
            (r'.*temp.*mail.*', 0.9), (r'.*10min.*', 0.95), (r'.*throwaway.*', 0.9),
            (r'.*guerrilla.*', 0.95), (r'.*\.tk$', 0.7), (r'.*\.ml$', 0.7), (r'^[0-9]+\..*', 0.6)
        ]
        
        for pattern, confidence in patterns:
            if re.match(pattern, domain_lower):
                return True, confidence, "pattern_match"
        
        return False, 0.0, "not_disposable"
    
    async def validate_domain(self, domain: str) -> dict:
        result = {'exists': False, 'mx_records': [], 'typo_suggestion': None}
        
        try:
            result['typo_suggestion'] = self.suggest_typo_correction(domain)
            
            try:
                await self.dns_resolver.query(domain, 'A')
                result['exists'] = True
            except:
                pass
            
            try:
                mx_result = await self.dns_resolver.query(domain, 'MX')
                result['mx_records'] = [mx.host for mx in mx_result]
                result['exists'] = True
            except:
                pass
            
        except Exception as e:
            logger.warning(f"Domain validation error for {domain}: {e}")
        
        return result
    
    async def validate_smtp(self, email: str, mx_records: List[str]) -> dict:
        if not mx_records:
            return {'deliverable': False, 'message': 'No MX records'}
        
        async with self.smtp_semaphore:
            for mx_server in mx_records[:3]:
                try:
                    loop = asyncio.get_event_loop()
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        result = await loop.run_in_executor(
                            executor, self._smtp_check, email, mx_server
                        )
                    
                    if result:
                        return result
                        
                except Exception as e:
                    logger.warning(f"SMTP check failed for {mx_server}: {e}")
                    continue
            
            return {'deliverable': False, 'message': 'All SMTP servers failed'}
    
    def _smtp_check(self, email: str, mx_server: str) -> Optional[dict]:
        try:
            with smtplib.SMTP(timeout=self.config.smtp_timeout) as smtp:
                smtp.connect(mx_server, 25)
                smtp.helo('validator.example.com')
                smtp.mail('test@validator.example.com')
                
                code, message = smtp.rcpt(email)
                
                return {
                    'deliverable': code == 250,
                    'code': code,
                    'message': str(message),
                    'server': mx_server
                }
        except Exception:
            return None
    
    def calculate_confidence_score(self, checks: dict) -> float:
        score = 0.0
        
        if checks['syntax_valid']:
            score += 0.2
        if checks['domain_exists']:
            score += 0.2
        if checks['has_mx_records']:
            score += 0.2
        if checks.get('smtp_deliverable'):
            score += 0.3
        
        if checks['is_disposable']:
            score -= 0.3
        if checks['is_role_account']:
            score -= 0.1
        
        return max(0.0, min(1.0, score))
    
    def determine_result_and_risk(self, checks: dict, confidence: float) -> tuple[ValidationResult, RiskLevel]:
        if checks['is_disposable']:
            return ValidationResult.RISKY, RiskLevel.CRITICAL
        
        if not checks['syntax_valid'] or not checks['domain_exists']:
            return ValidationResult.UNDELIVERABLE, RiskLevel.HIGH
        
        if checks.get('smtp_deliverable') is True:
            return ValidationResult.DELIVERABLE, RiskLevel.LOW
        elif checks.get('smtp_deliverable') is False:
            return ValidationResult.UNDELIVERABLE, RiskLevel.HIGH
        
        if confidence >= 0.7:
            return ValidationResult.RISKY, RiskLevel.MEDIUM
        else:
            return ValidationResult.UNKNOWN, RiskLevel.HIGH
    
    async def validate_email(self, email: str, check_smtp: bool = True) -> EmailValidationResult:
        start_time = time.time()
        
        cache_key = f"validation:{hashlib.md5(email.encode()).hexdigest()}"
        cached = await self.redis.get(cache_key)
        
        if cached:
            result = EmailValidationResult.parse_raw(cached)
            result.cached = True
            return result
        
        domain = email.split('@')[1] if '@' in email else ''
        
        checks = {
            'syntax_valid': self.validate_syntax(email),
            'domain_exists': False,
            'has_mx_records': False,
            'smtp_deliverable': None,
            'is_disposable': False,
            'is_role_account': self.is_role_account(email)
        }
        
        recommendations = []
        typo_suggestion = None
        disposable_source = ""
        disposable_confidence = 0.0
        
        if checks['syntax_valid'] and domain:
            domain_info = await self.validate_domain(domain)
            checks['domain_exists'] = domain_info['exists']
            checks['has_mx_records'] = len(domain_info['mx_records']) > 0
            typo_suggestion = domain_info['typo_suggestion']
            
            if typo_suggestion:
                recommendations.append(f"Did you mean {typo_suggestion}?")
            
            is_disposable, disposable_confidence, disposable_source = await self.is_disposable_domain(domain)
            checks['is_disposable'] = is_disposable
            
            if check_smtp and checks['has_mx_records']:
                smtp_result = await self.validate_smtp(email, domain_info['mx_records'])
                checks['smtp_deliverable'] = smtp_result.get('deliverable')
        
        confidence_score = self.calculate_confidence_score(checks)
        result_status, risk_level = self.determine_result_and_risk(checks, confidence_score)
        
        if checks['is_disposable']:
            if disposable_source == "github_list":
                recommendations.append("Disposable email detected (verified from updated blocklist)")
            else:
                recommendations.append("Suspicious disposable email pattern detected")
        if checks['is_role_account']:
            recommendations.append("Role-based email - may have lower engagement")
        if not checks['syntax_valid']:
            recommendations.append("Invalid email format")
        
        result = EmailValidationResult(
            email=email,
            result=result_status,
            risk_level=risk_level,
            confidence_score=confidence_score,
            syntax_valid=checks['syntax_valid'],
            domain_exists=checks['domain_exists'],
            has_mx_records=checks['has_mx_records'],
            smtp_deliverable=checks['smtp_deliverable'],
            is_disposable=checks['is_disposable'],
            is_role_account=checks['is_role_account'],
            disposable_confidence=disposable_confidence,
            disposable_source=disposable_source,
            typo_suggestion=typo_suggestion,
            recommendations=recommendations,
            validated_at=datetime.utcnow(),
            processing_time_ms=int((time.time() - start_time) * 1000),
            cached=False
        )
        
        await self.redis.setex(cache_key, self.config.validation_cache_ttl, result.json())
        
        return result

validator = EmailValidatorWithAutoUpdate()

app = FastAPI(
    title="Email Validation Service with Auto-Updates",
    description="High-performance email validation with automatic disposable domain updates from GitHub",
    version="2.1.0"
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.on_event("startup")
async def startup_event():
    await validator.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    await validator.shutdown()

@app.get("/health")
async def health_check():
    disposable_status = await validator.domain_updater.get_status()
    return {
        "status": "healthy",
        "disposable_domains_loaded": disposable_status.total_domains,
        "auto_update_enabled": disposable_status.auto_update_enabled,
        "last_updated": disposable_status.last_updated,
        "instance": os.getenv('INSTANCE_NAME', 'unknown')
    }

@app.post("/validate", response_model=EmailValidationResult)
@limiter.limit("500/minute")
async def validate_single_email(request: EmailValidationRequest, req: Request):
    return await validator.validate_email(request.email, request.check_smtp)

@app.post("/validate/bulk")
@limiter.limit("50/minute")
async def validate_bulk_emails(request: BulkEmailValidationRequest, req: Request):
    if len(request.emails) > validator.config.max_bulk_size:
        raise HTTPException(status_code=400, detail=f"Maximum {validator.config.max_bulk_size} emails per request")
    
    start_time = time.time()
    
    tasks = [validator.validate_email(email, request.check_smtp) for email in request.emails]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = []
    summary = {'deliverable': 0, 'undeliverable': 0, 'risky': 0, 'unknown': 0}
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Validation error for {request.emails[i]}: {result}")
            error_result = EmailValidationResult(
                email=str(request.emails[i]),
                result=ValidationResult.UNKNOWN,
                risk_level=RiskLevel.HIGH,
                confidence_score=0.0,
                syntax_valid=False,
                domain_exists=False,
                has_mx_records=False,
                is_disposable=False,
                is_role_account=False,
                disposable_confidence=0.0,
                validated_at=datetime.utcnow(),
                processing_time_ms=0
            )
            valid_results.append(error_result)
            summary['unknown'] += 1
        else:
            valid_results.append(result)
            summary[result.result.value] += 1
    
    return {
        "results": valid_results,
        "summary": summary,
        "total_processed": len(valid_results),
        "processing_time_ms": int((time.time() - start_time) * 1000)
    }

@app.get("/disposable-domains/status", response_model=DisposableDomainsStatus)
async def get_disposable_domains_status():
    return await validator.domain_updater.get_status()

@app.post("/admin/disposable-domains/update")
@limiter.limit("5/hour")
async def force_update_disposable_domains(req: Request):
    try:
        result = await validator.domain_updater.check_and_update(force=True)
        return {
            "status": "success" if result.get('success') else "failed",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_validation_stats():
    disposable_status = await validator.domain_updater.get_status()
    
    return {
        "disposable_domains": {
            "total_domains": disposable_status.total_domains,
            "last_updated": disposable_status.last_updated,
            "next_update": disposable_status.next_update,
            "auto_update_enabled": disposable_status.auto_update_enabled
        },
        "redis_info": {
            "total_keys": await validator.redis.dbsize()
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)