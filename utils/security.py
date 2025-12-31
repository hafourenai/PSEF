import re
import html
import urllib.parse
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class SecuritySanitizer:
    """Prevent accidental exploitation of our own framework"""
    
    @staticmethod
    def sanitize_url(url: str) -> Tuple[str, bool]:
        """Validate and sanitize URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Block dangerous protocols
            if parsed.scheme not in ['http', 'https']:
                logger.warning(f"Blocked non-HTTP protocol: {parsed.scheme}")
                return "", False
            
            # Prevent SSRF attempts
            blacklisted_netlocs = [
                'localhost', '127.0.0.1', '169.254.169.254',
                '192.168.', '10.', '172.16.', '0.0.0.0'
            ]
            
            if any(parsed.netloc.startswith(bl) for bl in blacklisted_netlocs):
                logger.warning(f"Blocked internal network access: {parsed.netloc}")
                return "", False
            
            # Reconstruct sanitized URL
            sanitized = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                urllib.parse.quote(parsed.path),
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            return sanitized, True
            
        except Exception as e:
            logger.error(f"URL sanitization failed: {e}")
            return "", False
    
    @staticmethod
    def sanitize_payload(payload: str, context: str = 'general') -> str:
        """Sanitize payloads to prevent self-XSS"""
        if context == 'xss':
            # HTML encode for display contexts
            return html.escape(payload)
        elif context == 'sql':
            # Basic SQL injection prevention for logging
            return re.sub(r'[\'"\\;]', '', payload)
        return payload
    
    @staticmethod
    def validate_finding(finding_data: dict) -> bool:
        """Validate scanner finding before processing"""
        required_fields = ['target', 'endpoint', 'method', 'parameter', 
                          'value', 'vulnerability_type']
        
        if not all(field in finding_data for field in required_fields):
            return False
        
        # Validate HTTP method
        if finding_data['method'].upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            return False
        
        # Validate vulnerability type
        from models.enums import VulnerabilityType
        try:
            # Check if it's already an enum or a string that matches
            v_type = finding_data['vulnerability_type']
            if isinstance(v_type, str):
                VulnerabilityType[v_type.upper()]
            elif isinstance(v_type, VulnerabilityType):
                pass
            else:
                return False
        except (KeyError, ValueError, AttributeError):
            return False
        
        return True
