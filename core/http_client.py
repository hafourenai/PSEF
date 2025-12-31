import time
import ssl
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

from utils.security import SecuritySanitizer
from utils.logger import get_logger

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = get_logger(__name__)


class SecureHTTPClient:
    """Secure HTTP client with proper SSL, rate limiting, and safety checks"""
    
    def __init__(self, verify_ssl: bool = True, timeout: int = 30):
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.rate_limit_delay = 0.5  # seconds between requests
        
        # Custom SSL context
        if verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = True
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            # For testing only - clearly marked
            logger.warning("SSL verification disabled - for testing only")
            self.ssl_context = None
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set secure headers
        self.session.headers.update({
            'User-Agent': 'PSEF-Security-Scanner/2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',  # Prevent connection pooling for safety
        })
    
    def send_request(self, 
                    url: str,
                    method: str = 'GET',
                    params: Optional[Dict] = None,
                    data: Optional[Dict] = None,
                    headers: Optional[Dict] = None,
                    allow_redirects: bool = False) -> Tuple[Optional[requests.Response], float]:
        """
        Send HTTP request with security controls
        
        Returns: (response, response_time) or (None, 0.0) on failure
        """
        start_time = time.time()
        
        # Sanitize and validate URL
        sanitized_url, is_valid = SecuritySanitizer.sanitize_url(url)
        if not is_valid:
            logger.error(f"Invalid or dangerous URL blocked: {url}")
            return None, 0.0
        
        # Rate limiting
        time.sleep(self.rate_limit_delay)
        
        try:
            # Prepare request
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            # Send request
            response = self.session.request(
                method=method.upper(),
                url=sanitized_url,
                params=params,
                data=data,
                headers=request_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_ssl,
                stream=False  # Don't stream for security
            )
            
            response_time = time.time() - start_time
            
            # Log request (safely)
            safe_params = {k: SecuritySanitizer.sanitize_payload(str(v)) 
                          for k, v in (params or {}).items()}
            logger.info(f"{method} {sanitized_url} - {response.status_code} "
                       f"({response_time:.2f}s)")
            
            return response, response_time
            
        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout: {sanitized_url}")
            return None, time.time() - start_time
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error: {e}")
            return None, time.time() - start_time
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None, time.time() - start_time
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None, time.time() - start_time
    
    def close(self):
        """Cleanup resources"""
        self.session.close()
