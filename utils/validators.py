import urllib.parse
import re

def validate_url(url: str) -> bool:
    """Check if URL is valid and uses allowed schemes"""
    try:
        parsed = urllib.parse.urlparse(url)
        return all([parsed.scheme, parsed.netloc]) and parsed.scheme in ['http', 'https']
    except:
        return False

def validate_http_method(method: str) -> bool:
    """Check if HTTP method is valid"""
    return method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

def validate_email(email: str) -> bool:
    """Basic email validation"""
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))
