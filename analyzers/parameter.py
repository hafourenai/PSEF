import re
import json
import base64
from typing import Optional, Tuple, Dict, Any

from models.enums import ParameterType
from utils.logger import get_logger

logger = get_logger(__name__)


class AdvancedParameterAnalyzer:
    """Advanced parameter analysis with crypto detection"""
    
    # Enhanced patterns
    PATTERNS = {
        'numeric_id': re.compile(r'^\d{1,10}$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
        'session_token': re.compile(r'^[A-Za-z0-9+/=]{32,}$'),  # Base64-like
        'jwt': re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),
        'api_key': re.compile(r'^[A-Za-z0-9]{32,64}$'),
        'credit_card': re.compile(r'^\d{13,19}$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'phone': re.compile(r'^\+?[\d\s\-\(\)]{10,}$'),
        'file_path': re.compile(r'^.*\.(php|asp|aspx|jsp|html|htm|txt|pdf|doc|docx)$', re.I),
        'serialized': re.compile(r'^(a|O|s|i|d|b):\d+:'),
        'json': re.compile(r'^[\{\[].*[\}\]]$', re.DOTALL),
        'xml': re.compile(r'^<[^>]+>.*</[^>]+>$', re.DOTALL),
    }
    
    # Parameter name hints
    NAME_HINTS = {
        ParameterType.NUMERIC_ID: ['id', 'user_id', 'product_id', 'num', 'page', 'offset', 'limit'],
        ParameterType.UUID: ['uuid', 'guid', 'uid'],
        ParameterType.SESSION_TOKEN: ['session', 'token', 'auth', 'cookie', 'sid'],
        ParameterType.API_KEY: ['key', 'apikey', 'secret', 'password'],
        ParameterType.JWT_TOKEN: ['jwt', 'bearer', 'authorization'],
        ParameterType.EMAIL: ['email', 'mail', 'username'],
        ParameterType.PHONE: ['phone', 'mobile', 'tel'],
        ParameterType.CREDIT_CARD: ['card', 'cc', 'credit'],
        ParameterType.FILE_PATH: ['file', 'path', 'include', 'document', 'upload'],
        ParameterType.JSON_DATA: ['json', 'data', 'payload'],
        ParameterType.XML_DATA: ['xml', 'soap', 'rss'],
    }
    
    @classmethod
    def analyze(cls, param_name: str, param_value: str) -> Tuple[ParameterType, Dict[str, Any]]:
        """Analyze parameter with detailed metadata"""
        
        metadata = {
            'length': len(param_value),
            'entropy': cls._calculate_entropy(param_value),
            'structure': cls._detect_structure(param_value),
            'guessed_format': None
        }
        
        # 1. Try exact pattern matching
        for param_type_str, pattern in cls.PATTERNS.items():
            if pattern.match(param_value):
                enum_type = ParameterType[param_type_str.upper()]
                metadata['detection_method'] = 'pattern_match'
                return enum_type, metadata
        
        # 2. Try JSON parsing
        if param_value.strip().startswith(('{', '[')):
            try:
                json.loads(param_value)
                metadata['detection_method'] = 'json_parse'
                return ParameterType.JSON_DATA, metadata
            except:
                pass
        
        # 3. Try JWT decoding
        if len(param_value) > 50 and '.' in param_value:
            parts = param_value.split('.')
            if len(parts) == 3:
                try:
                    # Try to decode header
                    header_json = parts[0]
                    # Add padding if needed
                    header_json += '=' * (-len(header_json) % 4)
                    header = json.loads(base64.b64decode(header_json).decode())
                    if 'alg' in header:
                        metadata['jwt_header'] = header
                        metadata['detection_method'] = 'jwt_format'
                        return ParameterType.JWT_TOKEN, metadata
                except:
                    pass
        
        # 4. Check parameter name hints
        param_name_lower = param_name.lower()
        for param_type, hints in cls.NAME_HINTS.items():
            if any(hint in param_name_lower for hint in hints):
                metadata['detection_method'] = 'name_hint'
                metadata['guessed_format'] = param_type.name
                return param_type, metadata
        
        # 5. Default to unknown with analysis
        metadata['detection_method'] = 'unknown'
        return ParameterType.UNKNOWN, metadata
    
    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of string"""
        import math
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(chr(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    @staticmethod
    def _detect_structure(data: str) -> str:
        """Detect data structure"""
        if data.isdigit():
            return 'numeric'
        elif data.isalpha():
            return 'alphabetic'
        elif data.isalnum():
            return 'alphanumeric'
        elif any(c in data for c in './\\'):
            return 'path_like'
        elif '=' in data and '&' in data:
            return 'query_string'
        elif ':' in data and ',' in data:
            return 'key_value'
        
        return 'unstructured'
