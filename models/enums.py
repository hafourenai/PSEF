from enum import Enum, auto
from typing import Optional


class VulnerabilityType(Enum):
    """Vulnerability types with proper validation"""
    SQL_INJECTION = auto()
    XSS = auto()
    IDOR = auto()
    LFI = auto()
    RFI = auto()
    SSTI = auto()
    COMMAND_INJECTION = auto()
    SSRF = auto()
    AUTH_BYPASS = auto()
    LOGIC_FLAW = auto()
    XXE = auto()
    DESERIALIZATION = auto()
    SERVICE_DETECTION = auto()
    JSONP = auto()
    
    @classmethod
    def from_string(cls, value: str) -> Optional['VulnerabilityType']:
        """Safely convert string to enum"""
        try:
            return cls[value.upper()]
        except (KeyError, AttributeError):
            return None


class ExploitationStatus(Enum):
    """Enhanced exploitation status"""
    NOT_ATTEMPTED = auto()
    VERIFIED = auto()
    FAILED = auto()
    INCONCLUSIVE = auto()
    BLOCKED = auto()
    RATE_LIMITED = auto()
    CONFIRMED_SAFE = auto()  # Important: track false positives


class ParameterType(Enum):
    """Enhanced parameter classification"""
    NUMERIC_ID = auto()
    UUID = auto()
    SESSION_TOKEN = auto()
    API_KEY = auto()
    FILE_PATH = auto()
    JSON_DATA = auto()
    XML_DATA = auto()
    SERIALIZED = auto()
    EMAIL = auto()
    PHONE = auto()
    CREDIT_CARD = auto()
    JWT_TOKEN = auto()
    UNKNOWN = auto()

class ExploitationTechnique(Enum):
    """Techniques used for exploitation or verification"""
    UNION_BASED = auto()
    BOOLEAN_BASED = auto()
    TIME_BASED = auto()
    ERROR_BASED = auto()
    STACKED_QUERIES = auto()
    REFLECTION_ANALYSIS = auto()
    DOM_BASED = auto()
    PARAMETER_POLLUTION = auto()
    TOKEN_MANIPULATION = auto()
    PATH_TRAVERSAL = auto()
    COMMAND_DELIMITER = auto()
    TEMPLATE_INJECTION = auto()
