from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime

from models.enums import VulnerabilityType
from utils.validators import validate_url, validate_http_method


@dataclass
class ScannerFinding:
    """Validated scanner finding"""
    
    target: str
    endpoint: str
    method: str
    parameter: str
    value: str
    vulnerability_type: VulnerabilityType
    scanner_evidence: Dict[str, Any] = field(default_factory=dict)
    scanner_id: Optional[str] = None
    confidence: float = 0.0
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate finding after initialization"""
        # Convert string to enum if needed
        if isinstance(self.vulnerability_type, str):
            try:
                self.vulnerability_type = VulnerabilityType[self.vulnerability_type.upper()]
            except (KeyError, AttributeError):
                raise ValueError(f"Invalid vulnerability type: {self.vulnerability_type}")
        
        # Validate fields
        if not validate_url(self.target):
            raise ValueError(f"Invalid target URL: {self.target}")
        
        if not validate_http_method(self.method):
            raise ValueError(f"Invalid HTTP method: {self.method}")
        
        if self.confidence < 0 or self.confidence > 1:
            raise ValueError(f"Confidence must be between 0 and 1: {self.confidence}")
    
    @property
    def full_url(self) -> str:
        """Get full URL"""
        base = self.target.rstrip('/')
        endpoint = self.endpoint.lstrip('/')
        return f"{base}/{endpoint}"
    
    @property
    def is_high_confidence(self) -> bool:
        """Check if finding is high confidence"""
        return self.confidence >= 0.7
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'target': self.target,
            'endpoint': self.endpoint,
            'method': self.method,
            'parameter': self.parameter,
            'value': self.value,
            'vulnerability_type': self.vulnerability_type.name,
            'confidence': self.confidence,
            'scanner_id': self.scanner_id,
            'discovered_at': self.discovered_at.isoformat()
        }
