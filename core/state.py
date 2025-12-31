import threading
import hashlib
from typing import Dict, Set, Optional
from dataclasses import dataclass, field
from models.enums import ExploitationTechnique


@dataclass
class ThreadSafeState:
    """Thread-safe state manager for concurrent exploitation"""
    
    target_base: str
    _lock: threading.RLock = field(default_factory=threading.RLock)
    attempted_payloads: Set[str] = field(default_factory=set)
    successful_techniques: Set[ExploitationTechnique] = field(default_factory=set)
    failed_techniques: Set[ExploitationTechnique] = field(default_factory=set)
    session_tokens: Dict[str, str] = field(default_factory=dict)
    
    def payload_hash(self, payload: str) -> str:
        """Create deterministic hash for payload tracking"""
        return hashlib.sha256(payload.encode()).hexdigest()
    
    def is_payload_attempted(self, payload: str) -> bool:
        """Thread-safe check if payload was attempted"""
        with self._lock:
            return self.payload_hash(payload) in self.attempted_payloads
    
    def record_attempt(self, payload: str, success: bool, 
                      technique: ExploitationTechnique) -> None:
        """Thread-safe attempt recording"""
        with self._lock:
            payload_hash = self.payload_hash(payload)
            self.attempted_payloads.add(payload_hash)
            
            if success:
                self.successful_techniques.add(technique)
                # Remove from failed if now successful
                self.failed_techniques.discard(technique)
            else:
                self.failed_techniques.add(technique)
    
    def get_session_token(self, key: str) -> Optional[str]:
        """Thread-safe token retrieval"""
        with self._lock:
            return self.session_tokens.get(key)
    
    def set_session_token(self, key: str, value: str) -> None:
        """Thread-safe token storage"""
        with self._lock:
            self.session_tokens[key] = value
