import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from core.http_client import SecureHTTPClient
from core.state import ThreadSafeState
from models.finding import ScannerFinding
from models.exploit import ExploitationResult
from models.enums import ExploitationStatus
from exploits.registry import ExploitRegistry
from utils.logger import get_logger

logger = get_logger(__name__)

class ExploitationEngine:
    """Main engine to orchestrate exploitation across multiple findings"""
    
    def __init__(self, config: Dict[str, Any] = None, max_threads: int = 5, verify_ssl: bool = False):
        self.config = config or {}
        self.max_threads = max_threads
        self.verify_ssl = verify_ssl
        self.http_client = SecureHTTPClient(verify_ssl=verify_ssl)
        self.registry = ExploitRegistry(self.http_client)
        
    def exploit_all(self, findings_data: List[Dict[str, Any]]) -> List[ExploitationResult]:
        """Execute exploitation on all findings using a thread pool"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Convert dicts to ScannerFinding objects
            findings = []
            for data in findings_data:
                try:
                    findings.append(ScannerFinding(**data))
                except Exception as e:
                    logger.error(f"Failed to parse finding: {e}")
            
            # Submit tasks
            future_to_finding = {executor.submit(self._exploit_single, f): f for f in findings}
            
            for future in future_to_finding:
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    finding = future_to_finding[future]
                    logger.error(f"Exploitation failed for {finding.full_url}: {e}")
        
        return results
    
    def _exploit_single(self, finding: ScannerFinding) -> ExploitationResult:
        """Exploit a single finding"""
        logger.info(f"Processing finding: {finding.vulnerability_type.name} on {finding.endpoint}")
        
        exploit_module = self.registry.get_exploit(finding.vulnerability_type)
        
        if not exploit_module:
            logger.warning(f"No exploit module found for {finding.vulnerability_type.name}")
            return ExploitationResult(finding=finding, status=ExploitationStatus.NOT_ATTEMPTED)
        
        try:
            return exploit_module.exploit(finding)
        except Exception as e:
            logger.exception(f"Unexpected error during exploitation of {finding.full_url}: {e}")
            return ExploitationResult(finding=finding, status=ExploitationStatus.FAILED)
    
    def close(self):
        """Cleanup resources"""
        self.http_client.close()
