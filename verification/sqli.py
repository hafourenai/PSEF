import re
import time
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
import statistics
import requests

from models.enums import ExploitationTechnique

@dataclass
class VerificationMetrics:
    """Metrics for vulnerability verification"""
    response_time_diff: float = 0.0
    content_length_diff: int = 0
    status_code_diff: int = 0
    error_indicators: int = 0
    success_indicators: int = 0
    confidence_score: float = 0.0


class AdvancedSQLiVerifier:
    """Advanced SQL injection verification with statistical analysis"""
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        
        # Database error patterns
        self.db_error_patterns = {
            'mysql': [
                r"MySQLSyntaxErrorException",
                r"you have an error in your sql syntax",
                r"mysql_fetch",
                r"MySQL server version",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"pg_.*error",
                r"PSQLException",
            ],
            'mssql': [
                r"Microsoft SQL Server",
                r"SQLServer JDBC Driver",
                r"ODBC Driver",
                r"OLEDB",
            ],
            'oracle': [
                r"ORA-\d{5}",
                r"Oracle error",
                r"Oracle.*Driver",
            ],
            'sqlite': [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
            ]
        }
        
        # Success indicators
        self.success_indicators = [
            r"UNION.*SELECT",
            r"@@version",
            r"database\(\)",
            r"user\(\)",
            r"version\(\)",
            r"current_user",
            r"LOAD_FILE",
        ]
    
    def verify_boolean_based(self, 
                           true_responses: List[requests.Response],
                           false_responses: List[requests.Response]) -> Tuple[bool, VerificationMetrics]:
        """Verify boolean-based SQLi with statistical significance"""
        
        metrics = VerificationMetrics()
        
        # Calculate averages
        true_lengths = [len(r.text) for r in true_responses]
        false_lengths = [len(r.text) for r in false_responses]
        
        if len(true_lengths) < 2 or len(false_lengths) < 2:
            return False, metrics
        
        true_avg = statistics.mean(true_lengths)
        false_avg = statistics.mean(false_lengths)
        
        metrics.content_length_diff = abs(true_avg - false_avg)
        
        # Calculate standard deviation
        true_std = statistics.stdev(true_lengths) if len(true_lengths) > 1 else 0
        false_std = statistics.stdev(false_lengths) if len(false_lengths) > 1 else 0
        
        # Check if difference is statistically significant
        diff_threshold = max(true_std, false_std) * 3
        
        if metrics.content_length_diff > diff_threshold and metrics.content_length_diff > 50:
            # Strong indication of boolean-based SQLi
            metrics.confidence_score = min(0.9, metrics.content_length_diff / 1000)
            return True, metrics
        
        # Check for content differences beyond length
        content_diffs = []
        for true_resp, false_resp in zip(true_responses[:3], false_responses[:3]):
            diff = self._calculate_content_difference(true_resp.text, false_resp.text)
            content_diffs.append(diff)
        
        avg_content_diff = statistics.mean(content_diffs) if content_diffs else 0
        
        if avg_content_diff > 0.3:  # 30% content difference
            metrics.confidence_score = avg_content_diff * 0.8
            return True, metrics
        
        return False, metrics
    
    def verify_time_based(self,
                         test_responses: List[Tuple[requests.Response, float]],
                         baseline_time: float) -> Tuple[bool, VerificationMetrics]:
        """Verify time-based SQLi with statistical analysis"""
        
        metrics = VerificationMetrics()
        
        response_times = [rt for _, rt in test_responses]
        
        if len(response_times) < 3:
            return False, metrics
        
        avg_time = statistics.mean(response_times)
        std_time = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        metrics.response_time_diff = avg_time - baseline_time
        
        # Check if delay is statistically significant
        if metrics.response_time_diff > max(std_time * 2, 2.0):  # At least 2 seconds
            # Calculate confidence based on consistency
            consistent_delays = sum(1 for rt in response_times 
                                  if rt > baseline_time + 1.5)
            
            consistency_ratio = consistent_delays / len(response_times)
            metrics.confidence_score = consistency_ratio * 0.7
            
            if consistency_ratio > 0.8:  # 80% consistent delays
                return True, metrics
        
        return False, metrics
    
    def verify_error_based(self, response: requests.Response) -> Tuple[bool, str, float]:
        """Verify error-based SQLi and identify DBMS"""
        
        text = response.text.lower()
        
        # Check for database errors
        db_errors_found = []
        for dbms, patterns in self.db_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern.lower(), text):
                    db_errors_found.append(dbms)
                    break
        
        if not db_errors_found:
            return False, "", 0.0
        
        # Count unique error indicators
        error_count = 0
        for patterns in self.db_error_patterns.values():
            for pattern in patterns:
                if re.search(pattern.lower(), text):
                    error_count += 1
        
        confidence = min(0.9, error_count / 10.0)
        
        # Most common DBMS in errors
        from collections import Counter
        if db_errors_found:
            dbms = Counter(db_errors_found).most_common(1)[0][0]
        else:
            dbms = "unknown"
        
        return True, dbms, confidence
    
    def verify_union_injection(self, response: requests.Response, 
                             payload: str) -> Tuple[bool, VerificationMetrics]:
        """Verify UNION-based injection"""
        
        metrics = VerificationMetrics()
        text = response.text.lower()
        
        # Check for UNION keyword reflection
        if 'union' in text:
            metrics.success_indicators += 1
        
        # Check for database data in response
        for indicator in self.success_indicators:
            if re.search(indicator.lower(), text):
                metrics.success_indicators += 1
        
        # Check for absence of errors
        error_found = False
        for patterns in self.db_error_patterns.values():
            for pattern in patterns:
                if re.search(pattern.lower(), text):
                    metrics.error_indicators += 1
                    error_found = True
        
        # Calculate confidence
        if error_found:
            # Error might indicate wrong column count
            metrics.confidence_score = max(0.3, metrics.success_indicators / 10.0)
        else:
            metrics.confidence_score = min(0.9, 
                                         (metrics.success_indicators * 0.3 + 
                                          (len(response.text) > 1000) * 0.2))
        
        return metrics.confidence_score > self.confidence_threshold, metrics
    
    @staticmethod
    def _calculate_content_difference(text1: str, text2: str) -> float:
        """Calculate content difference ratio (0.0 to 1.0)"""
        
        if not text1 or not text2:
            return 1.0 if text1 or text2 else 0.0
        
        # Quick comparison
        set1 = set(text1.split())
        set2 = set(text2.split())
        
        if not set1 and not set2:
            return 0.0
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return 1.0 - (intersection / union) if union > 0 else 1.0
