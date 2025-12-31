import json
import yaml
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import asdict
import jinja2
import os

from models.exploit import ExploitationResult
from utils.logger import get_logger

logger = get_logger(__name__)


class ProfessionalReporter:
    """Generate professional exploitation reports"""
    
    def __init__(self, template_dir: str = None):
        self.template_dir = template_dir or "reporting/templates"
        # Ensure template dir exists
        os.makedirs(self.template_dir, exist_ok=True)
        
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    def generate_html_report(self, results: List[ExploitationResult], 
                           metadata: Dict[str, Any]) -> str:
        """Generate HTML report"""
        
        try:
            template = self.env.get_template('report.html')
        except jinja2.TemplateNotFound:
            logger.warning("HTML template not found, returning simplistic report")
            return f"<html><body><h1>PSEF Report</h1><p>Results: {len(results)}</p></body></html>"
        
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'target': metadata.get('target', 'Unknown'),
                'scanner': metadata.get('scanner', 'PSEF'),
                'version': metadata.get('version', '2.0'),
            },
            'summary': self._generate_summary(results),
            'verified_exploits': [
                self._format_result(r) for r in results 
                if r.status.name == 'VERIFIED'
            ],
            'failed_exploits': [
                self._format_result(r) for r in results 
                if r.status.name == 'FAILED'
            ],
            'technical_details': self._generate_technical_details(results),
            'recommendations': self._generate_recommendations(results),
        }
        
        return template.render(**report_data)
    
    def generate_json_report(self, results: List[ExploitationResult], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JSON report"""
        return {
            'metadata': metadata,
            'results': [self._format_result(r) for r in results]
        }

    def generate_markdown_report(self, results: List[ExploitationResult]) -> str:
        """Generate Markdown report"""
        
        verified = [r for r in results if r.status.name == 'VERIFIED']
        failed = [r for r in results if r.status.name == 'FAILED']
        
        report_lines = [
            "# Exploitation Framework Report",
            f"Generated: {datetime.now().isoformat()}",
            "",
            f"## Summary",
            f"- Total Findings: {len(results)}",
            f"- Verified Exploits: {len(verified)}",
            f"- Failed Exploits: {len(failed)}",
            "",
            "## Verified Vulnerabilities",
        ]
        
        for result in verified:
            report_lines.extend([
                f"### {result.finding.vulnerability_type.name}",
                f"- **Endpoint**: {result.finding.endpoint}",
                f"- **Parameter**: {result.finding.parameter}",
                f"- **Impact**: {result.impact}",
                f"- **Proof**: {result.verified_proof.primary_signal if result.verified_proof else 'N/A'}",
                f"- **Reproduction**:",
                f"  ```http",
                f"  {result.finding.method} {result.finding.full_url}",
                f"  {result.finding.parameter}: {result.attempts[-1].payload if result.attempts else 'N/A'}",
                f"  ```",
                "",
            ])
        
        report_lines.append("## Technical Details")
        
        for result in results:
            report_lines.extend([
                f"### {result.finding.vulnerability_type.name} - {result.status.name}",
                f"- **URL**: {result.finding.full_url}",
                f"- **Attempts**: {len(result.attempts)}",
                f"- **Evidence**: {json.dumps(result.evidence, indent=2)}",
                "",
            ])
        
        return "\n".join(report_lines)
    
    def _generate_summary(self, results: List[ExploitationResult]) -> Dict[str, Any]:
        """Generate report summary"""
        
        verified = [r for r in results if r.status.name == 'VERIFIED']
        failed = [r for r in results if r.status.name == 'FAILED']
        inconclusive = [r for r in results if r.status.name == 'INCONCLUSIVE']
        
        # Calculate risk scores
        risk_scores = []
        for result in verified:
            if 'SQL' in result.finding.vulnerability_type.name:
                risk_scores.append(9.0)
            elif 'XSS' in result.finding.vulnerability_type.name:
                risk_scores.append(7.0)
            elif 'IDOR' in result.finding.vulnerability_type.name:
                risk_scores.append(8.0)
            else:
                risk_scores.append(5.0)
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return {
            'total_findings': len(results),
            'verified_count': len(verified),
            'failed_count': len(failed),
            'inconclusive_count': len(inconclusive),
            'success_rate': len(verified) / len(results) if results else 0,
            'average_risk': avg_risk,
            'critical_count': sum(1 for s in risk_scores if s >= 9.0),
            'high_count': sum(1 for s in risk_scores if 7.0 <= s < 9.0),
            'medium_count': sum(1 for s in risk_scores if 5.0 <= s < 7.0),
            'low_count': sum(1 for s in risk_scores if s < 5.0),
        }
    
    def _format_result(self, result: ExploitationResult) -> Dict[str, Any]:
        """Format result for reporting"""
        
        formatted = {
            'vulnerability': result.finding.vulnerability_type.name,
            'endpoint': result.finding.endpoint,
            'parameter': result.finding.parameter,
            'status': result.status.name,
            'impact': result.impact,
            'attempts_count': len(result.attempts),
            'successful_payload': result.attempts[-1].payload if result.attempts else None,
            'evidence': result.evidence,
        }
        
        if result.verified_proof:
            formatted.update({
                'verification': {
                    'primary': result.verified_proof.primary_signal,
                    'secondary': result.verified_proof.secondary_signal,
                    'reproducible': result.verified_proof.reproducible,
                }
            })
        
        return formatted
    
    def _generate_technical_details(self, results: List[ExploitationResult]) -> List[Dict[str, Any]]:
        """Generate technical details section"""
        
        details = []
        for result in results:
            if result.status.name != 'VERIFIED':
                continue
            
            detail = {
                'vulnerability': result.finding.vulnerability_type.name,
                'technical_analysis': "Detailed technical analysis of the vulnerability...",
                'exploitation_chain': [
                    {
                        'step': i + 1,
                        'technique': attempt.technique.name if attempt.technique else 'Unknown',
                        'payload': attempt.payload[:100] + '...' if len(attempt.payload) > 100 else attempt.payload,
                        'success': attempt.success,
                    }
                    for i, attempt in enumerate(result.attempts[:5])  # Limit to 5 attempts
                ],
                'indicators_of_compromise': ["SQL queries in logs", "Suspicious traffic"],
                'detection_methods': ["WAF", "SIEM logs"],
            }
            details.append(detail)
        
        return details
    
    def _generate_recommendations(self, results: List[ExploitationResult]) -> List[Dict[str, Any]]:
        """Generate remediation recommendations"""
        
        recommendations = []
        vuln_types = set(r.finding.vulnerability_type.name for r in results 
                        if r.status.name == 'VERIFIED')
        
        recommendation_map = {
            'SQL_INJECTION': {
                'title': 'SQL Injection Prevention',
                'priority': 'Critical',
                'recommendations': [
                    'Use parameterized queries or prepared statements',
                    'Implement input validation and sanitization',
                    'Apply the principle of least privilege to database accounts',
                ],
                'references': [
                    'OWASP SQL Injection Prevention Cheat Sheet',
                ]
            },
            'XSS': {
                'title': 'Cross-Site Scripting Prevention',
                'priority': 'High',
                'recommendations': [
                    'Implement Content Security Policy (CSP)',
                    'Use context-appropriate output encoding',
                ],
                'references': [
                    'OWASP XSS Prevention Cheat Sheet',
                ]
            }
        }
        
        for vuln in vuln_types:
            if vuln in recommendation_map:
                recommendations.append(recommendation_map[vuln])
        
        return recommendations
