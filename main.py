#!/usr/bin/env python3
"""
Post-Scanning Exploitation Framework (PSEF) - Professional Edition

A deterministic, verification-focused exploitation framework
for penetration testers and security researchers.
"""

import json
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import ExploitationEngine
from core.config import load_config, validate_config
from reporting.reporter import ProfessionalReporter
from utils.logger import setup_logging, get_logger
from utils.security import SecuritySanitizer

logger = get_logger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Post-Scanning Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --findings scan_results.json --output report.html
  %(prog)s --config config.yaml --verbose
  %(prog)s --target https://example.com --single-finding finding.json
        """
    )
    
    parser.add_argument(
        '--findings',
        type=str,
        help='JSON file containing scanner findings'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='exploitation_report',
        help='Output report basename (default: exploitation_report)'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['html', 'json', 'md', 'all'],
        default='all',
        help='Output format (default: all)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=5,
        help='Maximum concurrent threads (default: 5)'
    )
    
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        default=False,
        help='Verify SSL certificates (default: False for testing)'
    )
    
    parser.add_argument(
        '--interactive',
        '-i',
        action='store_true',
        help='Run in interactive mode to manually input findings'
    )
    
    return parser.parse_args()


def load_findings(file_path: str) -> List[Dict[str, Any]]:
    """Load and validate scanner findings"""
    
    try:
        with open(file_path, 'r') as f:
            raw_findings = json.load(f)
        
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]
        
        # Validate each finding
        valid_findings = []
        for i, finding in enumerate(raw_findings):
            if SecuritySanitizer.validate_finding(finding):
                valid_findings.append(finding)
            else:
                logger.warning(f"Finding {i} failed validation: {finding.get('target', 'Unknown')}")
        
        logger.info(f"Loaded {len(valid_findings)} valid findings from {len(raw_findings)} total")
        return valid_findings
        
    except FileNotFoundError:
        logger.error(f"Findings file not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in findings file: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading findings: {e}")
        sys.exit(1)


def interactive_mode():
    """Run interactive prompt to collect finding details"""
    from models.enums import VulnerabilityType
    import colorama
    from colorama import Fore, Style
    
    colorama.init()
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.YELLOW}PSEF INTERACTIVE MODE")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    try:
        target = input(f"{Fore.GREEN}Target URL (e.g. https://example.com): {Style.RESET_ALL}").strip()
        endpoint = input(f"{Fore.GREEN}Endpoint (e.g. /api/user): {Style.RESET_ALL}").strip()
        method = input(f"{Fore.GREEN}Method (GET/POST/etc, default GET): {Style.RESET_ALL}").strip() or "GET"
        parameter = input(f"{Fore.GREEN}Vulnerable Parameter: {Style.RESET_ALL}").strip()
        value = input(f"{Fore.GREEN}Original Value: {Style.RESET_ALL}").strip()
        
        print(f"\n{Fore.YELLOW}Select Vulnerability Type:{Style.RESET_ALL}")
        vuln_types = list(VulnerabilityType)
        for i, vt in enumerate(vuln_types):
            print(f"  [{i+1}] {vt.name}")
            
        choice = int(input(f"\n{Fore.GREEN}Choice [1-{len(vuln_types)}]: {Style.RESET_ALL}"))
        v_type = vuln_types[choice-1]
        
        finding = {
            'target': target,
            'endpoint': endpoint,
            'method': method.upper(),
            'parameter': parameter,
            'value': value,
            'vulnerability_type': v_type.name,
            'confidence': 1.0
        }
        
        print(f"\n{Fore.CYAN}Generating exploitation scripts for {v_type.name}...{Style.RESET_ALL}\n")
        return [finding]
        
    except (ValueError, IndexError):
        logger.error("Invalid selection")
        return []
    except KeyboardInterrupt:
        print("\nAborted.")
        return []


def main():
    """Main execution function"""
    
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(level=log_level)
    
    logger.info("Starting Post-Scanning Exploitation Framework")
    
    # Load configuration
    config = load_config(args.config)
    if not config:
        config = {
            'http': {'timeout': 30, 'max_retries': 3},
            'exploitation': {'max_threads': 5}
        }
    
    # Load findings
    findings_data = []
    if args.interactive:
        findings_data = interactive_mode()
    elif args.findings:
        findings_data = load_findings(args.findings)
    else:
        logger.error("No findings specified and not in interactive mode. Use --findings or --interactive.")
        sys.exit(1)
        
    if not findings_data:
        logger.error("No valid findings to process")
        sys.exit(1)
    
    # Initialize engine
    engine = ExploitationEngine(
        config=config,
        max_threads=args.threads,
        verify_ssl=args.verify_ssl
    )
    
    # Run exploitation
    logger.info(f"Starting exploitation of {len(findings_data)} findings")
    
    try:
        results = engine.exploit_all(findings_data)
        logger.info(f"Exploitation complete: {len(results)} results")
        
        # Generate report
        reporter = ProfessionalReporter()
        
        metadata = {
            'target': findings_data[0].get('target', 'Unknown'),
            'scanner': 'PSEF Professional',
            'version': '2.0',
            'config': config.get('name', 'Default')
        }
        
        if args.format in ['html', 'all']:
            html_report = reporter.generate_html_report(results, metadata)
            with open(f"{args.output}.html", 'w') as f:
                f.write(html_report)
            logger.info(f"HTML report saved to {args.output}.html")
        
        if args.format in ['json', 'all']:
            json_report = reporter.generate_json_report(results, metadata)
            with open(f"{args.output}.json", 'w') as f:
                json.dump(json_report, f, indent=2)
            logger.info(f"JSON report saved to {args.output}.json")
        
        if args.format in ['md', 'all']:
            md_report = reporter.generate_markdown_report(results)
            with open(f"{args.output}.md", 'w') as f:
                f.write(md_report)
            logger.info(f"Markdown report saved to {args.output}.md")
        
        # Print summary
        verified = [r for r in results if r.status.name == 'VERIFIED']
        logger.info(f"\n{'='*60}")
        logger.info("EXPLOITATION SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total findings processed: {len(results)}")
        logger.info(f"Verified vulnerabilities: {len(verified)}")
        logger.info(f"Success rate: {(len(verified)/len(results)*100):.1f}%" if results else "N/A")
        
        if verified:
            logger.info("\nVERIFIED VULNERABILITIES:")
            for result in verified:
                logger.info(f"  • {result.finding.vulnerability_type.name}: "
                          f"{result.finding.endpoint} ({result.impact[:50]}...)")
        
        logger.info("\nFramework execution completed successfully")
        
    except KeyboardInterrupt:
        logger.warning("\nExploitation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Framework execution failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()