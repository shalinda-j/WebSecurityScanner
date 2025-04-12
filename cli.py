#!/usr/bin/env python3
import argparse
import sys
import json
import os
import logging
from modules.scanner_engine import ScannerEngine
from modules.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='Web Application Penetration Testing Toolkit')
    
    # Main arguments
    parser.add_argument('--url', '-u', type=str, help='Target URL to scan')
    parser.add_argument('--output', '-o', type=str, help='Output file for report (JSON format)')
    parser.add_argument('--modules', '-m', type=str, help='Comma-separated list of modules to run (default: all)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    # Module specific arguments
    parser.add_argument('--depth', '-d', type=int, default=2, help='Crawling depth for the scanner')
    parser.add_argument('--timeout', '-t', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--user-agent', type=str, help='Custom User-Agent string')
    parser.add_argument('--cookies', type=str, help='Cookies to include with requests (format: name1=value1;name2=value2)')
    
    return parser.parse_args()

def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        logger.error("URL must start with http:// or https://")
        return False
    return True

def setup_modules(modules_str):
    available_modules = {
        'sql': 'SQL Injection Scanner',
        'xss': 'Cross-Site Scripting Scanner',
        'version': 'Version Detection',
        'config': 'Configuration Analysis',
        'exposure': 'Data Exposure Scanner'
    }
    
    if not modules_str:
        # Default to all modules
        return list(available_modules.keys())
    
    modules = modules_str.split(',')
    valid_modules = []
    
    for module in modules:
        module = module.strip().lower()
        if module in available_modules:
            valid_modules.append(module)
        else:
            logger.warning(f"Unknown module: {module}")
    
    if not valid_modules:
        logger.error("No valid modules specified")
        print("Available modules:")
        for key, desc in available_modules.items():
            print(f"  {key}: {desc}")
        sys.exit(1)
    
    return valid_modules

def main():
    args = parse_args()
    
    if not args.url:
        logger.error("Target URL is required")
        sys.exit(1)
        
    if not validate_url(args.url):
        sys.exit(1)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Setup scan configuration
    config = {
        'url': args.url,
        'depth': args.depth,
        'timeout': args.timeout,
        'user_agent': args.user_agent,
        'cookies': args.cookies
    }
    
    modules = setup_modules(args.modules)
    
    # Run the scan
    logger.info(f"Starting scan on {args.url}")
    logger.info(f"Modules enabled: {', '.join(modules)}")
    
    scanner = ScannerEngine(config)
    results = scanner.run_scan(modules)
    
    # Generate report
    report_gen = ReportGenerator()
    report = report_gen.generate_report(args.url, results)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=4)
        logger.info(f"Report saved to {args.output}")
    else:
        # Print summary to console
        print("\n=== SCAN REPORT SUMMARY ===")
        print(f"Target: {args.url}")
        print(f"Scan Date: {report['scan_date']}")
        
        vuln_count = sum(len(results[module]) for module in results)
        print(f"Total Vulnerabilities Found: {vuln_count}")
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = sum(1 for module in results for vuln in results[module] if vuln['severity'] == severity)
            print(f"  {severity}: {count}")
        
        print("\nTop 5 Vulnerabilities:")
        all_vulns = []
        for module in results:
            all_vulns.extend(results[module])
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        all_vulns.sort(key=lambda x: severity_order.get(x['severity'], 99))
        
        for i, vuln in enumerate(all_vulns[:5]):
            print(f"  {i+1}. [{vuln['severity']}] {vuln['type']} - {vuln['location']}")

if __name__ == '__main__':
    main()
