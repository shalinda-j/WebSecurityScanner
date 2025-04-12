import logging
import json
import os
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Module to generate comprehensive reports from scan results
    """
    
    def __init__(self):
        """
        Initialize report generator
        """
        self.current_time = datetime.now()
    
    def generate_report(self, target_url, scan_results):
        """
        Generate a comprehensive report from scan results
        
        Args:
            target_url (str): Target URL that was scanned
            scan_results (dict): Results from scanner modules
            
        Returns:
            dict: Complete report in dictionary format
        """
        # Create basic report structure
        report = {
            'target': target_url,
            'scan_date': self.current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_vulnerabilities': 0,
                'severity_counts': {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                }
            },
            'modules': {},
            'vulnerabilities': [],
            'findings_by_severity': {
                'Critical': [],
                'High': [],
                'Medium': [],
                'Low': [],
                'Info': []
            }
        }
        
        # Process results from each module
        for module_name, module_results in scan_results.items():
            report['modules'][module_name] = {
                'vulnerability_count': len(module_results),
                'findings': []
            }
            
            # Add each vulnerability to the report
            for vuln in module_results:
                # Add module name to vulnerability
                vuln['module'] = module_name
                
                # Add to module findings
                report['modules'][module_name]['findings'].append(vuln)
                
                # Add to overall vulnerabilities list
                report['vulnerabilities'].append(vuln)
                
                # Add to findings by severity
                severity = vuln.get('severity', 'Info')
                report['findings_by_severity'][severity].append(vuln)
                
                # Update summary counts
                report['summary']['total_vulnerabilities'] += 1
                report['summary']['severity_counts'][severity] += 1
        
        # Generate executive summary
        report['executive_summary'] = self._generate_executive_summary(report)
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def save_report(self, report, output_format='json', output_dir='reports'):
        """
        Save report to file
        
        Args:
            report (dict): Report to save
            output_format (str): Output format (json, html, txt)
            output_dir (str): Directory to save report
            
        Returns:
            str: Path to saved report
        """
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate filename based on target and timestamp
        target_host = report['target'].replace('://', '_').replace('/', '_').replace(':', '_')
        timestamp = self.current_time.strftime('%Y%m%d_%H%M%S')
        filename = f"{target_host}_{timestamp}"
        
        if output_format == 'json':
            output_path = os.path.join(output_dir, f"{filename}.json")
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=4)
        elif output_format == 'txt':
            output_path = os.path.join(output_dir, f"{filename}.txt")
            with open(output_path, 'w') as f:
                self._write_text_report(report, f)
        else:
            # Default to JSON if format not supported
            output_path = os.path.join(output_dir, f"{filename}.json")
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=4)
        
        logger.info(f"Report saved to {output_path}")
        return output_path
    
    def _generate_executive_summary(self, report):
        """
        Generate an executive summary from the report
        
        Args:
            report (dict): Complete report
            
        Returns:
            str: Executive summary text
        """
        total_vulns = report['summary']['total_vulnerabilities']
        severity_counts = report['summary']['severity_counts']
        
        # Calculate risk score (simplified)
        risk_score = (
            severity_counts['Critical'] * 10 + 
            severity_counts['High'] * 5 + 
            severity_counts['Medium'] * 2 + 
            severity_counts['Low'] * 0.5
        )
        
        # Determine overall risk level
        if risk_score >= 20:
            risk_level = "Critical"
        elif risk_score >= 10:
            risk_level = "High"
        elif risk_score >= 5:
            risk_level = "Medium"
        elif risk_score > 0:
            risk_level = "Low"
        else:
            risk_level = "Informational"
        
        # Generate summary text
        summary = f"""
Executive Summary for {report['target']}

Security Assessment
------------------
Scan Date: {report['scan_date']}
Overall Risk Level: {risk_level}
Total Vulnerabilities Found: {total_vulns}

Vulnerability Breakdown:
- Critical: {severity_counts['Critical']}
- High: {severity_counts['High']}
- Medium: {severity_counts['Medium']}
- Low: {severity_counts['Low']}
- Informational: {severity_counts['Info']}

Key Findings:
"""
        
        # Add top findings
        critical_findings = report['findings_by_severity']['Critical']
        high_findings = report['findings_by_severity']['High']
        
        # Add critical findings
        if critical_findings:
            summary += "CRITICAL ISSUES:\n"
            for i, finding in enumerate(critical_findings[:3]):  # Top 3 critical findings
                summary += f"- {finding['type']} at {finding['location']}\n"
            if len(critical_findings) > 3:
                summary += f"- {len(critical_findings) - 3} more critical issues...\n"
            summary += "\n"
        
        # Add high findings
        if high_findings:
            summary += "HIGH SEVERITY ISSUES:\n"
            for i, finding in enumerate(high_findings[:3]):  # Top 3 high findings
                summary += f"- {finding['type']} at {finding['location']}\n"
            if len(high_findings) > 3:
                summary += f"- {len(high_findings) - 3} more high severity issues...\n"
            summary += "\n"
        
        # Add conclusion based on risk level
        if risk_level in ["Critical", "High"]:
            summary += "URGENT ACTION REQUIRED: Critical security issues were identified that require immediate attention."
        elif risk_level == "Medium":
            summary += "ACTION RECOMMENDED: Several security issues were identified that should be addressed in the near future."
        else:
            summary += "MINOR ISSUES: Only minor security issues were identified, suggesting good overall security practices."
        
        return summary
    
    def _generate_recommendations(self, report):
        """
        Generate prioritized recommendations based on findings
        
        Args:
            report (dict): Complete report
            
        Returns:
            list: List of recommendation dictionaries
        """
        recommendations = []
        
        # Collect all unique remediation steps and count their occurrence
        remediation_counts = {}
        vulnerability_types = {}
        
        for vuln in report['vulnerabilities']:
            if 'remediation' in vuln:
                remediation = vuln['remediation']
                severity = vuln['severity']
                vuln_type = vuln['type']
                
                # Group similar remediation advice
                if remediation not in remediation_counts:
                    remediation_counts[remediation] = {
                        'count': 0,
                        'types': [],
                        'severities': [],
                        'highest_severity': 'Info',
                        'remediation': remediation
                    }
                
                remediation_counts[remediation]['count'] += 1
                if vuln_type not in remediation_counts[remediation]['types']:
                    remediation_counts[remediation]['types'].append(vuln_type)
                if severity not in remediation_counts[remediation]['severities']:
                    remediation_counts[remediation]['severities'].append(severity)
                
                # Track highest severity
                severity_order = {
                    'Critical': 0,
                    'High': 1,
                    'Medium': 2,
                    'Low': 3,
                    'Info': 4
                }
                
                if severity_order[severity] < severity_order[remediation_counts[remediation]['highest_severity']]:
                    remediation_counts[remediation]['highest_severity'] = severity
        
        # Convert to list and sort by severity and count
        recommendation_list = list(remediation_counts.values())
        
        # Sort by severity first, then by count
        severity_rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        recommendation_list.sort(key=lambda x: (severity_rank[x['highest_severity']], -x['count']))
        
        # Format recommendations
        for rec in recommendation_list:
            recommendations.append({
                'priority': rec['highest_severity'],
                'affected_vulnerabilities': rec['types'],
                'recommendation': rec['remediation'],
                'finding_count': rec['count']
            })
        
        return recommendations
    
    def _write_text_report(self, report, file):
        """
        Write report in text format
        
        Args:
            report (dict): Complete report
            file: File object to write to
        """
        # Write header
        file.write(f"SECURITY SCAN REPORT\n")
        file.write(f"{'=' * 80}\n\n")
        
        # Write target and date
        file.write(f"Target: {report['target']}\n")
        file.write(f"Scan Date: {report['scan_date']}\n\n")
        
        # Write executive summary
        file.write(f"EXECUTIVE SUMMARY\n")
        file.write(f"{'-' * 80}\n")
        file.write(report['executive_summary'])
        file.write("\n\n")
        
        # Write vulnerability summary
        file.write(f"VULNERABILITY SUMMARY\n")
        file.write(f"{'-' * 80}\n")
        file.write(f"Total vulnerabilities found: {report['summary']['total_vulnerabilities']}\n\n")
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = report['summary']['severity_counts'][severity]
            file.write(f"{severity}: {count}\n")
        
        file.write("\n")
        
        # Write vulnerabilities by severity
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulnerabilities = report['findings_by_severity'][severity]
            
            if vulnerabilities:
                file.write(f"{severity.upper()} FINDINGS\n")
                file.write(f"{'-' * 80}\n")
                
                for i, vuln in enumerate(vulnerabilities):
                    file.write(f"{i+1}. {vuln['type']}\n")
                    file.write(f"   Location: {vuln['location']}\n")
                    file.write(f"   Description: {vuln['description']}\n")
                    if 'proof' in vuln:
                        file.write(f"   Evidence: {vuln['proof']}\n")
                    if 'remediation' in vuln:
                        file.write(f"   Remediation: {vuln['remediation']}\n")
                    file.write("\n")
        
        # Write recommendations
        file.write(f"RECOMMENDATIONS\n")
        file.write(f"{'-' * 80}\n")
        
        for i, rec in enumerate(report['recommendations']):
            file.write(f"{i+1}. [{rec['priority']}] {rec['recommendation']}\n")
            file.write(f"   Affects: {', '.join(rec['affected_vulnerabilities'])}\n")
            file.write(f"   Findings: {rec['finding_count']}\n\n")
