#!/usr/bin/env python3
"""
Report Generator Module
Generates comprehensive JSON and Markdown reports for security scan results.
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any


class ReportGenerator:
    """Generates security scan reports in multiple formats."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.findings = []
        self.metadata = {}
    
    def add_findings(self, findings: List[Dict[str, Any]], source: str = None):
        """
        Add findings to the report.
        
        Args:
            findings: List of findings to add
            source: Source of the findings (e.g., 'secret_scanner', 'compliance_checker')
        """
        for finding in findings:
            if source:
                finding['source'] = source
            self.findings.append(finding)
    
    def set_metadata(self, **kwargs):
        """
        Set report metadata.
        
        Args:
            **kwargs: Metadata key-value pairs
        """
        self.metadata.update(kwargs)
    
    def _categorize_by_severity(self) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by severity level."""
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'low')
            if severity in categorized:
                categorized[severity].append(finding)
        
        return categorized
    
    def _get_statistics(self) -> Dict[str, Any]:
        """Calculate summary statistics."""
        categorized = self._categorize_by_severity()
        
        return {
            'total_findings': len(self.findings),
            'critical': len(categorized['critical']),
            'high': len(categorized['high']),
            'medium': len(categorized['medium']),
            'low': len(categorized['low']),
            'by_type': self._count_by_type()
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count findings by type."""
        type_counts = {}
        
        for finding in self.findings:
            finding_type = finding.get('type', 'unknown')
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        
        return type_counts
    
    def generate_json_report(self, output_path: str = None) -> str:
        """
        Generate a JSON report.
        
        Args:
            output_path: Path to save the report (optional)
            
        Returns:
            JSON report as a string
        """
        report = {
            'metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'scanner_version': '1.0.0',
                **self.metadata
            },
            'statistics': self._get_statistics(),
            'findings': self.findings
        }
        
        json_content = json.dumps(report, indent=2)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_content)
        
        return json_content
    
    def generate_markdown_report(self, output_path: str = None) -> str:
        """
        Generate a Markdown report.
        
        Args:
            output_path: Path to save the report (optional)
            
        Returns:
            Markdown report as a string
        """
        categorized = self._categorize_by_severity()
        stats = self._get_statistics()
        
        # Build the report
        lines = [
            "# Security Scan Report",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        
        # Add metadata
        if self.metadata:
            lines.append("")
            lines.append("## Scan Information")
            for key, value in self.metadata.items():
                lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
        
        # Add summary
        lines.extend([
            "",
            "## Executive Summary",
            "",
            f"Total findings: **{stats['total_findings']}**",
            "",
            "### Findings by Severity",
            "",
            f"- 🔴 **Critical:** {stats['critical']}",
            f"- 🟠 **High:** {stats['high']}",
            f"- 🟡 **Medium:** {stats['medium']}",
            f"- 🔵 **Low:** {stats['low']}",
            "",
        ])
        
        # Add severity breakdown
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = categorized[severity]
            
            if findings:
                lines.extend([
                    "",
                    f"## {severity_icons[severity]} {severity.upper()} Severity Findings",
                    "",
                ])
                
                for i, finding in enumerate(findings, start=1):
                    lines.append(f"### {i}. {finding.get('name', 'Unknown Issue')}")
                    lines.append("")
                    
                    if 'description' in finding:
                        lines.append(f"**Description:** {finding['description']}")
                        lines.append("")
                    
                    # Add details
                    details = []
                    if 'file' in finding:
                        details.append(f"**File:** `{finding['file']}`")
                    if 'line' in finding:
                        details.append(f"**Line:** {finding['line']}")
                    if 'commit' in finding:
                        details.append(f"**Commit:** `{finding['commit']}`")
                    if 'branch' in finding:
                        details.append(f"**Branch:** `{finding['branch']}`")
                    if 'match' in finding:
                        details.append(f"**Match:** `{finding['match']}`")
                    
                    if details:
                        lines.extend(details)
                        lines.append("")
                    
                    # Add recommendation if available
                    if 'recommendation' in finding:
                        lines.append(f"**Recommendation:** {finding['recommendation']}")
                        lines.append("")
                    
                    lines.append("---")
                    lines.append("")
        
        # Add recommendations section
        if stats['total_findings'] > 0:
            lines.extend([
                "",
                "## Remediation Recommendations",
                "",
                "### Immediate Actions (Critical & High)",
                "",
            ])
            
            critical_high = categorized['critical'] + categorized['high']
            if critical_high:
                for finding in critical_high[:5]:  # Top 5 critical/high issues
                    lines.append(f"- **{finding.get('name')}**: {finding.get('description', 'No description')}")
            else:
                lines.append("No critical or high severity issues found.")
            
            lines.extend([
                "",
                "### Best Practices",
                "",
                "1. **Secrets Management**: Use environment variables or secret management tools (e.g., HashiCorp Vault, AWS Secrets Manager)",
                "2. **Code Review**: Implement mandatory code reviews before merging to protected branches",
                "3. **Dependency Updates**: Regularly update dependencies and scan for vulnerabilities",
                "4. **Git Hygiene**: Follow conventional commit messages and proper .gitignore practices",
                "5. **Security Training**: Ensure team members are aware of security best practices",
                "",
            ])
        
        markdown_content = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(markdown_content)
        
        return markdown_content
    
    def generate_github_annotations(self) -> List[str]:
        """
        Generate GitHub Actions workflow command annotations.
        
        Returns:
            List of annotation commands
        """
        annotations = []
        
        for finding in self.findings:
            severity = finding.get('severity', 'low')
            
            # Map severity to GitHub annotation level
            if severity == 'critical':
                level = 'error'
            elif severity == 'high':
                level = 'error'
            elif severity == 'medium':
                level = 'warning'
            else:
                level = 'notice'
            
            # Build annotation
            file_path = finding.get('file', '')
            line = finding.get('line', 1)
            title = finding.get('name', 'Security Finding')
            message = finding.get('description', '')
            
            if file_path:
                annotation = f"::{level} file={file_path},line={line},title={title}::{message}"
            else:
                annotation = f"::{level} title={title}::{message}"
            
            annotations.append(annotation)
        
        return annotations
    
    def generate_summary_comment(self) -> str:
        """
        Generate a summary comment suitable for PR comments.
        
        Returns:
            Markdown formatted comment
        """
        stats = self._get_statistics()
        
        if stats['total_findings'] == 0:
            return "✅ **Security scan completed successfully!** No issues found."
        
        lines = [
            "## 🔍 Security Scan Results",
            "",
            f"Found **{stats['total_findings']}** potential issues:",
            "",
            f"- 🔴 Critical: {stats['critical']}",
            f"- 🟠 High: {stats['high']}",
            f"- 🟡 Medium: {stats['medium']}",
            f"- 🔵 Low: {stats['low']}",
            "",
        ]
        
        if stats['critical'] > 0 or stats['high'] > 0:
            lines.extend([
                "⚠️ **Action Required:** Please review and address critical and high severity findings.",
                "",
            ])
        
        lines.append("📊 See the detailed report artifact for complete information.")
        
        return '\n'.join(lines)
    
    def save_reports(self, output_dir: str, base_name: str = 'security-report'):
        """
        Save reports in multiple formats.
        
        Args:
            output_dir: Directory to save reports
            base_name: Base name for report files
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Save JSON report
        json_path = os.path.join(output_dir, f'{base_name}.json')
        self.generate_json_report(json_path)
        
        # Save Markdown report
        md_path = os.path.join(output_dir, f'{base_name}.md')
        self.generate_markdown_report(md_path)
        
        # Save annotations
        annotations_path = os.path.join(output_dir, f'{base_name}-annotations.txt')
        with open(annotations_path, 'w') as f:
            f.write('\n'.join(self.generate_github_annotations()))
        
        print(f"Reports saved to {output_dir}/")
        print(f"  - JSON: {json_path}")
        print(f"  - Markdown: {md_path}")
        print(f"  - Annotations: {annotations_path}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate security scan reports')
    parser.add_argument('--input', required=True, help='Input JSON file with findings')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--base-name', default='security-report', help='Base name for report files')
    args = parser.parse_args()
    
    # Load findings from JSON
    with open(args.input, 'r') as f:
        data = json.load(f)
    
    generator = ReportGenerator()
    
    if 'findings' in data:
        generator.add_findings(data['findings'])
    
    if 'metadata' in data:
        generator.set_metadata(**data['metadata'])
    
    # Generate and save reports
    generator.save_reports(args.output_dir, args.base_name)
