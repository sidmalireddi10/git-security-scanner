#!/usr/bin/env python3
"""
Quality Analyzer Module
Analyzes code quality, security patterns, and dependency vulnerabilities.
"""

import os
import re
import json
from typing import List, Dict, Any
from pathlib import Path


class QualityAnalyzer:
    """Analyzes code quality and security patterns."""
    
    def __init__(self):
        """Initialize the quality analyzer."""
        self.findings = []
    
    def check_dependency_vulnerabilities(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Check for known dependency vulnerabilities in package files.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Check for package.json (Node.js)
        package_json_path = os.path.join(repo_path, 'package.json')
        if os.path.exists(package_json_path):
            findings.append({
                'type': 'dependency_check',
                'severity': 'medium',
                'name': 'Node.js dependencies found',
                'file': 'package.json',
                'description': 'Run `npm audit` to check for vulnerabilities',
                'recommendation': 'npm audit fix'
            })
        
        # Check for requirements.txt (Python)
        requirements_path = os.path.join(repo_path, 'requirements.txt')
        if os.path.exists(requirements_path):
            findings.append({
                'type': 'dependency_check',
                'severity': 'medium',
                'name': 'Python dependencies found',
                'file': 'requirements.txt',
                'description': 'Run `pip-audit` or `safety check` to scan for vulnerabilities',
                'recommendation': 'pip install pip-audit && pip-audit'
            })
        
        # Check for pom.xml (Maven/Java)
        pom_path = os.path.join(repo_path, 'pom.xml')
        if os.path.exists(pom_path):
            findings.append({
                'type': 'dependency_check',
                'severity': 'medium',
                'name': 'Maven dependencies found',
                'file': 'pom.xml',
                'description': 'Run OWASP Dependency Check to scan for vulnerabilities',
                'recommendation': 'mvn dependency-check:check'
            })
        
        # Check for Gemfile (Ruby)
        gemfile_path = os.path.join(repo_path, 'Gemfile')
        if os.path.exists(gemfile_path):
            findings.append({
                'type': 'dependency_check',
                'severity': 'medium',
                'name': 'Ruby dependencies found',
                'file': 'Gemfile',
                'description': 'Run `bundle audit` to check for vulnerabilities',
                'recommendation': 'bundle audit check --update'
            })
        
        return findings
    
    def check_code_complexity(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze code complexity metrics.
        
        Args:
            file_path: Path to the code file
            
        Returns:
            List of code quality findings
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Count total lines
            total_lines = len(lines)
            
            # Count non-empty, non-comment lines
            code_lines = 0
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and not stripped.startswith('//'):
                    code_lines += 1
            
            # Check for excessively long files
            if total_lines > 1000:
                findings.append({
                    'type': 'code_complexity',
                    'severity': 'low',
                    'name': 'Large file',
                    'file': file_path,
                    'description': f"File has {total_lines} lines. Consider breaking it into smaller modules.",
                    'lines': total_lines
                })
            
            # Check for long functions (simple heuristic)
            current_function_lines = 0
            in_function = False
            
            for i, line in enumerate(lines, start=1):
                stripped = line.strip()
                
                # Simple function detection (works for Python, JavaScript, etc.)
                if re.match(r'^(def|function|func|public|private|protected)\s+\w+', stripped):
                    if in_function and current_function_lines > 50:
                        findings.append({
                            'type': 'code_complexity',
                            'severity': 'low',
                            'name': 'Long function',
                            'file': file_path,
                            'line': i - current_function_lines,
                            'description': f"Function has {current_function_lines} lines. Consider refactoring.",
                            'lines': current_function_lines
                        })
                    in_function = True
                    current_function_lines = 0
                elif in_function:
                    current_function_lines += 1
        
        except Exception as e:
            pass
        
        return findings
    
    def check_security_antipatterns(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Check for common security anti-patterns in code.
        
        Args:
            file_path: Path to the code file
            
        Returns:
            List of security findings
        """
        findings = []
        
        # Define security anti-patterns
        patterns = [
            {
                'name': 'SQL Injection Risk',
                'pattern': r'(execute|query|sql)\s*\(\s*["\'].*\+.*["\']',
                'severity': 'high',
                'description': 'Potential SQL injection vulnerability - use parameterized queries'
            },
            {
                'name': 'Command Injection Risk',
                'pattern': r'(exec|system|popen|subprocess\.call)\s*\([^)]*\+',
                'severity': 'high',
                'description': 'Potential command injection vulnerability - validate and sanitize input'
            },
            {
                'name': 'Eval Usage',
                'pattern': r'\beval\s*\(',
                'severity': 'high',
                'description': 'Use of eval() is dangerous - avoid dynamic code execution'
            },
            {
                'name': 'Hardcoded IP Address',
                'pattern': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'severity': 'low',
                'description': 'Hardcoded IP address - consider using configuration'
            },
            {
                'name': 'TODO/FIXME Comment',
                'pattern': r'(TODO|FIXME|XXX|HACK):',
                'severity': 'low',
                'description': 'Unresolved TODO/FIXME comment'
            },
            {
                'name': 'Debug Statement',
                'pattern': r'(console\.log|print\(|debugger|System\.out\.println)',
                'severity': 'low',
                'description': 'Debug statement should be removed before production'
            },
            {
                'name': 'Insecure Random',
                'pattern': r'(Math\.random|random\.random)\(',
                'severity': 'medium',
                'description': 'Insecure random number generation - use cryptographically secure random for security'
            },
        ]
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, start=1):
                for pattern_config in patterns:
                    if re.search(pattern_config['pattern'], line):
                        findings.append({
                            'type': 'security_antipattern',
                            'severity': pattern_config['severity'],
                            'name': pattern_config['name'],
                            'file': file_path,
                            'line': line_num,
                            'description': pattern_config['description']
                        })
        
        except Exception as e:
            pass
        
        return findings
    
    def check_sensitive_files_in_gitignore(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Verify that sensitive files are properly ignored.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            List of findings about sensitive files
        """
        findings = []
        
        gitignore_path = os.path.join(repo_path, '.gitignore')
        
        if not os.path.exists(gitignore_path):
            return findings
        
        try:
            with open(gitignore_path, 'r') as f:
                gitignore_content = f.read()
            
            # Common sensitive patterns that should be in .gitignore
            sensitive_patterns = [
                ('.env', 'Environment files'),
                ('.pem', 'Private key files'),
                ('.key', 'Key files'),
                ('secrets', 'Secret files/directories'),
                ('credentials', 'Credential files'),
            ]
            
            for pattern, description in sensitive_patterns:
                if pattern not in gitignore_content:
                    findings.append({
                        'type': 'gitignore_security',
                        'severity': 'medium',
                        'name': 'Missing .gitignore entry',
                        'description': f"{description} ({pattern}) should be in .gitignore",
                        'recommendation': f"Add '{pattern}' to .gitignore"
                    })
        
        except Exception as e:
            pass
        
        return findings
    
    def analyze_repository(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Perform a comprehensive quality analysis of the repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            List of all quality findings
        """
        findings = []
        
        # Check dependencies
        findings.extend(self.check_dependency_vulnerabilities(repo_path))
        
        # Check .gitignore for sensitive files
        findings.extend(self.check_sensitive_files_in_gitignore(repo_path))
        
        # Scan code files
        code_extensions = ['.py', '.js', '.java', '.rb', '.go', '.php', '.ts', '.tsx', '.jsx']
        exclude_dirs = ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build', 'vendor']
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1]
                
                if file_ext in code_extensions:
                    rel_path = os.path.relpath(file_path, repo_path)
                    
                    # Check code complexity
                    findings.extend(self.check_code_complexity(rel_path))
                    
                    # Check security anti-patterns
                    findings.extend(self.check_security_antipatterns(file_path))
        
        self.findings = findings
        return findings
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings."""
        return self.findings
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of quality findings.
        
        Returns:
            Dictionary with summary statistics
        """
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for finding in self.findings:
            severity = finding.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'total': len(self.findings),
            **severity_counts
        }


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze code quality and security')
    parser.add_argument('path', help='Path to repository')
    args = parser.parse_args()
    
    analyzer = QualityAnalyzer()
    findings = analyzer.analyze_repository(args.path)
    
    print(f"\n{'='*60}")
    print("QUALITY ANALYZER RESULTS")
    print(f"{'='*60}\n")
    
    if findings:
        for finding in findings:
            print(f"[{finding['severity'].upper()}] {finding['name']}")
            if 'file' in finding:
                print(f"  File: {finding['file']}")
            if 'line' in finding:
                print(f"  Line: {finding['line']}")
            print(f"  {finding['description']}")
            if 'recommendation' in finding:
                print(f"  Recommendation: {finding['recommendation']}")
            print()
    else:
        print("No quality issues found!")
    
    summary = analyzer.get_summary()
    print(f"\nSummary: {summary['total']} total findings")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
