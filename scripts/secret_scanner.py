#!/usr/bin/env python3
"""
Secret Scanner Module
Scans Git repositories for exposed secrets, API keys, tokens, and passwords.
"""

import re
import os
import yaml
from typing import List, Dict, Any
from pathlib import Path


class SecretScanner:
    """Scans for secrets in code and Git history."""
    
    def __init__(self, config_path: str = None):
        """
        Initialize the secret scanner.
        
        Args:
            config_path: Path to the secret patterns configuration file
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'config',
                'secret_patterns.yml'
            )
        
        self.patterns = self._load_patterns(config_path)
        self.findings = []
    
    def _load_patterns(self, config_path: str) -> List[Dict[str, Any]]:
        """Load secret patterns from YAML configuration."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('patterns', [])
        except Exception as e:
            print(f"Warning: Could not load patterns from {config_path}: {e}")
            return self._get_default_patterns()
    
    def _get_default_patterns(self) -> List[Dict[str, Any]]:
        """Return default secret patterns if config file is not available."""
        return [
            {
                'name': 'AWS Access Key ID',
                'pattern': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
                'severity': 'critical'
            },
            {
                'name': 'GitHub Personal Access Token',
                'pattern': r'ghp_[a-zA-Z0-9]{36}',
                'severity': 'critical'
            },
            {
                'name': 'Generic API Key',
                'pattern': r'(?i)(api[_-]?key|apikey)[_-]?[=:][\'"]?[a-zA-Z0-9]{32,}[\'"]?',
                'severity': 'high'
            },
            {
                'name': 'Private SSH Key',
                'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'severity': 'critical'
            },
        ]
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a single file for secrets.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, start=1):
                for pattern_config in self.patterns:
                    pattern = pattern_config['pattern']
                    matches = re.finditer(pattern, line)
                    
                    for match in matches:
                        finding = {
                            'type': 'secret',
                            'name': pattern_config['name'],
                            'severity': pattern_config['severity'],
                            'file': file_path,
                            'line': line_num,
                            'match': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                            'description': pattern_config.get('description', f"{pattern_config['name']} detected")
                        }
                        findings.append(finding)
        except Exception as e:
            # Skip binary files and files that can't be read
            pass
        
        return findings
    
    def scan_directory(self, directory: str, exclude_dirs: List[str] = None) -> List[Dict[str, Any]]:
        """
        Scan all files in a directory recursively.
        
        Args:
            directory: Root directory to scan
            exclude_dirs: List of directory names to exclude
            
        Returns:
            List of all findings
        """
        if exclude_dirs is None:
            exclude_dirs = ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build']
        
        findings = []
        
        for root, dirs, files in os.walk(directory):
            # Remove excluded directories from the search
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_findings = self.scan_file(file_path)
                findings.extend(file_findings)
        
        self.findings = findings
        return findings
    
    def scan_git_history(self, repo_path: str, num_commits: int = 10) -> List[Dict[str, Any]]:
        """
        Scan Git commit history for secrets.
        
        Args:
            repo_path: Path to the Git repository
            num_commits: Number of recent commits to scan
            
        Returns:
            List of findings from commit history
        """
        findings = []
        
        try:
            import git
            repo = git.Repo(repo_path)
            
            # Get recent commits
            commits = list(repo.iter_commits(max_count=num_commits))
            
            for commit in commits:
                # Scan commit message
                for pattern_config in self.patterns:
                    pattern = pattern_config['pattern']
                    matches = re.finditer(pattern, commit.message)
                    
                    for match in matches:
                        finding = {
                            'type': 'secret_in_commit_message',
                            'name': pattern_config['name'],
                            'severity': pattern_config['severity'],
                            'commit': commit.hexsha[:8],
                            'match': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                            'description': f"{pattern_config['name']} found in commit message"
                        }
                        findings.append(finding)
                
                # Scan commit diff
                try:
                    if commit.parents:
                        diffs = commit.parents[0].diff(commit, create_patch=True)
                    else:
                        diffs = commit.diff(None, create_patch=True)
                    
                    for diff in diffs:
                        if diff.diff:
                            diff_text = diff.diff.decode('utf-8', errors='ignore')
                            
                            for pattern_config in self.patterns:
                                pattern = pattern_config['pattern']
                                matches = re.finditer(pattern, diff_text)
                                
                                for match in matches:
                                    finding = {
                                        'type': 'secret_in_diff',
                                        'name': pattern_config['name'],
                                        'severity': pattern_config['severity'],
                                        'commit': commit.hexsha[:8],
                                        'file': diff.b_path if diff.b_path else diff.a_path,
                                        'match': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0),
                                        'description': f"{pattern_config['name']} found in commit diff"
                                    }
                                    findings.append(finding)
                except Exception as e:
                    # Skip problematic diffs
                    pass
        
        except ImportError:
            print("Warning: GitPython not installed. Skipping Git history scan.")
        except Exception as e:
            print(f"Warning: Could not scan Git history: {e}")
        
        return findings
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings."""
        return self.findings
    
    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get findings filtered by severity level.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            Filtered list of findings
        """
        return [f for f in self.findings if f.get('severity') == severity]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of findings.
        
        Returns:
            Dictionary with summary statistics
        """
        summary = {
            'total': len(self.findings),
            'critical': len(self.get_findings_by_severity('critical')),
            'high': len(self.get_findings_by_severity('high')),
            'medium': len(self.get_findings_by_severity('medium')),
            'low': len(self.get_findings_by_severity('low'))
        }
        return summary


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan for secrets in files and Git history')
    parser.add_argument('path', help='Path to scan (file or directory)')
    parser.add_argument('--config', help='Path to secret patterns config file')
    parser.add_argument('--history', type=int, default=0, help='Number of Git commits to scan')
    args = parser.parse_args()
    
    scanner = SecretScanner(config_path=args.config)
    
    if os.path.isfile(args.path):
        findings = scanner.scan_file(args.path)
    else:
        findings = scanner.scan_directory(args.path)
        
        if args.history > 0:
            history_findings = scanner.scan_git_history(args.path, args.history)
            findings.extend(history_findings)
    
    print(f"\n{'='*60}")
    print("SECRET SCANNER RESULTS")
    print(f"{'='*60}\n")
    
    if findings:
        for finding in findings:
            print(f"[{finding['severity'].upper()}] {finding['name']}")
            if 'file' in finding:
                print(f"  File: {finding['file']}")
            if 'line' in finding:
                print(f"  Line: {finding['line']}")
            if 'commit' in finding:
                print(f"  Commit: {finding['commit']}")
            print(f"  Match: {finding['match']}")
            print()
    else:
        print("No secrets found!")
    
    summary = scanner.get_summary()
    print(f"\nSummary: {summary['total']} total findings")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
