#!/usr/bin/env python3
"""
Compliance Checker Module
Validates Git best practices, commit standards, and repository compliance.
"""

import re
import os
import yaml
from typing import List, Dict, Any
from pathlib import Path


class ComplianceChecker:
    """Checks repository compliance with Git best practices."""
    
    def __init__(self, config_path: str = None):
        """
        Initialize the compliance checker.
        
        Args:
            config_path: Path to the compliance rules configuration file
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'config',
                'compliance_rules.yml'
            )
        
        self.rules = self._load_rules(config_path)
        self.findings = []
    
    def _load_rules(self, config_path: str) -> Dict[str, Any]:
        """Load compliance rules from YAML configuration."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load rules from {config_path}: {e}")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> Dict[str, Any]:
        """Return default compliance rules if config file is not available."""
        return {
            'commit_message': {
                'conventional_types': ['feat', 'fix', 'docs', 'style', 'refactor', 'test', 'chore'],
                'min_length': 10,
                'max_subject_length': 72
            },
            'file_restrictions': {
                'max_file_size_mb': 50,
                'forbidden_extensions': ['.env', '.pem', '.key']
            },
            'branch_naming': {
                'protected_branches': ['main', 'master', 'production']
            }
        }
    
    def check_commit_message(self, message: str, commit_sha: str = None) -> List[Dict[str, Any]]:
        """
        Validate commit message against conventional commit standards.
        
        Args:
            message: Commit message to validate
            commit_sha: Optional commit SHA for reference
            
        Returns:
            List of compliance findings
        """
        findings = []
        rules = self.rules.get('commit_message', {})
        
        # Split message into subject and body
        lines = message.strip().split('\n')
        subject = lines[0] if lines else ''
        
        # Check minimum length
        min_length = rules.get('min_length', 10)
        if len(subject) < min_length:
            findings.append({
                'type': 'commit_message',
                'severity': 'low',
                'name': 'Short commit message',
                'description': f"Commit message subject is too short (minimum {min_length} characters)",
                'commit': commit_sha
            })
        
        # Check maximum subject length
        max_length = rules.get('max_subject_length', 72)
        if len(subject) > max_length:
            findings.append({
                'type': 'commit_message',
                'severity': 'low',
                'name': 'Long commit message subject',
                'description': f"Commit message subject exceeds {max_length} characters",
                'commit': commit_sha
            })
        
        # Check conventional commit format
        conventional_types = rules.get('conventional_types', [])
        conventional_pattern = r'^(' + '|'.join(conventional_types) + r')(\(.+\))?:\s.+'
        
        if not re.match(conventional_pattern, subject):
            findings.append({
                'type': 'commit_message',
                'severity': 'medium',
                'name': 'Non-conventional commit message',
                'description': f"Commit message does not follow conventional commit format. Expected: type(scope): description",
                'commit': commit_sha
            })
        
        return findings
    
    def check_file_size(self, file_path: str, size_mb: float = None) -> List[Dict[str, Any]]:
        """
        Check if file size exceeds the maximum allowed size.
        
        Args:
            file_path: Path to the file
            size_mb: File size in MB (if already known)
            
        Returns:
            List of compliance findings
        """
        findings = []
        max_size_mb = self.rules.get('file_restrictions', {}).get('max_file_size_mb', 50)
        
        try:
            if size_mb is None:
                size_mb = os.path.getsize(file_path) / (1024 * 1024)
            
            if size_mb > max_size_mb:
                findings.append({
                    'type': 'large_file',
                    'severity': 'high',
                    'name': 'Large file detected',
                    'file': file_path,
                    'description': f"File size ({size_mb:.2f} MB) exceeds maximum ({max_size_mb} MB)",
                    'size_mb': round(size_mb, 2)
                })
        except Exception as e:
            pass
        
        return findings
    
    def check_forbidden_files(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Check if file has a forbidden extension or name.
        
        Args:
            file_path: Path to the file
            
        Returns:
            List of compliance findings
        """
        findings = []
        forbidden_extensions = self.rules.get('file_restrictions', {}).get('forbidden_extensions', [])
        
        file_ext = os.path.splitext(file_path)[1]
        
        if file_ext in forbidden_extensions:
            findings.append({
                'type': 'forbidden_file',
                'severity': 'critical',
                'name': 'Forbidden file type',
                'file': file_path,
                'description': f"File with forbidden extension '{file_ext}' should not be committed"
            })
        
        # Check for specific sensitive filenames
        sensitive_files = self.rules.get('security', {}).get('sensitive_files', [])
        file_name = os.path.basename(file_path)
        
        for sensitive_pattern in sensitive_files:
            # Convert glob pattern to regex
            regex_pattern = sensitive_pattern.replace('*', '.*').replace('.', r'\.')
            if re.match(regex_pattern, file_name):
                findings.append({
                    'type': 'sensitive_file',
                    'severity': 'critical',
                    'name': 'Sensitive file detected',
                    'file': file_path,
                    'description': f"Sensitive file '{file_name}' should be in .gitignore"
                })
        
        return findings
    
    def check_binary_files(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Check for binary files that might be inappropriately committed.
        
        Args:
            file_path: Path to the file
            
        Returns:
            List of compliance findings
        """
        findings = []
        binary_extensions = self.rules.get('file_restrictions', {}).get('binary_extensions', [])
        
        file_ext = os.path.splitext(file_path)[1]
        
        if file_ext in binary_extensions:
            findings.append({
                'type': 'binary_file',
                'severity': 'medium',
                'name': 'Binary file detected',
                'file': file_path,
                'description': f"Binary file with extension '{file_ext}' - verify if it should be tracked"
            })
        
        return findings
    
    def check_gitignore(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Validate .gitignore file existence and required entries.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            List of compliance findings
        """
        findings = []
        gitignore_path = os.path.join(repo_path, '.gitignore')
        
        # Check if .gitignore exists
        require_gitignore = self.rules.get('gitignore_rules', {}).get('require_gitignore', True)
        
        if require_gitignore and not os.path.exists(gitignore_path):
            findings.append({
                'type': 'missing_gitignore',
                'severity': 'high',
                'name': 'Missing .gitignore',
                'description': 'Repository should have a .gitignore file'
            })
            return findings
        
        # Check for required entries
        if os.path.exists(gitignore_path):
            try:
                with open(gitignore_path, 'r') as f:
                    gitignore_content = f.read()
                
                required_entries = self.rules.get('gitignore_rules', {}).get('required_entries', [])
                
                for entry in required_entries:
                    if entry not in gitignore_content:
                        findings.append({
                            'type': 'gitignore_incomplete',
                            'severity': 'medium',
                            'name': 'Incomplete .gitignore',
                            'description': f"Missing recommended entry in .gitignore: {entry}"
                        })
            except Exception as e:
                pass
        
        return findings
    
    def check_branch_name(self, branch_name: str) -> List[Dict[str, Any]]:
        """
        Validate branch naming convention.
        
        Args:
            branch_name: Name of the branch
            
        Returns:
            List of compliance findings
        """
        findings = []
        valid_patterns = self.rules.get('branch_naming', {}).get('valid_patterns', [])
        
        if valid_patterns:
            is_valid = any(re.match(pattern, branch_name) for pattern in valid_patterns)
            
            if not is_valid:
                findings.append({
                    'type': 'branch_naming',
                    'severity': 'low',
                    'name': 'Invalid branch name',
                    'branch': branch_name,
                    'description': f"Branch name '{branch_name}' does not follow naming conventions"
                })
        
        return findings
    
    def check_direct_commit_to_protected(self, branch_name: str, commit_sha: str = None) -> List[Dict[str, Any]]:
        """
        Check if commit was made directly to a protected branch.
        
        Args:
            branch_name: Name of the branch
            commit_sha: Optional commit SHA
            
        Returns:
            List of compliance findings
        """
        findings = []
        protected_branches = self.rules.get('branch_naming', {}).get('protected_branches', [])
        
        if branch_name in protected_branches:
            findings.append({
                'type': 'protected_branch_commit',
                'severity': 'high',
                'name': 'Direct commit to protected branch',
                'branch': branch_name,
                'commit': commit_sha,
                'description': f"Direct commits to '{branch_name}' branch should be avoided. Use pull requests instead."
            })
        
        return findings
    
    def scan_repository(self, repo_path: str, check_history: bool = False, num_commits: int = 10) -> List[Dict[str, Any]]:
        """
        Perform a full compliance scan of the repository.
        
        Args:
            repo_path: Path to the repository
            check_history: Whether to check commit history
            num_commits: Number of recent commits to check
            
        Returns:
            List of all compliance findings
        """
        findings = []
        
        # Check .gitignore
        findings.extend(self.check_gitignore(repo_path))
        
        # Scan files
        exclude_dirs = ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build']
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                
                # Check file size
                findings.extend(self.check_file_size(file_path))
                
                # Check forbidden files
                findings.extend(self.check_forbidden_files(rel_path))
                
                # Check binary files
                findings.extend(self.check_binary_files(rel_path))
        
        # Check Git history if requested
        if check_history:
            try:
                import git
                repo = git.Repo(repo_path)
                
                # Get current branch
                try:
                    current_branch = repo.active_branch.name
                    findings.extend(self.check_branch_name(current_branch))
                except:
                    pass
                
                # Check recent commits
                commits = list(repo.iter_commits(max_count=num_commits))
                
                for commit in commits:
                    # Check commit message
                    findings.extend(self.check_commit_message(commit.message, commit.hexsha[:8]))
            
            except ImportError:
                print("Warning: GitPython not installed. Skipping Git history checks.")
            except Exception as e:
                print(f"Warning: Could not check Git history: {e}")
        
        self.findings = findings
        return findings
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings."""
        return self.findings
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of compliance findings.
        
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
    
    parser = argparse.ArgumentParser(description='Check repository compliance')
    parser.add_argument('path', help='Path to repository')
    parser.add_argument('--config', help='Path to compliance rules config file')
    parser.add_argument('--history', action='store_true', help='Check Git commit history')
    parser.add_argument('--commits', type=int, default=10, help='Number of commits to check')
    args = parser.parse_args()
    
    checker = ComplianceChecker(config_path=args.config)
    findings = checker.scan_repository(args.path, check_history=args.history, num_commits=args.commits)
    
    print(f"\n{'='*60}")
    print("COMPLIANCE CHECKER RESULTS")
    print(f"{'='*60}\n")
    
    if findings:
        for finding in findings:
            print(f"[{finding['severity'].upper()}] {finding['name']}")
            if 'file' in finding:
                print(f"  File: {finding['file']}")
            if 'branch' in finding:
                print(f"  Branch: {finding['branch']}")
            if 'commit' in finding:
                print(f"  Commit: {finding['commit']}")
            print(f"  {finding['description']}")
            print()
    else:
        print("No compliance issues found!")
    
    summary = checker.get_summary()
    print(f"\nSummary: {summary['total']} total findings")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
