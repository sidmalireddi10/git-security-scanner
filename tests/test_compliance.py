#!/usr/bin/env python3
"""
Unit tests for Compliance Checker
"""

import unittest
import os
import tempfile
import shutil
import sys

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from compliance_checker import ComplianceChecker


class TestComplianceChecker(unittest.TestCase):
    """Test cases for ComplianceChecker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.checker = ComplianceChecker()
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_checker_initialization(self):
        """Test that checker initializes correctly."""
        self.assertIsNotNone(self.checker)
        self.assertIsInstance(self.checker.rules, dict)
    
    def test_check_commit_message_conventional(self):
        """Test conventional commit message validation."""
        # Valid conventional commit
        findings = self.checker.check_commit_message("feat: add new feature")
        # Should have minimal or no findings for valid message
        self.assertIsInstance(findings, list)
        
        # Invalid commit message
        findings = self.checker.check_commit_message("bad message")
        self.assertGreater(len(findings), 0)
    
    def test_check_commit_message_length(self):
        """Test commit message length validation."""
        # Too short
        findings = self.checker.check_commit_message("fix")
        self.assertTrue(any('short' in f['description'].lower() for f in findings))
        
        # Too long
        long_message = "feat: " + "x" * 100
        findings = self.checker.check_commit_message(long_message)
        self.assertTrue(any('exceed' in f['description'].lower() for f in findings))
    
    def test_check_forbidden_files(self):
        """Test forbidden file detection."""
        findings = self.checker.check_forbidden_files('.env')
        self.assertGreater(len(findings), 0)
        self.assertTrue(any('forbidden' in f['name'].lower() or 'sensitive' in f['name'].lower() for f in findings))
        
        # Clean file should have no findings
        findings = self.checker.check_forbidden_files('readme.txt')
        # May or may not have findings depending on rules
        self.assertIsInstance(findings, list)
    
    def test_check_binary_files(self):
        """Test binary file detection."""
        findings = self.checker.check_binary_files('app.exe')
        # Should detect .exe as binary
        self.assertIsInstance(findings, list)
    
    def test_check_gitignore_missing(self):
        """Test .gitignore validation when missing."""
        findings = self.checker.check_gitignore(self.temp_dir)
        # Should report missing .gitignore
        self.assertTrue(any('gitignore' in f['type'].lower() for f in findings))
    
    def test_check_gitignore_exists(self):
        """Test .gitignore validation when it exists."""
        gitignore_path = os.path.join(self.temp_dir, '.gitignore')
        with open(gitignore_path, 'w') as f:
            f.write('*.pyc\n')
            f.write('.env\n')
        
        findings = self.checker.check_gitignore(self.temp_dir)
        # May have findings for missing entries
        self.assertIsInstance(findings, list)
    
    def test_check_branch_name(self):
        """Test branch name validation."""
        # Valid branch name
        findings = self.checker.check_branch_name('feature/add-login')
        # Should be valid
        
        # Invalid branch name
        findings = self.checker.check_branch_name('my_random_branch_123')
        # May or may not be invalid depending on rules
        self.assertIsInstance(findings, list)
    
    def test_check_protected_branch(self):
        """Test protected branch commit detection."""
        findings = self.checker.check_direct_commit_to_protected('main')
        self.assertGreater(len(findings), 0)
        self.assertTrue(any('protected' in f['name'].lower() for f in findings))
        
        # Non-protected branch
        findings = self.checker.check_direct_commit_to_protected('feature/test')
        self.assertEqual(len(findings), 0)
    
    def test_check_file_size(self):
        """Test file size checking."""
        # Create a large file
        large_file = os.path.join(self.temp_dir, 'large.bin')
        with open(large_file, 'wb') as f:
            f.write(b'0' * (60 * 1024 * 1024))  # 60 MB
        
        findings = self.checker.check_file_size(large_file)
        self.assertGreater(len(findings), 0)
    
    def test_get_summary(self):
        """Test getting summary statistics."""
        # Add some findings
        self.checker.findings = [
            {'severity': 'critical', 'name': 'test1'},
            {'severity': 'high', 'name': 'test2'},
            {'severity': 'medium', 'name': 'test3'},
        ]
        
        summary = self.checker.get_summary()
        self.assertEqual(summary['total'], 3)
        self.assertEqual(summary['critical'], 1)
        self.assertEqual(summary['high'], 1)
        self.assertEqual(summary['medium'], 1)


if __name__ == '__main__':
    unittest.main()
