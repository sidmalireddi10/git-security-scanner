#!/usr/bin/env python3
"""
Unit tests for Secret Scanner
"""

import unittest
import os
import tempfile
import shutil
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from secret_scanner import SecretScanner


class TestSecretScanner(unittest.TestCase):
    """Test cases for SecretScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = SecretScanner()
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_scanner_initialization(self):
        """Test that scanner initializes correctly."""
        self.assertIsNotNone(self.scanner)
        self.assertIsInstance(self.scanner.patterns, list)
        self.assertGreater(len(self.scanner.patterns), 0)
    
    def test_scan_file_with_aws_key(self):
        """Test detection of AWS access key."""
        test_file = os.path.join(self.temp_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        
        findings = self.scanner.scan_file(test_file)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any('AWS' in f['name'] for f in findings))
    
    def test_scan_file_with_github_token(self):
        """Test detection of GitHub token."""
        test_file = os.path.join(self.temp_dir, 'config.js')
        with open(test_file, 'w') as f:
            f.write('const token = "ghp_1234567890abcdefghijklmnopqrstuv123456";\n')
        
        findings = self.scanner.scan_file(test_file)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any('GitHub' in f['name'] for f in findings))
    
    def test_scan_file_with_private_key(self):
        """Test detection of private SSH key."""
        test_file = os.path.join(self.temp_dir, 'key.pem')
        with open(test_file, 'w') as f:
            f.write('-----BEGIN RSA PRIVATE KEY-----\n')
            f.write('MIIEpAIBAAKCAQEA...\n')
        
        findings = self.scanner.scan_file(test_file)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any('Private' in f['name'] or 'Key' in f['name'] for f in findings))
    
    def test_scan_file_no_secrets(self):
        """Test that clean file produces no findings."""
        test_file = os.path.join(self.temp_dir, 'clean.py')
        with open(test_file, 'w') as f:
            f.write('def hello():\n')
            f.write('    print("Hello, World!")\n')
        
        findings = self.scanner.scan_file(test_file)
        self.assertEqual(len(findings), 0)
    
    def test_scan_directory(self):
        """Test scanning entire directory."""
        # Create test files
        test_file1 = os.path.join(self.temp_dir, 'file1.py')
        with open(test_file1, 'w') as f:
            f.write('api_key = "sk_test_abcdefghijklmnopqrstuvwxyz123456"\n')
        
        test_file2 = os.path.join(self.temp_dir, 'file2.py')
        with open(test_file2, 'w') as f:
            f.write('def clean_function():\n    pass\n')
        
        findings = self.scanner.scan_directory(self.temp_dir)
        self.assertGreater(len(findings), 0)
    
    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        test_file = os.path.join(self.temp_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        
        self.scanner.scan_directory(self.temp_dir)
        
        critical = self.scanner.get_findings_by_severity('critical')
        self.assertIsInstance(critical, list)
    
    def test_get_summary(self):
        """Test getting summary statistics."""
        test_file = os.path.join(self.temp_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        
        self.scanner.scan_directory(self.temp_dir)
        summary = self.scanner.get_summary()
        
        self.assertIn('total', summary)
        self.assertIn('critical', summary)
        self.assertIn('high', summary)
        self.assertIn('medium', summary)
        self.assertIn('low', summary)


if __name__ == '__main__':
    unittest.main()
