#!/usr/bin/env python3
"""
Integration tests for the complete scanning workflow
"""

import unittest
import os
import tempfile
import shutil
import sys

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from secret_scanner import SecretScanner
from compliance_checker import ComplianceChecker
from quality_analyzer import QualityAnalyzer
from report_generator import ReportGenerator


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete scanning workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.reports_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.reports_dir)
    
    def test_full_scan_workflow(self):
        """Test the complete scanning workflow."""
        # Create a test repository with various issues
        test_file = os.path.join(self.temp_dir, 'app.py')
        with open(test_file, 'w') as f:
            f.write('# Test application\n')
            f.write('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            f.write('def long_function():\n')
            f.write('    ' + 'pass\n' * 100)
        
        # Run all scanners
        secret_scanner = SecretScanner()
        compliance_checker = ComplianceChecker()
        quality_analyzer = QualityAnalyzer()
        
        secret_findings = secret_scanner.scan_directory(self.temp_dir)
        compliance_findings = compliance_checker.scan_repository(self.temp_dir)
        quality_findings = quality_analyzer.analyze_repository(self.temp_dir)
        
        # Verify findings
        self.assertIsInstance(secret_findings, list)
        self.assertIsInstance(compliance_findings, list)
        self.assertIsInstance(quality_findings, list)
        
        # Generate report
        generator = ReportGenerator()
        generator.add_findings(secret_findings, 'secret_scanner')
        generator.add_findings(compliance_findings, 'compliance_checker')
        generator.add_findings(quality_findings, 'quality_analyzer')
        
        # Generate both formats
        json_report = generator.generate_json_report()
        md_report = generator.generate_markdown_report()
        
        self.assertIn('findings', json_report)
        self.assertIn('Security Scan Report', md_report)
    
    def test_report_generation(self):
        """Test report generation with sample findings."""
        generator = ReportGenerator()
        
        sample_findings = [
            {
                'type': 'secret',
                'severity': 'critical',
                'name': 'AWS Key',
                'file': 'config.py',
                'line': 10,
                'description': 'AWS access key detected'
            },
            {
                'type': 'compliance',
                'severity': 'high',
                'name': 'Large file',
                'file': 'data.bin',
                'description': 'File exceeds size limit'
            }
        ]
        
        generator.add_findings(sample_findings)
        generator.set_metadata(repository='test-repo')
        
        # Test JSON generation
        json_report = generator.generate_json_report()
        self.assertIn('"total_findings": 2', json_report)
        
        # Test Markdown generation
        md_report = generator.generate_markdown_report()
        self.assertIn('AWS Key', md_report)
        self.assertIn('Large file', md_report)
        
        # Test annotations
        annotations = generator.generate_github_annotations()
        self.assertEqual(len(annotations), 2)
        self.assertTrue(all('::error' in a or '::warning' in a for a in annotations))
    
    def test_save_reports(self):
        """Test saving reports to files."""
        generator = ReportGenerator()
        
        sample_findings = [
            {
                'type': 'test',
                'severity': 'low',
                'name': 'Test Finding',
                'description': 'This is a test'
            }
        ]
        
        generator.add_findings(sample_findings)
        generator.save_reports(self.reports_dir, 'test-report')
        
        # Check that files were created
        self.assertTrue(os.path.exists(os.path.join(self.reports_dir, 'test-report.json')))
        self.assertTrue(os.path.exists(os.path.join(self.reports_dir, 'test-report.md')))
        self.assertTrue(os.path.exists(os.path.join(self.reports_dir, 'test-report-annotations.txt')))
    
    def test_severity_categorization(self):
        """Test that findings are correctly categorized by severity."""
        generator = ReportGenerator()
        
        findings = [
            {'severity': 'critical', 'name': 'Critical Issue', 'type': 'test'},
            {'severity': 'high', 'name': 'High Issue', 'type': 'test'},
            {'severity': 'medium', 'name': 'Medium Issue', 'type': 'test'},
            {'severity': 'low', 'name': 'Low Issue', 'type': 'test'},
        ]
        
        generator.add_findings(findings)
        categorized = generator._categorize_by_severity()
        
        self.assertEqual(len(categorized['critical']), 1)
        self.assertEqual(len(categorized['high']), 1)
        self.assertEqual(len(categorized['medium']), 1)
        self.assertEqual(len(categorized['low']), 1)
    
    def test_empty_scan(self):
        """Test scanning with no findings."""
        # Create clean files
        clean_file = os.path.join(self.temp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('def hello():\n    return "Hello"\n')
        
        scanner = SecretScanner()
        findings = scanner.scan_directory(self.temp_dir)
        
        # May have no secret findings
        self.assertIsInstance(findings, list)
        
        summary = scanner.get_summary()
        self.assertIn('total', summary)


if __name__ == '__main__':
    unittest.main()
