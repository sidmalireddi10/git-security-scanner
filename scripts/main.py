#!/usr/bin/env python3
"""
Main CLI Entry Point
Orchestrates all security scanning modules.
"""

import argparse
import sys
import os
from typing import Dict, Any

# Import scanner modules
from secret_scanner import SecretScanner
from compliance_checker import ComplianceChecker
from quality_analyzer import QualityAnalyzer
from report_generator import ReportGenerator


def run_scan(
    repo_path: str,
    scan_secrets: bool = True,
    scan_compliance: bool = True,
    scan_quality: bool = True,
    scan_history: bool = False,
    num_commits: int = 10,
    output_dir: str = 'reports',
    severity_threshold: str = None
) -> Dict[str, Any]:
    """
    Run all security scans on the repository.
    
    Args:
        repo_path: Path to the repository to scan
        scan_secrets: Whether to run secret scanner
        scan_compliance: Whether to run compliance checker
        scan_quality: Whether to run quality analyzer
        scan_history: Whether to scan Git history
        num_commits: Number of commits to scan in history
        output_dir: Directory to save reports
        severity_threshold: Minimum severity to fail (critical, high, medium, low)
        
    Returns:
        Dictionary with scan results and statistics
    """
    print("=" * 70)
    print("GIT SECURITY & COMPLIANCE SCANNER")
    print("=" * 70)
    print(f"\nScanning repository: {repo_path}")
    print(f"Scan history: {scan_history} ({num_commits} commits)")
    print()
    
    all_findings = []
    generator = ReportGenerator()
    
    # Set metadata
    generator.set_metadata(
        repository_path=repo_path,
        scan_history=scan_history,
        commits_scanned=num_commits if scan_history else 0
    )
    
    # Run Secret Scanner
    if scan_secrets:
        print("🔍 Running Secret Scanner...")
        try:
            scanner = SecretScanner()
            findings = scanner.scan_directory(repo_path)
            
            if scan_history:
                history_findings = scanner.scan_git_history(repo_path, num_commits)
                findings.extend(history_findings)
            
            generator.add_findings(findings, source='secret_scanner')
            all_findings.extend(findings)
            
            summary = scanner.get_summary()
            print(f"   Found {summary['total']} potential secrets")
            print(f"   Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}")
        except Exception as e:
            print(f"   Error: {e}")
        print()
    
    # Run Compliance Checker
    if scan_compliance:
        print("📋 Running Compliance Checker...")
        try:
            checker = ComplianceChecker()
            findings = checker.scan_repository(repo_path, check_history=scan_history, num_commits=num_commits)
            
            generator.add_findings(findings, source='compliance_checker')
            all_findings.extend(findings)
            
            summary = checker.get_summary()
            print(f"   Found {summary['total']} compliance issues")
            print(f"   Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}")
        except Exception as e:
            print(f"   Error: {e}")
        print()
    
    # Run Quality Analyzer
    if scan_quality:
        print("⚙️  Running Quality Analyzer...")
        try:
            analyzer = QualityAnalyzer()
            findings = analyzer.analyze_repository(repo_path)
            
            generator.add_findings(findings, source='quality_analyzer')
            all_findings.extend(findings)
            
            summary = analyzer.get_summary()
            print(f"   Found {summary['total']} quality issues")
            print(f"   Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']}")
        except Exception as e:
            print(f"   Error: {e}")
        print()
    
    # Generate reports
    print("📊 Generating reports...")
    try:
        generator.save_reports(output_dir)
        print()
    except Exception as e:
        print(f"   Error generating reports: {e}")
        print()
    
    # Display summary
    stats = generator._get_statistics()
    
    print("=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"\nTotal Findings: {stats['total_findings']}")
    print(f"  🔴 Critical: {stats['critical']}")
    print(f"  🟠 High: {stats['high']}")
    print(f"  🟡 Medium: {stats['medium']}")
    print(f"  🔵 Low: {stats['low']}")
    print()
    
    # Check severity threshold
    exit_code = 0
    if severity_threshold:
        severity_levels = ['low', 'medium', 'high', 'critical']
        threshold_index = severity_levels.index(severity_threshold.lower())
        
        failing_count = 0
        for i in range(threshold_index, len(severity_levels)):
            failing_count += stats.get(severity_levels[i], 0)
        
        if failing_count > 0:
            print(f"❌ FAILED: {failing_count} findings at or above '{severity_threshold}' severity threshold")
            exit_code = 1
        else:
            print(f"✅ PASSED: No findings at or above '{severity_threshold}' severity threshold")
    else:
        if stats['total_findings'] == 0:
            print("✅ SUCCESS: No security or compliance issues found!")
        else:
            print("⚠️  Please review findings and take appropriate action.")
    
    print()
    
    return {
        'findings': all_findings,
        'statistics': stats,
        'exit_code': exit_code
    }


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Git Security & Compliance Scanner - Automated security scanning for Git repositories',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  python main.py .
  
  # Scan with Git history (last 20 commits)
  python main.py /path/to/repo --history --commits 20
  
  # Scan only secrets
  python main.py . --secrets-only
  
  # Set severity threshold to fail on high or critical
  python main.py . --severity-threshold high
  
  # Custom output directory
  python main.py . --output-dir /tmp/scan-results
        """
    )
    
    parser.add_argument(
        'repo_path',
        nargs='?',
        default='.',
        help='Path to the repository to scan (default: current directory)'
    )
    
    parser.add_argument(
        '--secrets-only',
        action='store_true',
        help='Run only the secret scanner'
    )
    
    parser.add_argument(
        '--compliance-only',
        action='store_true',
        help='Run only the compliance checker'
    )
    
    parser.add_argument(
        '--quality-only',
        action='store_true',
        help='Run only the quality analyzer'
    )
    
    parser.add_argument(
        '--history',
        action='store_true',
        help='Scan Git commit history'
    )
    
    parser.add_argument(
        '--commits',
        type=int,
        default=10,
        help='Number of commits to scan in history (default: 10)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    
    parser.add_argument(
        '--severity-threshold',
        choices=['low', 'medium', 'high', 'critical'],
        help='Minimum severity level to fail the scan'
    )
    
    args = parser.parse_args()
    
    # Determine which scanners to run
    if args.secrets_only:
        scan_secrets, scan_compliance, scan_quality = True, False, False
    elif args.compliance_only:
        scan_secrets, scan_compliance, scan_quality = False, True, False
    elif args.quality_only:
        scan_secrets, scan_compliance, scan_quality = False, False, True
    else:
        scan_secrets, scan_compliance, scan_quality = True, True, True
    
    # Validate repository path
    if not os.path.exists(args.repo_path):
        print(f"Error: Repository path '{args.repo_path}' does not exist")
        sys.exit(1)
    
    # Run the scan
    try:
        result = run_scan(
            repo_path=args.repo_path,
            scan_secrets=scan_secrets,
            scan_compliance=scan_compliance,
            scan_quality=scan_quality,
            scan_history=args.history,
            num_commits=args.commits,
            output_dir=args.output_dir,
            severity_threshold=args.severity_threshold
        )
        
        sys.exit(result['exit_code'])
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
