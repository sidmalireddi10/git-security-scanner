# 🔐 Git Security & Compliance Scanner

An automated, comprehensive security and compliance scanning tool for Git repositories. Built for source management teams to detect secrets, enforce best practices, and maintain code quality across all development activities.

## 🎯 Overview

This tool provides automated security scanning as a GitHub Action or standalone CLI tool. It helps development teams:

- **Prevent secret leaks** by detecting API keys, tokens, and credentials
- **Enforce compliance** with commit message standards and Git best practices  
- **Improve code quality** by identifying security anti-patterns and vulnerabilities
- **Automate reviews** reducing manual security review burden
- **Scale security** across enterprise repositories

## ✨ Features

### 🔍 Secret Scanner
- Detects 25+ types of secrets including:
  - AWS keys, GitHub tokens, API keys
  - Private SSH/PGP keys
  - Database credentials and connection strings
  - Slack webhooks, Stripe keys, Google API keys
  - And more...
- Scans both current files and Git commit history
- Configurable patterns via YAML

### 📋 Compliance Checker
- Validates conventional commit message format
- Detects large files (>50MB by default)
- Checks for forbidden file types (.env, .pem, .key, etc.)
- Validates .gitignore completeness
- Enforces branch naming conventions
- Prevents direct commits to protected branches

### ⚙️ Quality Analyzer
- Checks for dependency vulnerabilities (npm, pip, maven, bundler)
- Analyzes code complexity metrics
- Detects security anti-patterns:
  - SQL/Command injection risks
  - Use of eval()
  - Insecure random number generation
  - Debug statements in production code
- Validates sensitive files are in .gitignore

### 📊 Report Generator
- Generates comprehensive JSON and Markdown reports
- Severity-based categorization (Critical, High, Medium, Low)
- Actionable remediation suggestions
- GitHub-compatible annotations for PR comments
- Summary statistics and trend tracking

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     GitHub Actions Workflow                  │
│  (Push, PR, Manual Dispatch)                                │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                      Main Orchestrator                       │
│  (scripts/main.py)                                          │
└─────┬──────────────┬─────────────────┬─────────────────────┘
      │              │                 │
      ▼              ▼                 ▼
┌──────────┐  ┌─────────────┐  ┌──────────────┐
│ Secret   │  │ Compliance  │  │  Quality     │
│ Scanner  │  │  Checker    │  │  Analyzer    │
└─────┬────┘  └──────┬──────┘  └──────┬───────┘
      │              │                 │
      └──────────────┴─────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  Report Generator    │
          │  - JSON              │
          │  - Markdown          │
          │  - GitHub Annotations│
          └──────────────────────┘
```

## 🚀 Quick Start

### Installation

#### As a GitHub Action (Recommended)

1. Add to your repository at `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: actions/setup-python@v5
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run security scan
        run: |
          cd scripts
          python main.py .. --history --commits 10 --severity-threshold high
```

2. The scan will automatically run on every push and pull request!

#### As a CLI Tool

```bash
# Clone the repository
git clone https://github.com/sidmalireddi10/git-security-scanner.git
cd git-security-scanner

# Install dependencies
pip install -r requirements.txt

# Run a scan
cd scripts
python main.py /path/to/your/repo
```

## 📖 Usage

### Command Line Interface

```bash
# Basic scan of current directory
python main.py .

# Scan with Git history (last 20 commits)
python main.py /path/to/repo --history --commits 20

# Scan only for secrets
python main.py . --secrets-only

# Set severity threshold to fail on high or critical
python main.py . --severity-threshold high

# Custom output directory
python main.py . --output-dir /tmp/scan-results

# Full help
python main.py --help
```

### Individual Scanners

Each scanner can also be run independently:

```bash
# Secret scanner
python secret_scanner.py /path/to/repo --history 10

# Compliance checker  
python compliance_checker.py /path/to/repo --history --commits 10

# Quality analyzer
python quality_analyzer.py /path/to/repo
```

### GitHub Action Inputs

The provided GitHub Action workflow supports these inputs:

| Input | Description | Default | Options |
|-------|-------------|---------|---------|
| `severity-threshold` | Minimum severity to fail | `high` | critical, high, medium, low |
| `scan-history` | Number of commits to scan | `10` | Any number, 0 to skip |
| `create-issues` | Auto-create issues for critical findings | `false` | true, false |

Trigger manually via workflow_dispatch with custom parameters.

## 🔧 Configuration

### Secret Patterns

Edit `config/secret_patterns.yml` to customize secret detection:

```yaml
patterns:
  - name: "Custom API Key"
    pattern: "custom_api_[a-zA-Z0-9]{32}"
    severity: "critical"
    description: "Custom API key detected"
```

### Compliance Rules

Edit `config/compliance_rules.yml` to customize compliance checks:

```yaml
commit_message:
  conventional_types:
    - "feat"
    - "fix"
    - "docs"
  min_length: 10
  max_subject_length: 72

file_restrictions:
  max_file_size_mb: 50
  forbidden_extensions:
    - ".env"
    - ".pem"
```

## 📊 Sample Output

### CLI Output

```
======================================================================
GIT SECURITY & COMPLIANCE SCANNER
======================================================================

Scanning repository: /path/to/repo
Scan history: True (10 commits)

🔍 Running Secret Scanner...
   Found 3 potential secrets
   Critical: 2, High: 1, Medium: 0, Low: 0

📋 Running Compliance Checker...
   Found 5 compliance issues
   Critical: 0, High: 2, Medium: 2, Low: 1

⚙️  Running Quality Analyzer...
   Found 4 quality issues
   Critical: 0, High: 1, Medium: 2, Low: 1

📊 Generating reports...

======================================================================
SCAN SUMMARY
======================================================================

Total Findings: 12
  🔴 Critical: 2
  🟠 High: 4
  🟡 Medium: 4
  🔵 Low: 2

⚠️  Please review findings and take appropriate action.
```

### Report Files

After scanning, you'll find:
- `reports/security-report.json` - Machine-readable JSON
- `reports/security-report.md` - Human-readable Markdown
- `reports/security-report-annotations.txt` - GitHub annotations

See [examples/sample_report.md](examples/sample_report.md) for a complete example.

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=scripts --cov-report=term-missing
```