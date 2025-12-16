# ARTHEON-SAST

Static Application Security Testing tool

## Features

- 11 vulnerability categories
- 128 regex patterns for detection
- HTML reports with severity levels
- Line-by-line vulnerability detection
- Automatic duplicate prevention
- Responsive design for desktop and mobile

## Installation

### From PyPI
```bash
pip install artheon-sast
```

## Usage

### Command Line
```bash
artheon-sast /path/to/your/project
```

Scans all `.js` files, detects vulnerabilities, generates HTML report, and opens it in browser.

### Python API
```python
from language_analyzer import SecurityScanner

scanner = SecurityScanner("/path/to/project")
scanner.scan()
report_path = scanner.generate_html_report()
```

## Vulnerability Categories

| Category | Severity |
|----------|----------|
| eval() Usage | CRITICAL |
| Hardcoded Secrets | CRITICAL |
| SQL Injection | CRITICAL |
| Command Injection | CRITICAL |
| XSS Vulnerabilities | HIGH |
| Insecure Crypto | HIGH |
| Path Traversal | HIGH |
| Prototype Pollution | HIGH |
| No Input Validation | MEDIUM |
| Insecure CORS | MEDIUM |
| Insecure Dependencies | MEDIUM |

## Report Format

HTML report includes:
- Summary metrics (total, critical, high, medium)
- Vulnerabilities grouped by file
- Code context for each finding
- Severity color coding
- Recommendations per vulnerability

## Testing

```bash
pytest tests/ -v
```

Status: 6/6 tests passing

## Requirements

- Python 3.8+
- No external dependencies

## Authors

Dorian Tituaña, Ismael Toala
