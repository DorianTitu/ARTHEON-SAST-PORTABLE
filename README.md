# ARTHEON-SAST

Static Application Security Testing tool for multiple programming languages

## Supported Languages

- JavaScript (.js)
- Python (.py)
- Java (.java)
- C# (.cs)

## Features

- 40 vulnerability rules (10 per language)
- 400+ regex patterns for detection
- HTML reports with severity levels
- Line-by-line vulnerability detection
- Automatic duplicate prevention
- Responsive design for desktop and mobile

## Installation

### From PyPI
```bash
pip install artheon-sast
```

Includes HTML report support via Jinja2.

### Optional PDF Support (no browser headers/footers)
```bash
pip install "artheon-sast[pdf]"
python -m playwright install chromium
```

## Usage

### Command Line
```bash
artheon-sast /path/to/your/project
```

Generate report in a custom location with a unified flag:
```bash
artheon-sast /path/to/your/project --output ./reports/my_report.html
```

Generate PDF directly from Python (clean pages, no title/URL in margins):
```bash
artheon-sast /path/to/your/project --pdf
```

Generate PDF in custom path (with --pdf, .pdf means PDF output):
```bash
artheon-sast /path/to/your/project --pdf --output ./reports/my_report.pdf
```

Notes:
- Without --pdf, --output controls the HTML report path.
- With --pdf, --output controls the PDF report path.
- In --pdf mode the tool uses a temporary HTML internally and only keeps the PDF output.

Scans all source files, detects vulnerabilities, generates HTML report, and opens it in browser.

### Python API
```python
from language_analyzer import SecurityScanner

scanner = SecurityScanner("/path/to/project")
scanner.scan()
report_path = scanner.generate_html_report()

# Optional: PDF generation via Playwright
pdf_path = scanner.generate_pdf_report()
```

## Vulnerability Categories by Language

### JavaScript (10 rules)

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

### Python (10 rules)

| Category | Severity |
|----------|----------|
| eval() and exec() Usage | CRITICAL |
| Hardcoded Secrets | CRITICAL |
| SQL Injection | CRITICAL |
| Command Injection | CRITICAL |
| Insecure Deserialization | CRITICAL |
| Insecure Crypto | HIGH |
| Path Traversal | HIGH |
| No Input Validation | MEDIUM |
| Insecure Dependencies | MEDIUM |
| XXE Injection | HIGH |

### Java (10 rules)

| Category | Severity |
|----------|----------|
| SQL Injection | CRITICAL |
| Command Injection | CRITICAL |
| XXE Injection | CRITICAL |
| Hardcoded Secrets | CRITICAL |
| Insecure Deserialization | CRITICAL |
| Insecure Crypto | HIGH |
| Path Traversal | HIGH |
| XSS Vulnerabilities | HIGH |
| Insecure HTTP Headers | MEDIUM |
| Weak Authentication | HIGH |

### C# (10 rules)

| Category | Severity |
|----------|----------|
| SQL Injection | CRITICAL |
| Command Injection | CRITICAL |
| Hardcoded Secrets | CRITICAL |
| Deserialization Vulnerability | CRITICAL |
| XXE Injection | HIGH |
| Insecure Crypto | HIGH |
| Path Traversal | HIGH |
| Weak Authentication | HIGH |
| Insecure HTTP Headers | MEDIUM |
| LINQ Injection | HIGH |

## Report Format

HTML report includes:
- Summary metrics (total, critical, high, medium)
- Vulnerabilities grouped by file and language
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
- jinja2 (installed automatically)
- playwright (optional, only for PDF export)

## Authors

Dorian Tituaña, Ismael Toala

## License

MIT
