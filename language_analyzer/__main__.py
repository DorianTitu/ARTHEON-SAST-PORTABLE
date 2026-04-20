import sys
import os
import argparse
import tempfile
from .banner import print_banner
from .security_scanner import SecurityScanner


def _resolve_output_path(args):
    if args.pdf:
        return args.output or "sast_report.pdf"
    return args.output or "sast_report.html"


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="ARTHEON-SAST scanner")
    parser.add_argument("directory", nargs="?", default=None, help="Target directory to scan")
    parser.add_argument(
        "--output",
        default=None,
        help="Output path. Without --pdf generates HTML, with --pdf generates PDF.",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Generate PDF report with Playwright (no browser headers/footers)",
    )

    args = parser.parse_args()
    directory = args.directory
    
    try:
        scanner = SecurityScanner(directory)
        findings = scanner.scan()

        print(f"[+] Target: {directory or 'current directory'}")
        print(f"[+] Files scanned: {len(scanner.source_files)}")
        print(f"[+] Findings: {len(findings)}")

        output_path = _resolve_output_path(args)

        if args.pdf:
            tmp_html = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
            html_temp_path = tmp_html.name
            tmp_html.close()

            try:
                report_path = scanner.generate_pdf_report(
                    pdf_output_path=output_path,
                    html_output_path=html_temp_path,
                )
            finally:
                if os.path.exists(html_temp_path):
                    os.remove(html_temp_path)
        else:
            report_path = scanner.generate_html_report(output_path=output_path)

        print(f"[+] Report generated: {report_path}")
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
