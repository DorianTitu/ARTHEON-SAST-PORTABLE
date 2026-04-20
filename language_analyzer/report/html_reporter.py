from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape


class HTMLReporter:
    def __init__(self, findings, directory, js_files_count):
        self.findings = findings
        self.directory = directory
        self.js_files_count = js_files_count
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.severity_order = ["critical", "high", "medium", "low", "info"]

    def generate(self, output_path="sast_report.html"):
        env = Environment(
            loader=FileSystemLoader(self._get_template_dir()),
            autoescape=select_autoescape(["html"])
        )

        template = env.get_template("report.html")

        context = {
            "findings": self.findings,
            "directory": self.directory,
            "timestamp": self.timestamp,
            "js_files_count": self.js_files_count,
            "severity_counts": self._count_by_severity(),
            "severity_unique_counts": self._count_unique_by_severity(),
            "grouped": self._group_by_file(),
            "global_vulnerabilities": self._group_global_vulnerabilities(),
        }

        html = template.render(context)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

    def generate_pdf(self, html_path: str, pdf_output_path: str = "sast_report.pdf"):
        """Generate PDF from an HTML report using Playwright.

        This avoids browser print headers/footers and keeps full style control.
        """
        try:
            from playwright.sync_api import Error as PlaywrightError, sync_playwright  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "PDF generation requires Playwright. Install with:\n"
                "1) pip install playwright\n"
                "2) python -m playwright install chromium"
            ) from exc

        html_file = Path(html_path).resolve()
        pdf_file = Path(pdf_output_path).resolve()

        if not html_file.exists():
            raise ValueError(f"HTML report does not exist: {html_file}")

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page()
                page.goto(html_file.as_uri(), wait_until="networkidle")
                page.wait_for_selector("#chart")
                page.wait_for_timeout(400)
                page.emulate_media(media="print")
                page.pdf(
                    path=str(pdf_file),
                    format="A4",
                    print_background=True,
                    display_header_footer=False,
                    margin={
                        "top": "12mm",
                        "right": "12mm",
                        "bottom": "12mm",
                        "left": "12mm",
                    },
                )
                browser.close()
        except PlaywrightError as exc:
            raise RuntimeError(
                "Playwright browser is missing or not ready. Run:\n"
                "python -m playwright install chromium"
            ) from exc

        return str(pdf_file)

    def _get_template_dir(self):
        return Path(__file__).parent / "templates"

    def _count_by_severity(self):
        counts = {k: 0 for k in self.severity_order}
        for f in self.findings:
            counts[f['severity']] += 1
        return counts

    def _count_unique_by_severity(self):
        """Count unique vulnerability types (rule_id) by severity.

        Repeated hits of the same vulnerability across multiple lines are
        counted once for executive chart clarity.
        """
        counts = {k: 0 for k in self.severity_order}
        seen_rule_ids = set()

        for finding in self.findings:
            rule_id = finding["rule_id"]
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)
            counts[finding["severity"]] += 1

        return counts

    def _group_by_file(self):
        grouped = {}
        for f in self.findings:
            grouped.setdefault(f['file'], []).append(f)
        return grouped

    def _group_global_vulnerabilities(self):
        """Group global vulnerabilities by severity/rule/file and aggregate lines.

        This keeps the global table compact while preserving where each
        vulnerability appears within the file.
        """
        grouped = {}

        for finding in self.findings:
            key = (
                finding["severity"],
                finding["rule_id"],
                finding["rule_name"],
                finding["file"],
            )

            if key not in grouped:
                grouped[key] = {
                    "severity": finding["severity"],
                    "rule_id": finding["rule_id"],
                    "rule_name": finding["rule_name"],
                    "file": finding["file"],
                    "lines": set(),
                }

            grouped[key]["lines"].add(finding["line"])

        items = []
        for _, data in grouped.items():
            sorted_lines = sorted(data["lines"])
            data["lines"] = sorted_lines
            data["lines_display"] = ", ".join(str(line) for line in sorted_lines)
            items.append(data)

        severity_rank = {name: idx for idx, name in enumerate(self.severity_order)}
        items.sort(
            key=lambda item: (
                severity_rank.get(item["severity"], len(self.severity_order)),
                item["rule_id"],
                item["file"],
            )
        )

        return items