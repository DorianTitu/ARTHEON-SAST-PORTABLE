from typing import TYPE_CHECKING
from .report.html_reporter import HTMLReporter
from .js_vulnerabilities import VULN_RULES
from .python_vulnerabilities import PYTHON_VULN_RULES
from .java_vulnerabilities import JAVA_VULN_RULES
from .csharp_vulnerabilities import CSHARP_VULN_RULES

if TYPE_CHECKING:
	from .security_scanner import SecurityScanner

__version__ = "1.1"
__all__ = ["SecurityScanner", "HTMLReporter", "VULN_RULES", "PYTHON_VULN_RULES", "JAVA_VULN_RULES", "CSHARP_VULN_RULES"]


def __getattr__(name):
	if name == "SecurityScanner":
		from .security_scanner import SecurityScanner
		return SecurityScanner
	raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
