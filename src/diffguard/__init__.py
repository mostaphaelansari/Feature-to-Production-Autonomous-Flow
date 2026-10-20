"""DiffGuard: risk triage and security checks for code changes."""

__version__ = "0.2.0"

from .config import Config, load_config  # noqa: E402
from .models import Finding, Report, RiskLevel, Severity  # noqa: E402
from .scan import scan  # noqa: E402

__all__ = [
    "Config",
    "Finding",
    "Report",
    "RiskLevel",
    "Severity",
    "__version__",
    "load_config",
    "scan",
]
