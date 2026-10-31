import json
from pathlib import Path
from contracts import ScanResult, empty_result

ROOT = Path(__file__).resolve().parent

def run_scan(repo_path: str) -> ScanResult:
    """Load the complete golden scan result for a repository path."""
    try:
        data = json.loads((ROOT / "fixtures/golden/scan_result.json").read_text(encoding="utf-8"))
        data["target"] = repo_path
        return data  # type: ignore[return-value]
    except Exception as exc:
        return empty_result("scan", str(exc))  # type: ignore[return-value]
