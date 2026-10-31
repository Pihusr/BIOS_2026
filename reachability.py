import json
from pathlib import Path
from contracts import ReachResult, VulnTarget, empty_result

ROOT = Path(__file__).resolve().parent

def analyze(repo_path: str, targets: list[VulnTarget]) -> ReachResult:
    """Load the reachability golden fixture for targets."""
    try:
        return json.loads((ROOT / "fixtures/golden/reach.json").read_text(encoding="utf-8"))  # type: ignore[return-value]
    except Exception as exc:
        return empty_result("reach", str(exc))  # type: ignore[return-value]
