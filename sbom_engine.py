import json
from pathlib import Path
from contracts import SBOMResult, empty_result

ROOT = Path(__file__).resolve().parent

def build_sbom(repo_path: str) -> SBOMResult:
    """Load the SBOM golden fixture for a repository path."""
    try:
        return json.loads((ROOT / "fixtures/golden/sbom.json").read_text(encoding="utf-8"))  # type: ignore[return-value]
    except Exception as exc:
        return empty_result("sbom", str(exc))  # type: ignore[return-value]
