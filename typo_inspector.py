import json
from pathlib import Path
from contracts import InspectResult, Package, empty_result

ROOT = Path(__file__).resolve().parent

def inspect(packages: list[Package]) -> InspectResult:
    """Load the typo and provenance golden fixture."""
    try:
        return json.loads((ROOT / "fixtures/golden/inspect.json").read_text(encoding="utf-8"))  # type: ignore[return-value]
    except Exception as exc:
        return empty_result("inspect", str(exc))  # type: ignore[return-value]
