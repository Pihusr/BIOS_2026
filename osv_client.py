import json
from pathlib import Path
from contracts import Advisory, OSVResult, VulnTarget, empty_result

ROOT = Path(__file__).resolve().parent

def query_osv(name: str, version: str, ecosystem: str = "PyPI") -> OSVResult:
    """Load the golden OSV fixture for a package query."""
    try:
        return json.loads((ROOT / "fixtures/golden/osv.json").read_text(encoding="utf-8"))  # type: ignore[return-value]
    except Exception as exc:
        return empty_result("osv", str(exc))  # type: ignore[return-value]

def map_symbols(advisories: list[Advisory]) -> list[VulnTarget]:
    """Map advisories to curated vulnerable symbols."""
    try:
        symbols = json.loads((ROOT / "data/vuln_symbols.json").read_text(encoding="utf-8"))
    except Exception:
        symbols = {}
    return [{"cve_id": a["cve_id"], "package": a["package"], "symbols": symbols.get(a["cve_id"], []), "severity": a["severity"], "cvss": a["cvss"]} for a in advisories]
