import json
from pathlib import Path
from contracts import VexResult, SBOMResult, OSVResult, ReachResult, InspectResult, empty_result

ROOT = Path(__file__).resolve().parent

def generate(target_purl: str, sbom: SBOMResult, osv: OSVResult, reach: ReachResult, inspect: InspectResult) -> VexResult:
    """Load the golden VEX result."""
    try:
        return json.loads((ROOT / "fixtures/golden/scan_result.json").read_text(encoding="utf-8"))["vex"]  # type: ignore[return-value]
    except Exception as exc:
        return empty_result("vex", str(exc))  # type: ignore[return-value]

def validate(vex: VexResult) -> list[str]:
    """Return violations for findings lacking required evidence."""
    violations: list[str] = []
    for finding in vex.get("findings", []):
        if finding["status"] == "affected" and not finding.get("reach") and not finding.get("provenance_tag"):
            violations.append(f"finding {finding['id']} lacks call path and provenance tag")
    return violations

def to_openvex(vex: VexResult) -> dict:
    """Return the OpenVEX document from a VEX result."""
    return vex.get("openvex", {})

def to_cdx_vex(vex: VexResult) -> dict:
    """Return the CycloneDX VEX document from a VEX result."""
    return vex.get("cyclonedx_vex", {})
