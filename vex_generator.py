import json
from pathlib import Path
from jsonschema import Draft7Validator
from contracts import VexResult, SBOMResult, OSVResult, ReachResult, InspectResult, empty_result

ROOT = Path(__file__).resolve().parent


def _priority(advisory: dict, risk: bool = False) -> str:
    if risk:
        return "HIGH"
    cvss = advisory.get("cvss")
    try:
        score = float(cvss) if cvss is not None else -1.0
    except (TypeError, ValueError):
        score = -1.0
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 0:
        return "LOW"
    severity = str(advisory.get("severity", "")).upper()
    return severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "LOW"


def _has_call_path(reach: dict | None) -> bool:
    if not isinstance(reach, dict):
        return False
    paths = reach.get("paths", [])
    return isinstance(paths, list) and any(isinstance(path, list) and len(path) > 0 for path in paths)


def _provenance_tag(package: str, inspect: InspectResult) -> str | None:
    package_lower = package.lower()
    for typo in inspect.get("typo_flags", []) if isinstance(inspect, dict) else []:
        if str(typo.get("package", "")).lower() == package_lower:
            return f"typosquat: {typo.get('package')} -> {typo.get('matched')}"
    for report in inspect.get("provenance", []) if isinstance(inspect, dict) else []:
        if str(report.get("package", "")).lower() == package_lower:
            if report.get("has_source_repo") is False:
                violations = report.get("violations", [])
                source_violations = [
                    str(item) for item in violations
                    if "source" in str(item).casefold()
                ] if isinstance(violations, list) else []
                return "provenance: " + (
                    "; ".join(source_violations) or "missing_source_repo"
                )
    return None


def _provenance_note(package: str, inspect: InspectResult) -> str | None:
    for report in inspect.get("provenance", []) if isinstance(inspect, dict) else []:
        if str(report.get("package", "")).lower() != package.lower():
            continue
        missing = []
        if report.get("signature_verified") is None or report.get("signature_verified") is False:
            missing.append("signature/attestation")
        if report.get("slsa_attested") is None or report.get("slsa_attested") is False:
            missing.append("SLSA provenance")
        if missing:
            return "Informational only: " + " and ".join(missing) + " is missing or unverified."
    return None


def generate(target_purl: str, sbom: SBOMResult, osv: OSVResult, reach: ReachResult,
             inspect: InspectResult) -> VexResult:
    """Join advisory, reachability, typo, and provenance data into a VEX result."""
    try:
        if not isinstance(osv, dict) or not isinstance(reach, dict) or not isinstance(inspect, dict):
            return empty_result("vex", "invalid VEX input")
        advisories = osv.get("advisories", [])
        reachings = reach.get("findings", [])
        if not isinstance(advisories, list) or not isinstance(reachings, list):
            return empty_result("vex", "invalid advisory or reachability data")
        reach_by_id = {item.get("cve_id"): item for item in reachings if isinstance(item, dict)}
        findings = []
        for advisory in advisories:
            if not isinstance(advisory, dict) or not advisory.get("cve_id"):
                continue
            cve_id = str(advisory["cve_id"])
            package = str(advisory.get("package", "unknown"))
            rf = reach_by_id.get(cve_id)
            provenance_tag = _provenance_tag(package, inspect)
            degraded = bool(reach.get("degraded", False))
            status = "affected"
            justification = None
            manual = False
            if degraded:
                status = "affected"
                manual = bool(rf and rf.get("needs_manual_review"))
            elif provenance_tag:
                status = "affected"
                manual = False
            elif rf and rf.get("reach_status") == "unknown_dynamic_execution":
                status = "under_investigation"
            elif rf and rf.get("reach_status") == "over_approximated_path":
                status = "affected"
                manual = True
            elif rf and rf.get("reach_status") == "reachable":
                status = "affected"
            elif rf and rf.get("reach_status") == "unreachable" and float(rf.get("confidence", 0)) == 1.0:
                status = "not_affected"
                justification = "inline_code_not_reachable"
            risk = bool(provenance_tag)
            priority = "INFORMATIONAL" if status == "not_affected" else (
                "MEDIUM" if status == "under_investigation" else _priority(advisory, risk))
            summary = str(advisory.get("summary", "")).strip()
            impact = summary or f"Vulnerability assessment for {package}"
            if status == "not_affected":
                impact += ". static call-graph analysis found this code path unreachable."
            provenance_note = _provenance_note(package, inspect)
            if provenance_note:
                if not impact.endswith((".", "!", "?")):
                    impact += "."
                impact += f" {provenance_note}"
            findings.append({"id": cve_id, "package": package,
                             "version": str(advisory.get("version", "")), "status": status,
                             "priority": priority, "justification": justification,
                             "impact_statement": impact, "reach": rf,
                             "provenance_tag": provenance_tag,
                             "needs_manual_review": manual})
        raw = len(advisories)
        suppressed = sum(f["status"] == "not_affected" for f in findings)
        affected = [f for f in findings if f["status"] == "affected"]
        actionable = sum(_has_call_path(f["reach"]) or bool(f["provenance_tag"]) for f in affected)
        metrics = {"raw_cve_count": raw, "actionable_count": sum(f["status"] != "not_affected" for f in findings),
                   "suppressed_count": suppressed,
                   "under_investigation_count": sum(f["status"] == "under_investigation" for f in findings),
                   "noise_reduction_pct": round(suppressed / raw * 100, 2) if raw else 0.0,
                   "actionable_rate_pct": round(actionable / len(affected) * 100, 2) if affected else 100.0}
        vex = {"ok": True, "error": None, "warnings": list(osv.get("warnings", [])),
               "findings": findings, "metrics": metrics, "openvex": {}, "cyclonedx_vex": {}}
        vex["openvex"] = to_openvex(vex, target_purl)
        vex["cyclonedx_vex"] = to_cyclonedx_vex(vex, target_purl)
        violations = validate(vex)
        if violations:
            vex["ok"] = False
            vex["error"] = "; ".join(violations)
            vex["warnings"] = list(vex["warnings"])
        return vex
    except Exception as exc:
        return empty_result("vex", str(exc))


def validate(vex: VexResult) -> list[str]:
    """Return evidence, status, and JSON-schema violations."""
    violations: list[str] = []
    if not isinstance(vex, dict):
        return ["vex must be a dictionary"]
    findings = vex.get("findings", [])
    if not isinstance(findings, list):
        return ["findings must be a list"]
    for finding in findings:
        if not isinstance(finding, dict):
            violations.append("finding is not an object")
            continue
        finding_id = finding.get("id", "unknown")
        status = finding.get("status")
        if status == "affected" and not _has_call_path(finding.get("reach")) and not finding.get("provenance_tag"):
            violations.append(f"finding {finding_id} lacks call path and provenance tag")
        if finding.get("justification") is not None and status != "not_affected":
            violations.append(f"finding {finding_id} has justification outside not_affected")
        if status == "not_affected" and finding.get("justification") != "inline_code_not_reachable":
            violations.append(f"finding {finding_id} lacks inline_code_not_reachable justification")
    for field, filename in (("openvex", "openvex.schema.json"),
                            ("cyclonedx_vex", "cyclonedx_vex.schema.json")):
        document = vex.get(field)
        schema_path = ROOT / "schemas" / filename
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            validator = Draft7Validator(schema)
            violations.extend(f"{field} schema: {error.message}" for error in validator.iter_errors(document))
        except Exception as exc:
            violations.append(f"{field} schema could not be loaded: {exc}")
    return violations


def to_openvex(vex: VexResult, target_purl: str = "") -> dict:
    """Build an OpenVEX document from findings."""
    statements = []
    for finding in vex.get("findings", []) if isinstance(vex, dict) else []:
        statement = {"vulnerability": {"name": finding["id"]},
                     "products": [{"@id": target_purl}],
                     "status": finding["status"], "impact_statement": finding["impact_statement"]}
        if finding["status"] == "not_affected":
            statement["justification"] = "inline_code_not_reachable"
        statements.append(statement)
    return {"@context": "https://openvex.dev/ns/v1", "statements": statements}


def to_cyclonedx_vex(vex: VexResult, target_purl: str = "") -> dict:
    """Build a CycloneDX VEX document from findings."""
    vulnerabilities = []
    for finding in vex.get("findings", []) if isinstance(vex, dict) else []:
        detail = finding["impact_statement"]
        analysis = {"state": finding["status"], "detail": detail}
        if finding["status"] == "not_affected":
            analysis["justification"] = "inline_code_not_reachable"
        else:
            analysis["justification"] = None
        vulnerabilities.append({"id": finding["id"], "analysis": analysis})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "vulnerabilities": vulnerabilities}


def to_cdx_vex(vex: VexResult) -> dict:
    """Return the CycloneDX VEX document from a VEX result."""
    return vex.get("cyclonedx_vex", {}) if isinstance(vex, dict) else {}
