import copy

import vex_generator


def _six_cve_inputs():
    osv = {"ok": True, "error": None, "warnings": [], "advisories": [
        {"cve_id": "CVE-1", "osv_id": "O1", "package": "flask", "version": "1.0",
         "summary": "Flask issue", "severity": "HIGH", "cvss": 8.0, "fixed_in": []},
        {"cve_id": "CVE-2", "osv_id": "O2", "package": "pillow", "version": "1.0",
         "summary": "Image issue", "severity": "HIGH", "cvss": 8.1, "fixed_in": []},
        {"cve_id": "CVE-3", "osv_id": "O3", "package": "pyyaml", "version": "1.0",
         "summary": "YAML issue", "severity": "CRITICAL", "cvss": 9.8, "fixed_in": []},
        {"cve_id": "CVE-4", "osv_id": "O4", "package": "werkzeug", "version": "1.0",
         "summary": "Dynamic issue", "severity": "LOW", "cvss": 3.1, "fixed_in": []},
        {"cve_id": "CVE-5", "osv_id": "O5", "package": "jinja", "version": "1.0",
         "summary": "Branch issue", "severity": "MEDIUM", "cvss": 5.4, "fixed_in": []},
        {"cve_id": "CVE-6", "osv_id": "O6", "package": "requests", "version": "1.0",
         "summary": "Typosquat issue", "severity": "LOW", "cvss": 3.0, "fixed_in": []},
    ]}
    reach = {"ok": True, "error": None, "warnings": [], "findings": [
        {"cve_id": "CVE-1", "package": "flask", "symbol": "flask.run", "reach_status": "reachable",
         "confidence": 1.0, "paths": [[{"file": "app.py", "line": 4, "symbol": "flask.run"}]],
         "needs_manual_review": False, "notes": "reachable"},
        {"cve_id": "CVE-2", "package": "pillow", "symbol": "PIL.save", "reach_status": "unreachable",
         "confidence": 1.0, "paths": [], "needs_manual_review": False, "notes": "dead code"},
        {"cve_id": "CVE-3", "package": "pyyaml", "symbol": "yaml.load", "reach_status": "unreachable",
         "confidence": 1.0, "paths": [], "needs_manual_review": False, "notes": "dead branch"},
        {"cve_id": "CVE-4", "package": "werkzeug", "symbol": "werkzeug.parse", "reach_status": "unknown_dynamic_execution",
         "confidence": 0.6, "paths": [], "needs_manual_review": False, "notes": "getattr"},
        {"cve_id": "CVE-5", "package": "jinja", "symbol": "jinja.xmlattr", "reach_status": "over_approximated_path",
         "confidence": 0.8, "paths": [[{"file": "app.py", "line": 8, "symbol": "jinja.xmlattr"}]],
         "needs_manual_review": True, "notes": "approximate"},
        {"cve_id": "CVE-6", "package": "requests", "symbol": "requests.get", "reach_status": "unreachable",
         "confidence": 1.0, "paths": [], "needs_manual_review": False, "notes": "typosquat risk"},
    ], "entry_points": [], "parse_failures": [], "degraded": False}
    inspect = {"ok": True, "error": None, "warnings": [], "typo_flags": [
        {"package": "reqeusts", "matched": "requests", "distance": 1, "homoglyph": False, "risk_score": 0.9}
    ], "provenance": []}
    sbom = {"ok": True, "error": None, "warnings": [], "packages": [], "edges": [],
            "cyclonedx": {}, "spdx": {}, "source": "manifest"}
    return sbom, osv, reach, inspect


def test_generate_six_cve_metrics_and_documents():
    sbom, osv, reach, inspect = _six_cve_inputs()
    vex = vex_generator.generate("pkg:generic/demo@1", sbom, osv, reach, inspect)

    assert vex["ok"] is True
    assert vex["metrics"]["raw_cve_count"] == 6
    assert vex["metrics"]["noise_reduction_pct"] >= 50.0
    assert vex["metrics"]["actionable_rate_pct"] == 100.0
    assert vex["metrics"]["suppressed_count"] == 3
    assert vex_generator.validate(vex) == []

    statuses = {finding["id"]: finding["status"] for finding in vex["findings"]}
    assert statuses["CVE-2"] == "not_affected"
    assert statuses["CVE-3"] == "not_affected"
    assert statuses["CVE-4"] == "under_investigation"
    assert statuses["CVE-5"] == "affected"
    assert next(f for f in vex["findings"] if f["id"] == "CVE-5")["needs_manual_review"] is True
    assert statuses["CVE-6"] == "not_affected"

    openvex = vex["openvex"]
    assert openvex["@context"] == "https://openvex.dev/ns/v1"
    assert all(statement["products"] == [{"@id": "pkg:generic/demo@1"}] for statement in openvex["statements"])
    assert any("static call-graph analysis" in statement["impact_statement"] for statement in openvex["statements"])

    cdx = vex["cyclonedx_vex"]
    assert cdx["bomFormat"] == "CycloneDX"
    assert all("analysis" in vulnerability for vulnerability in cdx["vulnerabilities"])


def test_missing_attestation_and_slsa_are_informational():
    sbom, osv, reach, inspect = _six_cve_inputs()
    inspect["provenance"] = [{"package": "requests", "version": "1.0", "has_source_repo": None,
                              "signature_verified": None, "slsa_attested": None,
                              "violations": ["no_attestation", "no_slsa_provenance"]}]
    vex = vex_generator.generate("pkg:generic/demo@1", sbom, osv, reach, inspect)
    finding = next(item for item in vex["findings"] if item["id"] == "CVE-6")
    assert finding["status"] == "not_affected"
    assert finding["priority"] == "INFORMATIONAL"
    assert finding["provenance_tag"] is None
    assert "signature/attestation" in finding["impact_statement"]
    assert "SLSA provenance" in finding["impact_statement"]


def test_missing_source_repository_overrides_suppression():
    sbom, osv, reach, inspect = _six_cve_inputs()
    inspect["provenance"] = [{"package": "requests", "version": "1.0", "has_source_repo": False,
                              "signature_verified": True, "slsa_attested": True,
                              "violations": ["missing_source_repo"]}]
    vex = vex_generator.generate("pkg:generic/demo@1", sbom, osv, reach, inspect)
    finding = next(item for item in vex["findings"] if item["id"] == "CVE-6")

    assert finding["status"] == "affected"
    assert finding["priority"] == "HIGH"
    assert finding["provenance_tag"] == "provenance: missing_source_repo"
    assert vex["metrics"]["actionable_rate_pct"] == 100.0


def test_typosquat_flag_overrides_suppression():
    sbom, osv, reach, inspect = _six_cve_inputs()
    inspect["typo_flags"] = [
        {"package": "requests", "matched": "reqeusts", "distance": 1,
         "homoglyph": False, "risk_score": 0.9}
    ]
    vex = vex_generator.generate("pkg:generic/demo@1", sbom, osv, reach, inspect)
    finding = next(item for item in vex["findings"] if item["id"] == "CVE-6")

    assert finding["status"] == "affected"
    assert finding["provenance_tag"] == "typosquat: requests -> reqeusts"


def test_degraded_reach_keeps_every_cve_visible():
    sbom, osv, reach, inspect = _six_cve_inputs()
    reach["degraded"] = True
    vex = vex_generator.generate("pkg:generic/demo@1", sbom, osv, reach, inspect)
    assert all(finding["status"] == "affected" or finding["status"] == "under_investigation"
               for finding in vex["findings"])
    assert vex["metrics"]["suppressed_count"] == 0


def test_validate_rejects_bad_evidence_justification_and_schema():
    sbom, osv, reach, inspect = _six_cve_inputs()
    vex = vex_generator.generate("pkg:generic/demo@1", sbom, osv, reach, inspect)
    bad = copy.deepcopy(vex)
    bad["findings"][0]["reach"] = None
    bad["findings"][0]["provenance_tag"] = None
    bad["findings"][1]["justification"] = "wrong"
    bad["openvex"]["@context"] = "wrong-context"

    violations = vex_generator.validate(bad)
    assert any("lacks call path" in item for item in violations)
    assert any("inline_code_not_reachable" in item for item in violations)
    assert any("openvex schema" in item for item in violations)


def test_malformed_inputs_never_raise():
    vex = vex_generator.generate("pkg:generic/demo@1", None, None, None, None)
    assert vex["ok"] is False
    assert vex["findings"] == []
