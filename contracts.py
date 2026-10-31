from typing import TypedDict, Literal

class Base(TypedDict):
    ok: bool
    error: str | None
    warnings: list[str]

ReachStatus = Literal["reachable", "unreachable", "unknown_dynamic_execution", "over_approximated_path"]
VexStatus = Literal["affected", "not_affected", "under_investigation"]

class Package(TypedDict):
    name: str; version: str; ecosystem: str
    purl: str; scope: Literal["direct", "transitive"]
    depends_on: list[str]

class SBOMResult(Base):
    packages: list[Package]
    edges: list[tuple[str, str]]
    cyclonedx: dict; spdx: dict
    source: Literal["syft", "manifest"]

class Advisory(TypedDict):
    cve_id: str; osv_id: str; package: str; version: str
    summary: str; severity: str; cvss: float | None
    fixed_in: list[str]

class OSVResult(Base):
    advisories: list[Advisory]

class VulnTarget(TypedDict):
    cve_id: str; package: str
    symbols: list[str]
    severity: str; cvss: float | None

class CallFrame(TypedDict):
    file: str; line: int; symbol: str

class ReachFinding(TypedDict):
    cve_id: str; package: str; symbol: str
    reach_status: ReachStatus
    confidence: float
    paths: list[list[CallFrame]]
    needs_manual_review: bool; notes: str

class ReachResult(Base):
    findings: list[ReachFinding]
    entry_points: list[str]
    parse_failures: list[str]
    degraded: bool

class TypoFlag(TypedDict):
    package: str; matched: str; distance: int
    homoglyph: bool; risk_score: float

class ProvenanceReport(TypedDict):
    package: str; version: str
    has_source_repo: bool | None
    signature_verified: bool | None
    slsa_attested: bool | None
    violations: list[str]

class InspectResult(Base):
    typo_flags: list[TypoFlag]
    provenance: list[ProvenanceReport]

class Finding(TypedDict):
    id: str; package: str; version: str
    status: VexStatus; priority: str
    justification: str | None
    impact_statement: str
    reach: ReachFinding | None
    provenance_tag: str | None
    needs_manual_review: bool

class Metrics(TypedDict):
    raw_cve_count: int; actionable_count: int; suppressed_count: int
    under_investigation_count: int
    noise_reduction_pct: float
    actionable_rate_pct: float

class VexResult(Base):
    findings: list[Finding]; metrics: Metrics
    openvex: dict; cyclonedx_vex: dict

class ScanResult(Base):
    target: str
    sbom: SBOMResult; osv: OSVResult; reach: ReachResult
    inspect: InspectResult; vex: VexResult

def empty_result(kind: str, error: str | None) -> dict:
    """Return safe empty defaults for one result kind."""
    base = {"ok": False, "error": error, "warnings": []}
    empty_sbom = {"packages": [], "edges": [], "cyclonedx": {}, "spdx": {}, "source": "manifest"}
    empty_osv = {"advisories": []}
    empty_reach = {"findings": [], "entry_points": [], "parse_failures": [], "degraded": True}
    empty_inspect = {"typo_flags": [], "provenance": []}
    empty_metrics = {"raw_cve_count": 0, "actionable_count": 0, "suppressed_count": 0, "under_investigation_count": 0, "noise_reduction_pct": 0.0, "actionable_rate_pct": 100.0}
    empty_vex = {"findings": [], "metrics": empty_metrics, "openvex": {}, "cyclonedx_vex": {}}
    empty_scan = {"target": "", "sbom": {**base, **empty_sbom}, "osv": {**base, **empty_osv}, "reach": {**base, **empty_reach}, "inspect": {**base, **empty_inspect}, "vex": {**base, **empty_vex}}
    defaults = {"sbom": empty_sbom, "osv": empty_osv, "reach": empty_reach, "inspect": empty_inspect, "vex": empty_vex, "scan": empty_scan}
    if kind not in defaults:
        return {**base, "error": error or "unknown result kind"}
    return {**base, **defaults[kind]}
