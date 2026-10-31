import logging
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import osv_client
import reachability
import sbom_engine
import typo_inspector
import vex_generator
from contracts import ScanResult, empty_result

LOGGER = logging.getLogger(__name__)


def _failed_result(kind: str, stage: str, error: Exception | str) -> dict[str, Any]:
    result = empty_result(kind, str(error))
    message = f"{stage} failed: {error}"
    result["warnings"] = [message]
    return result


def _record_result(result: dict[str, Any], stage: str) -> None:
    stage_warnings = result.get("warnings", [])
    if isinstance(stage_warnings, list):
        stage_warnings = [item for item in stage_warnings if isinstance(item, str)]
    else:
        stage_warnings = [f"{stage} returned invalid warnings"]
    if result.get("ok") is False:
        error = result.get("error")
        message = str(error or "unspecified error")
        if not message.startswith(f"{stage} failed:"):
            message = f"{stage} failed: {message}"
        stage_warnings.append(message)
    result["warnings"] = list(dict.fromkeys(stage_warnings))


def run_scan(repo_path: str) -> ScanResult:
    """Run each analysis stage and return the combined scan, retaining partial results."""
    mapping_warnings: list[str] = []
    reach_warnings: list[str] = []
    target = repo_path if isinstance(repo_path, str) else ""

    if not target.strip():
        sbom = _failed_result("sbom", "build_sbom", "repo_path must be a non-empty string")
    else:
        try:
            sbom = sbom_engine.build_sbom(target)
            if not isinstance(sbom, dict) or not isinstance(sbom.get("packages"), list):
                raise ValueError("invalid SBOM result")
        except Exception as exc:
            LOGGER.exception("SBOM construction failed for %s", target)
            sbom = _failed_result("sbom", "build_sbom", exc)
    _record_result(sbom, "build_sbom")

    advisories: list[dict[str, Any]] = []
    query_warnings: list[str] = []
    query_errors: list[str] = []
    for package in sbom["packages"]:
        if not isinstance(package, dict) or not all(
            isinstance(package.get(field), str)
            for field in ("name", "version", "ecosystem")
        ):
            query_errors.append("package query skipped: invalid package data")
            continue
        try:
            result = osv_client.query_osv(
                package["name"], package["version"], package["ecosystem"]
            )
            if not isinstance(result, dict) or not isinstance(
                result.get("advisories"), list
            ):
                raise ValueError("invalid OSV result")
            if any(not isinstance(item, dict) for item in result["advisories"]):
                raise ValueError("OSV result contains invalid advisories")
            advisories.extend(result["advisories"])
            result_warnings = result.get("warnings", [])
            if isinstance(result_warnings, list):
                query_warnings.extend(
                    item for item in result_warnings if isinstance(item, str)
                )
            if result.get("ok") is False:
                error = result.get("error") or "unspecified error"
                query_errors.append(f"{package['name']}: {error}")
        except Exception as exc:
            LOGGER.exception("OSV query failed for package %s", package["name"])
            query_errors.append(f"{package['name']}: {exc}")

    advisories = osv_client.dedupe_advisories(advisories)
    osv = {
        "ok": not query_errors,
        "error": "; ".join(query_errors) if query_errors else None,
        "warnings": query_warnings + [
            f"query_osv failed for {error}" for error in query_errors
        ],
        "advisories": advisories,
    }
    _record_result(osv, "query_osv")

    try:
        targets = osv_client.map_symbols(osv["advisories"])
        if not isinstance(targets, list) or any(
            not isinstance(item, dict)
            or not isinstance(item.get("cve_id"), str)
            or not isinstance(item.get("package"), str)
            or not isinstance(item.get("symbols"), list)
            or any(not isinstance(symbol, str) for symbol in item.get("symbols", []))
            for item in targets
        ):
            raise ValueError("invalid vulnerable-symbol mapping")
        if len(targets) != len(advisories):
            mapping_warnings.append(
                f"map_symbols returned {len(targets)} targets for "
                f"{len(advisories)} advisories"
            )
    except Exception as exc:
        LOGGER.exception("Vulnerable-symbol mapping failed")
        targets = []
        mapping_warnings.append(f"map_symbols failed: {exc}")
    osv["warnings"] = list(
        dict.fromkeys(osv["warnings"] + mapping_warnings)
    )

    try:
        reach = reachability.analyze(target, targets)
        if not isinstance(reach, dict) or not isinstance(reach.get("findings"), list):
            raise ValueError("invalid reachability result")
        if reach.get("ok") is False:
            reach["degraded"] = True
        unresolved_ids = {
            finding["cve_id"]
            for finding in reach["findings"]
            if isinstance(finding, dict)
            and finding.get("reach_status") == "unreachable"
            and finding.get("confidence") == 1.0
        }
        package_targets = [
            {**item, "symbols": []}
            for item in targets
            if item.get("cve_id") in unresolved_ids and item.get("symbols")
        ]
        if package_targets:
            try:
                package_reach = reachability.analyze(target, package_targets)
                package_findings = {
                    finding["cve_id"]: finding
                    for finding in package_reach.get("findings", [])
                    if isinstance(finding, dict)
                    and finding.get("reach_status") in {
                        "reachable",
                        "over_approximated_path",
                        "unknown_dynamic_execution",
                    }
                }
                for index, finding in enumerate(reach["findings"]):
                    if not isinstance(finding, dict):
                        continue
                    fallback = package_findings.get(finding.get("cve_id"))
                    if fallback is not None:
                        reach["findings"][index] = fallback
                        reach_warnings.append("package-level only")
                        reach_warnings.append(
                            f"Used package-level reachability for {finding['cve_id']} "
                            "because its curated symbol was not resolved"
                        )
            except Exception as exc:
                LOGGER.exception("Package-level reachability fallback failed for %s", target)
                reach_warnings.append(f"Package-level reachability fallback failed: {exc}")
    except Exception as exc:
        LOGGER.exception("Reachability analysis failed for %s", target)
        reach = _failed_result("reach", "reachability.analyze", exc)
        reach["degraded"] = True
    _record_result(reach, "reachability.analyze")
    reach["warnings"] = list(dict.fromkeys(reach["warnings"] + reach_warnings))

    try:
        inspect = typo_inspector.inspect(sbom["packages"])
        if not isinstance(inspect, dict) or not all(
            isinstance(inspect.get(field), list)
            for field in ("typo_flags", "provenance")
        ):
            raise ValueError("invalid package inspection result")
    except Exception as exc:
        LOGGER.exception("Package inspection failed for %s", target)
        inspect = _failed_result("inspect", "typo_inspector.inspect", exc)
    _record_result(inspect, "typo_inspector.inspect")

    repo_name = Path(target).name if target else "repository"
    target_purl = f"pkg:generic/{quote(repo_name, safe='.-_')}"
    try:
        vex = vex_generator.generate(target_purl, sbom, osv, reach, inspect)
        if not isinstance(vex, dict) or not isinstance(vex.get("findings"), list):
            raise ValueError("invalid VEX result")
    except Exception as exc:
        LOGGER.exception("VEX generation failed for %s", target)
        vex = _failed_result("vex", "vex_generator.generate", exc)
    _record_result(vex, "vex_generator.generate")

    return cast(
        ScanResult,
        {
            "target": target,
            "sbom": sbom,
            "osv": osv,
            "reach": reach,
            "inspect": inspect,
            "vex": vex,
        },
    )
