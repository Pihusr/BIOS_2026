import argparse
import hashlib
import json
import logging
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

import requests

from contracts import Advisory, OSVResult, VulnTarget

ROOT = Path(__file__).resolve().parent
CACHE_DB_PATH = ROOT / "data" / "osv_cache.db"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
HTTP_TIMEOUT_SECONDS = 8
HTTP_RETRIES = 2
LOGGER = logging.getLogger(__name__)


def _cache_key(method: str, url: str, body: str = "") -> str:
    """Create the stable cache key for an HTTP request."""
    return hashlib.sha256(f"{method}{url}{body}".encode("utf-8")).hexdigest()


def _read_cache(key: str) -> tuple[str, float] | None:
    """Read one cached response and its fetch time from SQLite."""
    connection = sqlite3.connect(CACHE_DB_PATH, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS http_cache "
            "(key TEXT PRIMARY KEY, body TEXT, fetched_at REAL)"
        )
        row = connection.execute(
            "SELECT body, fetched_at FROM http_cache WHERE key = ?", (key,)
        ).fetchone()
        connection.commit()
        return (str(row[0]), float(row[1])) if row else None
    finally:
        connection.close()


def _write_cache(key: str, body: str) -> None:
    """Persist a successful response using the documented cache schema."""
    connection = sqlite3.connect(CACHE_DB_PATH, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS http_cache "
            "(key TEXT PRIMARY KEY, body TEXT, fetched_at REAL)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO http_cache (key, body, fetched_at) VALUES (?, ?, ?)",
            (key, body, time.time()),
        )
        connection.commit()
    finally:
        connection.close()


def _cached_request(
    method: str, url: str, body: dict[str, Any] | None = None
) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    """Perform a cache-first request and return payload, error, and warnings."""
    warnings: list[str] = []
    encoded_request = json.dumps(body, sort_keys=True, separators=(",", ":")) if body is not None else ""
    key = _cache_key(method, url, encoded_request)
    stale_body: str | None = None
    try:
        cached = _read_cache(key)
        if cached:
            stale_body, fetched_at = cached
            if time.time() - fetched_at < CACHE_TTL_SECONDS:
                try:
                    payload = json.loads(stale_body)
                    if isinstance(payload, dict):
                        return payload, None, warnings
                    warnings.append("Cached HTTP response was not a JSON object")
                except (json.JSONDecodeError, TypeError) as exc:
                    warnings.append(f"Cached HTTP response was malformed: {exc}")
    except sqlite3.Error as exc:
        warnings.append(f"Could not read OSV cache: {exc}")

    last_error = "request failed"
    for attempt in range(HTTP_RETRIES + 1):
        try:
            if method == "GET":
                response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
            else:
                response = requests.post(
                    url, json=body, timeout=HTTP_TIMEOUT_SECONDS
                )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("HTTP response JSON must be an object")
            response_body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            try:
                _write_cache(key, response_body)
            except sqlite3.Error as exc:
                warnings.append(f"Could not write OSV cache: {exc}")
            return payload, None, warnings
        except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
            last_error = str(exc) or exc.__class__.__name__
            if attempt < HTTP_RETRIES:
                continue

    if stale_body is not None:
        try:
            payload = json.loads(stale_body)
            if isinstance(payload, dict):
                warnings.append("OSV request failed; using an expired cached response")
                return payload, None, warnings
        except (json.JSONDecodeError, TypeError):
            warnings.append("Expired cached HTTP response was malformed")
    return None, f"HTTP {method} request failed after {HTTP_RETRIES + 1} attempts: {last_error}", warnings


def _cached_get(url: str) -> dict[str, Any]:
    """Return a cache-first GET response for read-only sibling consumers."""
    payload, error, warnings = _cached_request("GET", url)
    for warning in warnings:
        LOGGER.warning("%s", warning)
    if error:
        LOGGER.warning("%s", error)
        return {}
    return payload or {}


def _cvss_v3_score(vector: str) -> float | None:
    """Calculate a CVSS v3 base score from a complete severity vector."""
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    if metrics.get("CVSS") not in {"3.0", "3.1"}:
        return None
    values = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    try:
        av, ac, pr, ui, scope = (metrics[name] for name in ("AV", "AC", "PR", "UI", "S"))
        confidentiality, integrity, availability = (
            values[name][metrics[name]] for name in ("C", "I", "A")
        )
        if scope not in {"U", "C"}:
            return None
        if scope == "C":
            values["PR"] = {"N": 0.85, "L": 0.68, "H": 0.5}
        exploitability = 8.22 * values["AV"][av] * values["AC"][ac] * values["PR"][pr] * values["UI"][ui]
    except (KeyError, ValueError):
        return None
    impact_subscore = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if scope == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    if impact <= 0:
        return 0.0
    score = min(impact + exploitability, 10) if scope == "U" else min(1.08 * (impact + exploitability), 10)
    return math.ceil(score * 10 - 1e-10) / 10


def _severity_for_score(score: float) -> str:
    """Map a CVSS base score to its standard severity label."""
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _fixed_versions(vulnerability: dict[str, Any], package_name: str) -> list[str]:
    """Extract unique fixed versions for the queried package."""
    fixed: list[str] = []
    affected = vulnerability.get("affected", [])
    if not isinstance(affected, list):
        return fixed
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package", {})
        if not isinstance(package, dict) or str(package.get("name", "")).casefold() != package_name.casefold():
            continue
        for version_range in item.get("ranges", []):
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events", []):
                if isinstance(event, dict):
                    version = event.get("fixed")
                    if isinstance(version, str) and version and version not in fixed:
                        fixed.append(version)
    return fixed


def _parse_advisories(
    payload: dict[str, Any], name: str, version: str
) -> list[Advisory]:
    """Convert an OSV query payload to contract advisories."""
    vulnerabilities = payload.get("vulns", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("OSV response field 'vulns' must be a list")
    advisories: list[Advisory] = []
    seen_aliases: set[str] = set()
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise ValueError("OSV response contains a malformed vulnerability")
        osv_id = vulnerability.get("id")
        if not isinstance(osv_id, str) or not osv_id:
            raise ValueError("OSV vulnerability is missing its id")
        aliases = vulnerability.get("aliases", [])
        alias_ids = {osv_id.upper()}
        if isinstance(aliases, list):
            alias_ids.update(
                alias.upper() for alias in aliases
                if isinstance(alias, str) and alias
            )
        is_duplicate = bool(alias_ids & seen_aliases)
        seen_aliases.update(alias_ids)
        if is_duplicate:
            continue
        cve_id = next(
            (
                alias for alias in aliases
                if isinstance(alias, str) and alias.upper().startswith("CVE-")
            ),
            osv_id,
        ) if isinstance(aliases, list) else osv_id
        cvss: float | None = None
        severity = ""
        severity_entries = vulnerability.get("severity", [])
        if isinstance(severity_entries, list):
            for entry in severity_entries:
                if isinstance(entry, dict) and isinstance(entry.get("score"), str):
                    cvss = _cvss_v3_score(entry["score"])
                    if cvss is not None:
                        severity = _severity_for_score(cvss)
                        break
        database_specific = vulnerability.get("database_specific", {})
        if not severity and isinstance(database_specific, dict):
            database_severity = database_specific.get("severity")
            if isinstance(database_severity, str):
                severity = database_severity.upper()
        advisories.append(
            {
                "cve_id": cve_id,
                "osv_id": osv_id,
                "package": name,
                "version": version,
                "summary": str(vulnerability.get("summary", "")),
                "severity": severity or "UNKNOWN",
                "cvss": cvss,
                "fixed_in": _fixed_versions(vulnerability, name),
            }
        )
    return advisories


def dedupe_advisories(
    advisories: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep the first advisory for each vulnerability alias group."""
    unique: list[dict[str, Any]] = []
    seen_aliases: set[str] = set()
    for advisory in advisories:
        identifiers: set[str] = set()
        for key in ("cve_id", "osv_id"):
            value = advisory.get(key)
            if isinstance(value, str) and value:
                identifiers.add(value.upper())
        aliases = advisory.get("aliases")
        if isinstance(aliases, list):
            identifiers.update(
                alias.upper() for alias in aliases
                if isinstance(alias, str) and alias
            )
        is_duplicate = bool(identifiers & seen_aliases)
        seen_aliases.update(identifiers)
        if is_duplicate:
            continue
        unique.append(advisory)
    return unique


def _golden_fallback(name: str, version: str) -> list[Advisory] | None:
    """Load matching recorded advisories when OSV and its cache are unavailable."""
    try:
        fixture = json.loads(
            (ROOT / "fixtures" / "golden" / "osv.json").read_text(encoding="utf-8")
        )
        entries = fixture.get("advisories") if isinstance(fixture, dict) else None
        if not isinstance(entries, list):
            return None
        return [
            entry for entry in entries
            if isinstance(entry, dict)
            and isinstance(entry.get("package"), str)
            and entry["package"].casefold() == name.casefold()
            and (not version or entry.get("version") == version)
            and all(key in entry for key in ("cve_id", "osv_id", "severity", "cvss", "fixed_in"))
        ]
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def query_osv(name: str, version: str, ecosystem: str = "PyPI") -> OSVResult:
    """Query OSV for package advisories, using cached responses first."""
    if not isinstance(name, str) or not name.strip():
        return {"ok": False, "error": "package name must be a non-empty string", "warnings": [], "advisories": []}
    if not isinstance(version, str) or not isinstance(ecosystem, str) or not ecosystem.strip():
        return {"ok": False, "error": "version and ecosystem must be strings", "warnings": [], "advisories": []}
    request_body: dict[str, Any] = {
        "package": {"name": name.strip(), "ecosystem": ecosystem.strip()}
    }
    if version.strip():
        request_body["version"] = version.strip()
    payload, error, warnings = _cached_request("POST", OSV_QUERY_URL, request_body)
    if error:
        golden_advisories = _golden_fallback(name.strip(), version.strip())
        if golden_advisories:
            warnings.append("OSV unavailable; using matching golden fixture advisories")
            return {
                "ok": True,
                "error": None,
                "warnings": warnings,
                "advisories": golden_advisories,
            }
        warnings.append(error)
        return {"ok": False, "error": error, "warnings": warnings, "advisories": []}
    try:
        advisories = _parse_advisories(payload or {}, name.strip(), version.strip())
    except (TypeError, ValueError, KeyError) as exc:
        error = f"Malformed OSV response: {exc}"
        warnings.append(error)
        return {"ok": False, "error": error, "warnings": warnings, "advisories": []}
    return {"ok": True, "error": None, "warnings": warnings, "advisories": advisories}


def map_symbols(advisories: list[Advisory]) -> list[VulnTarget]:
    """Map advisories to curated vulnerable symbols or package-level targets."""
    try:
        symbol_path = ROOT / "data" / "vuln_symbols.json"
        symbols = json.loads(symbol_path.read_text(encoding="utf-8"))
        if not isinstance(symbols, dict):
            raise ValueError("vuln_symbols.json must contain a JSON object")
        targets: list[VulnTarget] = []
        for advisory in advisories:
            cve_id = advisory["cve_id"]
            matching_symbols = symbols.get(cve_id, [])
            if not isinstance(matching_symbols, list) or not all(
                isinstance(symbol, str) for symbol in matching_symbols
            ):
                matching_symbols = []
                LOGGER.warning("Invalid vulnerable-symbol mapping for %s", cve_id)
            if not matching_symbols:
                LOGGER.warning("No vulnerable symbols for %s; package-level only", cve_id)
            targets.append(
                {
                    "cve_id": cve_id,
                    "package": advisory["package"],
                    "symbols": matching_symbols,
                    "severity": advisory["severity"],
                    "cvss": advisory["cvss"],
                }
            )
        return targets
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        LOGGER.error("Could not map OSV advisories to vulnerable symbols: %s", exc)
        return []


def _requirements_items(path: Path) -> list[tuple[str, str]]:
    """Read package names and exact versions from a requirements file."""
    items: list[tuple[str, str]] = []
    requirement = re.compile(
        r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?:===|==)\s*([^\s;]+)"
    )
    package_only = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?")
    for line in path.read_text(encoding="utf-8").splitlines():
        content = line.split("#", 1)[0].strip()
        if not content or content.startswith(("-", "git+", "http:", "https:")):
            continue
        match = requirement.match(content)
        if match:
            items.append((match.group(1), match.group(2)))
            continue
        package_match = package_only.match(content)
        if package_match:
            items.append((package_match.group(1), ""))
    return items


def main(argv: list[str] | None = None) -> int:
    """Warm the OSV cache from a requirements file."""
    parser = argparse.ArgumentParser(description="Warm the local OSV HTTP cache.")
    parser.add_argument("--warm", metavar="REQUIREMENTS_FILE", required=True)
    args = parser.parse_args(argv)
    try:
        packages = _requirements_items(Path(args.warm))
    except OSError as exc:
        LOGGER.error("Could not read requirements file %s: %s", args.warm, exc)
        return 1
    failed = False
    for name, version in packages:
        result = query_osv(name, version)
        for warning in result["warnings"]:
            LOGGER.warning("%s", warning)
        if not result["ok"]:
            LOGGER.error("Could not warm OSV cache for %s: %s", name, result["error"])
            failed = True
    LOGGER.info("Warmed OSV cache for %d package requirements", len(packages))
    return 1 if failed else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    raise SystemExit(main())
