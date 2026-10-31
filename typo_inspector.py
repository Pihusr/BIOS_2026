import hashlib
import json
import logging
import sqlite3
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlparse

import Levenshtein
import requests

from contracts import InspectResult, Package, ProvenanceReport, TypoFlag, empty_result

ROOT = Path(__file__).resolve().parent
CACHE_DB = ROOT / "data" / "osv_cache.db"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
LOGGER = logging.getLogger(__name__)

_CONFUSABLES = str.maketrans(
    {
        "l": "1",
        "1": "1",
        "o": "0",
        "0": "0",
        "а": "a",
        "в": "b",
        "с": "c",
        "е": "e",
        "н": "h",
        "і": "i",
        "ї": "i",
        "к": "k",
        "м": "m",
        "о": "o",
        "р": "p",
        "ѕ": "s",
        "т": "t",
        "у": "y",
        "х": "x",
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "μ": "m",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "y",
        "χ": "x",
        "ϲ": "c",
    }
)
_REPOSITORY_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht")


@lru_cache(maxsize=2)
def _top_index(
    ecosystem: str,
) -> tuple[frozenset[str], dict[int, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    path = ROOT / "data" / f"top_packages_{ecosystem}.json"
    values = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"Invalid top-package data in {path.name}")

    names = tuple(value.casefold() for value in values)
    buckets: dict[int, list[str]] = {}
    normalized: dict[str, list[str]] = {}
    for name in names:
        buckets.setdefault(len(name), []).append(name)
        normalized.setdefault(_normalize_name(name), []).append(name)
    return (
        frozenset(names),
        {length: tuple(bucket) for length, bucket in buckets.items()},
        {key: tuple(matches) for key, matches in normalized.items()},
    )


def _normalize_name(name: str) -> str:
    """Map ASCII and Unicode lookalikes to a shared comparison form."""
    return name.casefold().translate(_CONFUSABLES).replace("rn", "m")


def _risk_score(distance: int, homoglyph: bool) -> float:
    return min(1.0, max(0.0, 0.9 - 0.2 * (distance - 1) + (0.1 if homoglyph else 0.0)))


def _find_typo(name: str, ecosystem: str) -> TypoFlag | None:
    top_names, buckets, normalized = _top_index(ecosystem)
    candidate_name = name.casefold()
    if candidate_name in top_names:
        return None

    candidates: list[TypoFlag] = []
    for match in normalized.get(_normalize_name(candidate_name), ()):
        distance = Levenshtein.distance(candidate_name, match)
        if distance > 0:
            candidates.append(
                {
                    "package": name,
                    "matched": match,
                    "distance": distance,
                    "homoglyph": True,
                    "risk_score": _risk_score(distance, True),
                }
            )

    for length in range(max(1, len(candidate_name) - 2), len(candidate_name) + 3):
        for match in buckets.get(length, ()):
            distance = Levenshtein.distance(candidate_name, match)
            if 1 <= distance <= 2:
                candidates.append(
                    {
                        "package": name,
                        "matched": match,
                        "distance": distance,
                        "homoglyph": False,
                        "risk_score": _risk_score(distance, False),
                    }
                )
    if not candidates:
        return None
    return min(candidates, key=lambda flag: (-flag["risk_score"], flag["distance"], flag["matched"]))


def _cached_get(url: str) -> tuple[dict[str, Any] | None, str | None]:
    """Read cached JSON before making a retry-limited registry request."""
    key = hashlib.sha256(f"GET{url}".encode("utf-8")).hexdigest()
    try:
        with sqlite3.connect(CACHE_DB) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS http_cache "
                "(key TEXT PRIMARY KEY, body TEXT, fetched_at REAL)"
            )
            row = connection.execute(
                "SELECT body, fetched_at FROM http_cache WHERE key = ?", (key,)
            ).fetchone()
    except sqlite3.Error as exc:
        return None, f"Registry cache read failed: {exc}"

    if row is not None and time.time() - row[1] < CACHE_TTL_SECONDS:
        try:
            cached = json.loads(row[0])
        except (TypeError, json.JSONDecodeError) as exc:
            return None, f"Cached registry response is invalid: {exc}"
        if isinstance(cached, dict):
            return cached, None
        return None, "Cached registry response is not a JSON object"

    last_error = "request failed"
    for _ in range(3):
        try:
            response = requests.get(url, timeout=8)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                return None, "Registry response is not a JSON object"
            body = json.dumps(payload)
            with sqlite3.connect(CACHE_DB) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS http_cache "
                    "(key TEXT PRIMARY KEY, body TEXT, fetched_at REAL)"
                )
                connection.execute(
                    "INSERT OR REPLACE INTO http_cache (key, body, fetched_at) VALUES (?, ?, ?)",
                    (key, body, time.time()),
                )
            return payload, None
        except requests.RequestException as exc:
            last_error = str(exc)
        except (ValueError, sqlite3.Error) as exc:
            return None, f"Registry response could not be cached: {exc}"
    return None, f"Registry request failed after 3 attempts: {last_error}"


def _is_repository_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").casefold()
    known_host = any(host == domain or host.endswith(f".{domain}") for domain in _REPOSITORY_HOSTS)
    return known_host or url.casefold().endswith(".git")


def _has_source_repo(info: dict[str, Any]) -> bool:
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for label, url in project_urls.items():
            if not isinstance(url, str) or not url.strip():
                continue
            if any(word in str(label).casefold() for word in ("source", "repository", "code")):
                return True
            if _is_repository_url(url):
                return True
    home_page = info.get("home_page")
    return isinstance(home_page, str) and _is_repository_url(home_page)


def _attestations(value: Any) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in {"attestation", "attestations"} and child:
                found.append(child)
            else:
                found.extend(_attestations(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_attestations(child))
    return found


def _has_slsa(value: Any) -> bool:
    if isinstance(value, str):
        return "slsa" in value.casefold()
    if isinstance(value, dict):
        return any(_has_slsa(key) or _has_slsa(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_has_slsa(child) for child in value)
    return False


def _provenance(package: Package) -> tuple[ProvenanceReport, str | None]:
    name = package["name"]
    version = package["version"]
    if package["ecosystem"].casefold() != "pypi":
        return (
            {
                "package": name,
                "version": version,
                "has_source_repo": None,
                "signature_verified": None,
                "slsa_attested": None,
                "violations": [],
            },
            f"Provenance is unsupported for {package['ecosystem']} package {name}",
        )

    url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
    metadata, error = _cached_get(url)
    if metadata is None:
        return (
            {
                "package": name,
                "version": version,
                "has_source_repo": None,
                "signature_verified": None,
                "slsa_attested": None,
                "violations": [],
            },
            f"Provenance could not be checked for {name}: {error or 'unknown registry error'}",
        )

    info = metadata.get("info")
    if not isinstance(info, dict):
        return (
            {
                "package": name,
                "version": version,
                "has_source_repo": None,
                "signature_verified": None,
                "slsa_attested": None,
                "violations": [],
            },
            f"Registry metadata is incomplete for {name}",
        )

    source = _has_source_repo(info)
    attestations = _attestations(metadata)
    signature = bool(attestations)
    slsa = signature and _has_slsa(attestations)
    violations = []
    if not source:
        violations.append("missing_source_repo")
    if not signature:
        violations.append("no_attestation")
    if not slsa:
        violations.append("no_slsa_provenance")
    return (
        {
            "package": name,
            "version": version,
            "has_source_repo": source,
            "signature_verified": signature,
            "slsa_attested": slsa,
            "violations": violations,
        },
        None,
    )


def inspect(packages: list[Package]) -> InspectResult:
    """Inspect packages for typosquats and registry provenance."""
    if not isinstance(packages, list):
        return cast(InspectResult, empty_result("inspect", "packages must be a list"))
    if any(
        not isinstance(package, dict)
        or any(
            not isinstance(package.get(field), str) or not package[field]
            for field in ("name", "version", "ecosystem")
        )
        for package in packages
    ):
        return cast(InspectResult, empty_result("inspect", "each package needs a non-empty name, version, and ecosystem"))

    typo_flags: list[TypoFlag] = []
    provenance: list[ProvenanceReport] = []
    warnings: list[str] = []
    try:
        for package in packages:
            ecosystem = package["ecosystem"].casefold()
            if ecosystem in {"pypi", "npm"}:
                flag = _find_typo(package["name"], ecosystem)
                if flag is not None:
                    typo_flags.append(flag)
            else:
                warnings.append(f"Typosquat checks are unsupported for {package['ecosystem']} package {package['name']}")

            report, warning = _provenance(package)
            provenance.append(report)
            if warning is not None:
                LOGGER.warning(warning)
                warnings.append(warning)
    except (OSError, ValueError, sqlite3.Error) as exc:
        return cast(InspectResult, empty_result("inspect", f"Package inspection failed: {exc}"))

    return {
        "ok": True,
        "error": None,
        "warnings": warnings,
        "typo_flags": typo_flags,
        "provenance": provenance,
    }
