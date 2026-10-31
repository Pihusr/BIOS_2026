import json
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from contracts import Package, SBOMResult, empty_result


def build_sbom(repo_path: str) -> SBOMResult:
    """Build a package SBOM from Syft or native project manifests."""
    try:
        root = Path(repo_path).expanduser()
        if not root.exists():
            return empty_result("sbom", f"repository path does not exist: {repo_path}")  # type: ignore[return-value]
        if not root.is_dir():
            return empty_result("sbom", f"repository path is not a directory: {repo_path}")  # type: ignore[return-value]

        syft = shutil.which("syft")
        if syft:
            result = _run_syft(syft, root)
            if result[0] is not None:
                return result[0]

        packages, warnings = _parse_manifests(root)
        cdx = _make_cyclonedx(packages)
        spdx = _make_spdx(packages)
        return {
            "ok": True, "error": None, "warnings": warnings,
            "packages": packages, "edges": [], "cyclonedx": cdx,
            "spdx": spdx, "source": "manifest",
        }
    except Exception as exc:
        return empty_result("sbom", f"failed to build SBOM: {exc}")  # type: ignore[return-value]


def _run_syft(syft: str, root: Path) -> tuple[SBOMResult | None, list[str]]:
    """Run both Syft formats and combine them into one SBOM result."""
    warnings: list[str] = []
    cdx: dict[str, Any] = {}
    spdx: dict[str, Any] = {}
    for fmt, target in (("cyclonedx-json", "cyclonedx"), ("spdx-json", "spdx")):
        try:
            completed = subprocess.run(
                [syft, f"dir:{root}", "-o", fmt],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if completed.returncode != 0:
                warnings.append(f"Syft {fmt} failed: {completed.stderr.strip() or 'unknown error'}")
                continue
            data = json.loads(completed.stdout)
            if target == "cyclonedx":
                cdx = data
            else:
                spdx = data
        except subprocess.TimeoutExpired:
            warnings.append(f"Syft {fmt} timed out after 60 seconds")
        except Exception as exc:
            warnings.append(f"Syft {fmt} failed: {exc}")

    if cdx or spdx:
        packages, edges = _map_syft(cdx, spdx, _manifest_direct_names(root))
        result_cdx = cdx or _make_cyclonedx(packages)
        result_spdx = spdx or _make_spdx(packages)
        return ({
            "ok": True, "error": None, "warnings": warnings,
            "packages": packages, "edges": edges,
            "cyclonedx": result_cdx, "spdx": result_spdx, "source": "syft",
        }, warnings)
    return (None, warnings)


def _manifest_direct_names(root: Path) -> set[str]:
    """Collect package names declared directly in native manifests."""
    packages, _ = _parse_manifests(root)
    return {package["name"].lower() for package in packages}


def _parse_manifests(root: Path) -> tuple[list[Package], list[str]]:
    """Parse supported manifest formats into direct packages."""
    packages: list[Package] = []
    warnings: list[str] = []
    seen: set[str] = set()

    def add(name: str, version: str, ecosystem: str = "PyPI") -> None:
        clean_name = name.strip()
        if not clean_name:
            return
        clean_version = version.strip()
        key = f"{ecosystem.lower()}:{clean_name.lower()}@{clean_version.lower()}"
        if key in seen:
            return
        seen.add(key)
        if not clean_version:
            warnings.append(f"unpinned version for {clean_name}")
        package: Package = {
            "name": clean_name, "version": clean_version, "ecosystem": ecosystem,
            "purl": _purl(clean_name, clean_version, ecosystem),
            "scope": "direct", "depends_on": [],
        }
        packages.append(package)

    for req_name in ("requirements.txt", "requirements-dev.txt"):
        req_path = root / req_name
        if req_path.exists():
            _parse_requirements(req_path, root, add, warnings, seen)

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        _parse_pyproject(pyproject, add, warnings)

    pipfile = root / "Pipfile"
    if pipfile.exists():
        _parse_pipfile(pipfile, add, warnings)

    package_json = root / "package.json"
    if package_json.exists():
        _parse_package_json(package_json, add, warnings)

    _parse_lockfiles(root, packages, add, warnings)
    return packages, warnings


def _parse_requirements(path: Path, root: Path, add: Any, warnings: list[str], seen: set[str]) -> None:
    """Parse a requirements file, including comments and -r includes."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except Exception as exc:
        warnings.append(f"could not read requirements file {path.name}: {exc}")
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r ") or line.startswith("--requirement "):
            include = line.split(None, 1)[1].strip()
            _parse_requirements((path.parent / include).resolve(), root, add, warnings, seen)
            continue
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "http://", "https://", "git+")):
            continue
        name = line
        version = ""
        name_part = line.split(";", 1)[0].strip()
        extras_at = name_part.find("[")
        extras_end = name_part.find("]", extras_at)
        if extras_at >= 0 and extras_end >= 0:
            name_part = name_part[:extras_at] + name_part[extras_end + 1:]
            name_part = name_part.strip()
        for separator in ("===", "=="):
            if separator in name_part:
                name, raw_version = name_part.split(separator, 1)
                version = raw_version.strip()
                break
        else:
            name = name_part.split(">=", 1)[0].split("<=", 1)[0].split("~=", 1)[0].split("!=", 1)[0].split(">", 1)[0].split("<", 1)[0].strip()
        if ">=" in line or "<= " in line or "~=" in line or "!= " in line:
            version = ""
        add(name, version)


def _parse_pyproject(path: Path, add: Any, warnings: list[str]) -> None:
    """Parse PEP 621 and Poetry dependency declarations from pyproject.toml."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        project = data.get("project", {})
        for item in project.get("dependencies", []) if isinstance(project, dict) else []:
            if isinstance(item, str):
                _add_dependency_string(item, add)
        poetry = data.get("tool", {}).get("poetry", {})
        dependencies = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(dependencies, dict):
            for name, spec in dependencies.items():
                if name.lower() == "python":
                    continue
                version = spec if isinstance(spec, str) else ""
                if isinstance(spec, dict):
                    version = str(spec.get("version", ""))
                add(name, _poetry_version(version))
    except Exception as exc:
        warnings.append(f"malformed pyproject.toml: {exc}")


def _add_dependency_string(item: str, add: Any) -> None:
    """Add a dependency from a PEP 508 dependency string."""
    name = item
    version = ""
    left = item.split(";", 1)[0].strip()
    match_name = left.split("==", 1)[0].split(">=", 1)[0].split("<=", 1)[0].split("~=", 1)[0].strip()
    name = match_name.split("[", 1)[0].strip()
    if "==" in left:
        version = left.split("==", 1)[1].strip().split(",", 1)[0].strip()
    add(name, version)


def _poetry_version(spec: str) -> str:
    """Extract a pinned Poetry version, otherwise return empty."""
    spec = spec.strip().lstrip("^~=")
    if spec.startswith("*") or spec.startswith((">", "<")) or " " in spec:
        return ""
    return spec if spec and spec[0].isdigit() else ""


def _parse_pipfile(path: Path, add: Any, warnings: list[str]) -> None:
    """Parse direct packages from Pipfile."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for section in ("packages", "dev-packages"):
            dependencies = data.get(section, {})
            if not isinstance(dependencies, dict):
                continue
            for name, spec in dependencies.items():
                if isinstance(spec, dict):
                    spec = spec.get("version", "")
                add(name, _poetry_version(str(spec)) if isinstance(spec, str) else "")
    except Exception as exc:
        warnings.append(f"malformed Pipfile: {exc}")


def _parse_package_json(path: Path, add: Any, warnings: list[str]) -> None:
    """Parse npm dependencies from package.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("package.json root must be an object")
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            dependencies = data.get(section, {})
            if not isinstance(dependencies, dict):
                continue
            for name, version in dependencies.items():
                package_version = str(version).lstrip("^~") if str(version)[0:1].isdigit() else ""
                package_version = "" if package_version.startswith((">", "<", "*")) else package_version
                add(str(name).strip(), package_version, "npm")
    except Exception as exc:
        warnings.append(f"malformed package.json: {exc}")


def _append_lock_package(packages: list[Package], name: str, version: str, ecosystem: str) -> None:
    """Add a locked package without duplicating or downgrading a direct package."""
    for package in packages:
        if package["name"].lower() == name.lower() and package["ecosystem"] == ecosystem:
            return
    packages.append({
        "name": name, "version": version, "ecosystem": ecosystem,
        "purl": _purl(name, version, ecosystem), "scope": "transitive", "depends_on": [],
    })


def _parse_lockfiles(root: Path, packages: list[Package], add: Any, warnings: list[str]) -> None:
    """Add transitive entries supplied by lock files."""
    poetry_lock = root / "poetry.lock"
    if poetry_lock.exists():
        try:
            data = tomllib.loads(poetry_lock.read_text(encoding="utf-8"))
            for package in data.get("package", []) if isinstance(data, dict) else []:
                if isinstance(package, dict) and package.get("name"):
                    _append_lock_package(packages, str(package["name"]), str(package.get("version", "")), "PyPI")
        except Exception as exc:
            warnings.append(f"malformed poetry.lock: {exc}")

    package_lock = root / "package-lock.json"
    if package_lock.exists():
        try:
            data = json.loads(package_lock.read_text(encoding="utf-8"))
            packages_data = data.get("packages", {}) if isinstance(data, dict) else {}
            if isinstance(packages_data, dict):
                for location, info in packages_data.items():
                    if not isinstance(info, dict):
                        continue
                    name = info.get("name") or (location.rsplit("node_modules/", 1)[-1] if location else "")
                    if name and isinstance(name, str):
                        _append_lock_package(packages, name, str(info.get("version", "")), "npm")
            dependencies = data.get("dependencies", {}) if isinstance(data, dict) else {}
            if isinstance(dependencies, dict):
                for name, info in dependencies.items():
                    if isinstance(info, dict):
                        _append_lock_package(packages, str(name), str(info.get("version", "")), "npm")
        except Exception as exc:
            warnings.append(f"malformed package-lock.json: {exc}")

    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.exists():
        try:
            data = json.loads(pipfile_lock.read_text(encoding="utf-8"))
            for section in ("default", "develop"):
                dependencies = data.get(section, {}) if isinstance(data, dict) else {}
                if not isinstance(dependencies, dict):
                    continue
                for name, info in dependencies.items():
                    version = info.get("version", "") if isinstance(info, dict) else info
                    clean_version = str(version).lstrip("=") if isinstance(version, str) else ""
                    _append_lock_package(packages, str(name), clean_version, "PyPI")
        except Exception as exc:
            warnings.append(f"malformed Pipfile.lock: {exc}")


def _map_syft(cdx: dict[str, Any], spdx: dict[str, Any], direct_names: set[str]) -> tuple[list[Package], list[tuple[str, str]]]:
    """Map CycloneDX or SPDX Syft output to Package contracts."""
    packages_by_purl: dict[str, Package] = {}
    ref_to_purl: dict[str, str] = {}
    for component in cdx.get("components", []) if isinstance(cdx, dict) else []:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name", "")).strip()
        if not name:
            continue
        version = str(component.get("version", "") or "")
        purl = str(component.get("purl", "") or _purl(name, version, "PyPI"))
        ecosystem = "npm" if purl.startswith("pkg:npm/") else "PyPI"
        package: Package = {
            "name": name, "version": version, "ecosystem": ecosystem, "purl": purl,
            "scope": "direct" if name.lower() in direct_names else "transitive", "depends_on": [],
        }
        packages_by_purl[purl] = package
        bom_ref = str(component.get("bom-ref", "") or "")
        if bom_ref:
            ref_to_purl[bom_ref] = purl

    for item in spdx.get("packages", []) if isinstance(spdx, dict) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        refs = item.get("externalRefs", []) if isinstance(item.get("externalRefs", []), list) else []
        purl = next((str(ref.get("referenceLocator", "")) for ref in refs if isinstance(ref, dict) and ref.get("referenceType") == "purl"), "")
        if not purl:
            version = str(item.get("versionInfo", "") or "")
            purl = _purl(name, version, "PyPI")
        if purl in packages_by_purl:
            continue
        ecosystem = "npm" if purl.startswith("pkg:npm/") else "PyPI"
        version = str(item.get("versionInfo", "") or "")
        packages_by_purl[purl] = {
            "name": name, "version": version, "ecosystem": ecosystem, "purl": purl,
            "scope": "direct" if name.lower() in direct_names else "transitive", "depends_on": [],
        }

    edges: list[tuple[str, str]] = []
    for dependency in cdx.get("dependencies", []) if isinstance(cdx, dict) else []:
        if not isinstance(dependency, dict):
            continue
        parent_ref = str(dependency.get("ref", ""))
        parent = ref_to_purl.get(parent_ref, parent_ref)
        for child_ref in dependency.get("dependsOn", []) if isinstance(dependency.get("dependsOn", []), list) else []:
            child = ref_to_purl.get(str(child_ref), str(child_ref))
            edges.append((parent, child))
    relationships = spdx.get("relationships", []) if isinstance(spdx, dict) else []
    for relationship in relationships if isinstance(relationships, list) else []:
        if not isinstance(relationship, dict) or relationship.get("relationshipType") != "DEPENDS_ON":
            continue
        parent = str(relationship.get("spdxElementId", "")).split(":", 1)[-1]
        child = str(relationship.get("relatedSpdxElement", "")).split(":", 1)[-1]
        parent_purl = _spdx_purl(parent, spdx)
        child_purl = _spdx_purl(child, spdx)
        if parent_purl and child_purl:
            edges.append((parent_purl, child_purl))

    for package in packages_by_purl.values():
        package["depends_on"] = list(dict.fromkeys(child for parent, child in edges if parent == package["purl"]))
    return list(packages_by_purl.values()), list(dict.fromkeys(edges))


def _spdx_purl(element_id: str, spdx: dict[str, Any]) -> str:
    """Resolve an SPDX element ID to an external PURL reference."""
    for item in spdx.get("packages", []) if isinstance(spdx, dict) else []:
        if not isinstance(item, dict) or element_id not in (str(item.get("SPDXID", "")), str(item.get("name", ""))):
            continue
        refs = item.get("externalRefs", []) if isinstance(item.get("externalRefs", []), list) else []
        for ref in refs:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                return str(ref.get("referenceLocator", ""))
    return ""


def _purl(name: str, version: str, ecosystem: str) -> str:
    """Create a canonical package URL."""
    clean_name = name.strip().lower().replace(" ", "-")
    type_name = "npm" if ecosystem.lower() == "npm" else "pypi"
    if not clean_name:
        return ""
    suffix = f"@{version.strip()}" if version.strip() else ""
    return f"pkg:{type_name}/{clean_name}{suffix}"


def _make_cyclonedx(packages: list[Package]) -> dict[str, Any]:
    """Create a minimal valid CycloneDX 1.5 document."""
    components = []
    for package in packages:
        component: dict[str, Any] = {
            "type": "library", "name": package["name"], "purl": package["purl"],
        }
        if package["version"]:
            component["version"] = package["version"]
        components.append(component)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def _make_spdx(packages: list[Package]) -> dict[str, Any]:
    """Create a minimal valid SPDX 2.3 document."""
    spdx_packages = []
    for index, package in enumerate(packages, start=1):
        item: dict[str, Any] = {
            "SPDXID": f"SPDXRef-Package-{index}", "name": package["name"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": package["purl"]}],
        }
        if package["version"]:
            item["versionInfo"] = package["version"]
        spdx_packages.append(item)
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": "dependency-sbom",
        "documentNamespace": "https://spdx.org/spdxdocs/dependency-sbom",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: bios-sbom-engine"]},
        "packages": spdx_packages, "relationships": [],
    }
