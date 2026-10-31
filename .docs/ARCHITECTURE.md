# ARCHITECTURE.md

Reachability-Aware Supply-Chain Security Engine — file structure, contracts, and dependencies.

## 1. Data Flow

```
 target repo path
       │
       ▼
 sbom_engine.build_sbom ──► SBOMResult (packages, CycloneDX, SPDX)
       │
       ├──────────────► osv_client.query_osv (per pkg) ──► OSVResult ──► map_symbols ──► VulnTarget[]
       │                                                                        │
       ├──────────────► typo_inspector.inspect ──► InspectResult                │
       │                                                │                       ▼
       └───────────────────────────────────────────────►│         reachability.analyze(repo, targets)
                                                        │                       │
                                                        ▼                       ▼
                                              vex_generator.generate(sbom, osv, reach, inspect)
                                                        │
                                                        ▼
                                  ScanResult (findings, metrics, OpenVEX, CycloneDX VEX)
                                                        │
                                                        ▼
                                           app.py  (Streamlit + PyVis)
```

`pipeline.run_scan()` is the **only** place modules are chained. Modules never import each other.

## 2. File Structure

```
bios-reachability/
├── CLAUDE.md                 # agent rules
├── ARCHITECTURE.md           # this file
├── SLICES.md                 # parallel build plan + prompts
├── Makefile                  # run | test | test-all | cache-warm | demo
├── requirements.txt
├── contracts.py              # FROZEN typed contracts (all TypedDicts)   [S0]
├── pipeline.py               # run_scan(repo_path) -> ScanResult          [S6]
├── sbom_engine.py            # build_sbom                                 [S1]
├── reachability.py           # analyze                                    [S2]
├── osv_client.py             # query_osv, map_symbols, SQLite cache       [S3]
├── typo_inspector.py         # inspect (typosquat + provenance)           [S4]
├── vex_generator.py          # generate, validate, to_openvex, to_cdx_vex [S5]
├── app.py                    # Streamlit shell: sidebar + tabs            [S0 shell, S6 wiring]
├── ui/
│   ├── __init__.py
│   ├── graph_panel.py        # PyVis dependency network                   [S7]
│   ├── callpath_panel.py     # call-path inspector                        [S7]
│   ├── findings_panel.py     # table, metrics, noise-reduction banner     [S7]
│   └── export_panel.py       # VEX download buttons                       [S7]
├── data/
│   ├── top_packages_pypi.json   # top 10k PyPI names (snapshot)
│   ├── top_packages_npm.json    # top 10k npm names (snapshot)
│   ├── vuln_symbols.json        # curated CVE -> dotted vulnerable symbols
│   └── osv_cache.db             # SQLite (gitignored except demo snapshot)
├── fixtures/
│   ├── ground_truth_repo/       # the 5-case benchmark target
│   │   ├── app.py               # entry point (Flask route + __main__)
│   │   ├── services/http_client.py   # calls vulnerable fn  -> REACHABLE
│   │   ├── legacy/old_parser.py      # imports vuln fn, never called -> DEAD CODE
│   │   ├── plugins/loader.py         # getattr/importlib dynamic call -> UNDER_INVESTIGATION
│   │   └── requirements.txt          # includes `reqeusts` + a no-source-repo package
│   └── golden/
│       ├── sbom.json  osv.json  reach.json  inspect.json  scan_result.json
├── schemas/
│   ├── openvex.schema.json
│   └── cyclonedx_vex.schema.json
└── tests/
    ├── test_sbom.py  test_reachability.py  test_osv.py
    ├── test_typo.py  test_vex.py  test_ui_smoke.py
    └── test_ground_truth.py     # end-to-end benchmark (the 5 cases + metrics)
```

`[Sx]` = owning slice. Only the owner edits a file.

## 3. Public Interfaces (frozen in `contracts.py`)

```python
from typing import TypedDict, Literal

class Base(TypedDict):
    ok: bool
    error: str | None
    warnings: list[str]

ReachStatus = Literal["reachable", "unreachable",
                      "unknown_dynamic_execution", "over_approximated_path"]
VexStatus   = Literal["affected", "not_affected", "under_investigation"]

class Package(TypedDict):
    name: str; version: str; ecosystem: str      # "PyPI" | "npm"
    purl: str; scope: Literal["direct", "transitive"]
    depends_on: list[str]                        # purls

class SBOMResult(Base):
    packages: list[Package]
    edges: list[tuple[str, str]]                 # (parent purl, child purl)
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
    symbols: list[str]                           # dotted; [] => package-level
    severity: str; cvss: float | None

class CallFrame(TypedDict):
    file: str; line: int; symbol: str

class ReachFinding(TypedDict):
    cve_id: str; package: str; symbol: str
    reach_status: ReachStatus
    confidence: float                            # 0.0-1.0
    paths: list[list[CallFrame]]                 # entry point -> vulnerable call
    needs_manual_review: bool; notes: str

class ReachResult(Base):
    findings: list[ReachFinding]
    entry_points: list[str]
    parse_failures: list[str]
    degraded: bool                               # True => manifest-only fallback

class TypoFlag(TypedDict):
    package: str; matched: str; distance: int
    homoglyph: bool; risk_score: float

class ProvenanceReport(TypedDict):
    package: str; version: str
    has_source_repo: bool | None
    signature_verified: bool | None              # None = unknown
    slsa_attested: bool | None
    violations: list[str]

class InspectResult(Base):
    typo_flags: list[TypoFlag]
    provenance: list[ProvenanceReport]

class Finding(TypedDict):
    id: str; package: str; version: str
    status: VexStatus; priority: str             # CRITICAL|HIGH|MEDIUM|INFORMATIONAL
    justification: str | None                    # "inline_code_not_reachable" iff not_affected
    impact_statement: str
    reach: ReachFinding | None
    provenance_tag: str | None
    needs_manual_review: bool

class Metrics(TypedDict):
    raw_cve_count: int; actionable_count: int; suppressed_count: int
    under_investigation_count: int
    noise_reduction_pct: float                   # suppressed / raw * 100
    actionable_rate_pct: float                   # must be 100.0

class VexResult(Base):
    findings: list[Finding]; metrics: Metrics
    openvex: dict; cyclonedx_vex: dict

class ScanResult(Base):
    target: str
    sbom: SBOMResult; osv: OSVResult; reach: ReachResult
    inspect: InspectResult; vex: VexResult
```

### Function signatures

| Module | Function | Returns |
|---|---|---|
| `sbom_engine` | `build_sbom(repo_path: str) -> SBOMResult` | Syft if on PATH, else native manifest parsers |
| `osv_client` | `query_osv(name: str, version: str, ecosystem: str = "PyPI") -> OSVResult` | cache-first |
| `osv_client` | `map_symbols(advisories: list[Advisory]) -> list[VulnTarget]` | uses `data/vuln_symbols.json` |
| `reachability` | `analyze(repo_path: str, targets: list[VulnTarget]) -> ReachResult` | |
| `typo_inspector` | `inspect(packages: list[Package]) -> InspectResult` | |
| `vex_generator` | `generate(target_purl: str, sbom: SBOMResult, osv: OSVResult, reach: ReachResult, inspect: InspectResult) -> VexResult` | |
| `vex_generator` | `validate(vex: VexResult) -> list[str]` | list of violations (empty = valid) |
| `pipeline` | `run_scan(repo_path: str) -> ScanResult` | only orchestrator |
| `ui.*` | `render(scan: ScanResult) -> None` | each panel exposes `render` |

## 4. Module Dependency Graph

```
contracts.py  ◄── every module (types only)

pipeline.py ──► sbom_engine, osv_client, reachability, typo_inspector, vex_generator
app.py      ──► pipeline, ui.*
ui.*        ──► contracts (types), networkx, pyvis, streamlit
reachability ─► ast, networkx, (pycg optional)
sbom_engine ──► subprocess(syft), tomllib, json
osv_client  ──► requests, sqlite3
typo_inspector ─► Levenshtein, requests, osv cache helpers (read-only via osv_client._cached_get)
vex_generator ─► jsonschema, contracts
```

**Rule:** no edges between sibling engine modules. The only cross-module import allowed is `contracts`.

## 5. Dependencies

`requirements.txt`
```
streamlit>=1.35
pyvis>=0.3.2
networkx>=3.2
python-Levenshtein>=0.25
requests>=2.31
jsonschema>=4.21
pytest>=8.0
# optional, wrapped in try/except at import:
pycg
```
External (optional): **Syft** binary (`brew install syft` / `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`). If absent, `sbom_engine` uses native parsers and sets `source="manifest"`.

| Dependency | Used by | Fallback if unavailable |
|---|---|---|
| Syft | sbom_engine | native manifest parsers (requirements.txt, pyproject.toml, Pipfile, package.json) |
| PyCG | reachability | own `ast`-based call graph (primary engine regardless; PyCG enrichment only if it imports and runs) |
| OSV REST | osv_client | SQLite cache → `fixtures/golden/osv.json` |
| PyPI JSON API | typo_inspector (provenance) | cache; `None` flags + warning |
| Sigstore / PEP 740 attestations | typo_inspector | `signature_verified=None` |

> ⚠️ **PyCG risk:** the project is unmaintained and is known to be brittle on newer Python versions. The architecture therefore treats the **native `ast` call graph as the primary engine**, and PyCG as an optional edge enrichment. Do not block the demo on PyCG.

## 6. Reachability Engine Internals (`reachability.py`)

1. Walk `*.py` (skip `venv`, `.git`, `site-packages`, `tests` optional). Parse with `ast`; on `SyntaxError` append to `parse_failures` and continue.
2. Build symbol table per module: imports (`import a.b as c`, `from a import b`), function/method defs, qualified names.
3. Build `networkx.DiGraph`: nodes = qualified function names (+ external dotted symbols); edges = call expressions resolved through the symbol table (record file+line on each edge).
4. Prune branches with constant-false conditions; indeterminate conditions mark downstream edges `over_approximated`.
5. Detect dynamic features (`getattr`, `eval`, `exec`, `__import__`, `importlib.import_module`) → mark the enclosing function `dynamic=True`.
6. Entry points: see `CLAUDE.md §2`. Add a virtual `__ENTRY__` node connected to each.
7. For each `VulnTarget` symbol: `nx.has_path(G, "__ENTRY__", symbol)` → `all_shortest_paths` (cap 3) → `CallFrame[]`. If a dynamic node lies on a plausible route to the package → `unknown_dynamic_execution`.
8. Whole-file failure for everything → `degraded=True`, return empty findings + warning (pipeline shows banner and treats CVEs as `affected`, no suppression).

## 7. Caching (`osv_client.py`)

SQLite table `http_cache(key TEXT PRIMARY KEY, body TEXT, fetched_at REAL)`; key = `sha256(method+url+body)`. Read-through; TTL 7 days; `make cache-warm` runs the ground-truth scan online once and commits `data/osv_cache.db` as demo snapshot.

## 8. UI Composition (`app.py`)

Sidebar: repo path input / "Scan ground-truth demo" button → `pipeline.run_scan` → stored in `st.session_state["scan"]`.
Tabs: **Overview** (findings_panel: metrics + noise banner) · **Dependency Graph** (graph_panel) · **Call Paths** (callpath_panel) · **VEX Export** (export_panel).
PyVis colors: Green `#2ecc71` safe · Yellow `#f1c40f` suppressed · Red `#e74c3c` reachable · Purple `#9b59b6` typosquat/provenance. Degraded mode → `st.warning` banner on every tab.

## 9. Failure Modes

| Failure | Behaviour |
|---|---|
| AST parse error in one file | skip file, add to `parse_failures`, warning |
| All parsing fails | `degraded=True`, manifest-only, red banner, no suppression |
| OSV offline | cache → golden → warning |
| Syft missing | manifest parsers |
| Registry metadata missing | provenance field `None`, not `False` |
| Schema validation fails | `vex.ok=False`, export buttons disabled, error shown |

## 10. Metrics Computation (`vex_generator.generate`)

- `raw_cve_count` = advisories from OSV
- `suppressed_count` = findings with `not_affected`
- `noise_reduction_pct = suppressed / raw * 100` (target ≥ 50 on ground truth)
- `actionable_rate_pct` = % of `affected` findings having a call path or `provenance_tag` (must be 100)
- Test `test_ground_truth.py` asserts both targets.
