# CLAUDE.md — Rules for AI Agents Working on This Repo

Project: **Reachability-Aware Supply-Chain Security Engine** (hackathon MVP, Python 3.11+).
Pipeline: repo → SBOM → OSV CVEs → static call-graph reachability → typosquat/provenance checks → VEX (OpenVEX + CycloneDX) → Streamlit dashboard.

**Before you write any code, read `ARCHITECTURE.md` and `contracts.py`. They are the source of truth.**

---

## 1. Prime Directives (never violate)

1. **Stay in your lane.** You are assigned ONE slice (see `SLICES.md`). Edit only the files that slice owns. If you need a change elsewhere, STOP and write it under "Requests for other slices" in your final report.
2. **`contracts.py` is frozen.** Never rename, remove, or retype a field, and never change a public function signature. Adding an *optional* field is allowed only if the human approves in the prompt.
3. **Never raise across a module boundary. Never return `None`.** Every public function returns its typed result dict with `ok: bool`, `error: str | None`, `warnings: list[str]`. Wrap parsing/network/subprocess in `try/except` and return `ok=False` + a useful `error` + safe empty defaults.
4. **Never silently suppress risk.** A CVE becomes `not_affected` ONLY when reachability proved `unreachable` with confidence 1.0. Any doubt → keep visible (`affected` or `under_investigation`).
5. **Approved stack only:** Python stdlib (`ast`, `tomllib`, `sqlite3`, `json`, `subprocess`), `networkx`, `pycg` (optional), `python-Levenshtein`, `requests`, `streamlit`, `pyvis`, `jsonschema`, `pytest`, Syft CLI (optional). **Do not add dependencies** — ask the human. No tree-sitter (post-MVP). No databases other than SQLite `osv_cache.db`.
6. **Simplest thing that passes the test.** 15-hour budget. No abstractions "for later", no frameworks, no async, no classes where a function works.

## 2. Domain Rules (from the PRD)

- **VEX status mapping (exact strings):**
  | Condition | status | justification | priority |
  |---|---|---|---|
  | CVE in dep AND `reachable` | `affected` | — | HIGH/CRITICAL (from CVSS) |
  | CVE in dep AND `unreachable` (conf = 1.0) | `not_affected` | `inline_code_not_reachable` | INFORMATIONAL |
  | `unknown_dynamic_execution` (getattr/eval/exec/`__import__`/importlib) | `under_investigation` | — | MEDIUM |
  | `over_approximated_path` | `affected` + `needs_manual_review=True` | — | keep original severity |
  | Typosquat or provenance failure | `affected` with `provenance_tag` | — | HIGH |
- Every `affected` finding MUST carry either a non-empty call path OR a `provenance_tag`. `vex_generator.validate()` enforces this; tests fail otherwise.
- Prune provably dead branches (`if False:`, `if 0:`, `if TYPE_CHECKING:`, literal-constant conditions, `if debug:` where `debug = False` is a module constant). Indeterminate branch → `over_approximated_path`, never prune.
- Decorators: unwrap simple decorators (`@app.route`, `@functools.wraps`, `@cli.command`) heuristically; if unsure lower `confidence` below 1.0.
- Entry points = `if __name__ == "__main__":` bodies, Flask/FastAPI route handlers (`@app.route`, `@app.get/post`), Click/argparse command functions, and top-level module statements of the main script.
- **Vulnerable symbols:** OSV rarely lists function names for PyPI. Use `data/vuln_symbols.json` (curated CVE → dotted symbols). If a CVE has no entry, fall back to **package-level reachability** (any call into the package) and add a warning `"package-level only"`. Never invent symbols.
- Typosquat rule: Levenshtein `1 ≤ d ≤ 2` against `data/top_packages_pypi.json` / `top_packages_npm.json` **or** homoglyph match (`l↔1`, `o↔0`, `rn↔m`, Unicode confusables). Exact match to a top package is never a typosquat. Do not flag a package that is itself in the top list.
- Provenance checks: missing source-repo link in registry metadata, no Sigstore/PEP 740 attestation, no SLSA provenance. `signature_verified` / `slsa_attested` are `True | False | None` (`None` = could not determine — never coerce to `False`).

## 3. Network & Caching

- All OSV and registry HTTP goes through `osv_client.py` / `typo_inspector.py` helpers that read/write `osv_cache.db` **first**. Timeout 8 s, 2 retries.
- Demo must run **offline**: `make cache-warm` pre-populates the cache; tests must never hit the real network (use `fixtures/golden/` + cache).
- No API keys, no secrets, no hardcoded absolute paths.

## 4. Code Style

- Type hints everywhere; `TypedDict`s imported from `contracts.py`.
- Functions ≤ 40 lines where practical; docstring = one line stating input → output.
- `logging` (not `print`) in engine modules; Streamlit code may use `st.*`.
- No dead code, no commented-out blocks, no TODOs without an owner slice name.

## 5. Testing Loop (mandatory)

After **every** meaningful change run:

```bash
make test        # pytest tests/test_<your_slice>.py  (fast, offline)
make test-all    # full suite incl. ground-truth benchmark
```

The **ground-truth repo** `fixtures/ground_truth_repo/` must always yield:
1. ≥ 1 reachable CVE → `affected` with a call path (file + line numbers)
2. ≥ 1 dead-code CVE → `not_affected` / `inline_code_not_reachable`
3. 1 dynamic-call CVE → `under_investigation`
4. `reqeusts` → typosquat flag (purple)
5. 1 package missing source-repo metadata → provenance violation

If a change breaks any of the 5, fix it before doing anything else. Never edit golden files to make a test pass — ask the human.

## 6. Working Style

- Read the relevant stub/contract first, then implement, then test, then report. Don't refactor unrelated code.
- If the task is ambiguous or the contract blocks you: **stop and ask** instead of improvising.
- Prefer small commits: `git commit -m "slice-N: <what>"`.
- Final report format (always):
  1. Files changed
  2. Public functions implemented (signature unchanged? yes/no)
  3. Tests run + result
  4. Known limitations / fallbacks
  5. Requests for other slices

## 7. Definition of Done (per slice)

- [ ] Implements the slice's public functions exactly per `contracts.py`
- [ ] Never raises / never returns `None` (a test feeds garbage input and asserts `ok=False`)
- [ ] `make test` green offline
- [ ] Works against the stub data of neighbouring slices (no cross-slice imports except `contracts.py`)
- [ ] Final report delivered

## 8. Don'ts (common vibe-coding failures)

- Don't "improve" function signatures or rename fields.
- Don't import another slice's module internals (call only its public function, and only from `pipeline.py`).
- Don't add `try/except: pass` — always return a populated `error`.
- Don't mock away the thing being tested.
- Don't hit live networks in tests.
- Don't mark unreachable on parse failure — parse failure ⇒ `degraded=True` and keep findings visible.
