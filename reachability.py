import ast
import logging
import operator
from pathlib import Path
from typing import Any

import networkx as nx

from contracts import CallFrame, ReachFinding, ReachResult, VulnTarget, empty_result

LOGGER = logging.getLogger(__name__)
ENTRY = "__ENTRY__"
SKIP_DIRS = {".git", "venv", ".venv", "site-packages", "tests", "__pycache__"}
DYNAMIC_CALLS = {"getattr", "eval", "exec", "__import__"}
COMPARES = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}


def _result_error(message: str) -> ReachResult:
    """Return a typed empty reachability result for invalid input."""
    return {
        "ok": False,
        "error": message,
        "warnings": [],
        "findings": [],
        "entry_points": [],
        "parse_failures": [],
        "degraded": True,
    }


def _python_files(root: Path) -> list[Path]:
    """Find source files while excluding generated and test directories."""
    return sorted(
        path
        for path in root.rglob("*.py")
        if not any(part in SKIP_DIRS for part in path.relative_to(root).parts)
    )


def _module_name(root: Path, path: Path) -> str:
    """Convert a source path to its importable dotted module name."""
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or path.stem


def _relative_path(root: Path, path: Path) -> str:
    """Return a stable repository-relative source path."""
    return path.relative_to(root).as_posix()


def _literal(node: ast.AST, constants: dict[str, Any]) -> Any:
    """Resolve a literal expression or return None when it is unknown."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    if isinstance(node, ast.Attribute) and node.attr == "TYPE_CHECKING":
        return False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.Not, ast.USub, ast.UAdd)):
        value = _literal(node.operand, constants)
        if value is not None:
            if isinstance(node.op, ast.Not):
                return not bool(value)
            return -value if isinstance(node.op, ast.USub) else +value
    return None


def _condition(node: ast.AST, constants: dict[str, Any]) -> bool | None:
    """Evaluate the supported constant-condition subset."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    literal = _literal(node, constants)
    if literal is not None:
        return bool(literal)
    if isinstance(node, ast.Name) and node.id == "TYPE_CHECKING":
        return False
    if isinstance(node, ast.BoolOp):
        values = [_condition(value, constants) for value in node.values]
        if isinstance(node.op, ast.And):
            if False in values:
                return False
            return True if all(value is True for value in values) else None
        if True in values:
            return True
        return False if all(value is False for value in values) else None
    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        left = _literal(node.left, constants)
        right = _literal(node.comparators[0], constants)
        compare = COMPARES.get(type(node.ops[0]))
        if left is not None and right is not None and compare is not None:
            try:
                return bool(compare(left, right))
            except (TypeError, ValueError):
                return None
    return None


def _main_guard(node: ast.If) -> bool:
    """Recognize the standard Python script entry-point condition."""
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and (
            isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
            or isinstance(test.comparators[0], ast.Name)
            and test.comparators[0].id == "__name__"
            and isinstance(test.left, ast.Constant)
            and test.left.value == "__main__"
        )
    )


def _collect_constants(tree: ast.Module) -> dict[str, Any]:
    """Collect simple module-level constants used to prune branches."""
    constants: dict[str, Any] = {"TYPE_CHECKING": False}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"typing", "typing_extensions"}:
            for item in node.names:
                if item.name == "TYPE_CHECKING":
                    constants[item.asname or item.name] = False
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                value = _literal(statement.value, constants)
                if value is not None:
                    constants[target.id] = value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            value = _literal(statement.value, constants) if statement.value else None
            if value is not None:
                constants[statement.target.id] = value
    return constants


def _resolve_relative(module: str, package_file: bool, level: int, imported: str) -> str:
    """Resolve a relative import against its containing package."""
    components = module.split(".") if module else []
    if not package_file and components:
        components.pop()
    keep = max(0, len(components) - level + 1)
    prefix = components[:keep]
    return ".".join(prefix + ([imported] if imported else []))


def _imports(module: str, path: Path, tree: ast.Module) -> dict[str, str]:
    """Map import bindings to their canonical dotted names."""
    aliases: dict[str, str] = {}
    package_file = path.name == "__init__.py"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                bound = item.asname or item.name.split(".")[0]
                aliases[bound] = item.name if item.asname else bound
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = _resolve_relative(module, package_file, node.level, base)
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = ".".join(
                        part for part in (base, item.name) if part
                    )
    return aliases


def _dotted(node: ast.AST) -> str:
    """Return a dotted name for a Name or Attribute expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _function_defs(
    module: str, path: Path, tree: ast.Module
) -> list[dict[str, Any]]:
    """Collect function definitions with qualified names and class context."""
    found: list[dict[str, Any]] = []

    def visit(statements: list[ast.stmt], scope: str, class_name: str | None) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{scope}.{statement.name}"
                found.append(
                    {
                        "node": statement,
                        "name": qualified,
                        "module": module,
                        "path": path,
                        "class": class_name,
                    }
                )
                visit(statement.body, qualified, class_name)
            elif isinstance(statement, ast.ClassDef):
                qualified = f"{scope}.{statement.name}"
                visit(statement.body, qualified, qualified)

    visit(tree.body, module, None)
    return found


def _call_name(
    call: ast.Call, info: dict[str, Any], owner: str, defined: set[str]
) -> str:
    """Resolve a call through module imports and local function definitions."""
    expression = _dotted(call.func)
    if not expression:
        return ""
    aliases: dict[str, str] = info["aliases"]
    first, separator, remainder = expression.partition(".")
    if first in aliases:
        return aliases[first] + (f".{remainder}" if separator else "")
    if expression.startswith("self.") or expression.startswith("cls."):
        class_name = owner.rpartition(".")[0]
        candidate = f"{class_name}.{expression.split('.', 1)[1]}"
        return candidate if candidate in defined else expression
    if "." not in expression:
        local = f"{info['module']}.{expression}"
        if local in defined:
            return local
    return expression


def _entry_decorator(decorator: ast.expr, aliases: dict[str, str]) -> bool:
    """Recognize common Flask, FastAPI, Click, and command decorators."""
    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = _dotted(expression)
    parts = name.split(".")
    if parts and parts[-1] in {
        "route", "api_route", "get", "post", "put", "delete", "patch", "options", "head"
    }:
        return True
    if name in aliases:
        name = aliases[name]
    return name.endswith(".command") or name in {"command", "click.command"}


def _opaque_decorator(decorator: ast.expr) -> bool:
    """Identify decorators whose call behavior cannot be safely unwrapped."""
    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = _dotted(expression)
    return name.rsplit(".", 1)[-1] not in {
        "route", "api_route", "get", "post", "put", "delete", "patch",
        "options", "head", "command", "group", "wraps", "staticmethod",
        "classmethod", "property",
    }


def _edge(
    graph: nx.DiGraph,
    source: str,
    target: str,
    file: str,
    line: int,
    uncertain: bool,
    dynamic: bool = False,
) -> None:
    """Add a call edge with its source location and uncertainty metadata."""
    location = {"file": file, "line": line, "uncertain": uncertain, "dynamic": dynamic}
    if graph.has_edge(source, target):
        data = graph[source][target]
        data.setdefault("locations", []).append(location)
        data["uncertain"] = data["uncertain"] or uncertain
        data["dynamic"] = data["dynamic"] or dynamic
        if (file, line) < (data["file"], data["line"]):
            data["file"], data["line"] = file, line
    else:
        graph.add_edge(
            source, target, file=file, line=line, uncertain=uncertain,
            dynamic=dynamic, locations=[location]
        )


def _record_expression_calls(
    expression: ast.AST,
    owner: str,
    info: dict[str, Any],
    graph: nx.DiGraph,
    defined: set[str],
    uncertain: bool,
    opaque: set[str],
) -> None:
    """Record calls in one expression without traversing nested function bodies."""
    for node in ast.walk(expression):
        if isinstance(node, ast.Call):
            name = _call_name(node, info, owner, defined)
            if not name:
                continue
            path = info["relative"]
            line = node.lineno
            call_uncertain = uncertain or owner in opaque or name in opaque
            if name.rsplit(".", 1)[-1] in DYNAMIC_CALLS or name.endswith(".import_module"):
                dynamic_node = f"@dynamic:{owner}:{line}"
                graph.add_node(dynamic_node, symbol="unknown_dynamic_execution")
                _edge(graph, owner, dynamic_node, path, line, call_uncertain, dynamic=True)
            else:
                graph.add_node(name, symbol=name)
                _edge(graph, owner, name, path, line, call_uncertain)


def _scan_body(
    statements: list[ast.stmt],
    owner: str,
    info: dict[str, Any],
    graph: nx.DiGraph,
    defined: set[str],
    uncertain: bool,
    opaque: set[str],
    top_level: bool = False,
) -> None:
    """Record active and possibly active calls in a statement sequence."""
    constants: dict[str, Any] = info["constants"]
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(statement, ast.If):
            if top_level and _main_guard(statement):
                _scan_body(statement.body, owner, info, graph, defined, uncertain, opaque)
                continue
            truth = _condition(statement.test, constants)
            if truth is True:
                _scan_body(statement.body, owner, info, graph, defined, uncertain, opaque)
            elif truth is False:
                _scan_body(statement.orelse, owner, info, graph, defined, uncertain, opaque)
            else:
                _scan_body(statement.body, owner, info, graph, defined, True, opaque)
                _scan_body(statement.orelse, owner, info, graph, defined, True, opaque)
            continue
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            header = statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test
            _record_expression_calls(header, owner, info, graph, defined, True, opaque)
            _scan_body(statement.body, owner, info, graph, defined, True, opaque)
            _scan_body(statement.orelse, owner, info, graph, defined, True, opaque)
            continue
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                _record_expression_calls(
                    item.context_expr, owner, info, graph, defined, True, opaque
                )
            _scan_body(statement.body, owner, info, graph, defined, True, opaque)
            continue
        if isinstance(statement, ast.Try):
            _scan_body(statement.body, owner, info, graph, defined, True, opaque)
            for handler in statement.handlers:
                _record_expression_calls(
                    handler.type or ast.Constant(None), owner, info, graph,
                    defined, True, opaque
                )
                _scan_body(handler.body, owner, info, graph, defined, True, opaque)
            _scan_body(statement.orelse, owner, info, graph, defined, True, opaque)
            _scan_body(statement.finalbody, owner, info, graph, defined, True, opaque)
            continue
        if isinstance(statement, ast.Match):
            _record_expression_calls(
                statement.subject, owner, info, graph, defined, uncertain, opaque
            )
            for case in statement.cases:
                if case.guard:
                    _record_expression_calls(
                        case.guard, owner, info, graph, defined, True, opaque
                    )
                _scan_body(case.body, owner, info, graph, defined, True, opaque)
            continue
        _record_expression_calls(statement, owner, info, graph, defined, uncertain, opaque)


def _argparse_entries(tree: ast.Module) -> set[str]:
    """Find functions registered through argparse set_defaults(func=...)."""
    entries: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func).endswith(".set_defaults"):
            for keyword in node.keywords:
                if keyword.arg == "func" and isinstance(keyword.value, ast.Name):
                    entries.add(keyword.value.id)
    return entries


def _entry_nodes(
    infos: list[dict[str, Any]],
    functions: list[dict[str, Any]],
    graph: nx.DiGraph,
) -> list[str]:
    """Connect script, route, and command entry points to the virtual root."""
    entries: set[str] = set()
    for info in infos:
        module = info["module"]
        path = info["relative"]
        has_main = any(isinstance(node, ast.If) and _main_guard(node) for node in info["tree"].body)
        if has_main or Path(path).name in {"app.py", "main.py", "__main__.py", "cli.py"}:
            module_node = f"@module:{module}"
            graph.add_node(module_node, symbol=f"{module}.__module__")
            _edge(graph, ENTRY, module_node, path, 1, False)
            entries.add(module_node)
        argparse_names = _argparse_entries(info["tree"])
        for function in functions:
            if function["module"] != module:
                continue
            node: ast.FunctionDef | ast.AsyncFunctionDef = function["node"]
            decorated = any(
                _entry_decorator(item, info["aliases"]) for item in node.decorator_list
            )
            if decorated or node.name in argparse_names:
                name = function["name"]
                _edge(graph, ENTRY, name, path, node.lineno, False)
                entries.add(name)
    return sorted(entries)


def _shortest_paths(
    graph: nx.DiGraph, target: str, limit: int = 3
) -> list[list[CallFrame]]:
    """Return up to three deterministic shortest entry-to-target paths."""
    if not graph.has_node(target) or not nx.has_path(graph, ENTRY, target):
        return []
    distances = nx.single_source_shortest_path_length(graph, ENTRY)
    reverse_distances = nx.single_source_shortest_path_length(graph.reverse(copy=False), target)
    shortest = distances[target]
    results: list[list[CallFrame]] = []

    def visit(node: str, nodes: list[str]) -> None:
        if len(results) >= limit:
            return
        if node == target:
            frames: list[CallFrame] = []
            for source, destination in zip(nodes, nodes[1:]):
                data = graph[source][destination]
                frames.append(
                    {
                        "file": data["file"],
                        "line": data["line"],
                        "symbol": graph.nodes[destination].get("symbol", destination),
                    }
                )
            results.append(frames)
            return
        for next_node in sorted(graph.successors(node)):
            if (
                distances.get(next_node) == distances[node] + 1
                and distances[next_node] + reverse_distances.get(next_node, shortest + 1)
                == shortest
            ):
                visit(next_node, nodes + [next_node])

    visit(ENTRY, [ENTRY])
    return results


def _path_is_uncertain(graph: nx.DiGraph, frames: list[CallFrame]) -> bool:
    """Check whether any edge on the selected path is approximate."""
    current = ENTRY
    for frame in frames:
        destination = next(
            (
                node for node in graph.successors(current)
                if graph.nodes[node].get("symbol", node) == frame["symbol"]
                and graph[current][node]["file"] == frame["file"]
                and graph[current][node]["line"] == frame["line"]
            ),
            None,
        )
        if destination is None:
            return True
        if graph[current][destination]["uncertain"]:
            return True
        current = destination
    return False


def _reachable_package_nodes(graph: nx.DiGraph, package: str) -> list[str]:
    """Find package call nodes reachable from the virtual entry."""
    if ENTRY not in graph:
        return []
    reachable = nx.descendants(graph, ENTRY)
    prefix = package.replace("-", "_")
    return sorted(
        node for node in reachable
        if isinstance(node, str) and (node == prefix or node.startswith(prefix + "."))
    )


def _has_static_package_evidence(target: VulnTarget, infos: list[dict[str, Any]]) -> bool:
    """Check whether first-party imports identify the target's package."""
    distribution_imports = {"pillow": "pil", "pyyaml": "yaml"}
    package_roots = {
        target["package"].replace("-", "_").casefold(),
        distribution_imports.get(target["package"].casefold(), ""),
        *(
            symbol.partition(".")[0].replace("-", "_").casefold()
            for symbol in target["symbols"]
            if "." in symbol
        ),
    }
    imported_roots = {
        imported.partition(".")[0].replace("-", "_").casefold()
        for info in infos
        for imported in info["aliases"].values()
    }
    return bool(package_roots & imported_roots)


def _finding(
    target: VulnTarget,
    symbol: str,
    graph: nx.DiGraph,
    parse_failures: list[str],
    dynamic_paths: list[list[CallFrame]],
) -> ReachFinding:
    """Build a reachability finding from graph evidence."""
    paths = _shortest_paths(graph, symbol)
    if paths:
        uncertain = any(_path_is_uncertain(graph, path) for path in paths)
        return {
            "cve_id": target["cve_id"],
            "package": target["package"],
            "symbol": symbol,
            "reach_status": "over_approximated_path" if uncertain else "reachable",
            "confidence": 0.75 if uncertain else 1.0,
            "paths": paths,
            "needs_manual_review": uncertain,
            "notes": "Path includes an indeterminate branch or decorator." if uncertain else "",
        }
    if dynamic_paths:
        return {
            "cve_id": target["cve_id"],
            "package": target["package"],
            "symbol": symbol,
            "reach_status": "unknown_dynamic_execution",
            "confidence": 0.5,
            "paths": dynamic_paths[:3],
            "needs_manual_review": True,
            "notes": "Reachable dynamic execution may invoke this symbol.",
        }
    if parse_failures:
        return {
            "cve_id": target["cve_id"],
            "package": target["package"],
            "symbol": symbol,
            "reach_status": "over_approximated_path",
            "confidence": 0.5,
            "paths": [],
            "needs_manual_review": True,
            "notes": "Source parsing was incomplete; unreachability cannot be proven.",
        }
    return {
        "cve_id": target["cve_id"],
        "package": target["package"],
        "symbol": symbol,
        "reach_status": "unreachable",
        "confidence": 1.0,
        "paths": [],
        "needs_manual_review": False,
        "notes": "",
    }


def analyze(repo_path: str, targets: list[VulnTarget]) -> ReachResult:
    """Build a native AST call graph and report entry-to-vulnerable-symbol paths."""
    if not isinstance(repo_path, str) or not repo_path.strip():
        return _result_error("repo_path must be a non-empty directory path")
    if not isinstance(targets, list):
        return _result_error("targets must be a list")
    for target in targets:
        if (
            not isinstance(target, dict)
            or not isinstance(target.get("cve_id"), str)
            or not isinstance(target.get("package"), str)
            or not isinstance(target.get("symbols"), list)
            or any(not isinstance(symbol, str) for symbol in target.get("symbols", []))
        ):
            return _result_error("each target must include cve_id, package, and string symbols")

    try:
        root = Path(repo_path).resolve()
        if not root.is_dir():
            return _result_error(f"repository path is not a directory: {repo_path}")
        infos: list[dict[str, Any]] = []
        parse_failures: list[str] = []
        for path in _python_files(root):
            relative = _relative_path(root, path)
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=relative)
            except SyntaxError as exc:
                parse_failures.append(relative)
                LOGGER.warning("Skipping syntax-invalid source file %s: %s", relative, exc)
                continue
            infos.append(
                {
                    "path": path,
                    "relative": relative,
                    "module": _module_name(root, path),
                    "tree": tree,
                    "aliases": _imports(_module_name(root, path), path, tree),
                    "constants": _collect_constants(tree),
                }
            )

        parse_failures.sort()
        if not infos:
            result = _result_error("no Python files could be parsed")
            result["parse_failures"] = parse_failures
            result["warnings"] = ["All Python files failed to parse."]
            result["degraded"] = True
            return result

        functions = [
            function
            for info in infos
            for function in _function_defs(info["module"], info["path"], info["tree"])
        ]
        defined = {function["name"] for function in functions}
        graph = nx.DiGraph()
        graph.add_node(ENTRY, symbol=ENTRY)
        opaque = {
            function["name"]
            for function in functions
            if any(_opaque_decorator(item) for item in function["node"].decorator_list)
        }
        for function in functions:
            node: ast.FunctionDef | ast.AsyncFunctionDef = function["node"]
            function_name = function["name"]
            info = next(item for item in infos if item["module"] == function["module"])
            graph.add_node(function_name, symbol=function_name)
            _scan_body(
                node.body, function_name, info, graph, defined, False, opaque
            )

        for info in infos:
            module_node = f"@module:{info['module']}"
            graph.add_node(module_node, symbol=f"{info['module']}.__module__")
            _scan_body(
                info["tree"].body, module_node, info, graph, defined, False, opaque,
                top_level=True,
            )
        entry_points = _entry_nodes(infos, functions, graph)

        dynamic_nodes = [
            node for node, data in graph.nodes(data=True)
            if data.get("symbol") == "unknown_dynamic_execution"
            and ENTRY in graph
            and nx.has_path(graph, ENTRY, node)
        ]
        dynamic_paths = sorted(
            (
                path
                for node in dynamic_nodes
                for path in _shortest_paths(graph, node, limit=3)
            ),
            key=lambda path: tuple((frame["file"], frame["line"], frame["symbol"]) for frame in path),
        )[:3]

        findings: list[ReachFinding] = []
        warnings: list[str] = []
        for target in sorted(targets, key=lambda item: (item["cve_id"], item["package"])):
            symbols = target["symbols"]
            target_dynamic_paths = (
                [] if _has_static_package_evidence(target, infos) else dynamic_paths
            )
            if not symbols:
                warnings.append("package-level only")
                package_nodes = _reachable_package_nodes(graph, target["package"])
                package_paths = [
                    path for node in package_nodes for path in _shortest_paths(graph, node, 3)
                ]
                package_paths.sort(
                    key=lambda path: tuple(
                        (frame["file"], frame["line"], frame["symbol"]) for frame in path
                    )
                )
                if package_paths:
                    finding = _finding(
                        target, target["package"], graph, parse_failures, target_dynamic_paths
                    )
                    finding["reach_status"] = (
                        "over_approximated_path"
                        if any(_path_is_uncertain(graph, path) for path in package_paths[:3])
                        else "reachable"
                    )
                    finding["confidence"] = (
                        0.75 if finding["reach_status"] == "over_approximated_path" else 1.0
                    )
                    finding["needs_manual_review"] = finding["reach_status"] != "reachable"
                    finding["paths"] = package_paths[:3]
                    finding["notes"] = (
                        "Package-level call path; vulnerable symbol was not specified."
                    )
                    findings.append(finding)
                else:
                    findings.append(
                        _finding(
                            target, target["package"], graph, parse_failures, target_dynamic_paths
                        )
                    )
            else:
                for symbol in sorted(set(symbols)):
                    findings.append(
                        _finding(target, symbol, graph, parse_failures, target_dynamic_paths)
                    )
        warnings.extend(
            f"Skipped invalid Python file: {path}" for path in parse_failures
        )
        return {
            "ok": True,
            "error": None,
            "warnings": list(dict.fromkeys(warnings)),
            "findings": sorted(
                findings, key=lambda item: (item["cve_id"], item["package"], item["symbol"])
            ),
            "entry_points": entry_points,
            "parse_failures": parse_failures,
            "degraded": not bool(infos),
        }
    except Exception as exc:
        LOGGER.exception("Reachability analysis failed for %s", repo_path)
        result = empty_result("reach", f"reachability analysis failed: {exc}")
        return result  # type: ignore[return-value]
