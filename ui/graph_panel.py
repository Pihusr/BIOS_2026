from collections.abc import Mapping, Sequence

import networkx as nx
import streamlit as st
from pyvis.network import Network
from streamlit.components.v1 import html as components_html

from contracts import ScanResult
from ui import (
    SEMANTIC_COLORS,
    active_theme,
    escape_html,
    html_document,
    show_degraded_warning,
)

NODE_SHAPES = {
    "reachable": "dot",
    "typosquat": "hexagon",
    "investigating": "square",
    "suppressed": "diamond",
    "safe": "dot",
}
STATE_LABELS = {
    "reachable": "Reachable CVE",
    "typosquat": "Typosquat / provenance",
    "investigating": "Investigating",
    "suppressed": "Suppressed CVE",
    "safe": "Safe",
}
INVESTIGATING_REACH = {"unknown_dynamic_execution", "over_approximated_path"}


def _items(section: object, key: str) -> list[Mapping[str, object]]:
    values = section.get(key, []) if isinstance(section, Mapping) else []
    return [value for value in values if isinstance(value, Mapping)] if isinstance(values, list) else []


def _matches_package(value: object, package_name: str, purl: str, requested: str) -> bool:
    candidates = {package_name.casefold(), purl.casefold(), requested.casefold()}
    return str(value or "").casefold() in candidates


def _is_reachable_finding(finding: Mapping[str, object]) -> bool:
    reach = finding.get("reach")
    return (
        finding.get("status") == "affected"
        and isinstance(reach, Mapping)
        and reach.get("reach_status") == "reachable"
    )


def package_state(purl_or_name: str, scan: Mapping[str, object]) -> str:
    """Map a package to exactly one state, prioritizing visible risk."""
    packages = _items(scan.get("sbom"), "packages")
    package = next(
        (
            item
            for item in packages
            if purl_or_name in {str(item.get("purl") or ""), str(item.get("name") or "")}
        ),
        {},
    )
    name = str(package.get("name") or purl_or_name)
    purl = str(package.get("purl") or purl_or_name)
    findings = [
        finding
        for finding in _items(scan.get("vex"), "findings")
        if _matches_package(finding.get("package"), name, purl, purl_or_name)
    ]

    for finding in findings:
        reach = finding.get("reach")
        if (
            finding.get("status") == "affected"
            and isinstance(reach, Mapping)
            and reach.get("reach_status") == "reachable"
        ):
            return "reachable"

    typo_flags = _items(scan.get("inspect"), "typo_flags")
    provenance = _items(scan.get("inspect"), "provenance")
    if any(_matches_package(flag.get("package"), name, purl, purl_or_name) for flag in typo_flags):
        return "typosquat"
    if any(finding.get("provenance_tag") for finding in findings):
        return "typosquat"
    if any(
        _matches_package(report.get("package"), name, purl, purl_or_name)
        and bool(report.get("violations"))
        for report in provenance
    ):
        return "typosquat"

    for finding in findings:
        reach = finding.get("reach")
        reach_status = reach.get("reach_status") if isinstance(reach, Mapping) else None
        if finding.get("status") == "under_investigation" or reach_status in INVESTIGATING_REACH:
            return "investigating"
    if findings and all(finding.get("status") == "not_affected" for finding in findings):
        return "suppressed"
    if not findings:
        return "safe"
    return "investigating"


def build_graph(scan: Mapping[str, object]) -> nx.DiGraph:
    """Build the package dependency graph, including isolated packages."""
    graph = nx.DiGraph()
    sbom = scan.get("sbom") or {}
    for package in _items(sbom, "packages"):
        node_id = package.get("purl") or package.get("name")
        if node_id:
            graph.add_node(str(node_id), package=package)
    edges = sbom.get("edges", []) if isinstance(sbom, Mapping) else []
    if isinstance(edges, list):
        for edge in edges:
            if isinstance(edge, Sequence) and not isinstance(edge, (str, bytes)) and len(edge) >= 2:
                parent, child = edge[0], edge[1]
                if parent and child:
                    graph.add_edge(str(parent), str(child))
    return graph


def package_tooltip(package: Mapping[str, object], scan: Mapping[str, object]) -> str:
    """Build an escaped tooltip with package, finding, and trust context."""
    name = str(package.get("name") or "Unknown package")
    purl = str(package.get("purl") or name)
    matches = [
        finding
        for finding in _items(scan.get("vex"), "findings")
        if _matches_package(finding.get("package"), name, purl, purl)
    ]
    lines = [
        f"Package: {name}",
        f"Version: {package.get('version') or 'unknown'}",
        "CVE ids: " + (", ".join(str(item.get("id")) for item in matches if item.get("id")) or "none"),
        "Status: " + (", ".join(str(item.get("status") or "unknown") for item in matches) or "safe"),
        "Priority: " + (", ".join(str(item.get("priority") or "unknown") for item in matches) or "none"),
    ]
    for flag in _items(scan.get("inspect"), "typo_flags"):
        if _matches_package(flag.get("package"), name, purl, purl):
            lines.append(
                f"Typosquat: resembles {flag.get('matched') or 'unknown'} "
                f"(distance {flag.get('distance', 'unknown')})"
            )
    for finding in matches:
        if finding.get("provenance_tag"):
            lines.append(f"Provenance: {finding['provenance_tag']}")
    for report in _items(scan.get("inspect"), "provenance"):
        if _matches_package(report.get("package"), name, purl, purl):
            violations = report.get("violations") or []
            if isinstance(violations, list):
                lines.extend(f"Provenance: {reason}" for reason in violations)
    return "<br>".join(escape_html(line) for line in lines)


def reachable_route_edges(graph: nx.DiGraph, scan: Mapping[str, object]) -> set[tuple[str, str]]:
    """Find dependency edges on direct-package routes to reachable findings."""
    packages = _items(scan.get("sbom"), "packages")
    direct_nodes = {
        str(package.get("purl") or package.get("name"))
        for package in packages
        if package.get("scope") == "direct" and (package.get("purl") or package.get("name"))
    }
    reachable_names = {
        str(finding.get("package") or "").casefold()
        for finding in _items(scan.get("vex"), "findings")
        if _is_reachable_finding(finding)
    }
    package_ids = {
        str(package.get("purl") or package.get("name")): str(package.get("name") or "").casefold()
        for package in packages
        if package.get("purl") or package.get("name")
    }
    marked = set()
    for target, name in package_ids.items():
        if name not in reachable_names or target not in graph:
            continue
        ancestors = nx.ancestors(graph, target) | {target}
        for root in direct_nodes:
            if root not in graph:
                continue
            descendants = nx.descendants(graph, root) | {root}
            if target not in descendants:
                continue
            marked.update(
                (parent, child)
                for parent, child in graph.edges
                if parent in descendants and child in ancestors
            )
    return marked


def legend_html(counts: Mapping[str, int]) -> str:
    """Build the graph's shape-and-color legend with per-state counts."""
    items = []
    for state, label in STATE_LABELS.items():
        color = SEMANTIC_COLORS[state]
        shape = NODE_SHAPES[state]
        shape_style = (
            "border-radius:50%" if shape == "dot" else
            "transform:rotate(45deg)" if shape == "diamond" else
            "clip-path:polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%)" if shape == "hexagon" else
            ""
        )
        items.append(
            '<span class="legend-item">'
            f'<span class="legend-shape" style="background:{color};{shape_style}"></span>'
            f"{escape_html(label)} ({int(counts.get(state, 0))})</span>"
        )
    return html_document('<div class="legend">' + "".join(items) + "</div>")


def _visible_nodes(graph: nx.DiGraph, scan: Mapping[str, object]) -> set[str]:
    packages = _items(scan.get("sbom"), "packages")
    selected = set()
    for package in packages:
        node_id = str(package.get("purl") or package.get("name") or "")
        if node_id and (package.get("scope") == "direct" or package_state(node_id, scan) != "safe"):
            selected.add(node_id)
    return selected & set(graph.nodes)


def _edge_styles(graph: nx.DiGraph, scan: Mapping[str, object]) -> dict[tuple[str, str], dict[str, object]]:
    route_edges = reachable_route_edges(graph, scan)
    styles = {}
    for parent, child in graph.edges:
        if package_state(child, scan) == "typosquat":
            styles[(parent, child)] = {"color": SEMANTIC_COLORS["typosquat"], "width": 2, "dashes": True}
        elif (parent, child) in route_edges:
            styles[(parent, child)] = {"color": SEMANTIC_COLORS["reachable"], "width": 3.5}
        else:
            styles[(parent, child)] = {"color": active_theme()["border"], "width": 1}
    return styles


def render(scan: ScanResult) -> None:
    """Render the filtered PyVis dependency graph and state legend."""
    show_degraded_warning(scan)
    st.subheader("Dependency Graph")
    graph = build_graph(scan)
    packages = _items(scan.get("sbom"), "packages")
    total_nodes = len(graph.nodes)
    show_all = st.toggle(f"Show all {len(packages)} components", value=False)
    visible_nodes = set(graph.nodes) if show_all else _visible_nodes(graph, scan)
    st.caption(f"{len(visible_nodes)} of {total_nodes} nodes")

    counts = {state: 0 for state in STATE_LABELS}
    for node in graph.nodes:
        counts[package_state(str(node), scan)] += 1
    st.markdown(legend_html(counts), unsafe_allow_html=True)

    theme = active_theme()
    network = Network(
        height="480px",
        cdn_resources="in_line",
        directed=True,
        bgcolor=theme["surface"],
        font_color=theme["text"],  # pyright: ignore[reportArgumentType]
    )
    network.set_options(
        '{"physics":{"stabilization":{"enabled":true,"iterations":1000,"fit":true}}}'
    )
    styles = _edge_styles(graph, scan)
    for node in visible_nodes:
        data = graph.nodes[node]
        package = data.get("package")
        package = package if isinstance(package, Mapping) else {"name": node, "version": "unknown"}
        state = package_state(str(node), scan)
        network.add_node(
            escape_html(node),
            label=escape_html(package.get("name") or node),
            title=package_tooltip(package, scan),
            color=SEMANTIC_COLORS[state],
            shape=NODE_SHAPES[state],
        )
    for parent, child, style in (
        (parent, child, style)
        for (parent, child), style in styles.items()
        if parent in visible_nodes and child in visible_nodes
    ):
        network.add_edge(
            escape_html(parent),
            escape_html(child),
            color=style["color"],
            width=style["width"],
            dashes=style.get("dashes", False),
        )
    sbom = scan.get("sbom")
    edges = sbom.get("edges", []) if isinstance(sbom, Mapping) else []
    if not edges:
        st.caption(
            "Dependency edges are not available for this manifest; "
            "packages are linked to the project root."
        )
        target = str(scan.get("target") or "Project").rstrip("/\\")
        project_name = target.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if project_name.endswith(".git"):
            project_name = project_name[:-4]
        project_name = project_name or "Project"

        root_id = "__project_root__"
        while root_id in graph:
            root_id = f"_{root_id}"
        network.add_node(
            escape_html(root_id),
            label=escape_html(project_name),
            color="#7f8c8d",
            shape="dot",
        )
        root_children = {
            str(package.get("purl") or package.get("name"))
            for package in packages
            if package.get("purl") or package.get("name")
            if package.get("scope") == "direct"
            or graph.in_degree(str(package.get("purl") or package.get("name"))) == 0
        }
        for child in root_children & visible_nodes:
            network.add_edge(
                escape_html(root_id),
                escape_html(child),
                color="#7f8c8d",
                width=1,
                dashes=True,
            )
    components_html(network.generate_html(), height=480)
