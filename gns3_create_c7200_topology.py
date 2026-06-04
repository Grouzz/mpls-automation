"""
Creates the MPLS/VPN topology directly in GNS3 using your Cisco c7200 IOS router template.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any


# ---------------------------------------------------------------------------
# Lab definition
# ---------------------------------------------------------------------------

NODES: dict[str, tuple[int, int]] = {
    # Customer sites on R1
    "R7": (-520, -180),   # headquarters CE
    "R5": (-520, 80),     # branch1 CE

    # Provider backbone
    "R1": (-300, -60),    # PE
    "R2": (-80, -60),     # P
    "R3": (140, -60),     # P
    "R4": (360, -60),     # PE
    "R12": (140, 170),    # PE

    # Customer sites on R4
    "R8": (580, -170),    # branch2 CE
    "R9": (580, 50),      # FINANCE_AUDIT CE

    # Customer sites on R12
    "R10": (-80, 330),    # SHARED_SERVICES CE
    "R11": (360, 330),    # ISOLATED_RESEARCH CE
}

# GNS3 link endpoints.
# These interface names must exist in the c7200 template.
LINKS: list[tuple[str, str, str, str]] = [
    # CE to PE links
    ("R1", "GigabitEthernet1/0", "R7", "GigabitEthernet1/0"),
    ("R1", "GigabitEthernet2/0", "R5", "GigabitEthernet1/0"),
    ("R4", "GigabitEthernet2/0", "R8", "GigabitEthernet1/0"),
    ("R4", "GigabitEthernet3/0", "R9", "GigabitEthernet1/0"),
    ("R12", "GigabitEthernet2/0", "R10", "GigabitEthernet1/0"),
    ("R12", "GigabitEthernet3/0", "R11", "GigabitEthernet1/0"),

    # Provider core links
    ("R1", "GigabitEthernet3/0", "R2", "GigabitEthernet1/0"),
    ("R2", "GigabitEthernet2/0", "R3", "GigabitEthernet1/0"),
    ("R3", "GigabitEthernet2/0", "R4", "GigabitEthernet1/0"),
    ("R3", "GigabitEthernet3/0", "R12", "GigabitEthernet1/0"),
]


class GNS3Error(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# REST helpers
# ---------------------------------------------------------------------------

def api_request(
    method: str,
    base_url: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 30,
) -> Any:
    url = base_url.rstrip("/") + path
    headers = {"Accept": "application/json"}
    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = raw
        raise GNS3Error(f"{method} {path} failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise GNS3Error(
            f"Cannot reach GNS3 at {base_url}. "
            f"Open GNS3 and check Edit > Preferences > Server. Details: {exc.reason}"
        ) from exc


def get(base_url: str, path: str) -> Any:
    return api_request("GET", base_url, path)


def post(base_url: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    return api_request("POST", base_url, path, payload or {})


def delete(base_url: str, path: str) -> Any:
    return api_request("DELETE", base_url, path)


# ---------------------------------------------------------------------------
# GNS3 project/template/node helpers
# ---------------------------------------------------------------------------

def list_templates(base_url: str) -> list[dict[str, Any]]:
    templates = get(base_url, "/v2/templates")
    if not isinstance(templates, list):
        raise GNS3Error("Unexpected response from /v2/templates")
    return templates


def print_templates(base_url: str) -> None:
    templates = sorted(list_templates(base_url), key=lambda t: str(t.get("name", "")).lower())
    print("\nAvailable templates:\n")
    for template in templates:
        name = template.get("name", "<unnamed>")
        template_type = template.get("template_type", "?")
        template_id = template.get("template_id", "?")
        print(f"  - {name}  type={template_type}  id={template_id}")
    print()


def find_template(base_url: str, template_name: str) -> dict[str, Any]:
    templates = list_templates(base_url)

    exact = [
        t for t in templates
        if str(t.get("name", "")).casefold() == template_name.casefold()
    ]
    if exact:
        return exact[0]

    partial = [
        t for t in templates
        if template_name.casefold() in str(t.get("name", "")).casefold()
    ]
    if len(partial) == 1:
        return partial[0]

    if len(partial) > 1:
        names = [t.get("name") for t in partial]
        raise GNS3Error(f"Template name {template_name!r} is ambiguous. Matches: {names}")

    raise GNS3Error(f"Template {template_name!r} not found. Run with --list-templates.")


def find_project(base_url: str, project_name_or_id: str) -> dict[str, Any] | None:
    projects = get(base_url, "/v2/projects")
    if not isinstance(projects, list):
        raise GNS3Error("Unexpected response from /v2/projects")

    for project in projects:
        if (
            project.get("project_id") == project_name_or_id
            or str(project.get("name", "")).casefold() == project_name_or_id.casefold()
        ):
            return project
    return None


def ensure_project(base_url: str, project_name: str) -> dict[str, Any]:
    project = find_project(base_url, project_name)
    if project:
        print(f"✓ Project found: {project['name']}")
        return project

    project = post(base_url, "/v2/projects", {"name": project_name})
    print(f"✓ Project created: {project['name']}")
    return project


def open_project(base_url: str, project_id: str) -> None:
    try:
        post(base_url, f"/v2/projects/{project_id}/open", {})
        print("✓ Project opened")
    except GNS3Error as exc:
        # Usually harmless if already open.
        print(f"⚠ Could not explicitly open project, continuing: {exc}")


def get_nodes(base_url: str, project_id: str) -> list[dict[str, Any]]:
    nodes = get(base_url, f"/v2/projects/{project_id}/nodes")
    if not isinstance(nodes, list):
        raise GNS3Error("Unexpected response from project nodes endpoint")
    return nodes


def get_links(base_url: str, project_id: str) -> list[dict[str, Any]]:
    links = get(base_url, f"/v2/projects/{project_id}/links")
    if not isinstance(links, list):
        raise GNS3Error("Unexpected response from project links endpoint")
    return links


def delete_existing_lab_nodes(base_url: str, project_id: str) -> None:
    wanted_names = set(NODES)
    for node in get_nodes(base_url, project_id):
        if node.get("name") in wanted_names:
            print(f"→ Deleting existing node {node['name']}")
            delete(base_url, f"/v2/projects/{project_id}/nodes/{node['node_id']}")


def create_node_from_template(
    base_url: str,
    project_id: str,
    template_id: str,
    name: str,
    x: int,
    y: int,
) -> dict[str, Any]:
    payload = {
        "name": name,
        "x": x,
        "y": y,
    }
    node = post(base_url, f"/v2/projects/{project_id}/templates/{template_id}", payload)
    print(f"✓ Created node {name}")
    return node


def ensure_nodes(
    base_url: str,
    project_id: str,
    template_id: str,
    rebuild: bool,
) -> dict[str, dict[str, Any]]:
    if rebuild:
        delete_existing_lab_nodes(base_url, project_id)
        time.sleep(1)

    existing = {node["name"]: node for node in get_nodes(base_url, project_id)}

    for name, (x, y) in NODES.items():
        if name in existing:
            print(f"✓ Node already exists: {name}")
        else:
            create_node_from_template(base_url, project_id, template_id, name, x, y)

    # Refresh after creation because ports may be populated after node creation.
    refreshed = {node["name"]: node for node in get_nodes(base_url, project_id)}
    missing = [name for name in NODES if name not in refreshed]
    if missing:
        raise GNS3Error(f"Missing nodes after creation: {missing}")
    return {name: refreshed[name] for name in NODES}


# ---------------------------------------------------------------------------
# Port/link helpers
# ---------------------------------------------------------------------------

def normalize_interface_name(name: str) -> str:
    return name.replace(" ", "").replace("_", "").casefold()


def find_port(node: dict[str, Any], interface_name: str) -> dict[str, Any]:
    target = normalize_interface_name(interface_name)
    ports = node.get("ports", [])

    for port in ports:
        candidates = [
            str(port.get("name", "")),
            str(port.get("short_name", "")),
            str(port.get("label", "")),
        ]
        for candidate in candidates:
            if normalize_interface_name(candidate) == target:
                return port

    available = [
        port.get("name") or port.get("short_name") or port.get("label")
        for port in ports
    ]

    raise GNS3Error(
        f"Node {node.get('name')} does not have interface {interface_name!r}.\n"
        f"Available interfaces on this node: {available}\n\n"
        f"Fix: edit the c7200 template and make sure Slot 1, Slot 2, Slot 3 are PA-GE, "
        f"then run this script again with --rebuild."
    )


def endpoint_for(node: dict[str, Any], interface_name: str) -> dict[str, Any]:
    port = find_port(node, interface_name)
    return {
        "node_id": node["node_id"],
        "adapter_number": int(port["adapter_number"]),
        "port_number": int(port["port_number"]),
    }


def link_key_from_endpoints(endpoint_a: dict[str, Any], endpoint_b: dict[str, Any]) -> frozenset[tuple[str, int, int]]:
    return frozenset(
        {
            (
                endpoint_a["node_id"],
                endpoint_a["adapter_number"],
                endpoint_a["port_number"],
            ),
            (
                endpoint_b["node_id"],
                endpoint_b["adapter_number"],
                endpoint_b["port_number"],
            ),
        }
    )


def existing_link_keys(base_url: str, project_id: str) -> set[frozenset[tuple[str, int, int]]]:
    keys: set[frozenset[tuple[str, int, int]]] = set()

    for link in get_links(base_url, project_id):
        nodes = link.get("nodes", [])
        if len(nodes) != 2:
            continue
        a, b = nodes
        keys.add(
            frozenset(
                {
                    (a["node_id"], int(a["adapter_number"]), int(a["port_number"])),
                    (b["node_id"], int(b["adapter_number"]), int(b["port_number"])),
                }
            )
        )

    return keys


def create_links(base_url: str, project_id: str, nodes: dict[str, dict[str, Any]]) -> None:
    already = existing_link_keys(base_url, project_id)

    for left_node_name, left_intf, right_node_name, right_intf in LINKS:
        left = endpoint_for(nodes[left_node_name], left_intf)
        right = endpoint_for(nodes[right_node_name], right_intf)
        key = link_key_from_endpoints(left, right)

        if key in already:
            print(f"✓ Link already exists: {left_node_name} {left_intf} <-> {right_node_name} {right_intf}")
            continue

        payload = {"nodes": [left, right]}
        post(base_url, f"/v2/projects/{project_id}/links", payload)
        print(f"✓ Created link: {left_node_name} {left_intf} <-> {right_node_name} {right_intf}")


def print_port_inventory(nodes: dict[str, dict[str, Any]]) -> None:
    print("\nDetected c7200 interfaces:\n")
    for name in sorted(nodes):
        ports = nodes[name].get("ports", [])
        readable = [
            port.get("name") or port.get("short_name") or port.get("label")
            for port in ports
        ]
        print(f"  {name}: {readable}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create the complex c7200 MPLS/VPN topology directly in GNS3."
    )
    parser.add_argument("--host", default="127.0.0.1", help="GNS3 server host. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=3080, help="GNS3 server port. Default: 3080")
    parser.add_argument("--project", default="mpls_testing", help="GNS3 project name. Default: mpls_testing")
    parser.add_argument("--template", default="c7200", help="GNS3 router template name. Default: c7200")
    parser.add_argument("--rebuild", action="store_true", help="Delete existing lab routers first.")
    parser.add_argument("--list-templates", action="store_true", help="Only list available GNS3 templates.")
    parser.add_argument("--no-open", action="store_true", help="Do not call the GNS3 project open endpoint.")
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}"

    try:
        print(f"→ Connecting to GNS3 at {base_url}")

        if args.list_templates:
            print_templates(base_url)
            return

        template = find_template(base_url, args.template)
        print(f"✓ Template found: {template['name']}  id={template['template_id']}")

        project = ensure_project(base_url, args.project)
        project_id = project["project_id"]

        if not args.no_open:
            open_project(base_url, project_id)

        nodes = ensure_nodes(
            base_url=base_url,
            project_id=project_id,
            template_id=template["template_id"],
            rebuild=args.rebuild,
        )

        print_port_inventory(nodes)

        create_links(base_url, project_id, nodes)

        print("\n✓ GNS3 topology created successfully.")
        print("\nNext commands:")
        print(f"  py main.py intent.json -o output_complex --phase4b --phase4b-policy policy.json")
        print(f"  py main.py intent.json -o output_complex --phase4b --phase4b-policy policy.json --drag-drop-bot --gns3-project \"{args.project}\" --gns3-start")
        print("\nIf config push fails because of interfaces, check that the printed interfaces include:")
        print("  GigabitEthernet1/0, GigabitEthernet2/0, GigabitEthernet3/0")

    except GNS3Error as exc:
        print(f"\n✗ {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
