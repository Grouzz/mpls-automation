#!/usr/bin/env python3
"""
Push generated startup configs to a running GNS3 project.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class GNS3Client:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3080,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self.base = f"http://{host}:{port}"
        self.username = username
        self.password = password

    def _headers(self, json_body: bool = False, content_type: str | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json"}

        if json_body:
            headers["Content-Type"] = "application/json"

        if content_type:
            headers["Content-Type"] = content_type

        if self.username is not None and self.password is not None:
            token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        return headers

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
        timeout: int = 15,
    ) -> tuple[int, Any]:
        url = self.base.rstrip("/") + path

        if payload is not None and raw_body is not None:
            raise ValueError("Use either payload or raw_body, not both")

        body = None
        headers = self._headers(json_body=payload is not None, content_type=content_type)

        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        elif raw_body is not None:
            body = raw_body

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if not raw:
                    return resp.status, {}
                try:
                    return resp.status, json.loads(raw.decode("utf-8"))
                except Exception:
                    return resp.status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception:
                data = raw.decode("utf-8", errors="replace")
            return exc.code, data
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Cannot reach GNS3 server at {self.base}: {exc.reason}") from exc

    def get(self, path: str) -> tuple[int, Any]:
        return self.request("GET", path)

    def post(self, path: str, data: dict[str, Any] | None = None) -> tuple[int, Any]:
        return self.request("POST", path, payload=data or {})

    def put(self, path: str, data: dict[str, Any] | None = None) -> tuple[int, Any]:
        return self.request("PUT", path, payload=data or {})

    def put_raw(self, path: str, body: bytes, content_type: str = "text/plain") -> tuple[int, Any]:
        return self.request("PUT", path, raw_body=body, content_type=content_type)


# ---------------------------------------------------------------------------
# GNS3 helpers
# ---------------------------------------------------------------------------

def find_project(client: GNS3Client, name_or_id: str) -> dict[str, Any]:
    status, projects = client.get("/v2/projects")
    if status != 200:
        raise RuntimeError(f"Failed to list projects: HTTP {status}: {projects}")

    for project in projects:
        if project.get("project_id") == name_or_id or project.get("name") == name_or_id:
            return project

    names = [p.get("name") for p in projects]
    raise ValueError(f"Project {name_or_id!r} not found. Available projects: {names}")


def list_nodes(client: GNS3Client, project_id: str) -> list[dict[str, Any]]:
    status, nodes = client.get(f"/v2/projects/{project_id}/nodes")
    if status != 200:
        raise RuntimeError(f"Failed to list nodes: HTTP {status}: {nodes}")
    return nodes


def get_dynamips_node(client: GNS3Client, project_id: str, node_id: str) -> dict[str, Any] | None:
    status, data = client.get(f"/v2/compute/projects/{project_id}/dynamips/nodes/{node_id}")
    if status == 200 and isinstance(data, dict):
        return data
    return None


def start_node(client: GNS3Client, project_id: str, node_id: str) -> bool:
    status, _ = client.post(f"/v2/projects/{project_id}/nodes/{node_id}/start", {})
    return status in (200, 201, 204)


def stop_node(client: GNS3Client, project_id: str, node_id: str) -> bool:
    status, _ = client.post(f"/v2/projects/{project_id}/nodes/{node_id}/stop", {})
    return status in (200, 201, 204)


# ---------------------------------------------------------------------------
# Config discovery
# ---------------------------------------------------------------------------

def discover_configs(config_dir: str) -> dict[str, str]:
    configs: dict[str, str] = {}
    root_dir = Path(config_dir)

    if not root_dir.exists():
        raise FileNotFoundError(f"Config directory does not exist: {config_dir}")

    for path in root_dir.rglob("*_startup.cfg"):
        router_name = path.name.replace("_startup.cfg", "")
        configs[router_name] = path.read_text(encoding="utf-8")

    return configs


# ---------------------------------------------------------------------------
# Dynamips upload strategies
# ---------------------------------------------------------------------------

def upload_dynamips_via_compute_api(
    client: GNS3Client,
    project_id: str,
    node_id: str,
    cfg_text: str,
) -> tuple[bool, str]:
    """
    First-choice method for c7200/Dynamips.
    Some GNS3 versions accept startup_config_content here.
    """
    status, resp = client.put(
        f"/v2/compute/projects/{project_id}/dynamips/nodes/{node_id}",
        {"startup_config_content": cfg_text},
    )

    if status in (200, 201, 204):
        return True, "Dynamips compute API"

    return False, f"Dynamips compute API failed: HTTP {status}: {resp}"


def candidate_project_paths(project: dict[str, Any], project_id: str) -> list[Path]:
    """
    Build possible local project paths.
    GNS3 usually stores local projects under:
      C:\\Users\\<user>\\GNS3\\projects\\<project_id>
    but the API may also expose path/project_path in some versions.
    """
    candidates: list[Path] = []

    for key in ("path", "project_path", "filename"):
        value = project.get(key)
        if isinstance(value, str) and value.strip():
            p = Path(value)
            if p.suffix == ".gns3":
                p = p.parent
            candidates.append(p)

    home = Path.home()
    candidates.extend(
        [
            home / "GNS3" / "projects" / project_id,
            home / "Documents" / "GNS3" / "projects" / project_id,
            home / "gns3" / "projects" / project_id,
        ]
    )

    # Deduplicate while preserving order.
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        try:
            key = str(p.resolve())
        except Exception:
            key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def possible_dynamips_config_files(
    project: dict[str, Any],
    project_id: str,
    node: dict[str, Any],
    dyn: dict[str, Any] | None,
) -> list[Path]:
    """
    Generate likely startup-config file locations for local Dynamips nodes.
    """
    node_id = node["node_id"]
    node_name = node.get("name", "router")
    candidates: list[Path] = []

    # Best source: compute API node_directory.
    if dyn:
        node_directory = dyn.get("node_directory")
        if isinstance(node_directory, str) and node_directory.strip():
            nd = Path(node_directory)
            if nd.is_absolute():
                startup_rel = dyn.get("startup_config") or dyn.get("startup_config_path")
                if isinstance(startup_rel, str) and startup_rel.strip():
                    candidates.append(nd / startup_rel)
                candidates.extend(
                    [
                        nd / "configs" / "i1_startup-config.cfg",
                        nd / "configs" / f"{node_name}_startup-config.cfg",
                    ]
                )

    # Controller node may expose node_directory/properties too.
    node_directory = node.get("node_directory")
    if isinstance(node_directory, str) and node_directory.strip():
        nd = Path(node_directory)
        if nd.is_absolute():
            props = node.get("properties", {})
            startup_rel = props.get("startup_config") if isinstance(props, dict) else None
            if isinstance(startup_rel, str) and startup_rel.strip():
                candidates.append(nd / startup_rel)
            candidates.append(nd / "configs" / "i1_startup-config.cfg")

    # Project folder guesses.
    for project_path in candidate_project_paths(project, project_id):
        candidates.extend(
            [
                project_path / "project-files" / "dynamips" / node_id / "configs" / "i1_startup-config.cfg",
                project_path / "project-files" / "dynamips" / node_id / "configs" / f"{node_name}_startup-config.cfg",
                project_path / "project-files" / "dynamips" / "configs" / "i1_startup-config.cfg",
            ]
        )

        # If directories already exist, prefer any existing startup-config under the node directory.
        node_dir = project_path / "project-files" / "dynamips" / node_id
        if node_dir.exists():
            for existing in node_dir.rglob("*startup-config*.cfg"):
                candidates.insert(0, existing)

    # Deduplicate.
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        try:
            key = str(p.resolve())
        except Exception:
            key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def upload_dynamips_via_local_filesystem(
    project: dict[str, Any],
    project_id: str,
    node: dict[str, Any],
    dyn: dict[str, Any] | None,
    cfg_text: str,
) -> tuple[bool, str]:
    """
    Fallback for local GNS3 server: write the startup config directly to disk.
    This only works when the GNS3 server runs on the same machine as this script.
    """
    candidates = possible_dynamips_config_files(project, project_id, node, dyn)

    # Prefer a path whose parent already exists.
    selected: Path | None = None
    for path in candidates:
        if path.parent.exists():
            selected = path
            break

    # Otherwise pick the most likely default and create parent directories.
    if selected is None and candidates:
        selected = candidates[0]

    if selected is None:
        return False, "No local filesystem candidate found"

    try:
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_text(cfg_text, encoding="utf-8")
        return True, f"local file: {selected}"
    except Exception as exc:
        return False, f"local filesystem write failed at {selected}: {exc}"


def upload_dynamips_config(
    client: GNS3Client,
    project: dict[str, Any],
    project_id: str,
    node: dict[str, Any],
    cfg_text: str,
) -> tuple[bool, str]:
    """
    Upload startup config to a Dynamips/c7200 router.
    """
    node_id = node["node_id"]

    dyn = get_dynamips_node(client, project_id, node_id)

    # Some GNS3 versions require node stopped for config update.
    was_started = node.get("status") == "started"
    if was_started:
        stop_node(client, project_id, node_id)
        time.sleep(1)

    ok, detail = upload_dynamips_via_compute_api(client, project_id, node_id, cfg_text)
    if ok:
        return True, detail

    ok2, detail2 = upload_dynamips_via_local_filesystem(project, project_id, node, dyn, cfg_text)
    if ok2:
        return True, f"{detail2} | after API issue: {detail}"

    return False, f"{detail} | {detail2}"


# ---------------------------------------------------------------------------
# Generic upload strategies
# ---------------------------------------------------------------------------

def upload_iou_config(client: GNS3Client, project_id: str, node: dict[str, Any], cfg_text: str) -> tuple[bool, str]:
    path = f"/v2/projects/{project_id}/nodes/{node['node_id']}/files/startup-config.cfg"
    status, resp = client.put_raw(path, cfg_text.encode("utf-8"), "text/plain")
    if status in (200, 201, 204):
        return True, "node file API"
    return False, f"IOU upload failed: HTTP {status}: {resp}"


def upload_generic_config(client: GNS3Client, project_id: str, node: dict[str, Any], cfg_text: str) -> tuple[bool, str]:
    # Kept as a fallback for non-Dynamips nodes.
    paths = [
        f"/v2/projects/{project_id}/nodes/{node['node_id']}/files/startup-config.cfg",
        f"/v2/projects/{project_id}/nodes/{node['node_id']}/files/configs/i1_startup-config.cfg",
    ]
    errors = []
    for path in paths:
        status, resp = client.put_raw(path, cfg_text.encode("utf-8"), "text/plain")
        if status in (200, 201, 204):
            return True, f"generic file API: {path}"
        errors.append(f"{path} -> HTTP {status}: {resp}")
    return False, " | ".join(errors)


def upload_startup_config(
    client: GNS3Client,
    project: dict[str, Any],
    project_id: str,
    node: dict[str, Any],
    cfg_text: str,
) -> tuple[bool, str]:
    node_type = node.get("node_type", "")

    if node_type == "dynamips":
        return upload_dynamips_config(client, project, project_id, node, cfg_text)

    if node_type == "iou":
        return upload_iou_config(client, project_id, node, cfg_text)

    return upload_generic_config(client, project_id, node, cfg_text)


# ---------------------------------------------------------------------------
# Main push workflow
# ---------------------------------------------------------------------------

def push_configs(
    host: str = "127.0.0.1",
    port: int = 3080,
    project_name: str = "",
    config_dir: str = "./output",
    start: bool = False,
    dry_run: bool = False,
    username: str | None = None,
    password: str | None = None,
) -> None:
    client = GNS3Client(host=host, port=port, username=username, password=password)

    print(f"→ Connecting to GNS3 at {client.base}")

    project = find_project(client, project_name)
    project_id = project["project_id"]
    print(f"✓ Project found: {project['name']}  (id={project_id})")

    nodes = list_nodes(client, project_id)
    node_map = {node["name"].upper(): node for node in nodes}
    print(f"✓ {len(nodes)} node(s) in project: {[node['name'] for node in nodes]}")

    configs = discover_configs(config_dir)
    if not configs:
        raise RuntimeError(f"No *_startup.cfg files found in {config_dir}")

    print(f"✓ {len(configs)} config file(s) discovered: {list(configs.keys())}")

    matched = 0
    failed = 0
    unmatched: list[str] = []

    for router_name, cfg_text in sorted(configs.items()):
        node = node_map.get(router_name.upper())
        if not node:
            unmatched.append(router_name)
            continue

        print(f"  → Uploading config for {router_name} ({node.get('node_type')}) ...", end=" ")

        if dry_run:
            print("[DRY RUN - matched]")
            matched += 1
            continue

        ok, detail = upload_startup_config(client, project, project_id, node, cfg_text)
        if ok:
            print(f"✓ ({detail})")
            matched += 1
        else:
            print(f"✗ FAILED")
            print(f"    {detail}")
            failed += 1

    if unmatched:
        print(f"\n[WARN] No matching GNS3 node for configs: {unmatched}")

    print(f"\n✓ {matched}/{len(configs)} configs pushed successfully.")
    if failed:
        print(f"✗ {failed} config(s) failed.")

    if start and matched > 0 and not dry_run:
        print("\n→ Starting matched nodes …")
        # Refresh nodes because some may have been stopped during upload.
        nodes = list_nodes(client, project_id)
        node_map = {node["name"].upper(): node for node in nodes}

        for router_name in sorted(configs):
            node = node_map.get(router_name.upper())
            if node:
                ok = start_node(client, project_id, node["node_id"])
                print(f"  {router_name}: {'✓ started' if ok else '✗ start failed'}")

        print("\nWaiting 3 s for nodes to boot …")
        time.sleep(3)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Push startup configs to a GNS3 project")
    parser.add_argument("--host", default="127.0.0.1", help="GNS3 server host")
    parser.add_argument("--port", type=int, default=3080, help="GNS3 server port")
    parser.add_argument("--username", default=None, help="GNS3 API username, if password protection is enabled")
    parser.add_argument("--password", default=None, help="GNS3 API password, if password protection is enabled")
    parser.add_argument("--project", required=True, help="GNS3 project name or UUID")
    parser.add_argument("--config-dir", default="./output", help="Directory containing *_startup.cfg files")
    parser.add_argument("--start", action="store_true", help="Start matched nodes after uploading configs")
    parser.add_argument("--dry-run", action="store_true", help="Match configs to nodes but do not upload")
    args = parser.parse_args()

    try:
        push_configs(
            host=args.host,
            port=args.port,
            project_name=args.project,
            config_dir=args.config_dir,
            start=args.start,
            dry_run=args.dry_run,
            username=args.username,
            password=args.password,
        )
    except Exception as exc:
        print(f"✗ {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
