from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Validation and helpers
# ---------------------------------------------------------------------------

def _as_key(intent_data: dict[str, Any], asn: int | str) -> str:
    key = str(asn)
    if "AS" not in intent_data or not isinstance(intent_data["AS"], dict):
        raise ValueError("Invalid intent data: missing top-level 'AS' dictionary")
    if key not in intent_data["AS"]:
        raise ValueError(f"Provider AS {key} not found in intent data")
    return key


def _provider_vrfs(intent_data: dict[str, Any], asn: int | str) -> dict[str, Any]:
    key = _as_key(intent_data, asn)
    vrfs = intent_data["AS"][key].get("vrfs", {})
    if not isinstance(vrfs, dict):
        raise ValueError(f"AS {key} has invalid 'vrfs' field; expected a dictionary")
    return vrfs


def _vrf_pe_routers(intent_data: dict[str, Any], asn: int | str, vrf_name: str) -> list[str]:
    vrfs = _provider_vrfs(intent_data, asn)
    if vrf_name not in vrfs:
        raise ValueError(f"VRF {vrf_name!r} not found in provider AS {asn}")

    pe_routers = vrfs[vrf_name].get("pe_routers", {})
    if not isinstance(pe_routers, dict) or not pe_routers:
        raise ValueError(f"VRF {vrf_name!r} has no PE routers")

    return sorted(pe_routers.keys())


def _existing_rts(intent_data: dict[str, Any], asn: int | str, vrf_name: str, direction: str) -> set[str]:
    vrfs = _provider_vrfs(intent_data, asn)
    if vrf_name not in vrfs:
        return set()

    route_targets = vrfs[vrf_name].get("route_targets", {})
    values = route_targets.get(direction, [])
    if isinstance(values, str):
        return {values}
    if isinstance(values, list):
        return {str(v) for v in values}
    return set()


def _add_rt(
    changes: dict[str, dict[str, dict[str, set[str]]]],
    *,
    pe_router: str,
    vrf_name: str,
    direction: str,
    rt: str,
) -> None:
    if direction not in {"import", "export"}:
        raise ValueError(f"Invalid route-target direction {direction!r}")

    changes.setdefault(pe_router, {})
    changes[pe_router].setdefault(vrf_name, {"import": set(), "export": set()})
    changes[pe_router][vrf_name][direction].add(str(rt))


def _policy_asn(policy: dict[str, Any], default_asn: int | str) -> str:
    return str(policy.get("pe_asn", policy.get("asn", default_asn)))


def _normalise_policy_list(
    intent_data: dict[str, Any],
    asn: int | str,
    sharing_policies: list[dict[str, Any]] | None,
    default_shared_rt: str | None,
) -> list[dict[str, Any]]:
    """
    Return explicit policy dictionaries.

    If sharing_policies is empty/None, create one full-mesh policy over all VRFs
    in the provider AS.
    """
    provider_asn = str(asn)

    if sharing_policies:
        return sharing_policies

    vrfs = sorted(_provider_vrfs(intent_data, provider_asn).keys())
    if len(vrfs) < 2:
        return []

    shared_rt = default_shared_rt or f"{provider_asn}:400"

    return [
        {
            "pe_asn": int(provider_asn),
            "vrfs": vrfs,
            "shared_rt": shared_rt,
            "mode": "full_mesh",
        }
    ]


# ---------------------------------------------------------------------------
# Core site-sharing generator
# ---------------------------------------------------------------------------

def site_sharing_commands(
    intent_data: dict[str, Any],
    sharing_policies: list[dict[str, Any]] | None = None,
    *,
    asn: int | str = 100,
    default_shared_rt: str | None = None,
) -> dict[str, list[str]]:
    """
    Generate per-router IOS commands for VRF site sharing via route-targets.

    Supported policy styles:

    A) Full mesh:
        {"pe_asn": 100, "vrfs": ["CUSTOMER_102", "CUSTOMER_103"], "shared_rt": "100:400"}

       Effect:
        Each VRF imports and exports the shared RT.

    B) Pair policy:
        {"pe_asn": 100, "from_vrf": "CUSTOMER_102", "to_vrf": "CUSTOMER_103",
         "shared_rt": "100:401", "bidirectional": true}

       Effect if bidirectional=false:
        from_vrf exports shared_rt, to_vrf imports shared_rt.

       Effect if bidirectional=true:
        both VRFs import and export shared_rt.
    """
    policies = _normalise_policy_list(
        intent_data=intent_data,
        asn=asn,
        sharing_policies=sharing_policies,
        default_shared_rt=default_shared_rt,
    )

    changes: dict[str, dict[str, dict[str, set[str]]]] = {}

    for policy in policies:
        pe_asn = _policy_asn(policy, asn)
        shared_rt = str(policy.get("shared_rt") or default_shared_rt or f"{pe_asn}:400")

        # Style A: full-mesh VRF group. Every listed VRF imports and exports same RT.
        if "vrfs" in policy:
            vrf_names = [str(v) for v in policy["vrfs"]]
            if len(vrf_names) < 2:
                raise ValueError(f"Site-sharing full-mesh policy needs at least 2 VRFs: {policy}")

            for vrf_name in vrf_names:
                pe_routers = _vrf_pe_routers(intent_data, pe_asn, vrf_name)
                existing_imports = _existing_rts(intent_data, pe_asn, vrf_name, "import")
                existing_exports = _existing_rts(intent_data, pe_asn, vrf_name, "export")

                for pe_router in pe_routers:
                    if shared_rt not in existing_imports:
                        _add_rt(changes, pe_router=pe_router, vrf_name=vrf_name, direction="import", rt=shared_rt)
                    if shared_rt not in existing_exports:
                        _add_rt(changes, pe_router=pe_router, vrf_name=vrf_name, direction="export", rt=shared_rt)

            continue

        # Style B: explicit from_vrf -> to_vrf.
        from_vrf = str(policy.get("from_vrf", ""))
        to_vrf = str(policy.get("to_vrf", ""))

        if not from_vrf or not to_vrf:
            raise ValueError(
                "Invalid site-sharing policy. Expected either 'vrfs' or both "
                f"'from_vrf'/'to_vrf'. Got: {policy}"
            )

        bidirectional = bool(policy.get("bidirectional", False))

        # Validate both VRFs exist before generating partial commands.
        from_pes = _vrf_pe_routers(intent_data, pe_asn, from_vrf)
        to_pes = _vrf_pe_routers(intent_data, pe_asn, to_vrf)

        from_existing_exports = _existing_rts(intent_data, pe_asn, from_vrf, "export")
        from_existing_imports = _existing_rts(intent_data, pe_asn, from_vrf, "import")
        to_existing_exports = _existing_rts(intent_data, pe_asn, to_vrf, "export")
        to_existing_imports = _existing_rts(intent_data, pe_asn, to_vrf, "import")

        # from_vrf exports; to_vrf imports.
        for pe_router in from_pes:
            if shared_rt not in from_existing_exports:
                _add_rt(changes, pe_router=pe_router, vrf_name=from_vrf, direction="export", rt=shared_rt)

        for pe_router in to_pes:
            if shared_rt not in to_existing_imports:
                _add_rt(changes, pe_router=pe_router, vrf_name=to_vrf, direction="import", rt=shared_rt)

        # Optional reverse direction.
        if bidirectional:
            for pe_router in to_pes:
                if shared_rt not in to_existing_exports:
                    _add_rt(changes, pe_router=pe_router, vrf_name=to_vrf, direction="export", rt=shared_rt)

            for pe_router in from_pes:
                if shared_rt not in from_existing_imports:
                    _add_rt(changes, pe_router=pe_router, vrf_name=from_vrf, direction="import", rt=shared_rt)

    return _render_changes(changes)


def _render_changes(changes: dict[str, dict[str, dict[str, set[str]]]]) -> dict[str, list[str]]:
    """
    Convert the internal change model into IOS config lines per PE router.
    """
    rendered: dict[str, list[str]] = {}

    for pe_router in sorted(changes):
        lines: list[str] = [
            "!",
            "! Phase 4.b - Site sharing via route-targets only",
        ]

        for vrf_name in sorted(changes[pe_router]):
            directions = changes[pe_router][vrf_name]
            imports = sorted(directions.get("import", set()))
            exports = sorted(directions.get("export", set()))

            if not imports and not exports:
                continue

            lines.extend(
                [
                    f"vrf definition {vrf_name}",
                    " address-family ipv4",
                ]
            )

            for rt in imports:
                lines.append(f"  route-target import {rt}")

            for rt in exports:
                lines.append(f"  route-target export {rt}")

            lines.append(" exit-address-family")
            lines.append("!")

        # Avoid returning a router with only the banner and no actual config.
        if any(line.startswith("vrf definition ") for line in lines):
            rendered[pe_router] = lines

    return rendered


# ---------------------------------------------------------------------------
# Compatibility entry point expected by main.py
# ---------------------------------------------------------------------------

def generate_phase4b(
    inv: Any,
    intent_data: dict[str, Any],
    asn: int = 100,
    *,
    enable_site_sharing: bool = False,
    sharing_policies: list[dict[str, Any]] | None = None,
    # The following arguments are kept only for compatibility with existing main.py.
    # They are intentionally ignored because this Phase 4.b file implements site
    # sharing only.
    enable_internet_vrf: bool = False,
    internet_rd: str = "100:999",
    internet_rt: str = "100:999",
    enable_ingress_te: bool = False,
    te_policies: list[dict[str, Any]] | None = None,
    enable_rsvp_te: bool = False,
    rsvp_tunnels: list[dict[str, Any]] | None = None,
    rsvp_bandwidth_mbps: int = 1000,
    default_shared_rt: str | None = None,
) -> dict[str, list[str]]:
    """
    Main Phase 4.b aggregator.

    This version intentionally returns config only for site-sharing.
    Non-site-sharing flags are ignored.
    """
    if not enable_site_sharing:
        return {}

    return site_sharing_commands(
        intent_data=intent_data,
        sharing_policies=sharing_policies,
        asn=asn,
        default_shared_rt=default_shared_rt,
    )


# ---------------------------------------------------------------------------
# Optional standalone preview CLI
# ---------------------------------------------------------------------------

def _load_policy_file(path: str | None) -> list[dict[str, Any]] | None:
    if not path:
        return None

    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Accept either {"site_sharing": {"policies": [...]}} or {"policies": [...]}.
        if "site_sharing" in data and isinstance(data["site_sharing"], dict):
            policies = data["site_sharing"].get("policies")
            if isinstance(policies, list):
                return policies

            vrfs = data["site_sharing"].get("vrfs")
            shared_rt = data["site_sharing"].get("shared_rt")
            pe_asn = data["site_sharing"].get("pe_asn", data["site_sharing"].get("asn", 100))
            if isinstance(vrfs, list) and shared_rt:
                return [{"pe_asn": pe_asn, "vrfs": vrfs, "shared_rt": shared_rt}]

        if "policies" in data and isinstance(data["policies"], list):
            return data["policies"]

    raise ValueError(f"Unsupported policy file format: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Preview Phase 4.b site-sharing route-target commands."
    )
    parser.add_argument("intent_file", help="Path to intent.json or intent_filled.json")
    parser.add_argument("--asn", type=int, default=100, help="Provider AS number. Default: 100")
    parser.add_argument("--policy", default=None, help="Optional JSON policy file")
    parser.add_argument("--shared-rt", default=None, help="Default shared RT. Default: <asn>:400")
    args = parser.parse_args()

    intent_data = json.loads(Path(args.intent_file).read_text(encoding="utf-8"))
    policies = _load_policy_file(args.policy)

    commands = generate_phase4b(
        inv=None,
        intent_data=intent_data,
        asn=args.asn,
        enable_site_sharing=True,
        sharing_policies=policies,
        default_shared_rt=args.shared_rt,
    )

    print(json.dumps(commands, indent=2))


if __name__ == "__main__":
    main()
