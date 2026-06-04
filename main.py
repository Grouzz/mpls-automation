from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from addressing import (
    fill_ipv4_ebgp_links,
    fill_ipv4_intra_as,
    fill_loopbacks,
    load_intent,
    save_intent,
)
from utils import (
    basic_validation,
    ce_bgp_commands,
    internal_interfaces,
    mpls_ldp_commands,
    ospf_commands,
    parse_info,
    vrf_commands,
    vpnv4_bgp_commands,
)


class Network:
    def __init__(
        self,
        intent_path: str,
        output_dir: str = "./output",
        *,
        enable_phase4b: bool = False,
        phase4b_policy_path: str | None = None,
        provider_asn: int = 100,
    ) -> None:
        self.intent_path = intent_path
        self.output_dir = output_dir
        self.enable_phase4b = enable_phase4b
        self.phase4b_policy_path = phase4b_policy_path
        self.provider_asn = provider_asn

        self.intent_data: dict[str, Any] | None = None
        self.inventory = None
        self.filled_intent_path: str | None = None
        self.generated_files: list[str] = []
        self.warnings: list[str] = []
        self.phase4b_extra: dict[str, list[str]] = {}

    def run(self) -> None:
        self.load_and_validate()
        print("✓ Loading intent file: done")

        self.fill_addresses()
        print("✓ Filling IPv4 addresses: done")

        self.validate_filled_intent()
        print("✓ All interfaces have IPs + correct reciprocity: done")

        if self.enable_phase4b:
            self.prepare_phase4b()
            print("✓ Phase 4.b site-sharing prepared: done")
        else:
            print("✓ Phase 4.b: skipped (base-only mode)")

        self.generate_configurations()
        print("✓ Configurations generated: done")

        self.write_reports()
        print("✓ Validation report and runtime commands generated: done")

    def load_and_validate(self) -> None:
        """Load and perform basic validation on the source intent file."""
        self.intent_data = load_intent(self.intent_path)
        self.inventory = basic_validation(self.intent_path)

    def fill_addresses(self) -> None:
        """Fill every missing IPv4 address and save intent_filled.json beside the intent."""
        assert self.intent_data is not None
        self.intent_data = fill_ipv4_intra_as(self.intent_data)
        self.intent_data = fill_ipv4_ebgp_links(self.intent_data)
        self.intent_data = fill_loopbacks(self.intent_data)

        self.filled_intent_path = os.path.join(
            os.path.dirname(self.intent_path) or ".",
            "intent_filled.json",
        )
        save_intent(self.intent_data, self.filled_intent_path)

    def validate_filled_intent(self) -> None:
        """Validate that generated addressing is complete and neighbor links are reciprocal."""
        if not self.filled_intent_path:
            raise RuntimeError("Internal error: filled intent path was not created")

        self.inventory = basic_validation(self.filled_intent_path)

        seen_ips: dict[str, str] = {}
        for asn, as_obj in self.inventory.ases.items():
            for router_name, router_obj in as_obj.routers.items():
                for if_name, if_obj in router_obj.interfaces.items():
                    if not if_obj.ipv4:
                        raise ValueError(f"Missing IPv4 address: {router_name}:{if_name}")

                    ip_only = if_obj.ipv4.split("/")[0]
                    owner = f"AS{asn}:{router_name}:{if_name}"
                    if ip_only in seen_ips:
                        self.warnings.append(
                            f"Duplicate IP address {ip_only}: {seen_ips[ip_only]} and {owner}"
                        )
                    else:
                        seen_ips[ip_only] = owner


    def prepare_phase4b(self) -> None:
        """
        For distant sites VRFs (site sharing between customer VRFs : adding import & export target rules)
        """
        assert self.intent_data is not None
        assert self.filled_intent_path is not None
        self.inventory = parse_info(self.filled_intent_path)

        try:
            from phase4b import generate_phase4b
        except ImportError as exc:
            raise RuntimeError(
                "--phase4b was requested, but phase4b.py could not be imported. "
                "Keep phase4b.py in the same folder as main.py."
            ) from exc

        policy = self.load_phase4b_policy()
        sharing_policies = self.extract_sharing_policies(policy)
        default_shared_rt = self.extract_default_shared_rt(policy)

        if sharing_policies is None and self.provider_vrf_count(self.provider_asn) < 2:
            self.warnings.append(
                "Phase 4.b site-sharing requested, but fewer than 2 VRFs exist on "
                f"provider AS {self.provider_asn}; no site-sharing commands generated."
            )

        self.phase4b_extra = generate_phase4b(
            self.inventory,
            self.intent_data,
            asn=self.provider_asn,
            enable_site_sharing=True,
            sharing_policies=sharing_policies,
            default_shared_rt=default_shared_rt,
        )

        if self.enable_phase4b and not self.phase4b_extra:
            self.warnings.append("Phase 4.b produced no extra commands.")

    def load_phase4b_policy(self) -> dict[str, Any]:
        """
        Load optional Phase 4.b policy JSON.

        Accepted places:
          - a top-level "phase4b" block inside intent.json;
          - an external JSON file passed with --phase4b-policy.

        The external file overrides same-name keys from intent.json.
        """
        assert self.intent_data is not None
        policy: dict[str, Any] = {}

        intent_policy = self.intent_data.get("phase4b")
        if isinstance(intent_policy, dict):
            policy.update(intent_policy)

        if self.phase4b_policy_path:
            with open(self.phase4b_policy_path, "r", encoding="utf-8") as f:
                file_policy = json.load(f)
            if not isinstance(file_policy, dict):
                raise ValueError("Phase 4.b policy file must contain a JSON object")
            policy.update(file_policy)

        return policy

    def extract_sharing_policies(self, policy: dict[str, Any]) -> list[dict[str, Any]] | None:
        """
        Normalize supported site-sharing policy formats.

        Supported forms:
          {"sharing_policies": [...]}
          {"policies": [...]}
          {"site_sharing": {"policies": [...]}}
          {"site_sharing": {"vrfs": [...], "shared_rt": "100:400"}}

        If no policy is supplied, return None so phase4b.py uses its default:
        full-mesh sharing among all provider VRFs with RT <provider_asn>:400.
        """
        if not policy:
            return None

        sharing_policies = policy.get("sharing_policies")
        if isinstance(sharing_policies, list):
            return sharing_policies

        policies = policy.get("policies")
        if isinstance(policies, list):
            return policies

        site_sharing = policy.get("site_sharing") or policy.get("site-sharing")
        if isinstance(site_sharing, dict):
            nested_policies = site_sharing.get("policies")
            if isinstance(nested_policies, list):
                return nested_policies

            vrfs = site_sharing.get("vrfs")
            shared_rt = site_sharing.get("shared_rt") or site_sharing.get("route_target")
            pe_asn = site_sharing.get("pe_asn", site_sharing.get("asn", self.provider_asn))
            if isinstance(vrfs, list) and shared_rt:
                return [
                    {
                        "pe_asn": int(pe_asn),
                        "vrfs": [str(vrf) for vrf in vrfs],
                        "shared_rt": str(shared_rt),
                    }
                ]

        return None

    def extract_default_shared_rt(self, policy: dict[str, Any]) -> str | None:
        """Read an optional default shared route-target from the policy."""
        for key in ("default_shared_rt", "shared_rt", "route_target"):
            value = policy.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        site_sharing = policy.get("site_sharing") or policy.get("site-sharing")
        if isinstance(site_sharing, dict):
            for key in ("default_shared_rt", "shared_rt", "route_target"):
                value = site_sharing.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        return None

    def provider_vrf_count(self, provider_asn: int) -> int:
        """Return the number of VRFs declared in the provider AS."""
        assert self.intent_data is not None
        as_data = self.intent_data.get("AS", {}).get(str(provider_asn), {})
        vrfs = as_data.get("vrfs", {})
        return len(vrfs) if isinstance(vrfs, dict) else 0

    def generate_configurations(self) -> None:
        """Generate one startup config per router."""
        if not self.filled_intent_path:
            raise RuntimeError("Internal error: filled intent was not produced before config generation")
        assert self.intent_data is not None

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        self.inventory = parse_info(self.filled_intent_path)
        self.generated_files.clear()

        for asn, as_obj in self.inventory.ases.items():
            as_dir = os.path.join(self.output_dir, f"AS{asn}")
            Path(as_dir).mkdir(parents=True, exist_ok=True)

            if as_obj.igp == "OSPF":
                igp_cmds = ospf_commands(self.inventory, asn)
            else:
                raise ValueError(f"Unsupported IGP: {as_obj.igp}")

            mpls_cmds = mpls_ldp_commands(self.inventory, asn)
            vrf_cmds = vrf_commands(self.inventory, asn, self.intent_data)
            vpnv4_bgp_cmds = vpnv4_bgp_commands(self.inventory, asn, self.intent_data)
            ce_bgp_cmds = ce_bgp_commands(self.inventory, asn, self.intent_data)

            for router_name in as_obj.routers.keys():
                config = self.build_router_config(
                    router_name=router_name,
                    asn=asn,
                    igp_lines=igp_cmds.get(router_name, []),
                    mpls_lines=mpls_cmds.get(router_name, []),
                    vrf_data=vrf_cmds.get(router_name, {}),
                    vpnv4_bgp_lines=vpnv4_bgp_cmds.get(router_name, []),
                    ce_bgp_lines=ce_bgp_cmds.get(router_name, []),
                    phase4b_lines=self.phase4b_extra.get(router_name, []),
                )

                config_file = os.path.join(as_dir, f"{router_name}_startup.cfg")
                with open(config_file, "w", encoding="utf-8", newline="\n") as f:
                    f.write(config)
                self.generated_files.append(config_file)

    def build_router_config(
        self,
        router_name: str,
        asn: int,
        igp_lines: list[str],
        mpls_lines: list[str],
        vrf_data: dict[str, Any],
        vpnv4_bgp_lines: list[str],
        ce_bgp_lines: list[str],
        phase4b_lines: list[str] | None = None,
    ) -> str:
        """Build a complete IOS-like startup configuration for one router."""
        assert self.inventory is not None

        lines: list[str] = []
        router_obj = self.inventory.ases[asn].routers[router_name]
        internal = internal_interfaces(self.inventory, asn)
        igp_type = self.inventory.ases[asn].igp
        as_obj = self.inventory.ases[asn]

        lines += [
            "!",
            f"hostname {router_name}",
            "!",
            "no ip domain lookup",
            "ip cef",
            "!",
        ]

        if mpls_lines:
            lines.extend(mpls_lines)
            lines.append("!")

        if vrf_data.get("vrf_defs"):
            lines.extend(vrf_data["vrf_defs"])
            lines.append("!")

        if igp_lines:
            lines.extend(igp_lines)
            lines.append("!")

        sorted_interfaces = sorted(
            router_obj.interfaces.items(),
            key=lambda x: (0 if "Loopback" in x[0] else 1, x[0]),
        )

        vrf_interfaces: dict[str, str] = {}
        if vrf_data.get("interfaces"):
            for intf_config in vrf_data["interfaces"]:
                vrf_interfaces[intf_config["name"]] = intf_config["vrf"]

        import ipaddress

        for if_name, if_obj in sorted_interfaces:
            if not if_obj.ipv4:
                continue

            iface = ipaddress.ip_interface(if_obj.ipv4)
            ip_addr = str(iface.ip)
            netmask = str(iface.netmask)

            lines.append(f"interface {if_name}")

            if if_name in vrf_interfaces:
                lines.append(f" vrf forwarding {vrf_interfaces[if_name]}")

            lines.append(f" ip address {ip_addr} {netmask}")

            if if_name not in vrf_interfaces:
                if igp_type == "OSPF" and if_name in internal.get(router_name, set()):
                    lines.append(f" ip ospf {asn} area 0")

                if as_obj.mpls_enabled and if_name in internal.get(router_name, set()):
                    if if_name != "Loopback0":
                        lines.append(" mpls ip")
                        if as_obj.ldp_enabled:
                            lines.append(" mpls label protocol ldp")

            lines.append(" no shutdown")
            lines.append("!")

        if vpnv4_bgp_lines:
            lines.extend(vpnv4_bgp_lines)
            if vrf_data.get("bgp"):
                lines.extend(vrf_data["bgp"])
            lines.append("!")

        if ce_bgp_lines:
            lines.extend(ce_bgp_lines)
            lines.append("!")

        if phase4b_lines:
            lines.extend(["!", "! ===== Phase 4.b site-sharing via route-targets ====="])
            lines.extend(phase4b_lines)
            lines.append("!")

        lines.append("end")
        return "\n".join(lines) + "\n"

    def write_reports(self) -> None:
        """Write human-readable validation and runtime command reports."""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        self.write_validation_report()
        self.write_runtime_commands()

    def write_validation_report(self) -> None:
        assert self.inventory is not None
        path = os.path.join(self.output_dir, "validation_report.md")
        lines: list[str] = [
            "# Validation report",
            "",
            f"Intent file: `{self.intent_path}`",
            f"Filled intent: `{self.filled_intent_path}`",
            f"Output directory: `{self.output_dir}`",
            f"Phase 4.b site-sharing: {'enabled' if self.enable_phase4b else 'disabled'}",
            "",
            "## Generated files",
            "",
        ]
        for file_path in sorted(self.generated_files):
            lines.append(f"- `{os.path.relpath(file_path, self.output_dir)}`")

        lines += ["", "## Topology", ""]
        for asn, as_obj in sorted(self.inventory.ases.items()):
            lines.append(f"### AS {asn}")
            lines.append("")
            for router_name, router_obj in sorted(as_obj.routers.items()):
                lines.append(f"- `{router_name}` role=`{router_obj.role}`")
                for if_name, if_obj in sorted(router_obj.interfaces.items()):
                    ngbr = if_obj.ngbr or "-"
                    lines.append(f"  - `{if_name}` `{if_obj.ipv4}` neighbor=`{ngbr}`")
            lines.append("")

        lines += ["## Warnings", ""]
        if self.warnings:
            for warning in self.warnings:
                lines.append(f"- {warning}")
        else:
            lines.append("- None")

        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def write_runtime_commands(self) -> None:
        path = os.path.join(self.output_dir, "runtime_commands.md")
        lines = [
            "# Runtime verification commands",
            "",
            "Run these after importing/pushing the startup configs in GNS3.",
            "",
            "## Basic router checks",
            "",
            "```text",
            "show ip interface brief",
            "show running-config | section ^interface|^router|^vrf|^mpls",
            "show ip route",
            "```",
            "",
            "## Provider core checks",
            "",
            "```text",
            "show ip ospf neighbor",
            "show mpls ldp neighbor",
            "show mpls forwarding-table",
            "show bgp vpnv4 unicast all summary",
            "show bgp vpnv4 unicast all",
            "```",
            "",
            "## VRF checks on PE routers",
            "",
            "```text",
            "show vrf",
            "show ip route vrf CUSTOMER_102",
            "show ip route vrf CUSTOMER_103",
            "show ip bgp vpnv4 vrf CUSTOMER_102",
            "show ip bgp vpnv4 vrf CUSTOMER_103",
            "```",
            "",
            "## CE checks",
            "",
            "```text",
            "show ip bgp summary",
            "show ip bgp",
            "show ip route bgp",
            "ping <remote-customer-ip> source <local-stub-interface-ip>",
            "```",
            "",
            "## Phase 4.b site-sharing checks, only if enabled",
            "",
            "```text",
            "show running-config | section ^vrf definition",
            "show ip bgp vpnv4 all route-target",
            "show ip bgp vpnv4 all",
            "show ip route vrf CUSTOMER_102",
            "show ip route vrf CUSTOMER_103",
            "```",
        ]
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")


def run_gns3_push(args: argparse.Namespace, output_dir: str) -> None:
    if not args.gns3_project:
        raise ValueError("--push-to-gns3/--drag-drop-bot requires --gns3-project <name-or-id>")

    try:
        from gns3_push import push_configs
    except ImportError as exc:
        raise RuntimeError(
            "GNS3 push was requested, but gns3_push.py could not be imported. "
            "Keep gns3_push.py in the same folder as main.py."
        ) from exc

    push_configs(
        host=args.gns3_host,
        port=args.gns3_port,
        project_name=args.gns3_project,
        config_dir=output_dir,
        start=args.gns3_start,
        dry_run=args.gns3_dry_run,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate BGP/MPLS VPN startup configs and optionally push them to GNS3."
    )
    parser.add_argument("intent_file", help="Path to the intent JSON file")
    parser.add_argument("-o", "--output", default="./output", help="Output directory for configs")

    phase = parser.add_argument_group("Phase 4.b options")
    phase.add_argument(
        "--phase4b",
        action="store_true",
        help="Enable Phase 4.b site-sharing via route-targets. Default is base-only mode.",
    )
    phase.add_argument(
        "--phase4b-policy",
        help=(
            "Optional JSON policy file for site-sharing. Supported keys: "
            "sharing_policies, policies, or site_sharing."
        ),
    )
    phase.add_argument(
        "--provider-asn",
        type=int,
        default=100,
        help="Provider AS used for Phase 4.b site-sharing (default: 100)",
    )

    gns3 = parser.add_argument_group("GNS3 push / drag-drop bot options")
    gns3.add_argument(
        "--push-to-gns3",
        action="store_true",
        help="After generation, push configs to a running GNS3 project using gns3_push.py.",
    )
    gns3.add_argument(
        "--drag-drop-bot",
        action="store_true",
        help="Alias for --push-to-gns3. Uses the project helper instead of manual drag-and-drop.",
    )
    gns3.add_argument("--gns3-host", default="127.0.0.1", help="GNS3 server host")
    gns3.add_argument("--gns3-port", type=int, default=3080, help="GNS3 server port")
    gns3.add_argument("--gns3-project", help="GNS3 project name or UUID")
    gns3.add_argument("--gns3-start", action="store_true", help="Start matched GNS3 nodes after pushing")
    gns3.add_argument("--gns3-dry-run", action="store_true", help="Match configs to nodes without uploading")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        generator = Network(
            args.intent_file,
            args.output,
            enable_phase4b=args.phase4b,
            phase4b_policy_path=args.phase4b_policy,
            provider_asn=args.provider_asn,
        )
        generator.run()

        print("\n✓ All configurations generated successfully!")
        print(f"✓ Output directory: {args.output}")
        print(f"✓ Validation report: {os.path.join(args.output, 'validation_report.md')}")
        print(f"✓ Runtime commands: {os.path.join(args.output, 'runtime_commands.md')}")

        if args.push_to_gns3 or args.drag_drop_bot:
            print("\n→ GNS3 push mode selected")
            run_gns3_push(args, args.output)

    except Exception as exc:
        print(f"✗ Error: {exc}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
