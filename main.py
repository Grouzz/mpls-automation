import os
import sys
from pathlib import Path
import argparse
from utils import *
from addressing import *

class Network:
    def __init__(self, intent_path: str, output_dir: str = "./output"):
        self.intent_path = intent_path
        self.output_dir = output_dir
        self.intent_data = None
        self.inventory = None

    def run(self) -> None:
        try:
            self.load_and_validate()
            print("✓ Loading intent file: done")

            self.fill_addresses()
            print("✓ Filling IPv4 addresses: done")

            self.validate_filled_intent()
            print("✓ All interfaces have IPs + correct reciprocity: done")

            self.generate_configurations()
            print("✓ Configurations generated: done")

        except Exception as e:
            print(f"✗ Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    def load_and_validate(self):
        """Load and perform basic validation on intent file"""
        self.intent_data = load_intent(self.intent_path)
        self.inventory = basic_validation(self.intent_path)

    def fill_addresses(self):
        """Fill in all IP addresses for interfaces"""
        self.intent_data = fill_ipv4_intra_as(self.intent_data)
        self.intent_data = fill_ipv4_ebgp_links(self.intent_data)
        self.intent_data = fill_loopbacks(self.intent_data)

        filled_path = os.path.join(os.path.dirname(self.intent_path) or ".", "intent_filled.json")
        save_intent(self.intent_data, filled_path)

    def validate_filled_intent(self):
        """Validate that all interfaces have IP addresses"""
        filled_path = os.path.join(os.path.dirname(self.intent_path) or ".", "intent_filled.json")
        self.inventory = basic_validation(filled_path)

        for asn, as_obj in self.inventory.ases.items():
            for router_name, router_obj in as_obj.routers.items():
                for if_name, if_obj in router_obj.interfaces.items():
                    if not if_obj.ipv4:
                        raise ValueError(f"Missing IPv4 address: {router_name}:{if_name}")

    def generate_configurations(self):
        """Generate router configurations"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        filled_path = os.path.join(os.path.dirname(self.intent_path) or ".", "intent_filled.json")
        self.inventory = parse_info(filled_path)

        for asn, as_obj in self.inventory.ases.items():
            as_dir = os.path.join(self.output_dir, f"AS{asn}")
            Path(as_dir).mkdir(parents=True, exist_ok=True)

            # Generate IGP commands
            if as_obj.igp == "OSPF":
                igp_cmds = ospf_commands(self.inventory, asn)
            else:
                raise ValueError(f"Unsupported IGP: {as_obj.igp}")

            # Generate MPLS/LDP commands
            mpls_cmds = mpls_ldp_commands(self.inventory, asn)

            # Generate VRF commands
            vrf_cmds = vrf_commands(self.inventory, asn, self.intent_data)

            # Generate VPNv4 BGP commands
            vpnv4_bgp_cmds = vpnv4_bgp_commands(self.inventory, asn, self.intent_data)

            # Generate CE BGP commands
            ce_bgp_cmds = ce_bgp_commands(self.inventory, asn, self.intent_data)

            # Generate configs for each router
            for router_name in as_obj.routers.keys():
                config = self.build_router_config(
                    router_name=router_name,
                    asn=asn,
                    igp_lines=igp_cmds.get(router_name, []),
                    mpls_lines=mpls_cmds.get(router_name, []),
                    vrf_data=vrf_cmds.get(router_name, {}),
                    vpnv4_bgp_lines=vpnv4_bgp_cmds.get(router_name, []),
                    ce_bgp_lines=ce_bgp_cmds.get(router_name, [])
                )

                config_file = os.path.join(as_dir, f"{router_name}_startup.cfg")
                with open(config_file, "w", encoding="utf-8") as f:
                    f.write(config)

    def build_router_config(
        self,
        router_name: str,
        asn: int,
        igp_lines: list[str],
        mpls_lines: list[str],
        vrf_data: dict,
        vpnv4_bgp_lines: list[str],
        ce_bgp_lines: list[str]
    ):
        """Build complete router configuration"""
        lines: list[str] = []
        router_obj = self.inventory.ases[asn].routers[router_name]
        internal = internal_interfaces(self.inventory, asn)
        igp_type = self.inventory.ases[asn].igp
        as_obj = self.inventory.ases[asn]

        # Basic configuration
        lines += [
            "!",
            f"hostname {router_name}",
            "!",
            "no ip domain lookup",
            "ip cef",
            "!",
        ]

        # MPLS/LDP global config
        if mpls_lines:
            lines.extend(mpls_lines)
            lines.append("!")

        # VRF definitions
        if vrf_data.get("vrf_defs"):
            lines.extend(vrf_data["vrf_defs"])
            lines.append("!")

        # IGP configuration
        if igp_lines:
            lines.extend(igp_lines)
            lines.append("!")

        # Interface configuration
        # Sort interfaces: Loopback first, then others
        sorted_interfaces = sorted(
            router_obj.interfaces.items(),
            key=lambda x: (0 if "Loopback" in x[0] else 1, x[0]),
        )

        # Track which interfaces belong to VRFs
        vrf_interfaces = {}
        if vrf_data.get("interfaces"):
            for intf_config in vrf_data["interfaces"]:
                vrf_interfaces[intf_config["name"]] = intf_config["vrf"]

        for if_name, if_obj in sorted_interfaces:
            if not if_obj.ipv4:
                continue

            import ipaddress
            iface = ipaddress.ip_interface(if_obj.ipv4)
            ip_addr = str(iface.ip)
            netmask = str(iface.netmask)

            lines.append(f"interface {if_name}")
            
            # VRF assignment
            if if_name in vrf_interfaces:
                lines.append(f" vrf forwarding {vrf_interfaces[if_name]}")
            
            lines.append(f" ip address {ip_addr} {netmask}")

            # OSPF configuration on internal interfaces (non-VRF)
            if if_name not in vrf_interfaces:
                if igp_type == "OSPF" and if_name in internal.get(router_name, set()):
                    lines.append(f" ip ospf {asn} area 0")

                # MPLS/LDP on internal interfaces
                if as_obj.mpls_enabled and if_name in internal.get(router_name, set()):
                    if if_name != "Loopback0":  # Don't enable on loopback
                        lines.append(" mpls ip")
                        if as_obj.ldp_enabled:
                            lines.append(" mpls label protocol ldp")

            lines.append(" no shutdown")
            lines.append("!")

        # VPNv4 BGP configuration (PE routers)
        if vpnv4_bgp_lines:
            lines.extend(vpnv4_bgp_lines)
            
            # Add VRF BGP configuration
            if vrf_data.get("bgp"):
                lines.extend(vrf_data["bgp"])
            
            lines.append("!")

        # CE BGP configuration
        if ce_bgp_lines:
            lines.extend(ce_bgp_lines)
            lines.append("!")

        lines.append("end")
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="BGP/MPLS VPN Network Configuration Automation")
    parser.add_argument("intent_file", help="Path to the intent JSON file")
    parser.add_argument("-o", "--output", default="./output", help="Output directory for configs")
    args = parser.parse_args()
    
    generator = Network(args.intent_file, args.output)
    generator.run()
    
    print("\n✓ All configurations generated successfully!")
    print(f"✓ Output directory: {args.output}")


if __name__ == "__main__":
    main()
