from dataclasses import dataclass
import json
import re
import ipaddress

SUPPORTED_IGP = {"OSPF"}

@dataclass
class Interface:
    ipv4: str
    ngbr: str
    relationship: str = ""

@dataclass
class Router:
    name: str
    role: str
    interfaces: dict[str, Interface]

@dataclass
class AS:
    asn: int
    igp: str
    routers: dict[str, Router]
    mpls_enabled: bool = False
    ldp_enabled: bool = False
    is_customer: bool = False

@dataclass
class Inventory:
    ases: dict[int, AS]
    router_to_as: dict[str, int]

def load_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def router_number(router_name: str) -> int:
    """Extract numeric part from router name (e.g., 'R3' -> 3)"""
    m = re.match(r"^[Rr](\d+)$", router_name.strip())
    if not m:
        return 1
    return int(m.group(1))

def router_id_v4(router_name: str, base: str = "10.10.10."):
    """Generate a router ID from router name"""
    n = router_number(router_name)
    last = max(1, min(254, n))
    return f"{base}{last}"

def parse_info(path: str):
    """Parse intent file and build inventory"""
    data = load_file(path)

    if not isinstance(data, dict) or "AS" not in data:
        raise ValueError("No AS information in the json file")

    as_raw = data["AS"]
    if not isinstance(as_raw, dict) or not as_raw:
        raise ValueError("Empty AS set")

    ases: dict[int, AS] = {}
    router_to_as: dict[str, int] = {}

    for asn_str, as_body in as_raw.items():
        as_number = int(asn_str)
        if as_number in ases:
            raise ValueError(f"AS {as_number} appears multiple times")

        igp = str(as_body.get("igp", "")).upper().strip()
        if igp not in SUPPORTED_IGP:
            raise ValueError(f"{igp} not supported, choose from {SUPPORTED_IGP}")

        # Parse MPLS configuration
        mpls_config = as_body.get("mpls", {})
        mpls_enabled = mpls_config.get("enabled", False)
        ldp_enabled = mpls_config.get("ldp", False)
        is_customer = as_body.get("customer", False)

        routers_raw = as_body.get("routers")
        if not routers_raw or not isinstance(routers_raw, dict):
            raise ValueError(f"AS {as_number} has no routers")

        routers: dict[str, Router] = {}

        for router_name, router_body in routers_raw.items():
            if router_name in router_to_as:
                raise ValueError(f"Router {router_name} appears in multiple ASes")

            role = router_body.get("role", "")
            int_raw = router_body.get("interfaces")
            if not isinstance(int_raw, dict) or not int_raw:
                raise ValueError(f"{router_name} has no interfaces")

            interfaces: dict[str, Interface] = {}
            for int_name, int_body in int_raw.items():
                ipv4 = str(int_body.get("ipv4", "")).strip()
                ngbr = str(int_body.get("ngbr", "")).strip()
                relationship = str(int_body.get("relationship", "")).strip()
                interfaces[int_name] = Interface(ipv4=ipv4, ngbr=ngbr, relationship=relationship)

            routers[router_name] = Router(name=router_name, role=role, interfaces=interfaces)
            router_to_as[router_name] = as_number

        ases[as_number] = AS(
            asn=as_number, 
            igp=igp, 
            routers=routers,
            mpls_enabled=mpls_enabled,
            ldp_enabled=ldp_enabled,
            is_customer=is_customer
        )

    return Inventory(ases=ases, router_to_as=router_to_as)

def basic_validation(path: str):
    """Validate intent file for consistency"""
    inventory = parse_info(path)
    
    # Check neighbor existence
    for _, as_body in inventory.ases.items():
        for router_name, router_body in as_body.routers.items():
            for interface_name, interface_body in router_body.interfaces.items():
                if interface_body.ngbr and interface_body.ngbr not in inventory.router_to_as:
                    raise ValueError(f"{router_name}:{interface_name} neighbor {interface_body.ngbr!r} not found")
    
    # Check reciprocity
    for _, as_body in inventory.ases.items():
        for router_name, router_body in as_body.routers.items():
            for interface_name, interface_body in router_body.interfaces.items():
                neighbor = interface_body.ngbr
                if not neighbor:
                    continue

                nasn = inventory.router_to_as[neighbor]
                nrouter = inventory.ases[nasn].routers[neighbor]

                matches = 0
                for _, n_if_body in nrouter.interfaces.items():
                    if n_if_body.ngbr == router_name:
                        matches += 1

                if matches == 0:
                    raise ValueError(f"Link not reciprocal: {router_name}:{interface_name} -> {neighbor}")
                if matches > 1:
                    raise ValueError(f"Multiple interfaces on {neighbor} pointing to {router_name}")
    
    return inventory

def internal_interfaces(inv: Inventory, asn: int):
    """Get internal interfaces (loopbacks and intra-AS links)"""
    as_obj = inv.ases[asn]
    internal: dict[str, set[str]] = {router_name: set() for router_name in as_obj.routers.keys()}

    for router_name, router_body in as_obj.routers.items():
        for interface_name, interface_body in router_body.interfaces.items():
            if interface_name == "Loopback0":
                internal[router_name].add(interface_name)
                continue

            neighbor = interface_body.ngbr
            if neighbor and neighbor in inv.router_to_as and inv.router_to_as[neighbor] == asn:
                internal[router_name].add(interface_name)

    return internal

def ospf_commands(inv: Inventory, asn: int):
    """Generate OSPF configuration commands"""
    as_obj = inv.ases[asn]
    out: dict[str, list[str]] = {}
    internal = internal_interfaces(inv, asn)

    for router_name, router_body in as_obj.routers.items():
        rid = router_id_v4(router_name)
        lines = [f"router ospf {asn}", f" router-id {rid}"]
        
        for if_name in internal.get(router_name, set()):
            if_obj = router_body.interfaces.get(if_name)
            if if_obj and if_obj.ipv4 and "/" in if_obj.ipv4:
                iface = ipaddress.ip_interface(if_obj.ipv4)
                wildcard = ipaddress.ip_address(int(iface.network.hostmask))
                lines.append(f" network {iface.network.network_address} {wildcard} area 0")
        
        out[router_name] = lines

    return out

def loopback(inv: Inventory, asn: int):
    """Get loopback addresses for all routers in an AS"""
    as_obj = inv.ases[asn]
    loop: dict[str, str] = {}
    
    for router_name, router_body in as_obj.routers.items():
        if "Loopback0" not in router_body.interfaces:
            continue
        ipv4_addr = router_body.interfaces["Loopback0"].ipv4
        if "/" in ipv4_addr:
            ipv4_addr = ipv4_addr.split("/")[0]
        loop[router_name] = ipv4_addr
    
    return loop

def mpls_ldp_commands(inv: Inventory, asn: int):
    """Generate MPLS and LDP configuration commands"""
    as_obj = inv.ases[asn]
    
    if not as_obj.mpls_enabled:
        return {}
    
    out: dict[str, list[str]] = {}
    internal = internal_interfaces(inv, asn)
    loopbacks = loopback(inv, asn)

    for router_name, router_body in as_obj.routers.items():
        lines = []
        
        if as_obj.ldp_enabled:
            # MPLS LDP router-id
            if router_name in loopbacks:
                lines.append("mpls ldp router-id Loopback0 force")
        
        out[router_name] = lines

    return out

def vpnv4_bgp_commands(inv: Inventory, asn: int, intent_data: dict):
    """Generate VPNv4 BGP configuration for PE routers"""
    as_obj = inv.ases[asn]
    
    if not as_obj.mpls_enabled:
        return {}
    
    out: dict[str, list[str]] = {}
    loopbacks = loopback(inv, asn)
    
    #finding all PE routers
    pe_routers = [r for r, robj in as_obj.routers.items() if robj.role == "PE"]
    
    if not pe_routers:
        return {}
    
    for router_name in pe_routers:
        lines = []
        rid_oct = router_number(router_name)
        rid = f"{rid_oct}.{rid_oct}.{rid_oct}.{rid_oct}"
        
        lines.append(f"router bgp {asn}")
        lines.append(f" bgp router-id {rid}")
        lines.append(" bgp log-neighbor-changes")
        lines.append(" no bgp default ipv4-unicast")
        
        # VPNv4 address family with other PE routers
        lines.append(" address-family vpnv4")
        
        for peer_router in pe_routers:
            if peer_router != router_name and peer_router in loopbacks:
                peer_lo = loopbacks[peer_router]
                lines.append(f"  neighbor {peer_lo} remote-as {asn}")
                lines.append(f"  neighbor {peer_lo} update-source Loopback0")
                lines.append(f"  neighbor {peer_lo} activate")
                lines.append(f"  neighbor {peer_lo} send-community both")
        
        lines.append(" exit-address-family")
        
        out[router_name] = lines
    
    return out

def vrf_commands(inv: Inventory, asn: int, intent_data: dict):
    as_obj = inv.ases[asn]
    as_data = intent_data["AS"][str(asn)]
    vrfs_config = as_data.get("vrfs", {})
    
    if not vrfs_config:
        return {}
    
    out: dict[str, dict] = {}
    
    for vrf_name, vrf_data in vrfs_config.items():
        rd = vrf_data.get("rd", f"{asn}:1")
        rt_import = vrf_data.get("route_targets", {}).get("import", [])
        rt_export = vrf_data.get("route_targets", {}).get("export", [])
        
        pe_routers_config = vrf_data.get("pe_routers", {})
        
        for pe_router, pe_config in pe_routers_config.items():
            if pe_router not in as_obj.routers:
                continue
            
            if pe_router not in out:
                out[pe_router] = {"vrf_defs": [], "interfaces": [], "bgp": []}
            
            #VRF def
            vrf_def_lines = [
                f"vrf definition {vrf_name}",
                f" rd {rd}",
                " address-family ipv4"
            ]
            
            for rt in rt_import:
                vrf_def_lines.append(f"  route-target import {rt}")
            for rt in rt_export:
                vrf_def_lines.append(f"  route-target export {rt}")
            
            vrf_def_lines.append(" exit-address-family")
            
            out[pe_router]["vrf_defs"].extend(vrf_def_lines)
            
            # Interface assignment
            interfaces_to_vrf = pe_config.get("interfaces", [])
            for intf in interfaces_to_vrf:
                out[pe_router]["interfaces"].append({
                    "name": intf,
                    "vrf": vrf_name
                })
            
            #PE-CE BGP configuration
            ce_peers = pe_config.get("ce_peers", {})
            if ce_peers:
                bgp_vrf_lines = []
                
                for ce_name, ce_config in ce_peers.items():
                    ce_asn = ce_config.get("ce_asn")
                    ce_interface = ce_config.get("interface")
                    
                    if not ce_asn or not ce_interface:
                        continue
                    
                    # Get CE IP address
                    ce_router_asn = inv.router_to_as.get(ce_name)
                    if not ce_router_asn:
                        continue
                    
                    ce_router = inv.ases[ce_router_asn].routers.get(ce_name)
                    if not ce_router:
                        continue
                    
                    # Find the interface on CE that connects to this PE
                    ce_ip = None
                    for ce_if_name, ce_if_obj in ce_router.interfaces.items():
                        if ce_if_obj.ngbr == pe_router:
                            ce_ip = ce_if_obj.ipv4
                            if "/" in ce_ip:
                                ce_ip = ce_ip.split("/")[0]
                            break
                    
                    if not ce_ip:
                        continue
                    
                    bgp_vrf_lines.extend([
                        f" address-family ipv4 vrf {vrf_name}",
                        f"  neighbor {ce_ip} remote-as {ce_asn}",
                        f"  neighbor {ce_ip} activate",
                        " exit-address-family"
                    ])
                
                out[pe_router]["bgp"].extend(bgp_vrf_lines)
    
    return out

def ce_bgp_commands(inv: Inventory, asn: int, intent_data: dict):
    """Generate BGP commands for CE routers"""
    as_obj = inv.ases[asn]
    
    if not as_obj.is_customer:
        return {}
    
    out: dict[str, list[str]] = {}
    
    for router_name, router_body in as_obj.routers.items():
        if router_body.role != "CE":
            continue
        
        lines = []
        rid_oct = router_number(router_name)
        rid = f"{rid_oct}.{rid_oct}.{rid_oct}.{rid_oct}"
        
        lines.append(f"router bgp {asn}")
        lines.append(f" bgp router-id {rid}")
        lines.append(" bgp log-neighbor-changes")
        lines.append(" no bgp default ipv4-unicast")
        
        # Find PE neighbors
        lines.append(" address-family ipv4")
        
        for if_name, if_obj in router_body.interfaces.items():
            if if_name.startswith("Loopback"):
                continue
            
            neighbor = if_obj.ngbr
            if not neighbor:
                continue
            
            neighbor_asn = inv.router_to_as.get(neighbor)
            if not neighbor_asn or neighbor_asn == asn:
                continue
            
            # Get PE IP
            pe_router = inv.ases[neighbor_asn].routers.get(neighbor)
            if not pe_router:
                continue
            
            for pe_if_name, pe_if_obj in pe_router.interfaces.items():
                if pe_if_obj.ngbr == router_name:
                    pe_ip = pe_if_obj.ipv4
                    if "/" in pe_ip:
                        pe_ip = pe_ip.split("/")[0]
                    
                    lines.append(f"  neighbor {pe_ip} remote-as {neighbor_asn}")
                    lines.append(f"  neighbor {pe_ip} activate")
                    break
        
        # Advertise local networks
        for if_name, if_obj in router_body.interfaces.items():
            if if_name.startswith("Loopback"):
                continue
            if if_obj.ngbr:  # Skip PE-CE links
                continue
            
            # This is a local network interface
            if if_obj.ipv4 and "/" in if_obj.ipv4:
                iface = ipaddress.ip_interface(if_obj.ipv4)
                network = iface.network.network_address
                netmask = iface.network.netmask
                lines.append(f"  network {network} mask {netmask}")
        
        lines.append(" exit-address-family")
        
        out[router_name] = lines
    
    return out
