from dataclasses import dataclass
import json
import re

SUPPORTED_IGP = {"OSPF", "RIP"}


@dataclass
class Interface:
    ipv4: str
    ngbr: str
    relationship: str = ""


@dataclass
class Router:
    name: str
    interfaces: dict[str, Interface]


@dataclass
class AS:
    asn: int
    igp: str
    routers: dict[str, Router]


@dataclass
class Inventory:
    ases: dict[int, AS]
    router_to_as: dict[str, int]


def load_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_intent(path: str):
    return load_file(path)


def save_intent(intent_data, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(intent_data, f, indent=2)


def router_number(router_name: str) -> int:
    m = re.match(r"^[Rr](\d+)$", router_name.strip())
    if not m:
        return 1
    return int(m.group(1))


def parse_info(path: str):
    data = load_file(path)
    if not isinstance(data, dict) or "AS" not in data:
        raise ValueError("No AS information in the json file")

    ases: dict[int, AS] = {}
    router_to_as: dict[str, int] = {}

    for asn_str, as_body in data["AS"].items():
        asn = int(asn_str)
        igp = str(as_body.get("igp", "")).upper().strip()
        if igp not in SUPPORTED_IGP:
            raise ValueError(f"{igp} not supported, choose from {SUPPORTED_IGP}")

        routers: dict[str, Router] = {}
        for router_name, router_body in as_body.get("routers", {}).items():
            interfaces: dict[str, Interface] = {}
            for if_name, if_body in router_body.get("interfaces", {}).items():
                interfaces[if_name] = Interface(
                    ipv4=str(if_body.get("ipv4", "")).strip(),
                    ngbr=str(if_body.get("ngbr", "")).strip(),
                    relationship=str(if_body.get("relationship", "")).strip(),
                )
            routers[router_name] = Router(name=router_name, interfaces=interfaces)
            router_to_as[router_name] = asn

        ases[asn] = AS(asn=asn, igp=igp, routers=routers)

    return Inventory(ases=ases, router_to_as=router_to_as)


def basic_validation(path: str):
    inventory = parse_info(path)
    for _, as_body in inventory.ases.items():
        for router_name, router_body in as_body.routers.items():
            for interface_name, interface_body in router_body.interfaces.items():
                if interface_body.ngbr and interface_body.ngbr not in inventory.router_to_as:
                    raise ValueError(f"{router_name}:{interface_name} neighbor {interface_body.ngbr!r} not found in inventory")

    for _, as_body in inventory.ases.items():
        for router_name, router_body in as_body.routers.items():
            for interface_name, interface_body in router_body.interfaces.items():
                neighbor = interface_body.ngbr
                if not neighbor:
                    continue
                nrouter = inventory.ases[inventory.router_to_as[neighbor]].routers[neighbor]
                matches = 0
                for _, n_if_body in nrouter.interfaces.items():
                    if n_if_body.ngbr == router_name:
                        matches += 1
                if matches == 0:
                    raise ValueError(f"link not reciprocal: {router_name}:{interface_name} -> {neighbor}")
                if matches > 1:
                    raise ValueError(f"multiple interfaces on {neighbor} pointing to {router_name} (ambiguous link)")
    return inventory


def internal_interfaces(inv: Inventory, asn: int):
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


def rip_commands(inv: Inventory, asn: int):
    as_obj = inv.ases[asn]
    out: dict[str, list[str]] = {}
    for router_name, _router_body in as_obj.routers.items():
        out[router_name] = ["router rip", " version 2", " no auto-summary"]
    return out


def loopback_ip(router_body: Router) -> str:
    lo = router_body.interfaces.get("Loopback0")
    if not lo or not lo.ipv4:
        raise ValueError(f"{router_body.name} is missing Loopback0 ipv4")
    return lo.ipv4.split("/")[0] if "/" in lo.ipv4 else lo.ipv4


def ospf_commands(inv: Inventory, asn: int):
    as_obj = inv.ases[asn]
    out: dict[str, list[str]] = {}
    for router_name, router_body in as_obj.routers.items():
        out[router_name] = [f"router ospf {asn}", f" router-id {loopback_ip(router_body)}"]
    return out


def loopback(inv: Inventory, asn: int):
    as_obj = inv.ases[asn]
    loop: dict[str, str] = {}
    for router_name, router_body in as_obj.routers.items():
        if "Loopback0" in router_body.interfaces and router_body.interfaces["Loopback0"].ipv4:
            loop[router_name] = loopback_ip(router_body)
    return loop


def all_and_external_routers(inv: Inventory, asn: int) -> tuple[set[str], set[str]]:
    as_obj = inv.ases[asn]
    all_routers = set(as_obj.routers.keys())
    external_routers = set()
    for router_name, router_body in as_obj.routers.items():
        for interface_name, interface_body in router_body.interfaces.items():
            if interface_name.startswith("Loopback"):
                continue
            ngbr = interface_body.ngbr
            if ngbr and inv.router_to_as.get(ngbr) != asn:
                external_routers.add(router_name)
                break
    return all_routers, external_routers


def ibgp_table(inv: Inventory, asn: int) -> dict[str, list[str]]:
    all_routers, _ = all_and_external_routers(inv, asn)
    loopbacks = loopback(inv, asn)
    ibgp_peers: dict[str, list[str]] = {}
    for router in all_routers:
        ibgp_peers[router] = [loopbacks[p] for p in all_routers if p != router and p in loopbacks]
    return ibgp_peers


def ebgp_table(inv: Inventory, asn: int):
    as_obj = inv.ases[asn]
    ebgp_peers: dict[str, list[dict]] = {}
    for router_name, router_body in as_obj.routers.items():
        for interface_name, interface_body in router_body.interfaces.items():
            if interface_name.startswith("Loopback"):
                continue
            neighbor = interface_body.ngbr
            if not neighbor:
                continue
            neighbor_asn = inv.router_to_as.get(neighbor)
            if neighbor_asn and neighbor_asn != asn:
                neighbor_router = inv.ases[neighbor_asn].routers[neighbor]
                for _, n_if_body in neighbor_router.interfaces.items():
                    if n_if_body.ngbr == router_name:
                        neighbor_ip = n_if_body.ipv4.split("/")[0] if "/" in n_if_body.ipv4 else n_if_body.ipv4
                        ebgp_peers.setdefault(router_name, []).append(
                            {
                                "neighbor_ip": neighbor_ip,
                                "neighbor_asn": neighbor_asn,
                                "local_interface": interface_name,
                                "neighbor_name": neighbor,
                            }
                        )
                        break
    return ebgp_peers


def ibgp_commands(inv: Inventory, asn: int):
    as_obj = inv.ases[asn]
    ibgp_peers = ibgp_table(inv, asn)
    out: dict[str, list[str]] = {}
    for router_name in as_obj.routers.keys():
        router_body = as_obj.routers[router_name]
        rid = loopback_ip(router_body)
        lines: list[str] = [f"router bgp {asn}", f" bgp router-id {rid}", " no bgp default ipv4-unicast"]
        for peer_loop in ibgp_peers.get(router_name, []):
            lines += [f" neighbor {peer_loop} remote-as {asn}", f" neighbor {peer_loop} update-source Loopback0"]
        lines += [" address-family vpnv4"]
        for peer_loop in ibgp_peers.get(router_name, []):
            lines += [f"  neighbor {peer_loop} activate", f"  neighbor {peer_loop} send-community both"]
        lines += [" exit-address-family"]
        lines += [" address-family ipv4"]
        if router_body.interfaces.get("Loopback0") and router_body.interfaces["Loopback0"].ipv4:
            lines += [f"  network {loopback_ip(router_body)} mask 255.255.255.255"]
        lines += [" exit-address-family"]
        out[router_name] = lines
    return out


def ebgp_commands(inv: Inventory, asn: int) -> dict[str, list[str]]:
    as_obj = inv.ases[asn]
    ebgp_peers_map = ebgp_table(inv, asn)
    out: dict[str, list[str]] = {}
    for router_name in as_obj.routers.keys():
        router_body = as_obj.routers[router_name]
        router_peers = ebgp_peers_map.get(router_name, [])
        if not router_peers:
            out[router_name] = []
            continue
        rid = loopback_ip(router_body)
        lines: list[str] = [f"router bgp {asn}", f" bgp router-id {rid}", " no bgp default ipv4-unicast"]
        for peer in router_peers:
            lines += [f" neighbor {peer['neighbor_ip']} remote-as {peer['neighbor_asn']}"]
        lines += [" address-family ipv4"]
        if router_body.interfaces.get("Loopback0") and router_body.interfaces["Loopback0"].ipv4:
            lines += [f"  network {loopback_ip(router_body)} mask 255.255.255.255"]
        for peer in router_peers:
            lines += [f"  neighbor {peer['neighbor_ip']} activate"]
        lines += [" exit-address-family"]
        out[router_name] = lines
    return out


def combine_bgp_blocks(ibgp_lines: list[str], ebgp_lines: list[str]) -> list[str]:
    if not ibgp_lines:
        return ebgp_lines
    if not ebgp_lines:
        return ibgp_lines

    def split_block(lines: list[str]) -> tuple[list[str], list[str], list[list[str]]]:
        header = lines[:3]
        af_start = next((i for i, line in enumerate(lines) if line.startswith(" address-family ")), len(lines))
        global_neighbors = lines[3:af_start]
        families: list[list[str]] = []
        i = af_start
        while i < len(lines):
            if not lines[i].startswith(" address-family "):
                i += 1
                continue
            j = i + 1
            while j < len(lines) and lines[j] != " exit-address-family":
                j += 1
            families.append(lines[i:j + 1])
            i = j + 1
        return header, global_neighbors, families

    header, ibgp_global, ibgp_families = split_block(ibgp_lines)
    _, ebgp_global, ebgp_families = split_block(ebgp_lines)
    merged = header + list(dict.fromkeys(ibgp_global + ebgp_global))
    for family in ibgp_families + ebgp_families:
        merged += family
    return merged
