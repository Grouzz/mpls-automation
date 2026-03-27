import ipaddress
from copy import deepcopy


def _iter_ases(intent_data):
    for asn_str, as_body in intent_data.get("AS", {}).items():
        yield int(asn_str), as_body


def _router_number(router_name: str) -> int:
    return int(router_name[1:]) if router_name.upper().startswith("R") and router_name[1:].isdigit() else 1


def fill_ipv4_intra_as(intent_data):
    data = deepcopy(intent_data)

    for asn, as_body in _iter_ases(data):
        network = ipaddress.ip_network(f"10.{asn}.0.0/16")
        routers = as_body.get("routers", {})
        assigned = {}
        next_link_index = 0

        for router_name, router_body in routers.items():
            for _if_name, if_body in router_body.get("interfaces", {}).items():
                ngbr = if_body.get("ngbr", "").strip()
                if not ngbr:
                    continue
                if ngbr not in routers:
                    continue
                link_key = tuple(sorted((router_name, ngbr)))
                if link_key in assigned:
                    subnet = assigned[link_key]
                else:
                    subnet = ipaddress.ip_network(f"{network.network_address + next_link_index * 4}/30", strict=False)
                    assigned[link_key] = subnet
                    next_link_index += 1

                first, second = list(subnet.hosts())
                local_ip = first if min(link_key) == router_name else second
                if not if_body.get("ipv4"):
                    if_body["ipv4"] = f"{local_ip}/{subnet.prefixlen}"

    return data


def fill_ipv4_ebgp_links(intent_data):
    data = deepcopy(intent_data)
    external_links = {}
    next_net = ipaddress.ip_network("172.16.0.0/16")
    next_index = 0
    router_to_as = {}

    for asn_str, as_body in data.get("AS", {}).items():
        for router_name in as_body.get("routers", {}):
            router_to_as[router_name] = int(asn_str)

    for _, as_body in data.get("AS", {}).items():
        for router_name, router_body in as_body.get("routers", {}).items():
            for _, if_body in router_body.get("interfaces", {}).items():
                ngbr = if_body.get("ngbr", "").strip()
                if not ngbr or ngbr not in router_to_as:
                    continue
                if router_to_as[router_name] == router_to_as[ngbr]:
                    continue
                link_key = tuple(sorted((router_name, ngbr)))
                if link_key in external_links:
                    subnet = external_links[link_key]
                else:
                    subnet = ipaddress.ip_network(f"{next_net.network_address + next_index * 4}/30", strict=False)
                    external_links[link_key] = subnet
                    next_index += 1
                first, second = list(subnet.hosts())
                local_ip = first if min(link_key) == router_name else second
                if not if_body.get("ipv4"):
                    if_body["ipv4"] = f"{local_ip}/{subnet.prefixlen}"

    return data


def fill_loopbacks(intent_data):
    data = deepcopy(intent_data)
    for asn, as_body in _iter_ases(data):
        for router_name, router_body in as_body.get("routers", {}).items():
            loop = router_body.get("interfaces", {}).get("Loopback0")
            if loop is not None and not loop.get("ipv4"):
                loop["ipv4"] = f"10.{asn}.255.{_router_number(router_name)}/32"
        as_body["add_range"] = f"10.{asn}.0.0/16"
        as_body["loopback"] = f"10.{asn}.255.0/24"
    return data
