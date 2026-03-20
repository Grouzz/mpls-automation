import json
import ipaddress

def load_intent(path="intent.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def save_intent(data, path="intent_filled_info.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def assign_default_ranges(intent):
    for asn, as_data in intent["AS"].items():
        as_num = int(asn)
        as_mod = as_num % 256
        as_data["add_range"] = f"10.{as_mod}.0.0/16"
        as_data["loopback"] = f"10.{as_mod}.255.0/24"
    return intent

def build_global_router_view(intent):
    routers_global = {}
    router_to_as = {}

    for asn in sorted(intent["AS"].keys(), key=lambda x: int(x)):
        as_data = intent["AS"][asn]
        for r_name in sorted(as_data["routers"].keys()):
            routers_global[r_name] = as_data["routers"][r_name]
            router_to_as[r_name] = asn
    return routers_global, router_to_as

def _find_reverse_iface(routers_global, src, dst):
    for ng_if, ng_if_data in routers_global[dst]["interfaces"].items():
        if ng_if_data.get("ngbr") == src:
            return ng_if
    return None

def discover_all_links(intent):
    routers_global, router_to_as = build_global_router_view(intent)
    intra_links = []
    inter_links = []
    seen_pairs = set()

    for r_name in sorted(routers_global.keys()):
        r_data = routers_global[r_name]
        as_r = router_to_as[r_name]

        for if_name in sorted(r_data["interfaces"].keys()):
            if_data = r_data["interfaces"][if_name]
            ngbr = if_data.get("ngbr")
            if not ngbr or ngbr not in routers_global:
                continue

            if (r_name, ngbr) in seen_pairs or (ngbr, r_name) in seen_pairs:
                continue

            ng_if = _find_reverse_iface(routers_global, r_name, ngbr)
            if ng_if is None:
                raise ValueError(f"Link not symmetric: {r_name}:{if_name} -> {ngbr} but no reverse interface exists")

            as_ng = router_to_as[ngbr]
            link = (r_name, if_name, as_r, ngbr, ng_if, as_ng)
            if as_r == as_ng:
                intra_links.append(link)
            else:
                inter_links.append(link)
            seen_pairs.add((r_name, ngbr))

    return intra_links, inter_links


def fill_ipv4_intra_as(intent):
    intent = assign_default_ranges(intent)
    intra_links, _ = discover_all_links(intent)

    pools = {}
    for asn, as_data in intent["AS"].items():
        net = ipaddress.ip_network(as_data["add_range"])
        pools[asn] = net.subnets(new_prefix=30)

    for r1, if1, as1, r2, if2, as2 in intra_links:
        subnet = next(pools[as1])
        hosts = list(subnet.hosts())
        intent["AS"][as1]["routers"][r1]["interfaces"][if1]["ipv4"] = f"{hosts[0]}/{subnet.prefixlen}"
        intent["AS"][as2]["routers"][r2]["interfaces"][if2]["ipv4"] = f"{hosts[1]}/{subnet.prefixlen}"

    return intent


def choose_ebgp_range(intent):
    as_nets = [ipaddress.ip_network(as_data["add_range"]) for as_data in intent["AS"].values()]
    ebgp_pool = ipaddress.ip_network("172.16.0.0/12")
    for cand in ebgp_pool.subnets(new_prefix=24):
        if all(not cand.overlaps(as_net) for as_net in as_nets):
            return cand
    raise ValueError("unable to find ebgp range")


def fill_ipv4_ebgp_links(intent):
    _, inter_links = discover_all_links(intent)
    if not inter_links:
        return intent

    ebgp_net = choose_ebgp_range(intent)
    subnets = ebgp_net.subnets(new_prefix=30)

    for r1, if1, as1, r2, if2, as2 in inter_links:
        subnet = next(subnets)
        hosts = list(subnet.hosts())
        intent["AS"][as1]["routers"][r1]["interfaces"][if1]["ipv4"] = f"{hosts[0]}/{subnet.prefixlen}"
        intent["AS"][as2]["routers"][r2]["interfaces"][if2]["ipv4"] = f"{hosts[1]}/{subnet.prefixlen}"

    return intent


def fill_loopbacks(intent):
    for asn, as_data in intent["AS"].items():
        loop_range = as_data.get("loopback")
        if not loop_range:
            continue

        net = ipaddress.ip_network(loop_range)
        hosts = net.hosts()

        for _r_name, r_data in as_data["routers"].items():
            if "Loopback0" not in r_data["interfaces"]:
                r_data["interfaces"]["Loopback0"] = {"ipv4": "", "ngbr": ""}
            ip_lo = next(hosts)
            r_data["interfaces"]["Loopback0"]["ipv4"] = f"{ip_lo}/32"

    return intent
