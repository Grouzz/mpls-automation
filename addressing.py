import json
import ipaddress

def load_intent(path="intent.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def save_intent(data, path="intent_filled.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def assign_default_ranges(intent):
    """Assign default IP ranges to ASes that don't have them specified"""
    for asn, as_data in intent["AS"].items():
        if not as_data.get("add_range"):
            as_num = int(asn)
            # Provider networks use 10.x
            if as_num < 65000:
                as_mod = as_num % 256
                as_data["add_range"] = f"10.{as_mod}.0.0/16"
                as_data["loopback"] = f"10.{as_mod}.255.0/24"
            # Customer networks use 192.168.x
            else:
                cust_num = (as_num - 65000) % 16  # Support up to 16 customer ASes per /24
                as_data["add_range"] = f"192.168.{cust_num}.0/24"
                as_data["loopback"] = f"192.168.255.{cust_num * 16}/28"
    return intent

def build_global_router_view(intent):
    """Build a global view of all routers across all ASes"""
    routers_global = {}
    router_to_as = {}

    for asn in sorted(intent["AS"].keys(), key=lambda x: int(x)):
        as_data = intent["AS"][asn]
        for r_name in sorted(as_data["routers"].keys()):
            routers_global[r_name] = as_data["routers"][r_name]
            router_to_as[r_name] = asn
    return routers_global, router_to_as

def _find_reverse_iface(routers_global, src, dst):
    """Find the interface on dst that connects back to src"""
    if dst not in routers_global:
        return None
    for ng_if, ng_if_data in routers_global[dst]["interfaces"].items():
        if ng_if_data.get("ngbr") == src:
            return ng_if
    return None

def discover_all_links(intent):
    """Discover all links in the network, separating intra-AS and inter-AS links"""
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
            
            # Skip if no neighbor or already has an IP assigned
            if not ngbr or ngbr not in routers_global:
                continue

            # Skip if already processed this pair
            if (r_name, ngbr) in seen_pairs or (ngbr, r_name) in seen_pairs:
                continue

            ng_if = _find_reverse_iface(routers_global, r_name, ngbr)
            if ng_if is None:
                raise ValueError(f"Link not symmetric: {r_name}:{if_name} -> {ngbr} but no reverse interface")

            as_ng = router_to_as[ngbr]
            link = (r_name, if_name, as_r, ngbr, ng_if, as_ng)
            
            if as_r == as_ng:
                intra_links.append(link)
            else:
                inter_links.append(link)
            
            seen_pairs.add((r_name, ngbr))

    return intra_links, inter_links

def fill_ipv4_intra_as(intent):
    """Fill IP addresses for intra-AS links"""
    intent = assign_default_ranges(intent)
    intra_links, _ = discover_all_links(intent)

    # Create subnet pools for each AS
    pools = {}
    for asn, as_data in intent["AS"].items():
        net = ipaddress.ip_network(as_data["add_range"])
        pools[asn] = net.subnets(new_prefix=30)

    # Assign IPs to intra-AS links
    for r1, if1, as1, r2, if2, as2 in intra_links:
        # Skip if already assigned
        if1_data = intent["AS"][as1]["routers"][r1]["interfaces"][if1]
        if if1_data.get("ipv4"):
            continue
            
        subnet = next(pools[as1])
        hosts = list(subnet.hosts())
        intent["AS"][as1]["routers"][r1]["interfaces"][if1]["ipv4"] = f"{hosts[0]}/{subnet.prefixlen}"
        intent["AS"][as2]["routers"][r2]["interfaces"][if2]["ipv4"] = f"{hosts[1]}/{subnet.prefixlen}"

    return intent

def choose_ebgp_range(intent):
    """Choose a non-overlapping range for eBGP links"""
    as_nets = [ipaddress.ip_network(as_data["add_range"]) for as_data in intent["AS"].values()]
    ebgp_pool = ipaddress.ip_network("172.16.0.0/12")
    
    for cand in ebgp_pool.subnets(new_prefix=24):
        if all(not cand.overlaps(as_net) for as_net in as_nets):
            return cand
    raise ValueError("Unable to find non-overlapping eBGP range")

def fill_ipv4_ebgp_links(intent):
    """Fill IP addresses for inter-AS (eBGP) links"""
    _, inter_links = discover_all_links(intent)
    if not inter_links:
        return intent

    ebgp_net = choose_ebgp_range(intent)
    subnets = ebgp_net.subnets(new_prefix=30)

    for r1, if1, as1, r2, if2, as2 in inter_links:
        # Skip if already assigned
        if1_data = intent["AS"][as1]["routers"][r1]["interfaces"][if1]
        if if1_data.get("ipv4"):
            continue
            
        subnet = next(subnets)
        hosts = list(subnet.hosts())
        intent["AS"][as1]["routers"][r1]["interfaces"][if1]["ipv4"] = f"{hosts[0]}/{subnet.prefixlen}"
        intent["AS"][as2]["routers"][r2]["interfaces"][if2]["ipv4"] = f"{hosts[1]}/{subnet.prefixlen}"

    return intent

def fill_loopbacks(intent):
    """Fill loopback addresses for all routers"""
    for asn, as_data in intent["AS"].items():
        loop_range = as_data.get("loopback")
        if not loop_range:
            continue

        net = ipaddress.ip_network(loop_range)
        
        # For /32, just use the network address
        if net.prefixlen == 32:
            hosts_list = [net.network_address]
        else:
            hosts_list = list(net.hosts())
        
        hosts = iter(hosts_list)

        for r_name, r_data in as_data["routers"].items():
            # Ensure Loopback0 exists
            if "Loopback0" not in r_data["interfaces"]:
                r_data["interfaces"]["Loopback0"] = {"ipv4": "", "ngbr": ""}
            
            # Skip if already assigned
            if r_data["interfaces"]["Loopback0"].get("ipv4"):
                continue
            
            try:
                ip_lo = next(hosts)
                r_data["interfaces"]["Loopback0"]["ipv4"] = f"{ip_lo}/32"
            except StopIteration:
                raise ValueError(f"Not enough loopback addresses in {loop_range} for AS {asn}")

    return intent
