from utils import Inventory, ibgp_table, loopback_ip, ebgp_table

CUSTOMER = "customer"
PROVIDER = "provider"
PEER = "peer"
VALID_RELATIONSHIPS = {CUSTOMER, PROVIDER, PEER}

COMMUNITY_CUSTOMER = "100:10"
COMMUNITY_PROVIDER = "100:20"
COMMUNITY_PEER = "100:30"
COMMUNITY_LOCAL = "100:40"

LOCALPREF_CUSTOMER = 200
LOCALPREF_PEER = 150
LOCALPREF_PROVIDER = 100


def validate_relationships(intent):
    router_to_as = {}
    for asn, as_data in intent.get("AS", {}).items():
        for r in as_data.get("routers", {}).keys():
            router_to_as[r] = asn

    def rel_of(r, n):
        asn = router_to_as[r]
        r_intfs = intent["AS"][asn]["routers"][r]["interfaces"]
        for _, if_data in r_intfs.items():
            if if_data.get("ngbr") == n:
                return str(if_data.get("relationship", "")).strip()
        return ""

    for asn, as_data in intent.get("AS", {}).items():
        for router_name, router_data in as_data.get("routers", {}).items():
            for if_name, if_data in router_data.get("interfaces", {}).items():
                neighbor = if_data.get("ngbr")
                if not neighbor or neighbor not in router_to_as:
                    continue
                if router_to_as[neighbor] == asn:
                    continue
                relationship = str(if_data.get("relationship", "")).strip()
                if relationship not in VALID_RELATIONSHIPS:
                    raise ValueError(f"invalid or missing relationship on {router_name}:{if_name}. which must be one of : {VALID_RELATIONSHIPS}")
                other_rel = rel_of(neighbor, router_name)
                if other_rel:
                    ok = (
                        (relationship == PEER and other_rel == PEER)
                        or (relationship == PROVIDER and other_rel == CUSTOMER)
                        or (relationship == CUSTOMER and other_rel == PROVIDER)
                    )
                    if not ok:
                        raise ValueError(f"Inconsistent relationship across link {router_name}({relationship}) <-> {neighbor}({other_rel}).")


def community_for_relationship(relationship):
    return {
        CUSTOMER: COMMUNITY_CUSTOMER,
        PROVIDER: COMMUNITY_PROVIDER,
        PEER: COMMUNITY_PEER,
    }.get(relationship, COMMUNITY_PEER)


def localpref_for_relationship(relationship):
    return {
        CUSTOMER: LOCALPREF_CUSTOMER,
        PROVIDER: LOCALPREF_PROVIDER,
        PEER: LOCALPREF_PEER,
    }.get(relationship, LOCALPREF_PEER)


def _relationship_map_from_intent(intent_data, asn):
    rm = {}
    as_data = intent_data["AS"][str(asn)]
    for router_name, router_data in as_data["routers"].items():
        rm[router_name] = {}
        for _, if_data in router_data["interfaces"].items():
            neighbor = if_data.get("ngbr")
            if not neighbor:
                continue
            rm[router_name][neighbor] = str(if_data.get("relationship", "")).strip() or PEER
    return rm


def policy_object_definitions():
    lines = [
        f"ip community-list standard COMM-CUST-OR-LOCAL permit {COMMUNITY_CUSTOMER}",
        f"ip community-list standard COMM-CUST-OR-LOCAL permit {COMMUNITY_LOCAL}",
        "route-map RM-SET-LOCAL permit 10",
        f" set community {COMMUNITY_LOCAL} additive",
    ]
    for rel in [CUSTOMER, PEER, PROVIDER]:
        lines += [
            f"route-map RM-IN-{rel.upper()} permit 10",
            f" set community {community_for_relationship(rel)} additive",
            f" set local-preference {localpref_for_relationship(rel)}",
        ]
    lines += [
        "route-map RM-OUT-TO-CUSTOMER permit 10",
        "route-map RM-OUT-TO-PEER permit 10",
        " match community COMM-CUST-OR-LOCAL",
        "route-map RM-OUT-TO-PEER deny 100",
        "route-map RM-OUT-TO-PROVIDER permit 10",
        " match community COMM-CUST-OR-LOCAL",
        "route-map RM-OUT-TO-PROVIDER deny 100",
    ]
    return lines


def build_bgp_with_policies(inv: Inventory, asn, intent_data):
    as_obj = inv.ases[asn]
    rel_map = _relationship_map_from_intent(intent_data, asn)
    ibgp_peers = ibgp_table(inv, asn)
    ebgp_peers = ebgp_table(inv, asn)
    per_router = {}
    global_objs = policy_object_definitions()

    for router_name, router_body in as_obj.routers.items():
        rid = loopback_ip(router_body)
        bgp_lines = [f"router bgp {asn}", f" bgp router-id {rid}", " bgp log-neighbor-changes", " no bgp default ipv4-unicast"]

        for peer_lo in ibgp_peers.get(router_name, []):
            bgp_lines += [f" neighbor {peer_lo} remote-as {asn}", f" neighbor {peer_lo} update-source Loopback0"]
        for peer in ebgp_peers.get(router_name, []):
            bgp_lines += [f" neighbor {peer['neighbor_ip']} remote-as {peer['neighbor_asn']}"]

        bgp_lines += [" address-family vpnv4"]
        for peer_lo in ibgp_peers.get(router_name, []):
            bgp_lines += [f"  neighbor {peer_lo} activate", f"  neighbor {peer_lo} send-community both"]
        bgp_lines += [" exit-address-family"]

        bgp_lines += [" address-family ipv4"]
        if router_body.interfaces.get("Loopback0") and router_body.interfaces["Loopback0"].ipv4:
            bgp_lines += [f"  network {loopback_ip(router_body)} mask 255.255.255.255 route-map RM-SET-LOCAL"]
        for peer in ebgp_peers.get(router_name, []):
            peer_ip = peer["neighbor_ip"]
            peer_name = peer.get("neighbor_name", "")
            relationship = rel_map.get(router_name, {}).get(peer_name, PEER)
            in_rm = f"RM-IN-{relationship.upper()}"
            out_rm = "RM-OUT-TO-CUSTOMER" if relationship == CUSTOMER else "RM-OUT-TO-PROVIDER" if relationship == PROVIDER else "RM-OUT-TO-PEER"
            bgp_lines += [f"  neighbor {peer_ip} activate", f"  neighbor {peer_ip} route-map {in_rm} in", f"  neighbor {peer_ip} route-map {out_rm} out", f"  neighbor {peer_ip} send-community both"]
        bgp_lines += [" exit-address-family"]

        per_router[router_name] = {"global": global_objs, "bgp": bgp_lines}

    return per_router
