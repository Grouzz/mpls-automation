from utils import Inventory, ibgp_table, loopback, ebgp_table, router_number

CUSTOMER = "customer"
PROVIDER = "provider"
PEER = "peer"
VALID_RELATIONSHIPS = {CUSTOMER, PROVIDER, PEER}

# communities
COMMUNITY_CUSTOMER = "100:10"
COMMUNITY_PROVIDER = "100:20"
COMMUNITY_PEER = "100:30"
COMMUNITY_LOCAL = "100:40"

# local pref
LOCALPREF_CUSTOMER = 200
LOCALPREF_PEER = 150
LOCALPREF_PROVIDER = 100


def validate_relationships(intent):
    router_to_as = {}
    for asn, as_data in intent.get("AS", {}).items():
        for r in as_data.get("routers", {}).keys():
            router_to_as[r] = asn

    # helper to get relationship on a link (router -> neighbor)
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
                if not neighbor:
                    continue
                if neighbor not in router_to_as:
                    continue
                neighbor_asn = router_to_as[neighbor]
                if neighbor_asn == asn:
                    continue  # intra-AS, no relationship required

                relationship = str(if_data.get("relationship", "")).strip()
                if relationship not in VALID_RELATIONSHIPS:
                    raise ValueError(
                        f"invalid or missing relationship on {router_name}:{if_name}. "
                        f"which must be one of : {VALID_RELATIONSHIPS}"
                    )

                # check consistency
                other_rel = rel_of(neighbor, router_name)
                if other_rel:
                    ok = (
                        (relationship == PEER and other_rel == PEER)
                        or (relationship == PROVIDER and other_rel == CUSTOMER)
                        or (relationship == CUSTOMER and other_rel == PROVIDER)
                    )
                    if not ok:
                        raise ValueError(
                            f"Inconsistent relationship across link {router_name}({relationship}) <-> "
                            f"{neighbor}({other_rel}). Expected peer/peer or provider/customer."
                        )


def community_for_relationship(relationship):
    mapping = {
        CUSTOMER: COMMUNITY_CUSTOMER,
        PROVIDER: COMMUNITY_PROVIDER,
        PEER: COMMUNITY_PEER,
    }
    return mapping.get(relationship, COMMUNITY_PEER)


def localpref_for_relationship(relationship):
    mapping = {
        CUSTOMER: LOCALPREF_CUSTOMER,
        PROVIDER: LOCALPREF_PROVIDER,
        PEER: LOCALPREF_PEER,
    }
    return mapping.get(relationship, LOCALPREF_PEER)


def _relationship_map_from_intent(intent_data, asn):
    rm = {}
    as_data = intent_data["AS"][str(asn)]
    for router_name, router_data in as_data["routers"].items():
        rm[router_name] = {}
        for _, if_data in router_data["interfaces"].items():
            neighbor = if_data.get("ngbr")
            if not neighbor:
                continue
            rel = str(if_data.get("relationship", "")).strip() or PEER
            rm[router_name][neighbor] = rel
    return rm


def policy_object_definitions():
    lines = []
    # community-lists
    lines += [f"ip community-list standard COMM-CUST-OR-LOCAL permit {COMMUNITY_CUSTOMER}"]
    lines += [f"ip community-list standard COMM-CUST-OR-LOCAL permit {COMMUNITY_LOCAL}"]
    #tag local routes at origin (no free exporting transit)
    lines += ["route-map RM-SET-LOCAL permit 10"]
    lines += [f" set community {COMMUNITY_LOCAL} additive"]

    #set comm + local pref by relationship type
    for rel in [CUSTOMER, PEER, PROVIDER]:
        comm = community_for_relationship(rel)
        lp = localpref_for_relationship(rel)
        lines += [f"route-map RM-IN-{rel.upper()} permit 10"]
        lines += [f" set community {comm} additive"]
        lines += [f" set local-preference {lp}"]

    #to customers, we advertise everything (permit all)
    lines += ["route-map RM-OUT-TO-CUSTOMER permit 10"]

    #to peers/providers, we only advertise customer + local
    lines += ["route-map RM-OUT-TO-PEER permit 10"]
    lines += [" match community COMM-CUST-OR-LOCAL"]
    lines += ["route-map RM-OUT-TO-PEER deny 100"]

    lines += ["route-map RM-OUT-TO-PROVIDER permit 10"]
    lines += [" match community COMM-CUST-OR-LOCAL"]
    lines += ["route-map RM-OUT-TO-PROVIDER deny 100"]

    return lines


def build_bgp_with_policies(inv, asn, intent_data): #returns per-router:{"R1": {"global": [...], "bgp": [...]},...}
    as_obj = inv.ases[asn]
    rel_map = _relationship_map_from_intent(intent_data, asn)
    ibgp_peers = ibgp_table(inv, asn)
    loopbacks = loopback(inv, asn)
    ebgp_peers = ebgp_table(inv, asn)
    per_router = {}

    global_objs = policy_object_definitions()

    for router_name, router_body in as_obj.routers.items():
        bgp_lines = []
        rid_oct = router_number(router_name)
        rid = f"{rid_oct}.{rid_oct}.{rid_oct}.{rid_oct}"

        bgp_lines += [f"router bgp {asn}"]
        bgp_lines += [f" bgp router-id {rid}"]
        bgp_lines += [" bgp log-neighbor-changes"]
        bgp_lines += [" no bgp default ipv4-unicast"]

        #ibgp neighbors (using loopback)
        for peer_lo in ibgp_peers.get(router_name, []):
            bgp_lines += [f" neighbor {peer_lo} remote-as {asn}"]
            bgp_lines += [f" neighbor {peer_lo} update-source Loopback0"]

        #ebgp neighbors
        for peer in ebgp_peers.get(router_name, []):
            peer_ip = peer["neighbor_ip"]
            peer_asn = peer["neighbor_asn"]
            bgp_lines += [f" neighbor {peer_ip} remote-as {peer_asn}"]

        #address-family
        bgp_lines += [" address-family ipv4 unicast"]
        lo = router_body.interfaces.get("Loopback0")
        if lo and lo.ipv4:
            lo_ip = lo.ipv4.split("/")[0] if "/" in lo.ipv4 else lo.ipv4
            bgp_lines += [f"  network {lo_ip} mask 255.255.255.255 route-map RM-SET-LOCAL"]

        #ibgp AF config
        for peer_lo in ibgp_peers.get(router_name, []):
            bgp_lines += [f"  neighbor {peer_lo} activate"]
            bgp_lines += [f"  neighbor {peer_lo} next-hop-self"]
            bgp_lines += [f"  neighbor {peer_lo} send-community both"]

        #ebgp policies
        for peer in ebgp_peers.get(router_name, []):
            peer_ip = peer["neighbor_ip"]
            peer_name = peer.get("neighbor_name", "")
            relationship = rel_map.get(router_name, {}).get(peer_name, PEER)

            in_rm = f"RM-IN-{relationship.upper()}"
            if relationship == CUSTOMER:
                out_rm = "RM-OUT-TO-CUSTOMER"
            elif relationship == PROVIDER:
                out_rm = "RM-OUT-TO-PROVIDER"
            else:
                out_rm = "RM-OUT-TO-PEER"

            bgp_lines += [f"  neighbor {peer_ip} activate"]
            bgp_lines += [f"  neighbor {peer_ip} route-map {in_rm} in"]
            bgp_lines += [f"  neighbor {peer_ip} route-map {out_rm} out"]
            bgp_lines += [f"  neighbor {peer_ip} send-community both"]

        bgp_lines += [" exit-address-family"]

        per_router[router_name] = {
            "global": global_objs,
            "bgp": bgp_lines,
        }

    return per_router
