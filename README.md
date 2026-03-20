# MPLS configuration automation (IPv4 addressing, OSPF, MPLS)

This project generates **router startup configurations** from an **intent JSON** file. It automatically assigns **IPv4 addresses**, configures **IGP** (OSPF), builds an **iBGP full-mesh** inside each AS using **loopbacks**, configures **eBGP** on inter-AS links, and optionally applies **routing policies** using **communities + local-preference + route-maps**.

---

## Output

After running the script, you get:

- `intent_filled.json`: the same intent, but with every missing IPv4 address filled.
- `output/AS<ASN>/R<id>_startup.cfg`: one config per router, ready to import into GNS3.

---

## Quick start

### Requirements
- Python **3.9+** (uses `list[str]` typing and standard libraries such as `ipaddress`, `dataclasses`)
- No external Python dependencies

### Run
From the project directory:

```bash
#basic run (default output: ./output)
python3 main.py intent.json

#choosing an output directory
python3 main.py intent.json -o ./output

#disabling BGP policies (generate only iBGP/eBGP without policies)
python3 main.py intent.json --no-policies

