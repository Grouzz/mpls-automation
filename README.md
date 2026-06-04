# MPLS configuration automation (IPv4 addressing, OSPF, MPLS)

This project automates the configuration of a complete **BGP/MPLS VPN** network, including basic IPv4 addressing, OSPF routing, MPLS with LDP, customer VRFs, PE-CE BGP peering, MP-BGP VPNv4 between PE routers, and an optional Phase 4.B for VRF site sharing through route-targets.

The goal is to start from a high-level `intent.json` file and automatically generate Cisco IOS startup configurations that can be imported into GNS3.

---

## Output

After running the script, you get:

- `intent_filled.json`: the same intent file, but with every missing IPv4 address filled.
- `output/AS<ASN>/R<id>_startup.cfg`: one config per router, ready to import into GNS3.
- `validation_report.txt`: a small report about generated files and warnings.
- `runtime_commands.txt`: useful commands to run and test the lab.

Example output structure:

```text
output/
├── AS100/
│   ├── R1_startup.cfg
│   ├── R2_startup.cfg
├── AS65001/
│   ├── R5_startup.cfg
│   └── R7_startup.cfg
└── AS65002/
    └── R8_startup.cfg
```

---

## Basic Usage

Generate the base MPLS/VPN configurations:

```bash
python main.py intent.json
```

or on Windows:

```powershell
py main.py intent.json
```

This will:

1. load and validate the intent file;
2. automatically assign IP addresses;
3. generate `intent_filled.json`;
4. create router configurations in `./output/`.

---

## Custom Output Directory

Generate the configurations in a custom directory:

```bash
python main.py intent.json -o /path/to/output
```

On Windows:

```powershell
py main.py intent.json -o output_base
```

---

## Create the GNS3 Topology

To create the c7200 topology directly in GNS3:

```powershell
py gns3_create_c7200_topology.py --project mpls_lab --template c7200 --rebuild
```

If you need to list available GNS3 templates:

```powershell
py gns3_create_c7200_topology.py --list-templates
```

Use the exact template name returned by GNS3 if `c7200` is not found.

---

## Push Configurations to GNS3

After generating the configurations, push them into the GNS3 project:

```powershell
py main.py intent.json -o output_base --drag-drop-bot --gns3-project mpls_lab --gns3-start
```

This command:

1. generates the configurations;
2. pushes them to the matching GNS3 routers;
3. starts the routers.

A dry-run mode is also available:

```powershell
py main.py intent.json -o output_base --drag-drop-bot --gns3-project mpls_lab --gns3-dry-run
```

---

## Phase 4.B: VRF Site Sharing

Phase 4.B adds site sharing between customer VRFs using an extra shared route-target.

```powershell
py main.py intent.json -o output_phase4b --phase4b
```

Push confs to GNS3 and start the routers:

```powershell
py main.py intent.json -o output_phase4b --phase4b --drag-drop-bot --gns3-project mpls_lab --gns3-start
```
---
