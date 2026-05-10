# MPLS configuration automation (IPv4 addressing, OSPF, MPLS)

This project automates the configuration of a complete BGP/MPLS VPN network including: basic network setup with OSPF routing, MPLS with LDP, cutomer VRFs, PE-CE BGP peering

---

## Output

After running the script, you get:

- `intent_filled.json`: the same intent, but with every missing IPv4 address filled.
- `output/AS<ASN>/R<id>_startup.cfg`: one config per router, ready to import into GNS3.

---

### Basic Usage

```bash
python main.py intent.json
```

This will:
1. Load and validate the intent file
2. Automatically assign IP addresses
3. Generate `intent_filled.json`
4. Create router configurations in `./output/`

### Custom Output Directory

```bash
python3 main.py intent.json -o /path/to/output
```

### Adding a New Customer

1. Add new customer AS in `intent.json`:
```json
"65003": {
  "igp": "OSPF",
  "customer": true,
  "routers": {
    "R9": {
      "role": "CE",
      "interfaces": { ... }
    }
  }
}
```

2. Add VRF configuration in provider AS:
```json
"CUSTOMER_104": {
  "rd": "100:104",
  "route_targets": {
    "import": ["100:104"],
    "export": ["100:104"]
  },
  "pe_routers": { ... }
}
```

3. Re-run: `python main.py intent.json`
