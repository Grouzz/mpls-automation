# MPLS configuration automation (IPv4 addressing, OSPF, MPLS)

This project generates router startup configurations from an intent JSON file.
It fills missing IPv4 addresses, configures OSPF, enables MPLS/LDP in the core,
and builds iBGP/eBGP configuration from the topology.

## Run

From the project directory:

```bash
python3 main.py intent.json
python3 main.py intent.json --no-policies
python3 main.py intent.json -o ./output
```
