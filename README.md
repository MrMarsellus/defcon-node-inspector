# DeFCoN Network Inspector

`defcon-node-inspector` is a VPS tool for analyzing DeFCoN masternodes over RPC from a network-wide perspective. It checks `masternodelist`, `protx list valid`, and optionally `protx info`, then correlates public node data to identify problematic nodes, suspicious operator-key reuse, shared IP clusters, subnet clusters, and PoSe ban waves.

The goal is not only to inspect your own node, but also to identify publicly visible patterns across the network so affected operators can be contacted in the community.

## Main command

The recommended one-liner to download and run the script is:

```bash
sudo bash -c '
  curl -fsSL https://raw.githubusercontent.com/MrMarsellus/defcon-node-inspector/refs/heads/main/defcon-node-inspector.sh \
    -o /tmp/defcon-node-inspector.sh &&
  chmod +x /tmp/defcon-node-inspector.sh &&
  /tmp/defcon-node-inspector.sh install &&
  /usr/local/bin/defcon-node-inspector menu
'
```

```bash
sudo /usr/local/bin/defcon-node-inspector menu
```

## What it analyzes

The tool combines public RPC data to detect:

- problematic nodes
- reused operator keys
- shared service IP clusters
- suspicious subnet clusters
- mismatches between `masternodelist` service and `protx info` service
- recent PoSe ban waves
- community contact targets based on public node evidence

## Quick workflow

- Start the script
- Run **Check requirements** first
- Run **Run one-time analysis** for an immediate snapshot
- Or use **Start background analysis** to collect historical data
- Review reports in `/var/lib/defcon-node-inspector/reports/`

## Menu functions

- Check requirements
- Run one-time analysis
- Start background analysis
- Stop background analysis
- Show status
- Show latest report
- Show problem nodes
- Show suspect clusters
- Show PoSe ban waves
- Show community contact list
- Show report/log paths
- Delete all stored data

## Main report outputs

The script writes reports to:

`/var/lib/defcon-node-inspector/reports/`

Important files include:

- `latest-summary.txt`
- `latest-report.html`
- `all-nodes.csv`
- `problem-nodes.csv`
- `suspect-operator-clusters.json`
- `suspect-ip-clusters.json`
- `suspect-subnet-clusters.json`
- `pose-ban-waves.json`
- `community-contact-list.csv`
- `community-contact-list.json`

## Default paths

The script uses these defaults:

- CLI: `/usr/local/bin/defcon-cli`
- Daemon: `/usr/local/bin/defcond`
- Config: `/home/defcon/.defcon/defcon.conf`
- RPC port: `8193`

## Notes

- The script can be useful even if you do not control all affected nodes directly.
- It is designed to identify publicly visible evidence that helps you contact operators of suspicious or affected nodes.
- Operator-key reuse and clustered PoSe bans are especially important indicators in deterministic masternode setups.

If you prefer not to use the one-liner, you can also copy only the `defcon-node-inspector.sh` file to the VPS and run it directly with:

```bash
sudo bash defcon-node-inspector.sh
```
