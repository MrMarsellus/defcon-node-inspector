# DeFCoN Network Inspector

`defcon-network-inspector` is a VPS tool for analyzing DeFCoN masternodes over RPC from a network-wide perspective. It checks `masternodelist`, `protx list valid`, and optionally `protx info`, then correlates public node data to identify problematic nodes, suspicious operator-key reuse, shared IP clusters, subnet clusters, service mismatches, and PoSe ban waves.

The goal is not only to inspect your own node, but also to identify publicly visible patterns across the network so affected operators can be contacted in the community.

## Main command

The recommended one-liner to download and run the script is:

```bash
sudo bash -c '
  curl -fsSL https://raw.githubusercontent.com/MrMarsellus/defcon-network-inspector/refs/heads/main/defcon-network-inspector.sh \
    -o /tmp/defcon-network-inspector.sh &&
  chmod +x /tmp/defcon-network-inspector.sh &&
  /tmp/defcon-network-inspector.sh install &&
  /usr/local/bin/defcon-network-inspector menu
'
```

You can start the menu later with:

```bash
sudo /usr/local/bin/defcon-network-inspector menu
```

If you prefer not to use the one-liner, you can also copy only the `defcon-network-inspector.sh` file to the VPS and run it directly with:

```bash
sudo bash defcon-network-inspector.sh
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

- Start the script.
- Run **Check requirements** first.
- Run **Run one-time analysis** for an immediate snapshot.
- Or use **Start background analysis** to collect historical data.
- Review reports in `/var/lib/defcon-network-inspector/reports/`.

## Menu functions

The menu currently provides these functions:

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

## Runtime behavior in v2

The v2 release adds safer background operation and bounded history handling.

- The systemd service runs as the configured `DEFCON_USER`.
- Historical node data in `history.json` is retained for 30 days by default.
- `history.json` includes a `_meta` section with pruning metadata.
- RPC calls use a timeout so stuck CLI calls do not hang the analyzer indefinitely.
- Repeated analyzer failures are counted and the runner exits after multiple consecutive failures so systemd can restart it cleanly.
- A health state file is written to `/var/lib/defcon-network-inspector/health.json`.
- If `history.json` becomes corrupt, the tool attempts to preserve it as a timestamped `.corrupt-*` backup before rebuilding a clean history file.
- The analyzer keeps snapshots and generated reports bounded by retention settings.
- The background runner rotates `analyzer.log` when it exceeds the configured size limit and deletes old log files by age.

## Main report outputs

The script writes reports to:

`/var/lib/defcon-network-inspector/reports/`

Important files include:

- `latest-summary.txt`
- `latest-summary.json`
- `latest-report.html`
- `latest-error.txt`
- `all-nodes.json`
- `all-nodes.csv`
- `problem-nodes.json`
- `problem-nodes.csv`
- `suspect-operator-clusters.json`
- `suspect-ip-clusters.json`
- `suspect-subnet-clusters.json`
- `pose-ban-waves.json`
- `community-contact-list.json`
- `community-contact-list.csv`

Download:

```bash
scp USER@HOST:/var/lib/defcon-network-inspector/reports/latest-report.html .
```

## State and health files

The script also stores runtime state under:

`/var/lib/defcon-network-inspector/`

Important state files include:

- `history.json`
- `health.json`
- `run.lock`

Snapshots are stored in:

`/var/lib/defcon-network-inspector/snapshots/`

## Logs

Runtime logs are stored under:

`/var/log/defcon-network-inspector/`

Important log files can include:

- `analyzer.log` for background analyzer output
- `manual-run.log` for one-time manual runs
- `nohup.log` when running without systemd fallback

The runner rotates `analyzer.log` when it reaches the configured size limit and removes older log files based on retention settings.

## Default paths

The script uses these defaults:

- CLI: `/usr/local/bin/defcon-cli`
- Daemon: `/usr/local/bin/defcond`
- Config: `/home/defcon/.defcon/defcon.conf`
- Data directory: `/home/defcon/.defcon`
- RPC port: `8193`

## Additional defaults in v2

The script also uses these runtime defaults:

- Background interval: `600` seconds
- Deep scan: `1`
- PoSe wave window: `1800` seconds
- History retention: `30` days
- Snapshot retention: `30` days
- Report retention: `30` days
- Log retention: `14` days
- RPC timeout: `30` seconds
- Max consecutive analyzer failures: `5`
- Max analyzer log size before rotation: `25` MB

## Notes

- The script can be useful even if you do not control all affected nodes directly.
- It is designed to identify publicly visible evidence that helps you contact operators of suspicious or affected nodes.
- Operator-key reuse and clustered PoSe bans are especially important indicators in deterministic masternode setups.
- The heuristics are intentionally aggressive and are meant to surface suspicious public patterns for manual review, not to serve as final proof on their own.

## Typical directories created

During installation and runtime, the script uses these directories:

- `/opt/defcon-network-inspector`
- `/var/lib/defcon-network-inspector`
- `/var/log/defcon-network-inspector`

## Operational note

For systemd-based systems, the background service is installed as:

`/etc/systemd/system/defcon-network-inspector.service`

The runtime environment file is stored at:

`/opt/defcon-network-inspector/env.sh`

The menu symlink is installed at:

`/usr/local/bin/defcon-network-inspector`

## Service hardening

On systemd-based systems, the service uses several hardening-related options in its unit definition, including:

- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `ProtectSystem=full`
- `ProtectHome=read-only`
- `ReadWritePaths=/var/lib/defcon-network-inspector /var/log/defcon-network-inspector`
