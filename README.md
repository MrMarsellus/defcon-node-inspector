# DeFCoN Node Inspector

`defcon-node-inspector` is a VPS tool for analyzing DeFCoN masternodes over RPC. It checks `masternodelist`, `protx list valid`, and optionally `protx info`, identifies problematic nodes, and shows likely causes together with recommended fixes.

## Main command

The recommended one-liner to download and run the script is:

```bash
sudo bash -c 'curl -fsSL https://raw.githubusercontent.com/MrMarsellus/defcon-node-inspector/refs/heads/main/defcon-node-inspector.sh -o /tmp/defcon-node-inspector.sh && chmod +x /tmp/defcon-node-inspector.sh && /tmp/defcon-node-inspector.sh menu'
```

## Quick workflow

- Start the script.
- In the menu, run “Check requirements” first.
- Then run either “Run one-time analysis” or “Start background analysis”.
- Reports will be written to `/var/lib/defcon-node-inspector/reports/`.

## Menu functions

- Check requirements
- Run one-time analysis
- Start/stop background analysis
- Show status
- Show latest evaluation and problem nodes
- Show report/log paths
- Delete all stored data

## Default paths

The script uses these defaults:

- CLI: `/usr/local/bin/defcon-cli`
- Daemon: `/usr/local/bin/defcond`
- Config: `/home/defcon/.defcon/defcon.conf`
- Port: `8192`

If you prefer not to use the one-liner, you can also copy only the `defcon-node-inspector.sh` file to the VPS and run it directly with `sudo bash defcon-node-inspector.sh`.
