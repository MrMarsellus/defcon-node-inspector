#!/usr/bin/env bash
set -euo pipefail

APP_NAME="defcon-node-inspector"
APP_DIR="/opt/${APP_NAME}"
STATE_DIR="/var/lib/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
RUNNER_PATH="${APP_DIR}/runner.sh"
ANALYZER_PATH="${APP_DIR}/analyzer.py"
MENU_LINK="/usr/local/bin/${APP_NAME}"
PID_FILE="${STATE_DIR}/${APP_NAME}.pid"
NOHUP_LOG="${LOG_DIR}/nohup.log"

DEFAULT_DEFCON_USER="defcon"
DEFAULT_DEFCON_HOME="/home/defcon"
DEFAULT_DATA_DIR="/home/defcon/.defcon"
DEFAULT_CONF_FILE="/home/defcon/.defcon/defcon.conf"
DEFAULT_CLI="/usr/local/bin/defcon-cli"
DEFAULT_DAEMON="/usr/local/bin/defcond"
DEFAULT_SERVICE="defcond"
DEFAULT_PORT="8192"
DEFAULT_INTERVAL="600"
DEFAULT_DEEP_SCAN="1"

DEFCON_USER="${DEFCON_USER:-$DEFAULT_DEFCON_USER}"
DEFCON_HOME="${DEFCON_HOME:-$DEFAULT_DEFCON_HOME}"
DATA_DIR="${DATA_DIR:-$DEFAULT_DATA_DIR}"
CONF_FILE="${CONF_FILE:-$DEFAULT_CONF_FILE}"
CLI_BIN="${CLI_BIN:-$DEFAULT_CLI}"
DAEMON_BIN="${DAEMON_BIN:-$DEFAULT_DAEMON}"
DEFCON_SERVICE="${DEFCON_SERVICE:-$DEFAULT_SERVICE}"
DEFCON_PORT="${DEFCON_PORT:-$DEFAULT_PORT}"
RUN_INTERVAL="${RUN_INTERVAL:-$DEFAULT_INTERVAL}"
DEEP_SCAN="${DEEP_SCAN:-$DEFAULT_DEEP_SCAN}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
mkdir_p() { mkdir -p "$1"; }
need_root() { [[ ${EUID} -eq 0 ]] || { echo -e "${RED}Please run as root: sudo bash $0${NC}"; exit 1; }; }
info() { echo -e "${BLUE}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*"; }

write_env() {
cat > "${APP_DIR}/env.sh" <<ENV
APP_NAME="${APP_NAME}"
APP_DIR="${APP_DIR}"
STATE_DIR="${STATE_DIR}"
LOG_DIR="${LOG_DIR}"
DEFAULT_DEFCON_USER="${DEFAULT_DEFCON_USER}"
DEFAULT_DEFCON_HOME="${DEFAULT_DEFCON_HOME}"
DEFAULT_DATA_DIR="${DEFAULT_DATA_DIR}"
DEFAULT_CONF_FILE="${DEFAULT_CONF_FILE}"
DEFAULT_CLI="${DEFAULT_CLI}"
DEFAULT_DAEMON="${DEFAULT_DAEMON}"
DEFAULT_SERVICE="${DEFAULT_SERVICE}"
DEFAULT_PORT="${DEFAULT_PORT}"
DEFCON_USER="${DEFCON_USER}"
DEFCON_HOME="${DEFCON_HOME}"
DATA_DIR="${DATA_DIR}"
CONF_FILE="${CONF_FILE}"
CLI_BIN="${CLI_BIN}"
DAEMON_BIN="${DAEMON_BIN}"
DEFCON_SERVICE="${DEFCON_SERVICE}"
DEFCON_PORT="${DEFCON_PORT}"
RUN_INTERVAL="${RUN_INTERVAL}"
DEEP_SCAN="${DEEP_SCAN}"
PID_FILE="${PID_FILE}"
NOHUP_LOG="${NOHUP_LOG}"
ENV
}

write_runner() {
cat > "${RUNNER_PATH}" <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail
source /opt/defcon-node-inspector/env.sh
mkdir -p "${STATE_DIR}/snapshots" "${STATE_DIR}/reports" "${LOG_DIR}"
while true; do
  python3 "${APP_DIR}/analyzer.py" --state-dir "${STATE_DIR}" --cli "${CLI_BIN}" --conf "${CONF_FILE}" --port "${DEFCON_PORT}" --deep-scan "${DEEP_SCAN}" >> "${LOG_DIR}/analyzer.log" 2>&1 || true
  sleep "${RUN_INTERVAL}"
done
RUNNER
chmod +x "${RUNNER_PATH}"
}

write_analyzer() {
cat > "${ANALYZER_PATH}" <<'PYEOF'
#!/usr/bin/env python3
import argparse, csv, datetime as dt, html, json, subprocess
from collections import defaultdict
from pathlib import Path


def run_cli(cli, *args):
    res = subprocess.run([cli] + list(args), capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"RPC error: {' '.join([cli] + list(args))}\n{res.stderr.strip()}")
    txt = res.stdout.strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return txt


def split_service(addr):
    if not addr:
        return None, None
    s = str(addr)
    if ':' not in s:
        return s, None
    ip, port = s.rsplit(':', 1)
    try:
        return ip, int(port)
    except Exception:
        return ip, port


def load_json(path, default):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return default
    return default


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=False))


def normalize_masternodelist(raw):
    rows = {}
    if isinstance(raw, dict):
        for outpoint, item in raw.items():
            if not isinstance(item, dict):
                continue
            service = item.get('address') or item.get('addr') or item.get('service')
            ip, port = split_service(service)
            protx = item.get('proTxHash') or item.get('protxHash')
            rows[protx or outpoint] = {
                'outpoint': outpoint,
                'protx_hash': protx,
                'service': service,
                'service_ip': ip,
                'service_port': port,
                'status': item.get('status'),
                'payee': item.get('payee'),
                'owner_address': item.get('owneraddress') or item.get('ownerAddress'),
                'operator_pubkey': item.get('pubkeyoperator') or item.get('operatorPubKey') or item.get('pubKeyOperator'),
                'voting_address': item.get('votingaddress') or item.get('votingAddress'),
                'lastpaidtime': item.get('lastpaidtime'),
                'lastpaidblock': item.get('lastpaidblock'),
                'source_masternodelist': True,
                'source_protx': False,
            }
    return rows


def normalize_protx(raw, rows):
    if not isinstance(raw, list):
        return rows
    for item in raw:
        if not isinstance(item, dict):
            continue
        protx = item.get('proTxHash') or item.get('protxHash') or item.get('hash')
        collateral_hash = item.get('collateralHash')
        collateral_index = item.get('collateralIndex')
        outpoint = f"{collateral_hash}-{collateral_index}" if collateral_hash is not None and collateral_index is not None else None
        service = item.get('service') or item.get('addr')
        ip, port = split_service(service)
        key = protx or outpoint or service
        row = rows.get(key, {
            'outpoint': outpoint,
            'protx_hash': protx,
            'service': service,
            'service_ip': ip,
            'service_port': port,
            'status': None,
            'payee': None,
            'owner_address': item.get('ownerAddress'),
            'operator_pubkey': item.get('pubKeyOperator'),
            'voting_address': item.get('votingAddress'),
            'lastpaidtime': None,
            'lastpaidblock': None,
            'source_masternodelist': False,
            'source_protx': True,
        })
        row['collateral_hash'] = collateral_hash
        row['collateral_index'] = collateral_index
        row['outpoint'] = row.get('outpoint') or outpoint
        row['protx_hash'] = row.get('protx_hash') or protx
        row['service'] = row.get('service') or service
        row['service_ip'] = row.get('service_ip') or ip
        row['service_port'] = row.get('service_port') or port
        row['owner_address'] = row.get('owner_address') or item.get('ownerAddress')
        row['operator_pubkey'] = row.get('operator_pubkey') or item.get('pubKeyOperator')
        row['voting_address'] = row.get('voting_address') or item.get('votingAddress')
        row['source_protx'] = True
        rows[key] = row
    return rows


def deep_scan(rows, cli, enabled):
    if str(enabled) not in ('1', 'true', 'True', 'yes', 'on'):
        return rows
    for row in rows.values():
        protx = row.get('protx_hash')
        if not protx:
            continue
        try:
            info = run_cli(cli, 'protx', 'info', protx)
            row['protx_info'] = info
            if isinstance(info, dict):
                state = info.get('state', {}) if isinstance(info.get('state'), dict) else {}
                registered_service = state.get('service') or info.get('service')
                reg_ip, reg_port = split_service(registered_service)
                row['registered_service'] = registered_service
                row['registered_service_ip'] = reg_ip
                row['registered_service_port'] = reg_port
                row['registered_owner_address'] = state.get('ownerAddress') or info.get('ownerAddress')
                row['registered_voting_address'] = state.get('votingAddress') or info.get('votingAddress')
                row['registered_operator_pubkey'] = state.get('pubKeyOperator') or state.get('operatorPubKey') or info.get('pubKeyOperator')
        except Exception as e:
            row['protx_info_error'] = str(e)
    return rows


def build_indexes(rows):
    by_owner, by_operator, by_ip = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in rows:
        if row.get('owner_address'):
            by_owner[row['owner_address']].append(row)
        if row.get('operator_pubkey'):
            by_operator[row['operator_pubkey']].append(row)
        if row.get('service_ip'):
            by_ip[row['service_ip']].append(row)
    return by_owner, by_operator, by_ip


def assess_node(row, by_owner, by_operator, by_ip, history):
    problems, fixes = [], []
    confidence, score = 'low', 0
    status = (row.get('status') or '').upper()
    node_id = row.get('protx_hash') or row.get('outpoint') or row.get('service') or 'unknown'
    hist = history.get(node_id, {})

    if status == 'POSE_BANNED':
        problems.append('Node is currently POSE_BANNED.')
        fixes.append('Check service IP/port, firewall, and the ProTx service address; after fixing, use protx update_service or restart if needed.')
        score += 100; confidence = 'high'
    elif status and status != 'ENABLED':
        problems.append(f'Node status is not ENABLED but {status}.')
        fixes.append('Check the root cause of the status; verify sync, reachability, and role/key assignment.')
        score += 30

    op = row.get('operator_pubkey')
    if op and len(by_operator.get(op, [])) > 1:
        problems.append(f'Operator key is used by {len(by_operator[op])} nodes.')
        fixes.append('Use a unique operator/BLS key for each node and compare the affected ProTx and node configurations.')
        score += 70; confidence = 'high'

    ip = row.get('service_ip')
    if ip and len(by_ip.get(ip, [])) > 1:
        problems.append(f'The same service IP is used by {len(by_ip[ip])} nodes.')
        fixes.append('Check whether the same external IP was accidentally registered multiple times or whether a NAT/copy-paste mistake exists.')
        score += 50
        if confidence != 'high': confidence = 'medium'

    owner = row.get('owner_address')
    if owner and owner in by_owner:
        total = len(by_owner[owner])
        banned = sum(1 for x in by_owner[owner] if (x.get('status') or '').upper() == 'POSE_BANNED')
        if total >= 2 and banned >= max(2, total // 2):
            problems.append(f'Owner address has {banned} of {total} nodes in POSE_BANNED state.')
            fixes.append('Review all nodes of this owner together: compare external IP, ProTx service address, operator key, and collateral mapping.')
            score += 40
            if confidence == 'low': confidence = 'medium'

    if row.get('source_protx') and not row.get('source_masternodelist'):
        problems.append('Node appears in protx list valid but not cleanly in masternodelist json.')
        fixes.append('Check node status, sync state, and registration; the local node may not be fully synced yet or the entry may be inconsistent.')
        score += 25

    reg_service = row.get('registered_service')
    if reg_service and row.get('service') and reg_service != row.get('service'):
        problems.append(f"Mismatch between masternodelist service ({row.get('service')}) and protx info service ({reg_service}).")
        fixes.append('Compare the ProTx service address with the running node configuration; if the registration is wrong, use protx update_service if needed.')
        score += 55
        if confidence == 'low': confidence = 'medium'

    reg_owner = row.get('registered_owner_address')
    if reg_owner and row.get('owner_address') and reg_owner != row.get('owner_address'):
        problems.append('Owner-Adresse aus protx info weicht of masternodelist ab.')
        fixes.append('Check owner mapping; compare local view, registration, and any fork-specific field names.')
        score += 30

    reg_op = row.get('registered_operator_pubkey')
    if reg_op and row.get('operator_pubkey') and reg_op != row.get('operator_pubkey'):
        problems.append('Operator-Key aus protx info weicht of masternodelist ab.')
        fixes.append('Check operator/BLS key and ProTx data; when the operator changed, verify the order of ProUpRegTx and ProUpServTx.')
        score += 45
        if confidence == 'low': confidence = 'medium'

    prev_status = hist.get('last_status')
    flips = hist.get('flips', 0)
    if prev_status and status and prev_status != status:
        flips += 1
    if flips >= 3:
        problems.append(f'Node shows status flapping with already {flips} status changes in history.')
        fixes.append('Check for instability: network issues, restarts, wrong service IP, or inconsistent masternode configuration.')
        score += 35
        if confidence == 'low': confidence = 'medium'

    history[node_id] = {'last_status': status, 'flips': flips, 'last_seen': dt.datetime.utcnow().isoformat() + 'Z'}
    row['problem_score'] = score
    row['confidence'] = confidence
    row['problems'] = problems
    row['recommended_fix'] = fixes
    row['is_problematic'] = bool(problems)
    return row


def esc(v):
    return html.escape('' if v is None else str(v))


def write_text_report(path, summary, problem_nodes, owner_groups, operator_groups, ip_groups):
    lines = [
        'DeFCoN Node Inspector Report',
        '================================',
        f"Timestamp UTC: {summary['timestamp']}",
        f"Total nodes: {summary['total_nodes']}",
        f"Problematic nodes: {summary['problem_nodes']}",
        f"POSE_BANNED: {summary['pose_banned']}",
        '', 'Problem nodes', '--------------------------------'
    ]
    for row in problem_nodes:
        lines.append(f"Node: {row.get('protx_hash') or row.get('outpoint') or row.get('service')}")
        lines.append(f"  Status: {row.get('status')}")
        lines.append(f"  Service: {row.get('service')}")
        lines.append(f"  Owner: {row.get('owner_address')}")
        lines.append(f"  Operator: {row.get('operator_pubkey')}")
        lines.append(f"  Confidence: {row.get('confidence')} | Score: {row.get('problem_score')}")
        for p in row.get('problems', []): lines.append(f"  Problem: {p}")
        for f in row.get('recommended_fix', []): lines.append(f"  Fix: {f}")
        lines.append('')
    lines += ['', 'Suspicious owner groups', '--------------------------------']
    for item in owner_groups:
        lines.append(f"{item['owner_address']} -> {item['pose_banned']}/{item['total_nodes']} POSE_BANNED")
    lines += ['', 'Reused operator keys', '--------------------------------']
    for key, items in operator_groups.items():
        ids = ', '.join([x.get('protx_hash') or x.get('outpoint') or '?' for x in items])
        lines.append(f"{key} -> {len(items)} Nodes -> {ids}")
    lines += ['', 'Reused service IPs', '--------------------------------']
    for key, items in ip_groups.items():
        ids = ', '.join([x.get('protx_hash') or x.get('outpoint') or '?' for x in items])
        lines.append(f"{key} -> {len(items)} Nodes -> {ids}")
    path.write_text('\n'.join(lines))


def write_html_report(path, summary, problem_nodes, owner_groups, operator_groups, ip_groups):
    cards = []
    for title, value, cls in [
        ('Gesamtzahl Nodes', summary['total_nodes'], 'neutral'),
        ('Problematische Nodes', summary['problem_nodes'], 'warn'),
        ('POSE_BANNED', summary['pose_banned'], 'bad'),
        ('Operator-Dubletten', summary['duplicate_operator_groups'], 'warn'),
        ('IP-Dubletten', summary['duplicate_ip_groups'], 'warn'),
    ]:
        cards.append(f'<div class="card {cls}"><div class="label">{esc(title)}</div><div class="value">{esc(value)}</div></div>')

    rows_html = []
    for r in problem_nodes:
        problems = ''.join(f'<li>{esc(x)}</li>' for x in r.get('problems', []))
        fixes = ''.join(f'<li>{esc(x)}</li>' for x in r.get('recommended_fix', []))
        rows_html.append(f'''
        <div class="node">
          <h3>{esc(r.get('protx_hash') or r.get('outpoint') or r.get('service'))}</h3>
          <div class="meta">
            <span>Status: {esc(r.get('status'))}</span>
            <span>Service: {esc(r.get('service'))}</span>
            <span>Confidence: {esc(r.get('confidence'))}</span>
            <span>Score: {esc(r.get('problem_score'))}</span>
          </div>
          <p><strong>Owner:</strong> {esc(r.get('owner_address'))}<br><strong>Operator:</strong> {esc(r.get('operator_pubkey'))}</p>
          <div class="cols">
            <div><h4>Why suspicious</h4><ul>{problems}</ul></div>
            <div><h4>What to change</h4><ul>{fixes}</ul></div>
          </div>
        </div>
        ''')

    owner_html = ''.join(f'<li>{esc(x["owner_address"])} -> {esc(x["pose_banned"])} / {esc(x["total_nodes"])} POSE_BANNED</li>' for x in owner_groups)
    op_html = ''.join(f'<li>{esc(k)} -> {esc(len(v))} Nodes</li>' for k, v in operator_groups.items())
    ip_html = ''.join(f'<li>{esc(k)} -> {esc(len(v))} Nodes</li>' for k, v in ip_groups.items())

    html_doc = f'''<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeFCoN Node Inspector Report</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1220; --panel:#121a2b; --panel2:#1a2438; --text:#e8eefc; --muted:#9cb0d1; --good:#1fb981; --warn:#f3b54a; --bad:#ef5b5b; --blue:#5aa9ff; }}
body {{ margin:0; font-family:Arial,sans-serif; background:var(--bg); color:var(--text); }}
.wrap {{ max-width:1200px; margin:0 auto; padding:24px; }}
h1,h2,h3,h4 {{ margin:0 0 12px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:18px 0 28px; }}
.card,.node,.panel {{ background:var(--panel); border:1px solid #26324c; border-radius:14px; padding:16px; box-shadow:0 8px 30px rgba(0,0,0,.25); }}
.card.warn {{ border-color:#7a5a18; }} .card.bad {{ border-color:#7a2222; }} .card.neutral {{ border-color:#294266; }}
.label {{ color:var(--muted); font-size:13px; margin-bottom:8px; }} .value {{ font-size:30px; font-weight:bold; }}
.meta {{ display:flex; flex-wrap:wrap; gap:12px; color:var(--muted); font-size:14px; margin-bottom:10px; }}
.cols {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
ul {{ margin:8px 0 0 18px; }}
.section {{ margin-top:30px; }}
.smallgrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; }}
@media (max-width: 800px) {{ .cols {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>DeFCoN Node Inspector</h1>
  <p>Snapshot UTC: {esc(summary['timestamp'])}</p>
  <div class="grid">{''.join(cards)}</div>
  <div class="section">
    <h2>Problem nodes</h2>
    {''.join(rows_html) if rows_html else '<div class="panel">None problematischen Nodes gefunden.</div>'}
  </div>
  <div class="section smallgrid">
    <div class="panel"><h2>Verdächtige Owner</h2><ul>{owner_html or '<li>None</li>'}</ul></div>
    <div class="panel"><h2>Operator-Dubletten</h2><ul>{op_html or '<li>None</li>'}</ul></div>
    <div class="panel"><h2>Service-IP-Dubletten</h2><ul>{ip_html or '<li>None</li>'}</ul></div>
  </div>
</div>
</body>
</html>'''
    path.write_text(html_doc)


def write_csv(path, rows):
    cols = ['protx_hash','outpoint','service','registered_service','service_ip','service_port','status','owner_address','registered_owner_address','operator_pubkey','registered_operator_pubkey','voting_address','payee','lastpaidtime','lastpaidblock','problem_score','confidence','is_problematic','problems','recommended_fix']
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for row in rows:
            x = {k: row.get(k) for k in cols}
            x['problems'] = ' | '.join(row.get('problems', []))
            x['recommended_fix'] = ' | '.join(row.get('recommended_fix', []))
            w.writerow(x)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--state-dir', required=True)
    ap.add_argument('--cli', required=True)
    ap.add_argument('--conf')
    ap.add_argument('--port')
    ap.add_argument('--deep-scan', default='1')
    args = ap.parse_args()

    state_dir = Path(args.state_dir)
    snapshots_dir = state_dir / 'snapshots'
    reports_dir = state_dir / 'reports'
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    history_path = state_dir / 'history.json'
    history = load_json(history_path, {})
    timestamp = dt.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

    try:
        mn = run_cli(args.cli, 'masternodelist', 'json')
        protx = run_cli(args.cli, 'protx', 'list', 'valid', '1')
    except Exception as e:
        (reports_dir / 'latest-error.txt').write_text(str(e) + '\n')
        raise

    rows = normalize_protx(protx, normalize_masternodelist(mn))
    rows = deep_scan(rows, args.cli, args.deep_scan)
    assessed = list(rows.values())
    by_owner, by_operator, by_ip = build_indexes(assessed)
    assessed = [assess_node(r, by_owner, by_operator, by_ip, history) for r in assessed]
    assessed.sort(key=lambda x: (not x.get('is_problematic'), -x.get('problem_score', 0), x.get('service') or ''))
    problem_nodes = [r for r in assessed if r.get('is_problematic')]
    pose_banned = [r for r in assessed if (r.get('status') or '').upper() == 'POSE_BANNED']
    owner_groups = []
    for owner, items in by_owner.items():
        banned = sum(1 for x in items if (x.get('status') or '').upper() == 'POSE_BANNED')
        if banned > 0:
            owner_groups.append({'owner_address': owner, 'total_nodes': len(items), 'pose_banned': banned})
    owner_groups.sort(key=lambda x: (-x['pose_banned'], -x['total_nodes']))
    operator_groups = {k: v for k, v in by_operator.items() if len(v) > 1}
    ip_groups = {k: v for k, v in by_ip.items() if len(v) > 1}
    summary = {
        'timestamp': timestamp,
        'total_nodes': len(assessed),
        'problem_nodes': len(problem_nodes),
        'pose_banned': len(pose_banned),
        'duplicate_operator_groups': len(operator_groups),
        'duplicate_ip_groups': len(ip_groups),
        'owner_groups_with_bans': len(owner_groups),
    }

    save_json(snapshots_dir / f'snapshot-{timestamp}.json', assessed)
    save_json(reports_dir / 'latest-summary.json', summary)
    save_json(reports_dir / 'problem nodes.json', problem_nodes)
    save_json(reports_dir / 'owner-groups.json', owner_groups)
    save_json(reports_dir / 'duplicate-operators.json', operator_groups)
    save_json(reports_dir / 'duplicate-ips.json', ip_groups)
    write_csv(reports_dir / 'problem nodes.csv', problem_nodes)
    write_text_report(reports_dir / 'latest-summary.txt', summary, problem_nodes, owner_groups, operator_groups, ip_groups)
    write_html_report(reports_dir / 'latest-report.html', summary, problem_nodes, owner_groups, operator_groups, ip_groups)
    save_json(history_path, history)
    print(json.dumps(summary))

if __name__ == '__main__':
    main()
PYEOF
chmod +x "${ANALYZER_PATH}"
}

write_service() {
cat > "${SERVICE_FILE}" <<SERVICE
[Unit]
Description=DeFCoN Node Inspector background analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${RUNNER_PATH}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
}

show_reports() {
  source "${APP_DIR}/env.sh"
  local report="${STATE_DIR}/reports/latest-summary.txt"
  [[ -f "$report" ]] && sed -n '1,240p' "$report" || warn "No report available yet."
}

show_problem_nodes_json() {
  source "${APP_DIR}/env.sh"
  local file="${STATE_DIR}/reports/problem nodes.json"
  if [[ -f "$file" ]]; then
    python3 - <<PY
import json
from pathlib import Path
p = Path("${STATE_DIR}/reports/problem nodes.json")
rows = json.loads(p.read_text())
if not rows:
    print("None problematischen Nodes gefunden.")
else:
    for i, r in enumerate(rows, 1):
        print(f"[{i}] {(r.get('protx_hash') or r.get('outpoint') or r.get('service'))}")
        print(f"  Status: {r.get('status')}")
        print(f"  Service: {r.get('service')}")
        print(f"  Owner: {r.get('owner_address')}")
        print(f"  Operator: {r.get('operator_pubkey')}")
        print(f"  Confidence: {r.get('confidence')} | Score: {r.get('problem_score')}")
        for x in r.get('problems', []): print(f"  Problem: {x}")
        for x in r.get('recommended_fix', []): print(f"  Fix: {x}")
        print()
PY
  else
    warn "No problem node list available yet."
  fi
}

run_once() {
  source "${APP_DIR}/env.sh"
  mkdir -p "${STATE_DIR}/snapshots" "${STATE_DIR}/reports" "${LOG_DIR}"
  python3 "${APP_DIR}/analyzer.py" --state-dir "${STATE_DIR}" --cli "${CLI_BIN}" --conf "${CONF_FILE}" --port "${DEFCON_PORT}" --deep-scan "${DEEP_SCAN}" | tee -a "${LOG_DIR}/manual-run.log"
}

check_requirements() {
  source "${APP_DIR}/env.sh"
  info "Checking requirements..."
  [[ -x "${CLI_BIN}" ]] && ok "CLI found: ${CLI_BIN}" || err "CLI not found: ${CLI_BIN}"
  [[ -x "${DAEMON_BIN}" ]] && ok "Daemon found: ${DAEMON_BIN}" || err "Daemon not found: ${DAEMON_BIN}"
  [[ -f "${CONF_FILE}" ]] && ok "Config found: ${CONF_FILE}" || err "Config not found: ${CONF_FILE}"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${DEFCON_SERVICE}"; then ok "Service ${DEFCON_SERVICE} is running"; else warn "Service ${DEFCON_SERVICE} is running nicht"; fi
  fi
  if [[ -x "${CLI_BIN}" ]]; then
    set +e; "${CLI_BIN}" getblockcount >/dev/null 2>&1
    [[ $? -eq 0 ]] && ok "RPC responds to getblockcount" || warn "RPC does not respond to getblockcount"
    set -e
  fi
}

start_background() {
  source "${APP_DIR}/env.sh"
  mkdir -p "${LOG_DIR}" "${STATE_DIR}"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "${APP_NAME}.service"
    ok "Background analysis started via systemd."
  else
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then warn "Analyse is running bereits mit PID $(cat "${PID_FILE}")"; return; fi
    nohup "${RUNNER_PATH}" >> "${NOHUP_LOG}" 2>&1 &
    echo $! > "${PID_FILE}"
    ok "Background analysis started via nohup. PID $(cat "${PID_FILE}")"
  fi
}

stop_background() {
  source "${APP_DIR}/env.sh"
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${APP_NAME}.service"; then systemctl stop "${APP_NAME}.service" || true; ok "Background analysis stopped."; fi
  if [[ -f "${PID_FILE}" ]]; then
    pid="$(cat "${PID_FILE}")"
    kill -0 "$pid" 2>/dev/null && kill "$pid" || true
    rm -f "${PID_FILE}"
  fi
}

status_background() {
  source "${APP_DIR}/env.sh"
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${APP_NAME}.service"; then
    systemctl --no-pager --full status "${APP_NAME}.service" || true
  elif [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    info "Running via nohup with PID $(cat "${PID_FILE}")"
  else
    warn "None laufende Hintergrund-Analyse gefunden."
  fi
}

show_paths() {
  source "${APP_DIR}/env.sh"
  cat <<PATHS
APP_DIR: ${APP_DIR}
STATE_DIR: ${STATE_DIR}
LOG_DIR: ${LOG_DIR}
Reports: ${STATE_DIR}/reports
HTML report: ${STATE_DIR}/reports/latest-report.html
Snapshots: ${STATE_DIR}/snapshots
Logs: ${LOG_DIR}
PATHS
}

wipe_all_data() {
  source "${APP_DIR}/env.sh"
  echo
  warn "This will delete ALL stored snapshots, reports, logs, and history for ${APP_NAME}."
  read -rp "Type DELETE exactly to confirm: " confirm
  if [[ "$confirm" == "DELETE" ]]; then
    rm -rf "${STATE_DIR:?}/snapshots"/* "${STATE_DIR:?}/reports"/* "${LOG_DIR:?}"/*
    rm -f "${STATE_DIR}/history.json" "${STATE_DIR}/latest-error.txt" "${PID_FILE}"
    ok "All stored data has been deleted."
  else
    warn "Cancelled."
  fi
}

menu() {
  while true; do
    echo
    echo -e "${BLUE}===============================${NC}"
    echo -e "${BLUE} DeFCoN Node Inspector v2${NC}"
    echo -e "${BLUE}===============================${NC}"
    echo "1) Check requirements"
    echo "2) Run one-time analysis"
    echo "3) Start background analysis"
    echo "4) Stop background analysis"
    echo "5) Show status"
    echo "6) Show latest report"
    echo "7) Problem nodes anzeigen"
    echo "8) Show report/log paths"
    echo "9) Delete all stored data"
    echo "0) Exit"
    echo
    read -rp "Selection: " choice
    case "$choice" in
      1) check_requirements ;;
      2) run_once ;;
      3) start_background ;;
      4) stop_background ;;
      5) status_background ;;
      6) show_reports ;;
      7) show_problem_nodes_json ;;
      8) show_paths ;;
      9) wipe_all_data ;;
      0) exit 0 ;;
      *) warn "Invalid selection." ;;
    esac
  done
}

install_app() {
  need_root
  mkdir_p "${APP_DIR}"; mkdir_p "${STATE_DIR}/snapshots"; mkdir_p "${STATE_DIR}/reports"; mkdir_p "${LOG_DIR}"
  write_env; write_runner; write_analyzer; write_service
  ln -sf "$0" "${MENU_LINK}"
  chmod +x "$0"
  ok "Installation completed."
}

usage() {
cat <<USAGE
Usage:
  bash defcon-node-inspector.sh                # installs on first run and shows the menu
  bash defcon-node-inspector.sh menu
  bash defcon-node-inspector.sh install
  bash defcon-node-inspector.sh run-once
  bash defcon-node-inspector.sh start
  bash defcon-node-inspector.sh stop
  bash defcon-node-inspector.sh status
  bash defcon-node-inspector.sh report
  bash defcon-node-inspector.sh problems
  bash defcon-node-inspector.sh wipe
USAGE
}

main() {
  cmd="${1:-menu}"
  if [[ ! -f "${APP_DIR}/env.sh" ]]; then echo "${APP_NAME} wird installiert..."; install_app; fi
  case "$cmd" in
    install) install_app ;;
    menu) menu ;;
    run-once) run_once ;;
    start) start_background ;;
    stop) stop_background ;;
    status) status_background ;;
    report) show_reports ;;
    problems) show_problem_nodes_json ;;
    wipe) wipe_all_data ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
