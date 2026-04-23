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
LOCK_FILE="${STATE_DIR}/run.lock"

DEFAULT_DEFCON_USER="defcon"
DEFAULT_DEFCON_HOME="/home/defcon"
DEFAULT_DATA_DIR="/home/defcon/.defcon"
DEFAULT_CONF_FILE="/home/defcon/.defcon/defcon.conf"
DEFAULT_CLI="/usr/local/bin/defcon-cli"
DEFAULT_DAEMON="/usr/local/bin/defcond"
DEFAULT_SERVICE="defcond"
DEFAULT_RPC_PORT="8193"
DEFAULT_INTERVAL="600"
DEFAULT_DEEP_SCAN="1"
DEFAULT_WAVE_WINDOW_SECONDS="1800"

DEFCON_USER="${DEFCON_USER:-$DEFAULT_DEFCON_USER}"
DEFCON_HOME="${DEFCON_HOME:-$DEFAULT_DEFCON_HOME}"
DATA_DIR="${DATA_DIR:-$DEFAULT_DATA_DIR}"
CONF_FILE="${CONF_FILE:-$DEFAULT_CONF_FILE}"
CLI_BIN="${CLI_BIN:-$DEFAULT_CLI}"
DAEMON_BIN="${DAEMON_BIN:-$DEFAULT_DAEMON}"
DEFCON_SERVICE="${DEFCON_SERVICE:-$DEFAULT_SERVICE}"
DEFCON_RPC_PORT="${DEFCON_RPC_PORT:-$DEFAULT_RPC_PORT}"
RUN_INTERVAL="${RUN_INTERVAL:-$DEFAULT_INTERVAL}"
DEEP_SCAN="${DEEP_SCAN:-$DEFAULT_DEEP_SCAN}"
WAVE_WINDOW_SECONDS="${WAVE_WINDOW_SECONDS:-$DEFAULT_WAVE_WINDOW_SECONDS}"

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
LOCK_FILE="${LOCK_FILE}"
DEFAULT_DEFCON_USER="${DEFAULT_DEFCON_USER}"
DEFAULT_DEFCON_HOME="${DEFAULT_DEFCON_HOME}"
DEFAULT_DATA_DIR="${DEFAULT_DATA_DIR}"
DEFAULT_CONF_FILE="${DEFAULT_CONF_FILE}"
DEFAULT_CLI="${DEFAULT_CLI}"
DEFAULT_DAEMON="${DEFAULT_DAEMON}"
DEFAULT_SERVICE="${DEFAULT_SERVICE}"
DEFAULT_RPC_PORT="${DEFAULT_RPC_PORT}"
DEFCON_USER="${DEFCON_USER}"
DEFCON_HOME="${DEFCON_HOME}"
DATA_DIR="${DATA_DIR}"
CONF_FILE="${CONF_FILE}"
CLI_BIN="${CLI_BIN}"
DAEMON_BIN="${DAEMON_BIN}"
DEFCON_SERVICE="${DEFCON_SERVICE}"
DEFCON_RPC_PORT="${DEFCON_RPC_PORT}"
RUN_INTERVAL="${RUN_INTERVAL}"
DEEP_SCAN="${DEEP_SCAN}"
WAVE_WINDOW_SECONDS="${WAVE_WINDOW_SECONDS}"
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
  (
    flock -n 9 || exit 0
    sudo -u "${DEFCON_USER}" python3 "${APP_DIR}/analyzer.py" \
      --state-dir "${STATE_DIR}" \
      --cli "${CLI_BIN}" \
      --conf "${CONF_FILE}" \
      --rpc-port "${DEFCON_RPC_PORT}" \
      --deep-scan "${DEEP_SCAN}" \
      --wave-window-seconds "${WAVE_WINDOW_SECONDS}" >> "${LOG_DIR}/analyzer.log" 2>&1 || true
  ) 9>"${LOCK_FILE}"
  sleep "${RUN_INTERVAL}"
done
RUNNER
chmod +x "${RUNNER_PATH}"
}

write_analyzer() {
cat > "${ANALYZER_PATH}" <<'PYEOF'
#!/usr/bin/env python3
import argparse, csv, datetime as dt, html, ipaddress, json, subprocess
from collections import defaultdict
from pathlib import Path


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def utc_iso(ts=None):
    ts = ts or utc_now()
    return ts.isoformat().replace('+00:00', 'Z')


def run_cli(cli, *args, conf=None, datadir=None, rpcport=None):
    cmd = [cli]
    if conf:
        cmd.append(f'-conf={conf}')
    if datadir:
        cmd.append(f'-datadir={datadir}')
    if rpcport:
        cmd.append(f'-rpcport={rpcport}')
    cmd += list(args)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"RPC error: {' '.join(cmd)}\n{res.stderr.strip()}")
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
    s = str(addr).strip()
    if s.startswith('[') and ']:' in s:
        host = s[1:s.rfind(']:')]
        port = s[s.rfind(']:') + 2:]
        try:
            return host, int(port)
        except Exception:
            return host, port
    if s.count(':') > 1 and not s.startswith('['):
        return s, None
    if ':' not in s:
        return s, None
    ip, port = s.rsplit(':', 1)
    try:
        return ip, int(port)
    except Exception:
        return ip, port


def subnet24(ip):
    if not ip:
        return None
    try:
        obj = ipaddress.ip_address(ip)
        if obj.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except Exception:
        return None


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
            key = protx or outpoint
            rows[key] = {
                'outpoint': outpoint,
                'protx_hash': protx,
                'service': service,
                'service_ip': ip,
                'service_port': port,
                'service_subnet': subnet24(ip),
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
            'service_subnet': subnet24(ip),
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
        row['service_subnet'] = row.get('service_subnet') or subnet24(ip)
        row['owner_address'] = row.get('owner_address') or item.get('ownerAddress')
        row['operator_pubkey'] = row.get('operator_pubkey') or item.get('pubKeyOperator')
        row['voting_address'] = row.get('voting_address') or item.get('votingAddress')
        row['source_protx'] = True
        rows[key] = row
    return rows


def deep_scan(rows, cli, enabled, conf=None, datadir=None, rpcport=None):
    if str(enabled).lower() not in ('1', 'true', 'yes', 'on'):
        return rows
    for row in rows.values():
        protx = row.get('protx_hash')
        if not protx:
            continue
        try:
            info = run_cli(cli, 'protx', 'info', protx, conf=conf, datadir=datadir, rpcport=rpcport)
            row['protx_info'] = info
            if isinstance(info, dict):
                state = info.get('state', {}) if isinstance(info.get('state'), dict) else {}
                registered_service = state.get('service') or info.get('service')
                reg_ip, reg_port = split_service(registered_service)
                row['registered_service'] = registered_service
                row['registered_service_ip'] = reg_ip
                row['registered_service_port'] = reg_port
                row['registered_service_subnet'] = subnet24(reg_ip)
                row['registered_owner_address'] = state.get('ownerAddress') or info.get('ownerAddress')
                row['registered_voting_address'] = state.get('votingAddress') or info.get('votingAddress')
                row['registered_operator_pubkey'] = state.get('pubKeyOperator') or state.get('operatorPubKey') or info.get('pubKeyOperator')
        except Exception as e:
            row['protx_info_error'] = str(e)
    return rows


def build_indexes(rows):
    by_owner, by_operator, by_ip, by_subnet = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for row in rows:
        if row.get('owner_address'):
            by_owner[row['owner_address']].append(row)
        if row.get('operator_pubkey'):
            by_operator[row['operator_pubkey']].append(row)
        if row.get('service_ip'):
            by_ip[row['service_ip']].append(row)
        if row.get('service_subnet'):
            by_subnet[row['service_subnet']].append(row)
    return by_owner, by_operator, by_ip, by_subnet


def update_history(history, row):
    node_id = row.get('protx_hash') or row.get('outpoint') or row.get('service') or 'unknown'
    now = utc_iso()
    status = (row.get('status') or '').upper()
    service = row.get('service')
    reg_service = row.get('registered_service')
    op = row.get('operator_pubkey')
    hist = history.get(node_id, {
        'first_seen': now,
        'last_seen': now,
        'last_status': status,
        'service_history': [],
        'registered_service_history': [],
        'pose_ban_events': [],
        'events': [],
    })

    prev_status = hist.get('last_status')
    prev_service = hist.get('service_history', [])[-1]['service'] if hist.get('service_history') else None
    prev_reg_service = hist.get('registered_service_history', [])[-1]['service'] if hist.get('registered_service_history') else None

    hist['last_seen'] = now

    if service and service != prev_service:
        hist.setdefault('service_history', []).append({'at': now, 'service': service})
    if reg_service and reg_service != prev_reg_service:
        hist.setdefault('registered_service_history', []).append({'at': now, 'service': reg_service})

    if prev_status != status:
        hist.setdefault('events', []).append({
            'at': now,
            'from_status': prev_status,
            'to_status': status,
            'service': service,
            'registered_service': reg_service,
            'operator_pubkey': op,
        })

    if status == 'POSE_BANNED':
        already = hist.get('pose_ban_events', [])
        if not already or already[-1].get('at') != now:
            if prev_status != 'POSE_BANNED':
                hist.setdefault('pose_ban_events', []).append({'at': now, 'service': service})

    hist['last_status'] = status
    history[node_id] = hist
    return hist


def assess_node(row, by_owner, by_operator, by_ip, by_subnet, history):
    problems, fixes = [], []
    score = 0
    evidence_level = 'weak'
    suspected_root_cause = 'unknown'

    status = (row.get('status') or '').upper()
    hist = update_history(history, row)

    if status == 'POSE_BANNED':
        problems.append('Node is currently POSE_BANNED.')
        fixes.append('Contact the operator of this node and verify the running node matches the registered ProTx service metadata.')
        score += 100
        evidence_level = 'moderate'

    op = row.get('operator_pubkey')
    if op and len(by_operator.get(op, [])) > 1:
        cnt = len(by_operator[op])
        banned = sum(1 for x in by_operator[op] if (x.get('status') or '').upper() == 'POSE_BANNED')
        problems.append(f'Operator key is reused by {cnt} nodes.')
        fixes.append('Very likely cloned or mispaired operator/masternode key material. Verify exactly one intended node per operator key.')
        score += 120
        suspected_root_cause = 'operator_key_reuse'
        evidence_level = 'strong'
        if banned >= 2:
            problems.append(f'Operator cluster has {banned} POSE_BANNED nodes.')
            fixes.append('This cluster is a high-priority candidate for wrong masternodeprivkey or operator-key pairing across nodes.')
            score += 80
            evidence_level = 'critical'

    ip = row.get('service_ip')
    if ip and len(by_ip.get(ip, [])) > 1:
        cnt = len(by_ip[ip])
        banned = sum(1 for x in by_ip[ip] if (x.get('status') or '').upper() == 'POSE_BANNED')
        problems.append(f'Same service IP is used by {cnt} nodes.')
        fixes.append('Check whether multiple nodes were accidentally registered to the same public IP or mapped incorrectly.')
        score += 45
        if banned >= 2 and evidence_level in ('weak', 'moderate'):
            evidence_level = 'strong'
            if suspected_root_cause == 'unknown':
                suspected_root_cause = 'shared_ip_conflict'

    subnet = row.get('service_subnet')
    if subnet and len(by_subnet.get(subnet, [])) >= 4:
        banned = sum(1 for x in by_subnet[subnet] if (x.get('status') or '').upper() == 'POSE_BANNED')
        total = len(by_subnet[subnet])
        if banned >= 3:
            problems.append(f'Service subnet {subnet} shows clustered bans ({banned}/{total}).')
            fixes.append('This may indicate shared infrastructure or a deployment template issue affecting multiple operators.')
            score += 40
            if evidence_level == 'weak':
                evidence_level = 'moderate'
            if suspected_root_cause == 'unknown':
                suspected_root_cause = 'ban_wave_cluster'

    reg_service = row.get('registered_service')
    if reg_service and row.get('service') and reg_service != row.get('service'):
        problems.append(f"Mismatch between masternodelist service ({row.get('service')}) and protx info service ({reg_service}).")
        fixes.append('Compare the public service currently announced by the node with the service stored in ProTx. Wrong mapping is likely.')
        score += 70
        if evidence_level == 'weak':
            evidence_level = 'moderate'
        if suspected_root_cause == 'unknown':
            suspected_root_cause = 'wrong_service_mapping'

    reg_op = row.get('registered_operator_pubkey')
    if reg_op and row.get('operator_pubkey') and reg_op != row.get('operator_pubkey'):
        problems.append('Operator key from protx info differs from masternodelist.')
        fixes.append('This inconsistency suggests stale local data, incomplete sync, or an operator update issue.')
        score += 50
        if evidence_level == 'weak':
            evidence_level = 'moderate'

    service_hist = hist.get('service_history', [])
    if len(service_hist) >= 3:
        problems.append(f'Node has changed service identity {len(service_hist)} times in stored history.')
        fixes.append('Frequent service changes should be reviewed; they often correlate with wrong deployment mapping or repeated reconfiguration.')
        score += 30
        if evidence_level == 'weak':
            evidence_level = 'moderate'

    owner = row.get('owner_address')
    if owner and len(by_owner.get(owner, [])) >= 2:
        banned = sum(1 for x in by_owner[owner] if (x.get('status') or '').upper() == 'POSE_BANNED')
        if banned >= 2:
            problems.append(f'Owner group has {banned} banned nodes.')
            fixes.append('Useful correlation signal, but operator-key and service mapping should be checked first.')
            score += 15

    row['problem_score'] = score
    row['evidence_level'] = evidence_level
    row['suspected_root_cause'] = suspected_root_cause
    row['problems'] = problems
    row['recommended_fix'] = fixes
    row['is_problematic'] = bool(problems)
    return row


def find_pose_ban_waves(rows, history, window_seconds=1800):
    events = []
    for row in rows:
        node_id = row.get('protx_hash') or row.get('outpoint') or row.get('service') or 'unknown'
        hist = history.get(node_id, {})
        for e in hist.get('pose_ban_events', []):
            try:
                at = dt.datetime.fromisoformat(e['at'].replace('Z', '+00:00'))
            except Exception:
                continue
            events.append({
                'at': at,
                'at_iso': e['at'],
                'node_id': node_id,
                'protx_hash': row.get('protx_hash'),
                'service_ip': row.get('service_ip'),
                'service_subnet': row.get('service_subnet'),
                'operator_pubkey': row.get('operator_pubkey'),
                'owner_address': row.get('owner_address'),
                'service': row.get('service'),
            })

    events.sort(key=lambda x: x['at'])
    waves = []
    used = set()

    for i, base in enumerate(events):
        if i in used:
            continue
        cluster = [base]
        for j in range(i + 1, len(events)):
            delta = (events[j]['at'] - base['at']).total_seconds()
            if delta > window_seconds:
                break
            cluster.append(events[j])

        unique_nodes = {}
        for item in cluster:
            unique_nodes[item['node_id']] = item
        cluster = list(unique_nodes.values())

        if len(cluster) >= 3:
            op_counts = defaultdict(int)
            subnet_counts = defaultdict(int)
            ips = []
            for item in cluster:
                if item.get('operator_pubkey'):
                    op_counts[item['operator_pubkey']] += 1
                if item.get('service_subnet'):
                    subnet_counts[item['service_subnet']] += 1
                if item.get('service_ip'):
                    ips.append(item['service_ip'])
            dominant_ops = sorted(
                [{'operator_pubkey': k, 'count': v} for k, v in op_counts.items() if v >= 2],
                key=lambda x: (-x['count'], x['operator_pubkey'])
            )
            dominant_subnets = sorted(
                [{'subnet': k, 'count': v} for k, v in subnet_counts.items() if v >= 2],
                key=lambda x: (-x['count'], x['subnet'])
            )
            waves.append({
                'started_at': base['at_iso'],
                'window_seconds': window_seconds,
                'total_nodes': len(cluster),
                'ips': sorted(set(ips)),
                'dominant_operator_clusters': dominant_ops,
                'dominant_subnets': dominant_subnets,
                'nodes': [{
                    'protx_hash': x.get('protx_hash'),
                    'service': x.get('service'),
                    'service_ip': x.get('service_ip'),
                    'service_subnet': x.get('service_subnet'),
                    'operator_pubkey': x.get('operator_pubkey'),
                    'owner_address': x.get('owner_address'),
                } for x in cluster]
            })
            for j in range(i, min(i + len(cluster), len(events))):
                used.add(j)

    waves.sort(key=lambda x: (-x['total_nodes'], x['started_at']))
    return waves


def build_clusters(rows, by_operator, by_ip, by_subnet):
    operator_clusters = []
    for op_key, items in by_operator.items():
        if len(items) <= 1:
            continue
        banned = [x for x in items if (x.get('status') or '').upper() == 'POSE_BANNED']
        evidence = 'critical' if len(banned) >= 2 else 'strong'
        operator_clusters.append({
            'cluster_type': 'operator_pubkey',
            'operator_pubkey': op_key,
            'total_nodes': len(items),
            'pose_banned': len(banned),
            'evidence_level': evidence,
            'suspected_root_cause': 'operator_key_reuse',
            'nodes': [{
                'protx_hash': x.get('protx_hash'),
                'service': x.get('service'),
                'service_ip': x.get('service_ip'),
                'status': x.get('status'),
                'owner_address': x.get('owner_address'),
            } for x in items]
        })
    operator_clusters.sort(key=lambda x: (-x['pose_banned'], -x['total_nodes']))

    ip_clusters = []
    for ip, items in by_ip.items():
        if len(items) <= 1:
            continue
        banned = [x for x in items if (x.get('status') or '').upper() == 'POSE_BANNED']
        evidence = 'strong' if len(banned) >= 2 else 'moderate'
        ip_clusters.append({
            'cluster_type': 'service_ip',
            'service_ip': ip,
            'total_nodes': len(items),
            'pose_banned': len(banned),
            'evidence_level': evidence,
            'suspected_root_cause': 'shared_ip_conflict',
            'nodes': [{
                'protx_hash': x.get('protx_hash'),
                'service': x.get('service'),
                'operator_pubkey': x.get('operator_pubkey'),
                'status': x.get('status'),
                'owner_address': x.get('owner_address'),
            } for x in items]
        })
    ip_clusters.sort(key=lambda x: (-x['pose_banned'], -x['total_nodes']))

    subnet_clusters = []
    for subnet, items in by_subnet.items():
        if len(items) < 4:
            continue
        banned = [x for x in items if (x.get('status') or '').upper() == 'POSE_BANNED']
        if len(banned) < 2:
            continue
        subnet_clusters.append({
            'cluster_type': 'service_subnet',
            'service_subnet': subnet,
            'total_nodes': len(items),
            'pose_banned': len(banned),
            'evidence_level': 'moderate' if len(banned) < 4 else 'strong',
            'suspected_root_cause': 'ban_wave_cluster',
            'nodes': [{
                'protx_hash': x.get('protx_hash'),
                'service': x.get('service'),
                'service_ip': x.get('service_ip'),
                'operator_pubkey': x.get('operator_pubkey'),
                'status': x.get('status'),
                'owner_address': x.get('owner_address'),
            } for x in items]
        })
    subnet_clusters.sort(key=lambda x: (-x['pose_banned'], -x['total_nodes']))

    return operator_clusters, ip_clusters, subnet_clusters


def build_contact_list(rows, operator_clusters, ip_clusters, subnet_clusters):
    contact_items = []

    critical_ops = {c['operator_pubkey']: c for c in operator_clusters if c['evidence_level'] in ('strong', 'critical')}
    suspect_ips = {c['service_ip']: c for c in ip_clusters if c['pose_banned'] >= 1}
    suspect_subnets = {c['service_subnet']: c for c in subnet_clusters if c['pose_banned'] >= 2}

    for row in rows:
        reasons = []
        ip = row.get('service_ip')
        op = row.get('operator_pubkey')
        subnet = row.get('service_subnet')
        status = (row.get('status') or '').upper()

        if op in critical_ops:
            reasons.append('shared operator key cluster')
        if ip in suspect_ips:
            reasons.append('shared service IP cluster')
        if subnet in suspect_subnets:
            reasons.append('subnet with clustered bans')
        if status == 'POSE_BANNED':
            reasons.append('currently POSE_BANNED')
        if row.get('registered_service') and row.get('service') and row.get('registered_service') != row.get('service'):
            reasons.append('service mismatch')

        if reasons:
            contact_items.append({
                'protx_hash': row.get('protx_hash'),
                'service': row.get('service'),
                'service_ip': ip,
                'service_subnet': subnet,
                'status': row.get('status'),
                'operator_pubkey': op,
                'owner_address': row.get('owner_address'),
                'evidence_level': row.get('evidence_level'),
                'suspected_root_cause': row.get('suspected_root_cause'),
                'reasons': sorted(set(reasons)),
            })

    seen = set()
    deduped = []
    for item in sorted(contact_items, key=lambda x: (
        x.get('service_ip') or '',
        x.get('protx_hash') or '',
        x.get('status') or ''
    )):
        key = (item.get('service_ip'), item.get('protx_hash'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def esc(v):
    return html.escape('' if v is None else str(v))


def write_csv(path, rows, cols):
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for row in rows:
            x = {k: row.get(k) for k in cols}
            if 'problems' in x and isinstance(row.get('problems'), list):
                x['problems'] = ' | '.join(row.get('problems', []))
            if 'recommended_fix' in x and isinstance(row.get('recommended_fix'), list):
                x['recommended_fix'] = ' | '.join(row.get('recommended_fix', []))
            if 'reasons' in x and isinstance(row.get('reasons'), list):
                x['reasons'] = ' | '.join(row.get('reasons', []))
            w.writerow(x)


def write_text_report(path, summary, problem_nodes, operator_clusters, ip_clusters, subnet_clusters, waves, contact_list):
    lines = [
        'DeFCoN Network Inspector Report',
        '================================',
        f"Timestamp UTC: {summary['timestamp']}",
        f"Total nodes: {summary['total_nodes']}",
        f"Problematic nodes: {summary['problem_nodes']}",
        f"POSE_BANNED: {summary['pose_banned']}",
        f"Operator clusters: {summary['operator_clusters']}",
        f"IP clusters: {summary['ip_clusters']}",
        f"Subnet clusters: {summary['subnet_clusters']}",
        f"PoSe ban waves: {summary['pose_ban_waves']}",
        f"Community contacts: {summary['community_contacts']}",
        '',
        'Top suspicious nodes',
        '--------------------------------',
    ]

    for row in problem_nodes[:80]:
        lines.append(f"Node: {row.get('protx_hash') or row.get('outpoint') or row.get('service')}")
        lines.append(f"  Status: {row.get('status')}")
        lines.append(f"  Service: {row.get('service')}")
        lines.append(f"  IP: {row.get('service_ip')}")
        lines.append(f"  Operator: {row.get('operator_pubkey')}")
        lines.append(f"  Evidence: {row.get('evidence_level')} | Score: {row.get('problem_score')} | Cause: {row.get('suspected_root_cause')}")
        for p in row.get('problems', []):
            lines.append(f"  Problem: {p}")
        for f in row.get('recommended_fix', []):
            lines.append(f"  Action: {f}")
        lines.append('')

    lines += ['', 'Suspect operator clusters', '--------------------------------']
    for c in operator_clusters[:50]:
        ids = ', '.join([x.get('protx_hash') or '?' for x in c.get('nodes', [])[:12]])
        lines.append(f"{c['operator_pubkey']} -> {c['pose_banned']}/{c['total_nodes']} POSE_BANNED | Evidence: {c['evidence_level']} | Nodes: {ids}")

    lines += ['', 'Suspect IP clusters', '--------------------------------']
    for c in ip_clusters[:50]:
        ids = ', '.join([x.get('protx_hash') or '?' for x in c.get('nodes', [])[:12]])
        lines.append(f"{c['service_ip']} -> {c['pose_banned']}/{c['total_nodes']} POSE_BANNED | Evidence: {c['evidence_level']} | Nodes: {ids}")

    lines += ['', 'Suspect subnet clusters', '--------------------------------']
    for c in subnet_clusters[:50]:
        lines.append(f"{c['service_subnet']} -> {c['pose_banned']}/{c['total_nodes']} POSE_BANNED | Evidence: {c['evidence_level']}")

    lines += ['', 'Recent PoSe ban waves', '--------------------------------']
    for w in waves[:30]:
        lines.append(f"{w['started_at']} -> {w['total_nodes']} nodes within {w['window_seconds']}s")
        if w.get('dominant_operator_clusters'):
            lines.append("  Dominant operators: " + ', '.join(f"{x['operator_pubkey']} ({x['count']})" for x in w['dominant_operator_clusters']))
        if w.get('dominant_subnets'):
            lines.append("  Dominant subnets: " + ', '.join(f"{x['subnet']} ({x['count']})" for x in w['dominant_subnets']))

    lines += ['', 'Community contact list', '--------------------------------']
    for item in contact_list[:100]:
        lines.append(f"{item.get('service_ip')} -> {item.get('protx_hash')} | {item.get('status')} | {item.get('evidence_level')} | {'; '.join(item.get('reasons', []))}")

    path.write_text('\n'.join(lines))


def write_html_report(path, summary, problem_nodes, operator_clusters, ip_clusters, subnet_clusters, waves, contact_list):
    cards = []
    for title, value, cls in [
        ('Total nodes', summary['total_nodes'], 'neutral'),
        ('Problematic nodes', summary['problem_nodes'], 'warn'),
        ('POSE_BANNED', summary['pose_banned'], 'bad'),
        ('Operator clusters', summary['operator_clusters'], 'warn'),
        ('IP clusters', summary['ip_clusters'], 'warn'),
        ('Ban waves', summary['pose_ban_waves'], 'bad'),
        ('Contact targets', summary['community_contacts'], 'neutral'),
    ]:
        cards.append(f'<div class="card {cls}"><div class="label">{esc(title)}</div><div class="value">{esc(value)}</div></div>')

    nodes_html = []
    for r in problem_nodes[:120]:
        problems = ''.join(f'<li>{esc(x)}</li>' for x in r.get('problems', []))
        fixes = ''.join(f'<li>{esc(x)}</li>' for x in r.get('recommended_fix', []))
        nodes_html.append(f'''
        <div class="node">
          <h3>{esc(r.get('protx_hash') or r.get('service'))}</h3>
          <div class="meta">
            <span>Status: {esc(r.get('status'))}</span>
            <span>IP: {esc(r.get('service_ip'))}</span>
            <span>Evidence: {esc(r.get('evidence_level'))}</span>
            <span>Cause: {esc(r.get('suspected_root_cause'))}</span>
            <span>Score: {esc(r.get('problem_score'))}</span>
          </div>
          <p><strong>Service:</strong> {esc(r.get('service'))}<br><strong>Operator:</strong> {esc(r.get('operator_pubkey'))}</p>
          <div class="cols">
            <div><h4>Why suspicious</h4><ul>{problems or "<li>None</li>"}</ul></div>
            <div><h4>Suggested action</h4><ul>{fixes or "<li>None</li>"}</ul></div>
          </div>
        </div>
        ''')

    def cluster_list(items, key):
        out = []
        for c in items[:80]:
            out.append(f"<li><strong>{esc(c.get(key))}</strong> → {esc(c.get('pose_banned'))}/{esc(c.get('total_nodes'))} banned ({esc(c.get('evidence_level'))})</li>")
        return ''.join(out) or '<li>None</li>'

    waves_html = []
    for w in waves[:40]:
        ops = ', '.join(f"{x['operator_pubkey']} ({x['count']})" for x in w.get('dominant_operator_clusters', [])) or 'None'
        subnets = ', '.join(f"{x['subnet']} ({x['count']})" for x in w.get('dominant_subnets', [])) or 'None'
        waves_html.append(f"<li><strong>{esc(w['started_at'])}</strong> → {esc(w['total_nodes'])} nodes in {esc(w['window_seconds'])}s | Operators: {esc(ops)} | Subnets: {esc(subnets)}</li>")

    contact_html = []
    for item in contact_list[:120]:
        contact_html.append(f"<li><strong>{esc(item.get('service_ip'))}</strong> → {esc(item.get('protx_hash'))} | {esc(item.get('status'))} | {esc(item.get('evidence_level'))} | {esc('; '.join(item.get('reasons', [])))}</li>")

    html_doc = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeFCoN Network Inspector Report</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1220; --panel:#121a2b; --panel2:#1a2438; --text:#e8eefc; --muted:#9cb0d1; --good:#1fb981; --warn:#f3b54a; --bad:#ef5b5b; --blue:#5aa9ff; }}
body {{ margin:0; font-family:Arial,sans-serif; background:var(--bg); color:var(--text); }}
.wrap {{ max-width:1280px; margin:0 auto; padding:24px; }}
h1,h2,h3,h4 {{ margin:0 0 12px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:18px 0 28px; }}
.card,.node,.panel {{ background:var(--panel); border:1px solid #26324c; border-radius:14px; padding:16px; box-shadow:0 8px 30px rgba(0,0,0,.25); }}
.card.warn {{ border-color:#7a5a18; }} .card.bad {{ border-color:#7a2222; }} .card.neutral {{ border-color:#294266; }}
.label {{ color:var(--muted); font-size:13px; margin-bottom:8px; }} .value {{ font-size:30px; font-weight:bold; }}
.meta {{ display:flex; flex-wrap:wrap; gap:12px; color:var(--muted); font-size:14px; margin-bottom:10px; }}
.cols {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
ul {{ margin:8px 0 0 18px; }}
.section {{ margin-top:30px; }}
.smallgrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
@media (max-width: 800px) {{ .cols {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>DeFCoN Network Inspector</h1>
  <p>Snapshot UTC: {esc(summary['timestamp'])}</p>
  <div class="grid">{''.join(cards)}</div>

  <div class="section">
    <h2>Top suspicious nodes</h2>
    {''.join(nodes_html) if nodes_html else '<div class="panel">No problematic nodes found.</div>'}
  </div>

  <div class="section smallgrid">
    <div class="panel"><h2>Operator clusters</h2><ul>{cluster_list(operator_clusters, 'operator_pubkey')}</ul></div>
    <div class="panel"><h2>IP clusters</h2><ul>{cluster_list(ip_clusters, 'service_ip')}</ul></div>
    <div class="panel"><h2>Subnet clusters</h2><ul>{cluster_list(subnet_clusters, 'service_subnet')}</ul></div>
  </div>

  <div class="section smallgrid">
    <div class="panel"><h2>PoSe ban waves</h2><ul>{''.join(waves_html) or '<li>None</li>'}</ul></div>
    <div class="panel"><h2>Community contact list</h2><ul>{''.join(contact_html) or '<li>None</li>'}</ul></div>
  </div>
</div>
</body>
</html>'''
    path.write_text(html_doc)


def show_json_pretty(path):
    p = Path(path)
    if not p.exists():
        print("[]")
        return
    print(json.dumps(json.loads(p.read_text()), indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--state-dir', required=True)
    ap.add_argument('--cli', required=True)
    ap.add_argument('--conf')
    ap.add_argument('--datadir')
    ap.add_argument('--rpc-port')
    ap.add_argument('--deep-scan', default='1')
    ap.add_argument('--wave-window-seconds', type=int, default=1800)
    args = ap.parse_args()

    state_dir = Path(args.state_dir)
    snapshots_dir = state_dir / 'snapshots'
    reports_dir = state_dir / 'reports'
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    history_path = state_dir / 'history.json'
    history = load_json(history_path, {})

    now = utc_now()
    timestamp = now.strftime('%Y%m%dT%H%M%SZ')

    try:
        mn = run_cli(args.cli, 'masternodelist', 'json', conf=args.conf, datadir=args.datadir, rpcport=args.rpc_port)
        protx = run_cli(args.cli, 'protx', 'list', 'valid', '1', conf=args.conf, datadir=args.datadir, rpcport=args.rpc_port)
    except Exception as e:
        (reports_dir / 'latest-error.txt').write_text(str(e) + '\n')
        raise

    rows = normalize_protx(protx, normalize_masternodelist(mn))
    rows = deep_scan(rows, args.cli, args.deep_scan, conf=args.conf, datadir=args.datadir, rpcport=args.rpc_port)

    assessed = list(rows.values())
    by_owner, by_operator, by_ip, by_subnet = build_indexes(assessed)
    assessed = [assess_node(r, by_owner, by_operator, by_ip, by_subnet, history) for r in assessed]

    assessed.sort(key=lambda x: (
        not x.get('is_problematic'),
        {'critical': 0, 'strong': 1, 'moderate': 2, 'weak': 3}.get(x.get('evidence_level', 'weak'), 9),
        -x.get('problem_score', 0),
        x.get('service') or ''
    ))

    problem_nodes = [r for r in assessed if r.get('is_problematic')]
    pose_banned = [r for r in assessed if (r.get('status') or '').upper() == 'POSE_BANNED']

    operator_clusters, ip_clusters, subnet_clusters = build_clusters(assessed, by_operator, by_ip, by_subnet)
    waves = find_pose_ban_waves(assessed, history, window_seconds=args.wave_window_seconds)
    contact_list = build_contact_list(assessed, operator_clusters, ip_clusters, subnet_clusters)

    summary = {
        'timestamp': timestamp,
        'total_nodes': len(assessed),
        'problem_nodes': len(problem_nodes),
        'pose_banned': len(pose_banned),
        'operator_clusters': len(operator_clusters),
        'ip_clusters': len(ip_clusters),
        'subnet_clusters': len(subnet_clusters),
        'pose_ban_waves': len(waves),
        'community_contacts': len(contact_list),
    }

    save_json(snapshots_dir / f'snapshot-{timestamp}.json', assessed)
    save_json(reports_dir / 'latest-summary.json', summary)
    save_json(reports_dir / 'all-nodes.json', assessed)
    save_json(reports_dir / 'problem-nodes.json', problem_nodes)
    save_json(reports_dir / 'suspect-operator-clusters.json', operator_clusters)
    save_json(reports_dir / 'suspect-ip-clusters.json', ip_clusters)
    save_json(reports_dir / 'suspect-subnet-clusters.json', subnet_clusters)
    save_json(reports_dir / 'pose-ban-waves.json', waves)
    save_json(reports_dir / 'community-contact-list.json', contact_list)

    write_csv(reports_dir / 'all-nodes.csv', assessed, [
        'protx_hash','outpoint','service','registered_service','service_ip','service_port','service_subnet',
        'status','owner_address','operator_pubkey','registered_operator_pubkey','problem_score',
        'evidence_level','suspected_root_cause','is_problematic','problems','recommended_fix'
    ])

    write_csv(reports_dir / 'problem-nodes.csv', problem_nodes, [
        'protx_hash','outpoint','service','registered_service','service_ip','service_port','service_subnet',
        'status','owner_address','operator_pubkey','registered_operator_pubkey','problem_score',
        'evidence_level','suspected_root_cause','is_problematic','problems','recommended_fix'
    ])

    write_csv(reports_dir / 'community-contact-list.csv', contact_list, [
        'protx_hash','service','service_ip','service_subnet','status','operator_pubkey',
        'owner_address','evidence_level','suspected_root_cause','reasons'
    ])

    write_text_report(
        reports_dir / 'latest-summary.txt',
        summary, problem_nodes, operator_clusters, ip_clusters, subnet_clusters, waves, contact_list
    )
    write_html_report(
        reports_dir / 'latest-report.html',
        summary, problem_nodes, operator_clusters, ip_clusters, subnet_clusters, waves, contact_list
    )

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
  [[ -f "$report" ]] && sed -n '1,320p' "$report" || warn "No report available yet."
}

show_problem_nodes_json() {
  source "${APP_DIR}/env.sh"
  local file="${STATE_DIR}/reports/problem-nodes.json"
  if [[ -f "$file" ]]; then
    python3 - <<PY
import json
from pathlib import Path
p = Path("${STATE_DIR}/reports/problem-nodes.json")
rows = json.loads(p.read_text())
if not rows:
    print("No problematic nodes found.")
else:
    for i, r in enumerate(rows[:80], 1):
        print(f"[{i}] {(r.get('protx_hash') or r.get('outpoint') or r.get('service'))}")
        print(f"  Status: {r.get('status')}")
        print(f"  Service: {r.get('service')}")
        print(f"  IP: {r.get('service_ip')}")
        print(f"  Operator: {r.get('operator_pubkey')}")
        print(f"  Evidence: {r.get('evidence_level')} | Score: {r.get('problem_score')} | Cause: {r.get('suspected_root_cause')}")
        for x in r.get('problems', []): print(f"  Problem: {x}")
        for x in r.get('recommended_fix', []): print(f"  Action: {x}")
        print()
PY
  else
    warn "No problem node list available yet."
  fi
}

show_suspect_clusters() {
  source "${APP_DIR}/env.sh"
  python3 - <<PY
import json
from pathlib import Path

files = [
    ("Operator clusters", Path("${STATE_DIR}/reports/suspect-operator-clusters.json"), "operator_pubkey"),
    ("IP clusters", Path("${STATE_DIR}/reports/suspect-ip-clusters.json"), "service_ip"),
    ("Subnet clusters", Path("${STATE_DIR}/reports/suspect-subnet-clusters.json"), "service_subnet"),
]
for title, path, key in files:
    print(f"\n=== {title} ===")
    if not path.exists():
        print("No data yet.")
        continue
    rows = json.loads(path.read_text())
    if not rows:
        print("None found.")
        continue
    for i, r in enumerate(rows[:50], 1):
        print(f"[{i}] {key}: {r.get(key)}")
        print(f"  Banned: {r.get('pose_banned')}/{r.get('total_nodes')}")
        print(f"  Evidence: {r.get('evidence_level')}")
        print(f"  Cause: {r.get('suspected_root_cause')}")
PY
}

show_ban_waves() {
  source "${APP_DIR}/env.sh"
  python3 - <<PY
import json
from pathlib import Path
p = Path("${STATE_DIR}/reports/pose-ban-waves.json")
if not p.exists():
    print("No PoSe ban wave data yet.")
else:
    rows = json.loads(p.read_text())
    if not rows:
        print("No PoSe ban waves found.")
    else:
        for i, w in enumerate(rows[:40], 1):
            print(f"[{i}] Started: {w.get('started_at')}")
            print(f"  Nodes: {w.get('total_nodes')} in {w.get('window_seconds')}s")
            if w.get('dominant_operator_clusters'):
                print("  Operators:", ', '.join(f"{x['operator_pubkey']} ({x['count']})" for x in w['dominant_operator_clusters']))
            if w.get('dominant_subnets'):
                print("  Subnets:", ', '.join(f"{x['subnet']} ({x['count']})" for x in w['dominant_subnets']))
            print()
PY
}

show_contact_list() {
  source "${APP_DIR}/env.sh"
  python3 - <<PY
import json
from pathlib import Path
p = Path("${STATE_DIR}/reports/community-contact-list.json")
if not p.exists():
    print("No community contact list yet.")
else:
    rows = json.loads(p.read_text())
    if not rows:
        print("No contact targets found.")
    else:
        for i, r in enumerate(rows[:100], 1):
            print(f"[{i}] IP: {r.get('service_ip')} | ProTx: {r.get('protx_hash')}")
            print(f"  Status: {r.get('status')} | Evidence: {r.get('evidence_level')} | Cause: {r.get('suspected_root_cause')}")
            print(f"  Reasons: {', '.join(r.get('reasons', []))}")
            print()
PY
}

run_once() {
  source "${APP_DIR}/env.sh"
  mkdir -p "${STATE_DIR}/snapshots" "${STATE_DIR}/reports" "${LOG_DIR}"
  (
    flock -n 9 || { warn "Analyzer already running."; exit 1; }
    sudo -u "${DEFCON_USER}" python3 "${APP_DIR}/analyzer.py" \
      --state-dir "${STATE_DIR}" \
      --cli "${CLI_BIN}" \
      --conf "${CONF_FILE}" \
      --rpc-port "${DEFCON_RPC_PORT}" \
      --deep-scan "${DEEP_SCAN}" \
      --wave-window-seconds "${WAVE_WINDOW_SECONDS}" | tee -a "${LOG_DIR}/manual-run.log"
  ) 9>"${LOCK_FILE}"
}

check_requirements() {
  source "${APP_DIR}/env.sh"
  info "Checking requirements..."
  [[ -x "${CLI_BIN}" ]] && ok "CLI found: ${CLI_BIN}" || err "CLI not found: ${CLI_BIN}"
  [[ -x "${DAEMON_BIN}" ]] && ok "Daemon found: ${DAEMON_BIN}" || err "Daemon not found: ${DAEMON_BIN}"
  [[ -f "${CONF_FILE}" ]] && ok "Config found: ${CONF_FILE}" || err "Config not found: ${CONF_FILE}"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${DEFCON_SERVICE}"; then
      ok "Service ${DEFCON_SERVICE} is running"
    else
      warn "Service ${DEFCON_SERVICE} is not running"
    fi
  fi
  if [[ -x "${CLI_BIN}" ]]; then
    if sudo -u "${DEFCON_USER}" "${CLI_BIN}" \
      -conf="${CONF_FILE}" \
      -datadir="${DATA_DIR}" \
      -rpcport="${DEFCON_RPC_PORT}" \
      getblockcount >/dev/null 2>&1; then
      ok "RPC responds to getblockcount (as ${DEFCON_USER})"
    else
      warn "RPC does not respond to getblockcount with current CLI/conf/datadir"
    fi
  fi
}

start_background() {
  source "${APP_DIR}/env.sh"
  mkdir -p "${LOG_DIR}" "${STATE_DIR}"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "${APP_NAME}.service"
    ok "Background analysis started via systemd."
  else
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
      warn "Background analysis is already running with PID $(cat "${PID_FILE}")"
      return
    fi
    nohup "${RUNNER_PATH}" >> "${NOHUP_LOG}" 2>&1 &
    echo $! > "${PID_FILE}"
    ok "Background analysis started via nohup. PID $(cat "${PID_FILE}")"
  fi
}

stop_background() {
  source "${APP_DIR}/env.sh"

  local had_running=0

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service | grep -q "^${APP_NAME}.service"; then
    if systemctl is-active --quiet "${APP_NAME}.service"; then
      had_running=1
      systemctl stop "${APP_NAME}.service" || true
      sleep 1
      if systemctl is-active --quiet "${APP_NAME}.service"; then
        warn "Tried to stop ${APP_NAME}.service, but it is still running."
      else
        ok "Background analysis stopped via systemd."
      fi
      return
    fi
  fi

  if [[ -f "${PID_FILE}" ]]; then
    local pid
    pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      had_running=1
      kill "${pid}" || true
      sleep 1
      if kill -0 "${pid}" 2>/dev/null; then
        warn "Tried to stop nohup process PID ${pid}, but it is still running."
      else
        ok "Background analysis stopped via nohup (PID ${pid})."
      fi
      rm -f "${PID_FILE}"
      return
    fi
    rm -f "${PID_FILE}"
  fi

  if [[ "${had_running}" -eq 0 ]]; then
    warn "No running background analysis found."
  fi
}

status_background() {
  source "${APP_DIR}/env.sh"

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "^${APP_NAME}.service"; then
    local active enabled substate pid start_ts start_epoch now_epoch uptime_sec uptime_human mem task state

    active="$(systemctl is-active "${APP_NAME}.service" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "${APP_NAME}.service" 2>/dev/null || true)"
    substate="$(systemctl show -p SubState --value "${APP_NAME}.service" 2>/dev/null || true)"
    pid="$(systemctl show -p ExecMainPID --value "${APP_NAME}.service" 2>/dev/null || true)"
    start_ts="$(systemctl show -p ActiveEnterTimestamp --value "${APP_NAME}.service" 2>/dev/null || true)"
    task="$(systemctl show -p TasksCurrent --value "${APP_NAME}.service" 2>/dev/null || true)"
    mem="$(systemctl show -p MemoryCurrent --value "${APP_NAME}.service" 2>/dev/null || true)"
    state="$(systemctl show -p ActiveState --value "${APP_NAME}.service" 2>/dev/null || true)"

    if [[ "${active}" == "active" ]]; then
      now_epoch="$(date +%s)"
      start_epoch=""
      uptime_sec=""
      uptime_human="unknown"

      if [[ -n "${start_ts}" ]]; then
        start_epoch="$(date -d "${start_ts}" +%s 2>/dev/null || true)"
      fi

      if [[ -n "${start_epoch}" ]]; then
        uptime_sec=$(( now_epoch - start_epoch ))
        local d h m s
        d=$(( uptime_sec / 86400 ))
        h=$(( (uptime_sec % 86400) / 3600 ))
        m=$(( (uptime_sec % 3600) / 60 ))
        s=$(( uptime_sec % 60 ))
        if (( d > 0 )); then
          uptime_human="${d}d ${h}h ${m}m ${s}s"
        elif (( h > 0 )); then
          uptime_human="${h}h ${m}m ${s}s"
        elif (( m > 0 )); then
          uptime_human="${m}m ${s}s"
        else
          uptime_human="${s}s"
        fi
      fi

      if [[ -n "${mem}" && "${mem}" =~ ^[0-9]+$ ]]; then
        mem="$(numfmt --to=iec --suffix=B "${mem}" 2>/dev/null || echo "${mem}")"
      fi

      ok "Background analysis is running via systemd."
      echo "Service: ${APP_NAME}.service"
      echo "ActiveState: ${state}"
      echo "SubState: ${substate}"
      echo "Enabled: ${enabled}"
      echo "Main PID: ${pid}"
      echo "Started: ${start_ts}"
      echo "Uptime: ${uptime_human}"
      echo "Tasks: ${task:-unknown}"
      echo "Memory: ${mem:-unknown}"
      echo
      echo "Recent log lines:"
      journalctl -u "${APP_NAME}.service" -n 12 --no-pager 2>/dev/null || true
      return
    fi

    warn "Service exists but is not currently running."
    echo "Service: ${APP_NAME}.service"
    echo "ActiveState: ${state:-unknown}"
    echo "is-active: ${active:-unknown}"
    echo "Enabled: ${enabled:-unknown}"
    echo
    echo "Last log lines:"
    journalctl -u "${APP_NAME}.service" -n 20 --no-pager 2>/dev/null || true
    return
  fi

  if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    local pid started uptime_sec uptime_human
    pid="$(cat "${PID_FILE}")"
    started="$(ps -o lstart= -p "${pid}" 2>/dev/null | sed 's/^ *//')"
    uptime_human="unknown"

    if [[ -n "${started}" ]]; then
      local start_epoch now_epoch d h m s
      start_epoch="$(date -d "${started}" +%s 2>/dev/null || true)"
      now_epoch="$(date +%s)"
      if [[ -n "${start_epoch}" ]]; then
        uptime_sec=$(( now_epoch - start_epoch ))
        d=$(( uptime_sec / 86400 ))
        h=$(( (uptime_sec % 86400) / 3600 ))
        m=$(( (uptime_sec % 3600) / 60 ))
        s=$(( uptime_sec % 60 ))
        if (( d > 0 )); then
          uptime_human="${d}d ${h}h ${m}m ${s}s"
        elif (( h > 0 )); then
          uptime_human="${h}h ${m}m ${s}s"
        elif (( m > 0 )); then
          uptime_human="${m}m ${s}s"
        else
          uptime_human="${s}s"
        fi
      fi
    fi

    ok "Background analysis is running via nohup."
    echo "PID: ${pid}"
    echo "Started: ${started:-unknown}"
    echo "Uptime: ${uptime_human}"
    echo "Log: ${NOHUP_LOG}"
    return
  fi

  warn "No running background analysis found."
}

show_paths() {
  source "${APP_DIR}/env.sh"
  cat <<PATHS
APP_DIR: ${APP_DIR}
STATE_DIR: ${STATE_DIR}
LOG_DIR: ${LOG_DIR}
Reports: ${STATE_DIR}/reports
HTML report: ${STATE_DIR}/reports/latest-report.html
All nodes CSV: ${STATE_DIR}/reports/all-nodes.csv
Problem nodes CSV: ${STATE_DIR}/reports/problem-nodes.csv
Community contact CSV: ${STATE_DIR}/reports/community-contact-list.csv
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
    rm -f "${STATE_DIR}/history.json" "${PID_FILE}" "${LOCK_FILE}"
    ok "All stored data has been deleted."
  else
    warn "Cancelled."
  fi
}

menu() {
  while true; do
    echo
    echo -e "${BLUE}=====================================${NC}"
    echo -e "${BLUE} DeFCoN Network Inspector v3${NC}"
    echo -e "${BLUE}=====================================${NC}"
    echo "1) Check requirements"
    echo "2) Run one-time analysis"
    echo "3) Start background analysis"
    echo "4) Stop background analysis"
    echo "5) Show status"
    echo "6) Show latest report"
    echo "7) Show problem nodes"
    echo "8) Show suspect clusters"
    echo "9) Show PoSe ban waves"
    echo "10) Show community contact list"
    echo "11) Show report/log paths"
    echo "12) Delete all stored data"
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
      8) show_suspect_clusters ;;
      9) show_ban_waves ;;
      10) show_contact_list ;;
      11) show_paths ;;
      12) wipe_all_data ;;
      0) exit 0 ;;
      *) warn "Invalid selection." ;;
    esac
  done
}

install_app() {
  need_root
  mkdir_p "${APP_DIR}"
  mkdir_p "${STATE_DIR}/snapshots"
  mkdir_p "${STATE_DIR}/reports"
  mkdir_p "${LOG_DIR}"
  chown -R "${DEFCON_USER}:${DEFCON_USER}" "${STATE_DIR}" "${LOG_DIR}"
  write_env
  write_runner
  write_analyzer
  write_service
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
  if [[ ! -f "${APP_DIR}/env.sh" ]]; then
    echo "${APP_NAME} is being installed..."
    install_app
  fi
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
    *) menu ;;
  esac
}

main "$@"
