#!/usr/bin/env bash
set -euo pipefail

APP_NAME="defcon-network-inspector"
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
HEALTH_FILE="${STATE_DIR}/health.json"

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
DEFAULT_HISTORY_RETENTION_DAYS="30"
DEFAULT_RPC_TIMEOUT_SECONDS="30"
DEFAULT_MAX_CONSECUTIVE_FAILURES="5"

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
HISTORY_RETENTION_DAYS="${HISTORY_RETENTION_DAYS:-$DEFAULT_HISTORY_RETENTION_DAYS}"
RPC_TIMEOUT_SECONDS="${RPC_TIMEOUT_SECONDS:-$DEFAULT_RPC_TIMEOUT_SECONDS}"
MAX_CONSECUTIVE_FAILURES="${MAX_CONSECUTIVE_FAILURES:-$DEFAULT_MAX_CONSECUTIVE_FAILURES}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;36m'; NC='\033[0m'
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

HISTORY_RETENTION_DAYS="${HISTORY_RETENTION_DAYS:-30}"
SNAPSHOT_RETENTION_DAYS="${SNAPSHOT_RETENTION_DAYS:-30}"
REPORT_RETENTION_DAYS="${REPORT_RETENTION_DAYS:-30}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-14}"
MAX_LOG_SIZE_MB="${MAX_LOG_SIZE_MB:-25}"
RPC_TIMEOUT_SECONDS="${RPC_TIMEOUT_SECONDS:-30}"
MAX_CONSECUTIVE_FAILURES="${MAX_CONSECUTIVE_FAILURES:-5}"
ENV
}

write_runner() {
cat > "${RUNNER_PATH}" <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail

APP_NAME="defcon-network-inspector"
APP_DIR="/opt/${APP_NAME}"
STATE_DIR="/var/lib/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"

if [[ -r "${APP_DIR}/env.sh" ]]; then
  # shellcheck source=/opt/defcon-network-inspector/env.sh
  source "${APP_DIR}/env.sh"
fi

mkdir -p "${STATE_DIR}/snapshots" "${STATE_DIR}/reports" "${LOG_DIR}"

FAIL_COUNT=0

rotate_log_if_needed() {
  local file="$1"
  local max_mb="${2:-25}"
  local max_bytes=$(( max_mb * 1024 * 1024 ))

  [[ -f "$file" ]] || return 0

  local size
  size="$(stat -c '%s' "$file" 2>/dev/null || echo 0)"
  [[ "$size" =~ ^[0-9]+$ ]] || size=0

  if (( size >= max_bytes )); then
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$file" "${file}.${ts}"
    : > "$file"
  fi
}

cleanup_old_logs() {
  local dir="$1"
  local days="${2:-14}"
  find "$dir" -maxdepth 1 -type f \( -name '*.log' -o -name '*.log.*' \) -mtime +"$days" -delete 2>/dev/null || true
}

while true; do
  rotate_log_if_needed "${LOG_DIR}/analyzer.log" "${MAX_LOG_SIZE_MB:-25}"
  cleanup_old_logs "${LOG_DIR}" "${LOG_RETENTION_DAYS:-14}"

  if (
    flock -n 9 || exit 0
    python3 "${APP_DIR}/analyzer.py" \
      --state-dir "${STATE_DIR}" \
      --cli "${CLI_BIN}" \
      --conf "${CONF_FILE}" \
      --datadir "${DATA_DIR}" \
      --rpc-port "${DEFCON_RPC_PORT}" \
      --deep-scan "${DEEP_SCAN}" \
      --wave-window-seconds "${WAVE_WINDOW_SECONDS}" \
      --history-retention-days "${HISTORY_RETENTION_DAYS:-30}" \
      --snapshot-retention-days "${SNAPSHOT_RETENTION_DAYS:-30}" \
      --report-retention-days "${REPORT_RETENTION_DAYS:-30}" \
      --rpc-timeout-seconds "${RPC_TIMEOUT_SECONDS:-30}" >> "${LOG_DIR}/analyzer.log" 2>&1
  ) 9>"${LOCK_FILE}"; then
    FAIL_COUNT=0
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] analyzer failed (${FAIL_COUNT}/${MAX_CONSECUTIVE_FAILURES:-5})" >> "${LOG_DIR}/analyzer.log"
    if (( FAIL_COUNT >= ${MAX_CONSECUTIVE_FAILURES:-5} )); then
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] too many consecutive analyzer failures, exiting for systemd restart" >> "${LOG_DIR}/analyzer.log"
      exit 1
    fi
  fi

  sleep "${RUN_INTERVAL}"
done
RUNNER
chmod +x "${RUNNER_PATH}"
}

write_analyzer() {
cat > "${ANALYZER_PATH}" <<'PYEOF'
#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
import subprocess
from collections import defaultdict
from pathlib import Path


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def utc_iso(ts=None):
    ts = ts or utc_now()
    return ts.isoformat().replace('+00:00', 'Z')


def load_json(path, default, salvage_corrupt=False):
    if path.exists():
        try:
            return json.loads(path.read_text()), None
        except Exception as e:
            backup_path = None
            if salvage_corrupt:
                backup_path = path.with_name(path.name + f".corrupt-{utc_now().strftime('%Y%m%dT%H%M%SZ')}")
                try:
                    path.rename(backup_path)
                except Exception:
                    backup_path = None
            return default, (str(e), str(backup_path) if backup_path else None)
    return default, None


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=False))

def parse_iso_utc(value):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except Exception:
        return None


def prune_list_by_days(items, days, ts_key='at'):
    if not isinstance(items, list):
        return []
    cutoff = utc_now() - dt.timedelta(days=days)
    kept = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ts = parse_iso_utc(item.get(ts_key))
        if ts and ts >= cutoff:
            kept.append(item)
    return kept


def prune_history(history, retention_days=30):
    if not isinstance(history, dict):
        return {}

    cutoff = utc_now() - dt.timedelta(days=retention_days)
    pruned = {
        "_meta": {
            "history_retention_days": retention_days,
            "last_pruned_at": utc_iso(),
        }
    }

    for node_id, hist in history.items():
        if node_id == "_meta" or not isinstance(hist, dict):
            continue

        hist = dict(hist)
        hist['service_history'] = prune_list_by_days(hist.get('service_history', []), retention_days)
        hist['registered_service_history'] = prune_list_by_days(hist.get('registered_service_history', []), retention_days)
        hist['pose_ban_events'] = prune_list_by_days(hist.get('pose_ban_events', []), retention_days)
        hist['events'] = prune_list_by_days(hist.get('events', []), retention_days)

        last_seen = parse_iso_utc(hist.get('last_seen'))
        keep_node = False

        if last_seen and last_seen >= cutoff:
            keep_node = True
        if hist['service_history'] or hist['registered_service_history'] or hist['pose_ban_events'] or hist['events']:
            keep_node = True

        if keep_node:
            pruned[node_id] = hist

    return pruned


def cleanup_old_files_by_age(directory, pattern, retention_days):
    directory = Path(directory)
    if not directory.exists():
        return 0

    cutoff = utc_now() - dt.timedelta(days=retention_days)
    removed = 0

    for path in directory.glob(pattern):
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
            if mtime < cutoff:
                path.unlink()
                removed += 1
        except Exception:
            continue

    return removed


def cleanup_reports(reports_dir, retention_days=30):
    reports_dir = Path(reports_dir)
    if not reports_dir.exists():
        return 0

    keep_names = {
        'latest-summary.json',
        'all-nodes.json',
        'problem-nodes.json',
        'suspect-operator-clusters.json',
        'suspect-ip-clusters.json',
        'suspect-subnet-clusters.json',
        'pose-ban-waves.json',
        'community-contact-list.json',
        'all-nodes.csv',
        'problem-nodes.csv',
        'community-contact-list.csv',
        'latest-summary.txt',
        'latest-report.html',
        'latest-error.txt',
    }

    cutoff = utc_now() - dt.timedelta(days=retention_days)
    removed = 0

    for path in reports_dir.iterdir():
        if not path.is_file():
            continue
        if path.name in keep_names:
            continue
        try:
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
            if mtime < cutoff:
                path.unlink()
                removed += 1
        except Exception:
            continue

    return removed

def write_health(path, status, **extra):
    payload = {'status': status, 'updated_at': utc_iso()}
    payload.update(extra)
    save_json(path, payload)


def run_cli(cli, *args, conf=None, datadir=None, rpcport=None, timeout_seconds=30):
    cmd = [cli]
    if conf:
        cmd.append(f'-conf={conf}')
    if datadir:
        cmd.append(f'-datadir={datadir}')
    if rpcport:
        cmd.append(f'-rpcport={rpcport}')
    cmd += list(args)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"RPC timeout after {timeout_seconds}s: {' '.join(cmd)}") from e
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


def deep_scan(rows, cli, enabled, conf=None, datadir=None, rpcport=None, timeout_seconds=30):
    if str(enabled).lower() not in ('1', 'true', 'yes', 'on'):
        return rows
    for row in rows.values():
        protx = row.get('protx_hash')
        if not protx:
            continue
        try:
            info = run_cli(cli, 'protx', 'info', protx, conf=conf, datadir=datadir, rpcport=rpcport, timeout_seconds=timeout_seconds)
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
                'event_id': f"{node_id}|{e['at']}",
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

    events.sort(key=lambda x: (x['at'], x['node_id']))
    waves = []
    used_event_ids = set()

    for i, base in enumerate(events):
        if base['event_id'] in used_event_ids:
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
            for item in cluster:
                used_event_ids.add(item['event_id'])

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
    def to_int(v, default=0):
        try:
            return int(v)
        except Exception:
            return default

    def pct(part, whole):
        try:
            part = float(part or 0)
            whole = float(whole or 0)
            if whole <= 0:
                return "0.0%"
            return f"{(part / whole) * 100:.1f}%"
        except Exception:
            return "0.0%"

    def short_hex(v, left=12, right=10):
        s = str(v or "")
        if len(s) <= left + right + 3:
            return s or "n/a"
        return f"{s[:left]}...{s[-right:]}"

    total_nodes = to_int(summary.get("total_nodes"))
    problem_count = to_int(summary.get("problem_nodes"))
    pose_banned = to_int(summary.get("pose_banned"))

    root_cause_counts = defaultdict(int)
    evidence_counts = defaultdict(int)
    status_counts = defaultdict(int)

    for r in problem_nodes:
        root_cause_counts[str(r.get("suspected_root_cause") or "unknown")] += 1
        evidence_counts[str(r.get("evidence_level") or "unknown")] += 1
        status_counts[str(r.get("status") or "unknown")] += 1

    sorted_root_causes = sorted(root_cause_counts.items(), key=lambda x: (-x[1], x[0]))
    sorted_evidence = sorted(evidence_counts.items(), key=lambda x: (-x[1], x[0]))
    sorted_status = sorted(status_counts.items(), key=lambda x: (-x[1], x[0]))

    dominant_cause = sorted_root_causes[0][0] if sorted_root_causes else "unknown"
    dominant_cause_count = sorted_root_causes[0][1] if sorted_root_causes else 0

    lines = [
        "DeFCoN Network Inspector Report",
        "================================",
        f"Timestamp UTC: {summary.get('timestamp', 'unknown')}",
        "",
        "Executive summary",
        "--------------------------------",
        f"POSE_BANNED: {pose_banned}/{total_nodes} ({pct(pose_banned, total_nodes)})",
        f"Problematic nodes: {problem_count}/{total_nodes} ({pct(problem_count, total_nodes)})",
        f"Dominant suspected root cause: {dominant_cause} ({dominant_cause_count} nodes)",
        f"Operator clusters: {summary.get('operator_clusters', 0)}",
        f"IP clusters: {summary.get('ip_clusters', 0)}",
        f"Subnet clusters: {summary.get('subnet_clusters', 0)}",
        f"PoSe ban waves: {summary.get('pose_ban_waves', 0)}",
        f"Community contact targets: {summary.get('community_contacts', 0)}",
        "",
        "Dominant root causes",
        "--------------------------------",
    ]

    if sorted_root_causes:
        for cause, count in sorted_root_causes[:10]:
            lines.append(f"- {cause}: {count} nodes")
    else:
        lines.append("- None")

    lines += ["", "Evidence levels", "--------------------------------"]
    if sorted_evidence:
        for level, count in sorted_evidence[:10]:
            lines.append(f"- {level}: {count} nodes")
    else:
        lines.append("- None")

    lines += ["", "Problem node statuses", "--------------------------------"]
    if sorted_status:
        for status, count in sorted_status[:10]:
            lines.append(f"- {status}: {count} nodes")
    else:
        lines.append("- None")

    lines += ["", "Top suspicious nodes", "--------------------------------"]
    if problem_nodes:
        for row in problem_nodes[:60]:
            lines.append(f"Node: {row.get('protx_hash') or row.get('service') or 'unknown'}")
            lines.append(f"  Status: {row.get('status') or 'unknown'}")
            lines.append(f"  Service: {row.get('service') or 'n/a'}")
            lines.append(f"  IP: {row.get('service_ip') or 'n/a'}")
            lines.append(f"  Subnet: {row.get('service_subnet') or 'n/a'}")
            lines.append(f"  Operator: {row.get('operator_pubkey') or 'n/a'}")
            lines.append(f"  Owner: {row.get('owner_address') or 'n/a'}")
            lines.append(f"  Evidence: {row.get('evidence_level') or 'unknown'}")
            lines.append(f"  Cause: {row.get('suspected_root_cause') or 'unknown'}")
            lines.append(f"  Score: {row.get('problem_score') or 0}")

            problems = row.get("problems", [])
            fixes = row.get("recommended_fix", [])

            if problems:
                lines.append("  Why suspicious:")
                for p in problems:
                    lines.append(f"    - {p}")
            else:
                lines.append("  Why suspicious: None")

            if fixes:
                lines.append("  Suggested action:")
                for fx in fixes:
                    lines.append(f"    - {fx}")
            else:
                lines.append("  Suggested action: None")

            lines.append("")
    else:
        lines.append("No problematic nodes found.")

    lines += ["", "Top operator clusters", "--------------------------------"]
    if operator_clusters:
        for c in operator_clusters[:20]:
            sample_nodes = ", ".join(
                (x.get("protx_hash") or x.get("service") or "unknown")
                for x in c.get("nodes", [])[:5]
            ) or "None"
            lines.append(f"Operator key: {c.get('operator_pubkey') or 'unknown'}")
            lines.append(f"  Banned: {c.get('pose_banned', 0)}/{c.get('total_nodes', 0)}")
            lines.append(f"  Evidence: {c.get('evidence_level') or 'unknown'}")
            lines.append(f"  Cause: {c.get('suspected_root_cause') or 'unknown'}")
            lines.append(f"  Sample nodes: {sample_nodes}")
            lines.append("")
    else:
        lines.append("None")

    lines += ["", "Top IP clusters", "--------------------------------"]
    if ip_clusters:
        for c in ip_clusters[:20]:
            sample_nodes = ", ".join(
                (x.get("protx_hash") or x.get("service") or "unknown")
                for x in c.get("nodes", [])[:5]
            ) or "None"
            lines.append(f"Service IP: {c.get('service_ip') or 'unknown'}")
            lines.append(f"  Banned: {c.get('pose_banned', 0)}/{c.get('total_nodes', 0)}")
            lines.append(f"  Evidence: {c.get('evidence_level') or 'unknown'}")
            lines.append(f"  Cause: {c.get('suspected_root_cause') or 'unknown'}")
            lines.append(f"  Sample nodes: {sample_nodes}")
            lines.append("")
    else:
        lines.append("None")

    lines += ["", "Top subnet clusters", "--------------------------------"]
    if subnet_clusters:
        for c in subnet_clusters[:20]:
            sample_nodes = ", ".join(
                (x.get("protx_hash") or x.get("service_ip") or "unknown")
                for x in c.get("nodes", [])[:5]
            ) or "None"
            lines.append(f"Subnet: {c.get('service_subnet') or 'unknown'}")
            lines.append(f"  Banned: {c.get('pose_banned', 0)}/{c.get('total_nodes', 0)}")
            lines.append(f"  Evidence: {c.get('evidence_level') or 'unknown'}")
            lines.append(f"  Cause: {c.get('suspected_root_cause') or 'unknown'}")
            lines.append(f"  Sample nodes: {sample_nodes}")
            lines.append("")
    else:
        lines.append("None")

    lines += ["", "PoSe ban waves", "--------------------------------"]
    if waves:
        for w in waves[:20]:
            lines.append(f"Started at: {w.get('started_at') or 'unknown'}")
            lines.append(f"  Window: {w.get('window_seconds') or 0}s")
            lines.append(f"  Total nodes: {w.get('total_nodes') or 0}")

            dominant_ops = w.get("dominant_operator_clusters", [])
            if dominant_ops:
                lines.append("  Dominant operators:")
                for x in dominant_ops[:10]:
                    lines.append(f"    - {x.get('operator_pubkey')}: {x.get('count')}")
            else:
                lines.append("  Dominant operators: None")

            dominant_subnets = w.get("dominant_subnets", [])
            if dominant_subnets:
                lines.append("  Dominant subnets:")
                for x in dominant_subnets[:10]:
                    lines.append(f"    - {x.get('subnet')}: {x.get('count')}")
            else:
                lines.append("  Dominant subnets: None")

            sample_nodes = ", ".join(
                (x.get("protx_hash") or x.get("service") or "unknown")
                for x in w.get("nodes", [])[:5]
            ) or "None"
            lines.append(f"  Sample nodes: {sample_nodes}")
            lines.append("")
    else:
        lines.append("None")

    lines += ["", "Community contact list", "--------------------------------"]
    if contact_list:
        for item in contact_list[:80]:
            lines.append(f"Service IP: {item.get('service_ip') or 'unknown'}")
            lines.append(f"  Node: {item.get('protx_hash') or 'unknown'}")
            lines.append(f"  Status: {item.get('status') or 'unknown'}")
            lines.append(f"  Evidence: {item.get('evidence_level') or 'unknown'}")
            lines.append(f"  Service: {item.get('service') or 'n/a'}")
            lines.append(f"  Operator: {short_hex(item.get('operator_pubkey'))}")
            reasons = item.get("reasons", [])
            if reasons:
                lines.append("  Why contact:")
                for r in reasons:
                    lines.append(f"    - {r}")
            else:
                lines.append("  Why contact: None")
            lines.append("")
    else:
        lines.append("None")

    lines += [
        "",
        "Notes",
        "--------------------------------",
        "This report shows visible RPC-derived patterns and historical PoSe-ban correlations.",
        "It highlights likely misconfiguration groups, but it does not prove private-key ownership or operator intent.",
    ]

    path.write_text("\n".join(lines))

def write_html_report(path, summary, problem_nodes, operator_clusters, ip_clusters, subnet_clusters, waves, contact_list):
    def to_int(v, default=0):
        try:
            return int(v)
        except Exception:
            return default

    def short_hex(v, left=12, right=10):
        s = str(v or '')
        if len(s) <= left + right + 3:
            return s or 'n/a'
        return f'{s[:left]}...{s[-right:]}'

    def pct(part, whole):
        try:
            part = float(part or 0)
            whole = float(whole or 0)
            if whole <= 0:
                return '0.0%'
            return f'{(part / whole) * 100:.1f}%'
        except Exception:
            return '0.0%'

    total_nodes = to_int(summary.get('total_nodes'))
    problem_count = to_int(summary.get('problem_nodes'))
    pose_banned = to_int(summary.get('pose_banned'))

    root_cause_counts = defaultdict(int)
    evidence_counts = defaultdict(int)
    status_counts = defaultdict(int)

    for r in problem_nodes:
        root_cause_counts[str(r.get('suspected_root_cause') or 'unknown')] += 1
        evidence_counts[str(r.get('evidence_level') or 'unknown')] += 1
        status_counts[str(r.get('status') or 'unknown')] += 1

    sorted_root_causes = sorted(root_cause_counts.items(), key=lambda x: (-x[1], x[0]))
    sorted_evidence = sorted(evidence_counts.items(), key=lambda x: (-x[1], x[0]))
    sorted_status = sorted(status_counts.items(), key=lambda x: (-x[1], x[0]))

    dominant_cause = sorted_root_causes[0][0] if sorted_root_causes else 'unknown'
    dominant_cause_count = sorted_root_causes[0][1] if sorted_root_causes else 0

    summary_text = (
        f'{pose_banned} of {total_nodes} masternodes are currently POSE_BANNED '
        f'({pct(pose_banned, total_nodes)} of the observed network). '
        f'{problem_count} nodes are currently classified as problematic '
        f'({pct(problem_count, total_nodes)} of all nodes). '
        f'The most common suspected root cause in this snapshot is '
        f'"{dominant_cause}" affecting {dominant_cause_count} nodes.'
    )

    cards = []
    for title, value, sub, cls in [
        ('Total nodes', total_nodes, 'Observed in current snapshot', 'neutral'),
        ('Problematic nodes', problem_count, pct(problem_count, total_nodes), 'warn'),
        ('POSE_BANNED', pose_banned, pct(pose_banned, total_nodes), 'bad'),
        ('Operator clusters', to_int(summary.get('operator_clusters')), 'Repeated operator keys', 'warn'),
        ('IP clusters', to_int(summary.get('ip_clusters')), 'Shared service IPs', 'warn'),
        ('Subnet clusters', to_int(summary.get('subnet_clusters')), 'Grouped by subnet', 'neutral'),
        ('Ban waves', to_int(summary.get('pose_ban_waves')), 'Grouped PoSe events', 'bad'),
        ('Contact targets', to_int(summary.get('community_contacts')), 'Nodes to notify', 'neutral'),
    ]:
        cards.append(f'''
        <div class="card {cls}">
          <div class="label">{esc(title)}</div>
          <div class="value">{esc(value)}</div>
          <div class="subvalue">{esc(sub)}</div>
        </div>
        ''')

    root_causes_html = ''.join(
        f'<li><span class="mono">{esc(cause)}</span><span>{esc(count)} nodes</span></li>'
        for cause, count in sorted_root_causes[:8]
    ) or '<li><span>None</span><span>0</span></li>'

    evidence_html = ''.join(
        f'<li><span class="mono">{esc(level)}</span><span>{esc(count)} nodes</span></li>'
        for level, count in sorted_evidence[:8]
    ) or '<li><span>None</span><span>0</span></li>'

    status_html = ''.join(
        f'<li><span class="mono">{esc(status)}</span><span>{esc(count)} nodes</span></li>'
        for status, count in sorted_status[:8]
    ) or '<li><span>None</span><span>0</span></li>'

    nodes_html = []
    for r in problem_nodes[:120]:
        problems = ''.join(f'<li>{esc(x)}</li>' for x in r.get('problems', [])) or '<li>None</li>'
        fixes = ''.join(f'<li>{esc(x)}</li>' for x in r.get('recommended_fix', [])) or '<li>None</li>'

        nodes_html.append(f'''
        <article class="node">
          <div class="node-head">
            <h3 class="mono">{esc(r.get('protx_hash') or r.get('service') or 'unknown')}</h3>
            <span class="pill {esc(str(r.get('evidence_level') or 'neutral').lower())}">{esc(r.get('evidence_level') or 'unknown')}</span>
          </div>
          <div class="meta">
            <span>Status: {esc(r.get('status') or 'unknown')}</span>
            <span>IP: <span class="mono">{esc(r.get('service_ip') or 'n/a')}</span></span>
            <span>Subnet: <span class="mono">{esc(r.get('service_subnet') or 'n/a')}</span></span>
            <span>Cause: <span class="mono">{esc(r.get('suspected_root_cause') or 'unknown')}</span></span>
            <span>Score: {esc(r.get('problem_score') or 0)}</span>
          </div>

          <div class="kv">
            <div><span class="k">Service</span><span class="v mono">{esc(r.get('service') or 'n/a')}</span></div>
            <div><span class="k">Operator</span><span class="v mono">{esc(r.get('operator_pubkey') or 'n/a')}</span></div>
            <div><span class="k">Owner</span><span class="v mono">{esc(r.get('owner_address') or 'n/a')}</span></div>
            <div><span class="k">Outpoint</span><span class="v mono">{esc(r.get('outpoint') or 'n/a')}</span></div>
          </div>

          <div class="cols">
            <div>
              <h4>Why suspicious</h4>
              <ul>{problems}</ul>
            </div>
            <div>
              <h4>Suggested action</h4>
              <ul>{fixes}</ul>
            </div>
          </div>
        </article>
        ''')

    def cluster_cards(items, key, label):
        out = []
        for c in items[:24]:
            sample_nodes = ''.join(
                f'<li class="mono">{esc(x.get("protx_hash") or x.get("service") or "unknown")}</li>'
                for x in c.get('nodes', [])[:5]
            ) or '<li>None</li>'

            out.append(f'''
            <article class="panel cluster-card">
              <div class="node-head">
                <h3 class="mono">{esc(c.get(key) or 'unknown')}</h3>
                <span class="pill {esc(str(c.get("evidence_level") or "neutral").lower())}">{esc(c.get("evidence_level") or "unknown")}</span>
              </div>
              <div class="meta">
                <span>{esc(label)}: <span class="mono">{esc(c.get(key) or 'unknown')}</span></span>
                <span>Banned: {esc(c.get('pose_banned') or 0)}/{esc(c.get('total_nodes') or 0)}</span>
                <span>Cause: <span class="mono">{esc(c.get('suspected_root_cause') or 'unknown')}</span></span>
              </div>
              <h4>Sample nodes</h4>
              <ul>{sample_nodes}</ul>
            </article>
            ''')
        return ''.join(out) or '<div class="panel">None</div>'

    waves_html = []
    for w in waves[:40]:
        ops = ''.join(
            f'<li><span class="mono">{esc(short_hex(x.get("operator_pubkey")))}</span><span>{esc(x.get("count"))}</span></li>'
            for x in w.get('dominant_operator_clusters', [])
        ) or '<li><span>None</span><span>0</span></li>'

        subnets = ''.join(
            f'<li><span class="mono">{esc(x.get("subnet"))}</span><span>{esc(x.get("count"))}</span></li>'
            for x in w.get('dominant_subnets', [])
        ) or '<li><span>None</span><span>0</span></li>'

        sample_nodes = ''.join(
            f'<li class="mono">{esc(x.get("protx_hash") or x.get("service") or "unknown")}</li>'
            for x in w.get('nodes', [])[:5]
        ) or '<li>None</li>'

        waves_html.append(f'''
        <article class="panel wave-card">
          <div class="node-head">
            <h3>{esc(w.get("started_at") or "unknown")}</h3>
            <span class="pill bad">{esc(w.get("total_nodes") or 0)} nodes</span>
          </div>
          <div class="meta">
            <span>Window: {esc(w.get("window_seconds") or 0)}s</span>
            <span>Total nodes: {esc(w.get("total_nodes") or 0)}</span>
          </div>
          <div class="cols">
            <div>
              <h4>Dominant operators</h4>
              <ul class="statlist">{ops}</ul>
            </div>
            <div>
              <h4>Dominant subnets</h4>
              <ul class="statlist">{subnets}</ul>
            </div>
          </div>
          <h4>Sample nodes</h4>
          <ul>{sample_nodes}</ul>
        </article>
        ''')

    contact_html = []
    for item in contact_list[:80]:
        reasons = ''.join(f'<li>{esc(x)}</li>' for x in item.get('reasons', [])) or '<li>None</li>'
        contact_html.append(f'''
        <article class="panel contact-card">
          <div class="node-head">
            <h3 class="mono">{esc(item.get('service_ip') or 'unknown')}</h3>
            <span class="pill {esc(str(item.get('evidence_level') or 'neutral').lower())}">{esc(item.get('evidence_level') or 'unknown')}</span>
          </div>
          <div class="meta">
            <span>Status: {esc(item.get('status') or 'unknown')}</span>
            <span>Node: <span class="mono">{esc(short_hex(item.get('protx_hash')))}</span></span>
          </div>
          <div class="kv">
            <div><span class="k">Service</span><span class="v mono">{esc(item.get('service') or 'n/a')}</span></div>
            <div><span class="k">Operator</span><span class="v mono">{esc(short_hex(item.get('operator_pubkey')))}</span></div>
          </div>
          <h4>Why contact</h4>
          <ul>{reasons}</ul>
        </article>
        ''')

    html_doc = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeFCoN Network Inspector Report</title>
<style>
:root {{
  color-scheme: dark;
  --bg:#0b1220;
  --panel:#121a2b;
  --panel2:#182239;
  --panel3:#1f2b45;
  --text:#e8eefc;
  --muted:#9cb0d1;
  --faint:#7283a8;
  --good:#1fb981;
  --warn:#f3b54a;
  --bad:#ef5b5b;
  --blue:#8ec5ff;
  --border:#26324c;
  --border-soft:#31425f;
  --shadow:0 10px 30px rgba(0,0,0,.22);
}}

* {{ box-sizing:border-box; }}
html {{ scroll-behavior:smooth; }}
body {{
  margin:0;
  font-family:Arial,sans-serif;
  background:linear-gradient(180deg, #0b1220 0%, #0f1727 100%);
  color:var(--text);
  line-height:1.5;
}}

.wrap {{ max-width:1360px; margin:0 auto; padding:24px; }}
h1,h2,h3,h4 {{ margin:0 0 12px; line-height:1.2; }}
h1 {{ font-size:34px; }}
h2 {{ font-size:24px; margin-bottom:14px; }}
h3 {{ font-size:18px; }}
h4 {{ font-size:14px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}

p {{ margin:0; }}
a {{ color:var(--blue); }}
code,.mono {{
  font-family:Consolas, Monaco, 'Courier New', monospace;
  overflow-wrap:anywhere;
  word-break:break-word;
}}

.hero {{
  display:grid;
  gap:18px;
  margin-bottom:24px;
}}

.hero-top {{
  display:flex;
  flex-wrap:wrap;
  align-items:flex-end;
  justify-content:space-between;
  gap:12px;
}}

.subtitle {{
  color:var(--muted);
  font-size:15px;
}}

.summary-box {{
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:16px;
  padding:18px;
  box-shadow:var(--shadow);
}}

.grid {{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:16px;
  margin:20px 0 28px;
}}

.smallgrid {{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
  gap:16px;
}}

.card,.node,.panel {{
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:16px;
  padding:16px;
  box-shadow:var(--shadow);
}}

.card {{
  min-height:120px;
  display:flex;
  flex-direction:column;
  justify-content:space-between;
}}

.card.warn {{ border-color:#7a5a18; }}
.card.bad {{ border-color:#7a2222; }}
.card.neutral {{ border-color:#294266; }}

.label {{
  color:var(--muted);
  font-size:13px;
  margin-bottom:8px;
  text-transform:uppercase;
  letter-spacing:.04em;
}}

.value {{
  font-size:32px;
  font-weight:bold;
}}

.subvalue {{
  color:var(--faint);
  font-size:13px;
  margin-top:8px;
}}

.meta {{
  display:flex;
  flex-wrap:wrap;
  gap:10px 14px;
  color:var(--muted);
  font-size:14px;
  margin-bottom:12px;
}}

.meta span {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.05);
  border-radius: 999px;
  padding: 6px 10px;
}}


.meta span .mono {{
  background: transparent;
  border: 0;
  padding: 0;
  border-radius: 0;
  color: var(--text);
  font-size: 13px;
}}

.section {{
  margin-top:32px;
}}

.section-head {{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-bottom:12px;
}}

.section-note {{
  color:var(--faint);
  font-size:13px;
}}

.cols {{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:20px;
}}

.kv {{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
  gap:10px 16px;
  margin:12px 0 14px;
}}

.kv > div {{
  background:var(--panel2);
  border:1px solid var(--border-soft);
  border-radius:12px;
  padding:10px 12px;
}}

.k {{
  display:block;
  color:var(--faint);
  font-size:12px;
  text-transform:uppercase;
  letter-spacing:.04em;
  margin-bottom:4px;
}}

.v {{
  display:block;
  color:var(--text);
  font-size:14px;
}}

.node + .node {{
  margin-top:16px;
}}

.node-head {{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  margin-bottom:10px;
}}

.pill {{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:72px;
  padding:6px 10px;
  border-radius:999px;
  font-size:12px;
  font-weight:bold;
  text-transform:uppercase;
  letter-spacing:.04em;
  border:1px solid var(--border-soft);
  background:var(--panel2);
  color:var(--text);
}}

.pill.critical {{ background:rgba(239,91,91,.12); color:#ffb1b1; border-color:rgba(239,91,91,.35); }}
.pill.strong {{ background:rgba(243,181,74,.12); color:#ffd98b; border-color:rgba(243,181,74,.35); }}
.pill.moderate {{ background:rgba(142,197,255,.12); color:#bfe0ff; border-color:rgba(142,197,255,.35); }}
.pill.good {{ background:rgba(31,185,129,.12); color:#89f0c5; border-color:rgba(31,185,129,.35); }}
.pill.warn {{ background:rgba(243,181,74,.12); color:#ffd98b; border-color:rgba(243,181,74,.35); }}
.pill.bad {{ background:rgba(239,91,91,.12); color:#ffb1b1; border-color:rgba(239,91,91,.35); }}
.pill.neutral, .pill.unknown {{ background:rgba(142,197,255,.10); color:#bfe0ff; border-color:rgba(142,197,255,.25); }}

ul {{
  margin:8px 0 0 18px;
  padding:0;
}}

li {{
  margin:5px 0;
}}

.statlist {{
  list-style:none;
  margin:8px 0 0;
  padding:0;
}}

.statlist li {{
  display:flex;
  justify-content:space-between;
  gap:12px;
  padding:8px 0;
  border-bottom:1px solid rgba(255,255,255,.05);
}}

.statlist li:last-child {{
  border-bottom:0;
}}

.footer-note {{
  margin-top:26px;
  color:var(--faint);
  font-size:13px;
}}

@media (max-width: 900px) {{
  .cols {{ grid-template-columns:1fr; }}
  .hero-top {{ align-items:flex-start; }}
}}

@media (max-width: 640px) {{
  .wrap {{ padding:16px; }}
  .grid {{ grid-template-columns:1fr 1fr; }}
  .smallgrid {{ grid-template-columns:1fr; }}
  .meta {{ gap:8px; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>DeFCoN Network Inspector</h1>
        <p class="subtitle">Snapshot UTC: {esc(summary.get('timestamp') or 'unknown')}</p>
      </div>
      <div class="section-note">Generated from masternodelist / protx snapshot data and retained PoSe-ban history</div>
    </div>

    <div class="summary-box">
      <h2>Executive summary</h2>
      <p>{esc(summary_text)}</p>
    </div>
  </section>

  <div class="grid">{''.join(cards)}</div>

  <div class="section smallgrid">
    <div class="panel">
      <h2>Dominant root causes</h2>
      <ul class="statlist">{root_causes_html}</ul>
    </div>
    <div class="panel">
      <h2>Evidence levels</h2>
      <ul class="statlist">{evidence_html}</ul>
    </div>
    <div class="panel">
      <h2>Problem node statuses</h2>
      <ul class="statlist">{status_html}</ul>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2>Top suspicious nodes</h2>
      <div class="section-note">Highest-priority nodes to inspect first</div>
    </div>
    {''.join(nodes_html) if nodes_html else '<div class="panel">No problematic nodes found.</div>'}
  </div>

  <div class="section">
    <div class="section-head">
      <h2>Operator clusters</h2>
      <div class="section-note">Repeated operator keys across multiple nodes</div>
    </div>
    <div class="smallgrid">{cluster_cards(operator_clusters, 'operator_pubkey', 'Operator key')}</div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2>IP clusters</h2>
      <div class="section-note">Shared service IPs used by multiple nodes</div>
    </div>
    <div class="smallgrid">{cluster_cards(ip_clusters, 'service_ip', 'Service IP')}</div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2>Subnet clusters</h2>
      <div class="section-note">Grouped by network subnet for correlated outages or waves</div>
    </div>
    <div class="smallgrid">{cluster_cards(subnet_clusters, 'service_subnet', 'Subnet')}</div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2>PoSe ban waves</h2>
      <div class="section-note">Grouped historical PoSe events within the configured window</div>
    </div>
    <div class="smallgrid">{''.join(waves_html) if waves_html else '<div class="panel">No PoSe ban waves found.</div>'}</div>
  </div>

  <div class="section">
    <div class="section-head">
      <h2>Community contact list</h2>
      <div class="section-note">Nodes that should be reviewed or contacted first</div>
    </div>
    <div class="smallgrid">{''.join(contact_html) if contact_html else '<div class="panel">No contact targets found.</div>'}</div>
  </div>

  <p class="footer-note">
    This report shows visible on-chain / RPC-derived patterns and historical PoSe-ban correlations. It highlights likely misconfiguration groups, but it does not prove private-key ownership or exact operator intent.
  </p>
</div>
</body>
</html>'''
    path.write_text(html_doc)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--state-dir', required=True)
    ap.add_argument('--cli', required=True)
    ap.add_argument('--conf')
    ap.add_argument('--datadir')
    ap.add_argument('--rpc-port')
    ap.add_argument('--deep-scan', default='1')
    ap.add_argument('--wave-window-seconds', type=int, default=1800)
    ap.add_argument('--history-retention-days', type=int, default=30)
    ap.add_argument('--snapshot-retention-days', type=int, default=30)
    ap.add_argument('--report-retention-days', type=int, default=30)
    ap.add_argument('--rpc-timeout-seconds', type=int, default=30)
    args = ap.parse_args()

    state_dir = Path(args.state_dir)
    snapshots_dir = state_dir / 'snapshots'
    reports_dir = state_dir / 'reports'
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    history_path = state_dir / 'history.json'
    history, history_error = load_json(history_path, {}, salvage_corrupt=True)
    history = prune_history(history, retention_days=args.history_retention_days)
    
    if history_error:
        err_msg, backup_path = history_error
        msg = f"history.json was corrupt and has been reset: {err_msg}"
        if backup_path:
            msg += f" | backup: {backup_path}"
        (reports_dir / 'latest-error.txt').write_text(msg + '\n')

    now = utc_now()
    timestamp = now.strftime('%Y%m%dT%H%M%SZ')

    try:
        mn = run_cli(
            args.cli, 'masternodelist', 'json',
            conf=args.conf, datadir=args.datadir, rpcport=args.rpc_port,
            timeout_seconds=args.rpc_timeout_seconds
        )
        protx = run_cli(
            args.cli, 'protx', 'list', 'valid', '1',
            conf=args.conf, datadir=args.datadir, rpcport=args.rpc_port,
            timeout_seconds=args.rpc_timeout_seconds
        )
    except Exception as e:
        (reports_dir / 'latest-error.txt').write_text(str(e) + '\n')
        raise

    rows = normalize_protx(protx, normalize_masternodelist(mn))
    rows = deep_scan(
        rows, args.cli, args.deep_scan,
        conf=args.conf, datadir=args.datadir, rpcport=args.rpc_port,
        timeout_seconds=args.rpc_timeout_seconds
    )

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
        'history_retention_days': args.history_retention_days,
        'snapshot_retention_days': args.snapshot_retention_days,
        'report_retention_days': args.report_retention_days,
        'rpc_timeout_seconds': args.rpc_timeout_seconds,
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

    removed_snapshots = cleanup_old_files_by_age(snapshots_dir, 'snapshot-*.json', args.snapshot_retention_days)
    removed_reports = cleanup_reports(reports_dir, args.report_retention_days)

    summary['removed_old_snapshots'] = removed_snapshots
    summary['removed_old_reports'] = removed_reports

    save_json(reports_dir / 'latest-summary.json', summary)
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
Description=DeFCoN Network Inspector background analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${DEFCON_USER}
Group=${DEFCON_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${RUNNER_PATH}
Restart=always
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=${STATE_DIR} ${LOG_DIR}

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
    python3 "${APP_DIR}/analyzer.py" \
      --state-dir "${STATE_DIR}" \
      --cli "${CLI_BIN}" \
      --conf "${CONF_FILE}" \
      --datadir "${DATA_DIR}" \
      --rpc-port "${DEFCON_RPC_PORT}" \
      --deep-scan "${DEEP_SCAN}" \
      --wave-window-seconds "${WAVE_WINDOW_SECONDS}" \
      --history-retention-days "${HISTORY_RETENTION_DAYS:-30}" \
      --snapshot-retention-days "${SNAPSHOT_RETENTION_DAYS:-30}" \
      --report-retention-days "${REPORT_RETENTION_DAYS:-30}" \
      --rpc-timeout-seconds "${RPC_TIMEOUT_SECONDS:-30}" | tee -a "${LOG_DIR}/manual-run.log"
  ) 9>"${LOCK_FILE}"
}

check_requirements() {
  source "${APP_DIR}/env.sh"
  info "Checking requirements..."
  [[ -x "${CLI_BIN}" ]] && ok "CLI found: ${CLI_BIN}" || err "CLI not found: ${CLI_BIN}"
  [[ -x "${DAEMON_BIN}" ]] && ok "Daemon found: ${DAEMON_BIN}" || err "Daemon not found: ${DAEMON_BIN}"
  [[ -f "${CONF_FILE}" ]] && ok "Config found: ${CONF_FILE}" || err "Config not found: ${CONF_FILE}"
  [[ -d "${DATA_DIR}" ]] && ok "Datadir found: ${DATA_DIR}" || err "Datadir not found: ${DATA_DIR}"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${DEFCON_SERVICE}"; then
      ok "Service ${DEFCON_SERVICE} is running"
    else
      warn "Service ${DEFCON_SERVICE} is not running"
    fi
  fi
  if [[ -x "${CLI_BIN}" ]]; then
    if runuser -u "${DEFCON_USER}" -- "${CLI_BIN}" \
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
    systemctl enable --now "${APP_NAME}.service" || true

    if systemctl is-active --quiet "${APP_NAME}.service"; then
      ok "Background analysis started via systemd."
    else
      warn "Start command was issued, but ${APP_NAME}.service is not active."
      echo
      echo "Recent log lines:"
      journalctl -u "${APP_NAME}.service" -n 20 --no-pager 2>/dev/null || true
    fi
  else
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}" 2>/dev/null)" 2>/dev/null; then
      warn "Background analysis is already running with PID $(cat "${PID_FILE}")."
      return
    fi

    nohup runuser -u "${DEFCON_USER}" -- "${RUNNER_PATH}" >> "${NOHUP_LOG}" 2>&1 &
    echo $! > "${PID_FILE}"
    sleep 1

    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}" 2>/dev/null)" 2>/dev/null; then
      ok "Background analysis started via nohup. PID $(cat "${PID_FILE}")."
    else
      warn "Start command was issued, but nohup background process is not running."
      [[ -f "${NOHUP_LOG}" ]] && tail -n 20 "${NOHUP_LOG}" 2>/dev/null || true
    fi
  fi
}

stop_background() {
  source "${APP_DIR}/env.sh"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${APP_NAME}.service"; then
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

  warn "No running background analysis found."
}

status_background() {
  source "${APP_DIR}/env.sh"

  if command -v systemctl >/dev/null 2>&1; then
    local active enabled substate pid startts startepoch nowepoch uptimesec uptimehuman mem task state
    active="$(systemctl is-active "${APP_NAME}.service" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "${APP_NAME}.service" 2>/dev/null || true)"
    substate="$(systemctl show -p SubState --value "${APP_NAME}.service" 2>/dev/null || true)"
    pid="$(systemctl show -p ExecMainPID --value "${APP_NAME}.service" 2>/dev/null || true)"
    startts="$(systemctl show -p ActiveEnterTimestamp --value "${APP_NAME}.service" 2>/dev/null || true)"
    task="$(systemctl show -p TasksCurrent --value "${APP_NAME}.service" 2>/dev/null || true)"
    mem="$(systemctl show -p MemoryCurrent --value "${APP_NAME}.service" 2>/dev/null || true)"
    state="$(systemctl show -p ActiveState --value "${APP_NAME}.service" 2>/dev/null || true)"

    if [[ "${active}" == "active" ]]; then
      nowepoch="$(date +%s)"
      startepoch=""
      uptimesec=""
      uptimehuman="unknown"

      if [[ -n "${startts}" ]]; then
        startepoch="$(date -d "${startts}" +%s 2>/dev/null || true)"
      fi

      if [[ -n "${startepoch}" ]]; then
        uptimesec=$(( nowepoch - startepoch ))
        local d h m s
        d=$(( uptimesec / 86400 ))
        h=$(( (uptimesec % 86400) / 3600 ))
        m=$(( (uptimesec % 3600) / 60 ))
        s=$(( uptimesec % 60 ))

        if (( d > 0 )); then
          uptimehuman="${d}d ${h}h ${m}m ${s}s"
        elif (( h > 0 )); then
          uptimehuman="${h}h ${m}m ${s}s"
        elif (( m > 0 )); then
          uptimehuman="${m}m ${s}s"
        else
          uptimehuman="${s}s"
        fi
      fi

      if [[ -n "${mem}" && "${mem}" =~ ^[0-9]+$ ]]; then
        mem="$(numfmt --to=iec --suffix=B "${mem}" 2>/dev/null || echo "${mem}")"
      fi

      ok "Background analysis is running via systemd."
      echo "Service: ${APP_NAME}.service"
      echo "ActiveState: ${state:-unknown}"
      echo "SubState: ${substate:-unknown}"
      echo "Enabled: ${enabled:-unknown}"
      echo "Main PID: ${pid:-unknown}"
      echo "Started: ${startts:-unknown}"
      echo "Uptime: ${uptimehuman}"
      echo "Tasks: ${task:-unknown}"
      echo "Memory: ${mem:-unknown}"
      if [[ -f "${HEALTH_FILE}" ]]; then
        echo "Health: $(tr -d '\n' < "${HEALTH_FILE}")"
      fi
      echo
      echo "Recent log lines:"
      journalctl -u "${APP_NAME}.service" -n 12 --no-pager 2>/dev/null || true
      return
    fi

    if [[ -n "${state}" || -n "${enabled}" || "${active}" == "inactive" || "${active}" == "failed" || "${active}" == "activating" || "${active}" == "deactivating" ]]; then
      warn "Service exists but is not currently running."
      echo "Service: ${APP_NAME}.service"
      echo "ActiveState: ${state:-unknown}"
      echo "SubState: ${substate:-unknown}"
      echo "is-active: ${active:-unknown}"
      echo "Enabled: ${enabled:-unknown}"
      if [[ -f "${HEALTH_FILE}" ]]; then
        echo "Health: $(tr -d '\n' < "${HEALTH_FILE}")"
      fi
      echo
      echo "Last log lines:"
      journalctl -u "${APP_NAME}.service" -n 20 --no-pager 2>/dev/null || true
      return
    fi
  fi

  if [[ -f "${PID_FILE}" ]]; then
    local pid started uptimesec uptimehuman startepoch nowepoch d h m s
    pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      started="$(ps -o lstart= -p "${pid}" 2>/dev/null | sed 's/^ *//')"
      uptimehuman="unknown"

      if [[ -n "${started}" ]]; then
        startepoch="$(date -d "${started}" +%s 2>/dev/null || true)"
        nowepoch="$(date +%s)"
        if [[ -n "${startepoch}" ]]; then
          uptimesec=$(( nowepoch - startepoch ))
          d=$(( uptimesec / 86400 ))
          h=$(( (uptimesec % 86400) / 3600 ))
          m=$(( (uptimesec % 3600) / 60 ))
          s=$(( uptimesec % 60 ))

          if (( d > 0 )); then
            uptimehuman="${d}d ${h}h ${m}m ${s}s"
          elif (( h > 0 )); then
            uptimehuman="${h}h ${m}m ${s}s"
          elif (( m > 0 )); then
            uptimehuman="${m}m ${s}s"
          else
            uptimehuman="${s}s"
          fi
        fi
      fi

      ok "Background analysis is running via nohup."
      echo "PID: ${pid}"
      echo "Started: ${started:-unknown}"
      echo "Uptime: ${uptimehuman}"
      echo "Log: ${NOHUP_LOG}"
      [[ -f "${HEALTH_FILE}" ]] && echo "Health: $(tr -d '\n' < "${HEALTH_FILE}")"
      return
    fi
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
Health: ${HEALTH_FILE}
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
    rm -f "${STATE_DIR}/history.json" "${PID_FILE}" "${LOCK_FILE}" "${HEALTH_FILE}"
    ok "All stored data has been deleted."
  else
    warn "Cancelled."
  fi
}

menu() {
  while true; do
    echo
    echo -e "${BLUE}=====================================${NC}"
    echo -e "${BLUE} DeFCoN Network Inspector v2${NC}"
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
  write_env
  write_runner
  write_analyzer
  write_service
  chown -R "${DEFCON_USER}:${DEFCON_USER}" "${STATE_DIR}" "${LOG_DIR}"
  chown -R root:root "${APP_DIR}"
  chmod -R a=rX "${APP_DIR}"
  find "${APP_DIR}" -type f -name "*.sh" -exec chmod 755 {} \;
  find "${APP_DIR}" -type f -name "*.py" -exec chmod 755 {} \;
  ln -sf "$0" "${MENU_LINK}"
  chmod +x "$0"
  ok "Installation completed."
}

usage() {
cat <<USAGE
Usage:
  bash defcon-network-inspector.sh                # installs on first run and shows the menu
  bash defcon-network-inspector.sh menu
  bash defcon-network-inspector.sh install
  bash defcon-network-inspector.sh run-once
  bash defcon-network-inspector.sh start
  bash defcon-network-inspector.sh stop
  bash defcon-network-inspector.sh status
  bash defcon-network-inspector.sh report
  bash defcon-network-inspector.sh problems
  bash defcon-network-inspector.sh wipe
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
