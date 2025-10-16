# aorm_engine.py
# Patched version with external detection rules (detection_rules.json)
import json
import os
import time
import re
from profiler import HybridProfiler

# --- configuration & initialization ---
BASE_SCORE_THRESHOLD = 8.0
behavior_profiler = HybridProfiler(base_score_threshold=BASE_SCORE_THRESHOLD)

# process_tree: { pid: {'ppid': ppid, 'comm': comm, 'exe_path': path} }
process_tree = {}

def build_initial_process_tree():
    """
    Scan /proc at agent startup to populate an initial process tree.
    Non-fatal on permission errors or rapidly-exiting processes.
    """
    print("  [INFO] Building initial process tree from /proc...")
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            status_path = f'/proc/{pid}/status'
            exe_path = ''
            ppid = -1
            comm = "N/A"
            with open(status_path, 'r') as f:
                for line in f:
                    if line.startswith('Name:'):
                        comm = line.split(':', 1)[1].strip()
                    elif line.startswith('PPid:'):
                        try:
                            ppid = int(line.split(':', 1)[1].strip())
                        except Exception:
                            ppid = -1
            try:
                exe_path = os.readlink(f'/proc/{pid}/exe')
            except Exception:
                exe_path = ''
            process_tree[pid] = {'ppid': ppid, 'comm': comm, 'exe_path': exe_path}
        except (IOError, OSError):
            # permission issues or process disappeared
            continue
    print(f"  [INFO] Initial process tree built. {len(process_tree)} processes loaded.")

# Build initial tree once
build_initial_process_tree()

# Load system baseline execs if present
SYSTEM_BASELINE_EXECS = set()
if os.path.exists('system_baseline.json'):
    try:
        with open('system_baseline.json', 'r') as f:
            SYSTEM_BASELINE_EXECS = set(json.load(f).keys())
    except Exception:
        SYSTEM_BASELINE_EXECS = set()

# Thresholds and policy maps
CRITICAL_THRESHOLD = 12.0
WHITELIST_PATHS = ('/proc/', '/lib/', '/usr/lib/', '/etc/ld.so.cache',)
OBJECT_POLICY = {
    "/etc/shadow": "L0",
    "/etc/passwd": "L0",
    "/etc/sudoers": "L0",
    "bin": "L1",
    "/usr/bin": "L1",
    "/sbin": "L1",
    "/root/": "L1",
    "/etc/": "L2",
    "/var/log/": "L3",
    "/tmp/": "L3",
}
ACTION_POLICY = {
    "bash": "L2", "cat": "L3", "sshd": "L1", "vim": "L2", "rm": "L1", "mv": "L1",
    "cp": "L1", "nano": "L2", "systemd": "L0", "sudo": "L0", "find": "L3",
    "python3": "L2", "perl": "L2", "gcc": "L2", "g++": "L2", "make": "L2",
    "curl": "L2", "wget": "L2",
}
LEVEL_SCORES = {"L0": 10, "L1": 7, "L2": 4, "L3": 1}
LEVEL_NAMES = ["L0", "L1", "L2", "L3"]

# ---- Helper utilities ----
def safe_str(v):
    """Return a native string for bytes/str/None."""
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode('utf-8', errors='replace')
        except Exception:
            return str(v)
    return str(v)

# ---------------------------
# Load detection rules from external JSON (detection_rules.json)
# ---------------------------
DETECTION_RULES_PATH = 'detection_rules.json'
# default fallback rules (same shape as JSON)
_default_rules = {
    "whitelist_commands": [
        "date", "sleep", "apt-config", "dpkg", "apt-get", "apt",
        "systemd", "systemctl", "bash", "sh"
    ],
    "rules": {
        "1_recon": [
            {"field": "comm", "type": "contains", "pattern": "cat"},
            {"field": "fname", "type": "contains", "pattern": "/etc/passwd"},
            {"field": "comm", "type": "contains", "pattern": "find"},
            {"field": "fname", "type": "contains", "pattern": "/etc/cron.d/"},
            {"field": "comm", "type": "equals", "pattern": "ps"}
        ],
        "2_rootkit": [
            {"field": "fname", "type": "equals", "pattern": "/bin/ls"},
            {"field": "comm", "type": "contains", "pattern": "mv"},
            {"field": "comm", "type": "contains", "pattern": "cp"},
            {"field": "fname", "type": "contains", "pattern": "/tmp/malicious_ls"}
        ],
        "3_multistage": [
            {"field": "fname", "type": "contains", "pattern": "/etc/hosts"},
            {"field": "comm", "type": "contains", "pattern": "chmod"},
            {"field": "fname", "type": "contains", "pattern": "/tmp/payload_"},
            {"field": "comm", "type": "contains", "pattern": "sudo"}
        ]
    }
}

try:
    if os.path.exists(DETECTION_RULES_PATH):
        with open(DETECTION_RULES_PATH, 'r') as rf:
            _json_loaded = json.load(rf)
            WHITELIST_COMMANDS = set(_json_loaded.get("whitelist_commands", _default_rules["whitelist_commands"]))
            DETECTION_RULES = _json_loaded.get("rules", _default_rules["rules"])
            # ensure proper structure
            if not isinstance(DETECTION_RULES, dict):
                DETECTION_RULES = _default_rules["rules"]
    else:
        WHITELIST_COMMANDS = set(_default_rules["whitelist_commands"])
        DETECTION_RULES = _default_rules["rules"]
        print(f"[INFO] No {DETECTION_RULES_PATH} found — using built-in default detection rules.")
except Exception as e:
    print(f"[WARN] Failed to load detection rules from {DETECTION_RULES_PATH}: {e}")
    WHITELIST_COMMANDS = set(_default_rules["whitelist_commands"])
    DETECTION_RULES = _default_rules["rules"]

# matching helper
def match_pattern(value, match_type, pattern):
    """safe matching helper"""
    if value is None:
        return False
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8', 'replace')
        except Exception:
            value = str(value)
    value = str(value)

    if match_type == 'contains':
        return pattern in value
    if match_type == 'equals':
        return value == pattern
    if match_type == 'startswith':
        return value.startswith(pattern)
    if match_type == 'regex':
        try:
            return re.search(pattern, value) is not None
        except re.error:
            return False
    return False

def check_attack_indicators(event):
    """
    Returns: (matched_scenarios:list, matched_details:list)
    matched_details: list of (scenario_key, rule_dict, matched_value)
    """
    matched = []
    details = []

    comm_val = safe_str(getattr(event, 'comm', ''))
    # quick skip if benign comm exactly in whitelist
    if comm_val in WHITELIST_COMMANDS:
        return matched, details

    for scenario_key, rules in DETECTION_RULES.items():
        scenario_matched = False
        for rule in rules:
            field = rule.get('field', 'any')
            mtype = rule.get('type', 'contains')
            pattern = rule.get('pattern', '')
            if field == 'comm':
                v = getattr(event, 'comm', '')
            elif field == 'fname':
                v = getattr(event, 'fname', '')
            elif field == 'old_fname':
                v = getattr(event, 'old_fname', '')
            else:
                # any: check both comm and fname
                v = getattr(event, 'comm', '') or getattr(event, 'fname', '')

            if match_pattern(v, mtype, pattern):
                scenario_matched = True
                details.append((scenario_key, rule, safe_str(v)))
                # do not break — collect all matching details in this scenario
        if scenario_matched:
            matched.append(scenario_key)
    return matched, details

# --- Trajectory analysis (robust) ---
def get_trajectory_score_and_path(pid, max_depth=12):
    """
    Return: (trajectory_score: float, trajectory_path_str: str,
             ancestor_comms: list[str], ancestor_pids: list[int])

    Produces robust ancestor PID and comm lists and a heuristic score.
    """
    path = []
    ancestor_comms = []
    ancestor_pids = []
    current_pid = pid
    trajectory_score = 0.0
    untrusted_first_depth = None
    untrusted_count = 0

    # system comms that shouldn't by themselves be considered malicious
    system_comm_whitelist = set([
        "systemd", "init", "kthreadd", "rcu_sched", "kworker", "watchdog", "sshd"
    ])

    for depth in range(max_depth):
        if current_pid not in process_tree:
            break

        proc_info = process_tree[current_pid]
        comm = proc_info.get('comm', 'N/A')
        exe_path = proc_info.get('exe_path', '')

        path.append(f"{comm}({current_pid})")
        ancestor_comms.append(comm)
        ancestor_pids.append(current_pid)

        # consider external if not in baseline and exe path exists
        is_external = (exe_path and exe_path not in SYSTEM_BASELINE_EXECS)

        if is_external and comm not in system_comm_whitelist:
            untrusted_count += 1
            if untrusted_first_depth is None:
                untrusted_first_depth = depth

        current_pid = proc_info.get('ppid', 0)
        if not current_pid or current_pid == 0:
            break

    if untrusted_count == 0:
        trajectory_score = 0.0
    else:
        base = 0.4
        count_factor = min(0.5, 0.12 * untrusted_count)
        proximity = 0.0
        if untrusted_first_depth is not None:
            proximity = 0.5 / (untrusted_first_depth + 1)
        trajectory_score = min(1.0, base + count_factor + proximity)

    trajectory_path_str = " -> ".join(reversed(path)) if path else ""
    return trajectory_score, trajectory_path_str, list(reversed(ancestor_comms)), list(reversed(ancestor_pids))

# --- AORM level mapping helper ---
def get_aorm_levels(process_name, file_path):
    """Return a string visualizing [ActionLevel, ObjectLevel] based on policies."""
    obj_level = "L3"
    for pref, lvl in OBJECT_POLICY.items():
        if file_path.startswith(pref):
            obj_level = lvl
            break
    act_level = ACTION_POLICY.get(process_name, "L3")
    try:
        obj_idx = LEVEL_NAMES.index(obj_level)
    except ValueError:
        obj_idx = LEVEL_NAMES.index("L3")
    try:
        act_idx = LEVEL_NAMES.index(act_level)
    except ValueError:
        act_idx = LEVEL_NAMES.index("L3")
    return f"[L{act_idx}, L{obj_idx}]"

# --- core analysis functions ---
def analyze_file_event(event):
    """
    Analyze a file-related event (open/rename/unlink).
    """
    # defensive extraction
    process_name = safe_str(event.comm)
    file_path = safe_str(event.fname)
    pid = getattr(event, 'pid', None)
    try:
        pid = int(pid)
    except Exception:
        print(f"[WARN] analyze_file_event: invalid pid '{pid}'")
        return

    # whitelist paths: ignore
    if any(file_path.startswith(p) for p in WHITELIST_PATHS):
        return

    # --- attack indicator check (rule-based, exact scenario detection) ---
    matched_scenarios, matched_details = check_attack_indicators(event)
    if matched_scenarios:
        # Log details and force a high final score (TP treatment)
        print(f"[Indicator] Detected scenario(s): {matched_scenarios}; details: {matched_details}")
        # record to profiler so learning can adapt but ensure alert
        try:
            behavior_profiler.process_event(process_name, file_path, BASE_SCORE_THRESHOLD + 1.0)
        except Exception:
            pass
        forced_score = CRITICAL_THRESHOLD + 1.0
        print(f"🚨 ALERT! Indicator-based detection for scenarios: {matched_scenarios} | Forced Final Score: {forced_score:.1f}")
        return

    # 1) trajectory info
    trajectory_score, trajectory_path, ancestor_comms, ancestor_pids = get_trajectory_score_and_path(pid)

    # 2) object score
    object_level = "L3"
    for pref, lvl in OBJECT_POLICY.items():
        if file_path.startswith(pref):
            object_level = lvl
            break
    object_score = LEVEL_SCORES.get(object_level, 1)

    # 3) determine worst external action level among relevant ancestors
    worst_external_action_level = "L3"
    for anc_pid in ancestor_pids:
        if anc_pid in process_tree:
            proc_info = process_tree[anc_pid]
            anc_comm = proc_info.get('comm', 'N/A')
            anc_exe = proc_info.get('exe_path', '')
            if anc_exe and anc_exe not in SYSTEM_BASELINE_EXECS:
                proc_level_str = ACTION_POLICY.get(anc_comm, "L3")
                try:
                    if int(proc_level_str[1]) < int(worst_external_action_level[1]):
                        worst_external_action_level = proc_level_str
                except Exception:
                    continue

    action_score = LEVEL_SCORES.get(worst_external_action_level, 1)
    aorm_base_score = object_score + action_score

    # 4) anomaly score
    anomaly_score = behavior_profiler.process_event(process_name, file_path, aorm_base_score)

    # 5) final risk
    final_risk_score = aorm_base_score * (1 + anomaly_score) * (1 + trajectory_score)

    # logging
    aorm_cell = get_aorm_levels(process_name, file_path)
    print(f"[Trajectory] {trajectory_path} => {process_name} opens {file_path} | Mapping to {aorm_cell}")
    print(f"  [Scoring] Base: {aorm_base_score:.1f} (Obj:{object_level}, Act: {worst_external_action_level}), Anomaly: {anomaly_score:.2f}, Trajectory: {trajectory_score:.2f} -> Final: {final_risk_score:.1f}")

    if final_risk_score >= CRITICAL_THRESHOLD:
        print(f"🚨 ALERT! Suspicious Trajectory Detected. Final Score: {final_risk_score:.1f}")

# --- event dispatcher from kernel ---
def process_event_from_kernel(event):
    """
    Entry point for events coming from BPF agent.
    Expects `event` to expose .type, .pid, .ppid, .comm, .fname, .old_fname as attributes (bytes or str).
    """
    try:
        event_type = int(getattr(event, 'type', 0))
    except Exception:
        print("[WARN] process_event_from_kernel: event.type invalid, defaulting to 0")
        event_type = 0

    # exec events: update process_tree
    if event_type == 1:  # exec
        try:
            pid = int(getattr(event, 'pid', -1))
            ppid = int(getattr(event, 'ppid', 0))
        except Exception:
            print(f"[WARN] process_event_from_kernel: invalid pid/ppid values pid={getattr(event,'pid',None)} ppid={getattr(event,'ppid',None)}")
            return

        comm = safe_str(getattr(event, 'comm', ''))
        exe_path = safe_str(getattr(event, 'fname', ''))
        process_tree[pid] = {'ppid': ppid, 'comm': comm, 'exe_path': exe_path}

    # file events: analyze
    elif event_type in [0, 2, 3]:
        analyze_file_event(event)

    # else: ignore other event types for now
