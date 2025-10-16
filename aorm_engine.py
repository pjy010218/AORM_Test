# aorm_engine.py
# Patched to avoid alerting on system daemons (systemd, systemd-oomd, etc.)
# and to fallback to a conservative system baseline if none provided.

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
            continue
    print(f"  [INFO] Initial process tree built. {len(process_tree)} processes loaded.")

build_initial_process_tree()

# Load system baseline execs if present
SYSTEM_BASELINE_EXECS = set()
if os.path.exists('system_baseline.json'):
    try:
        with open('system_baseline.json', 'r') as f:
            SYSTEM_BASELINE_EXECS = set(json.load(f).keys())
    except Exception:
        SYSTEM_BASELINE_EXECS = set()

# --- Important fallback: populate a conservative baseline if empty ---
if not SYSTEM_BASELINE_EXECS:
    # If no baseline file provided, include common system binary directories' executables
    # This reduces false "external" classification for typical system daemons.
    possible_paths = ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/lib', '/usr/lib']
    for base in possible_paths:
        if os.path.exists(base):
            for root, dirs, files in os.walk(base):
                for fn in files:
                    SYSTEM_BASELINE_EXECS.add(os.path.join(root, fn))
    # Note: this is conservative and may include many files; it's safe to reduce FP.
    print(f"  [INFO] SYSTEM_BASELINE_EXECS auto-populated with {len(SYSTEM_BASELINE_EXECS)} paths (fallback).")
else:
    print(f"  [INFO] Loaded SYSTEM_BASELINE_EXECS with {len(SYSTEM_BASELINE_EXECS)} entries.")

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

# System comm whitelist: these names should not by themselves be treated as "external" threat actors
SYSTEM_COMM_WHITELIST = set([
    "systemd", "init", "kthreadd", "rcu_sched", "kworker", "watchdog", "sshd", "systemd-oomd"
])

# ---- Helper utilities ----
def safe_str(v):
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode('utf-8', errors='replace')
        except Exception:
            return str(v)
    return str(v)

# --- Trajectory analysis (robust) ---
def get_trajectory_score_and_path(pid, max_depth=12):
    path = []
    ancestor_comms = []
    ancestor_pids = []
    current_pid = pid
    trajectory_score = 0.0
    untrusted_first_depth = None
    untrusted_count = 0

    # system comms that shouldn't by themselves be considered malicious
    system_comm_whitelist = SYSTEM_COMM_WHITELIST

    for depth in range(max_depth):
        if current_pid not in process_tree:
            break

        proc_info = process_tree[current_pid]
        comm = proc_info.get('comm', 'N/A')
        exe_path = proc_info.get('exe_path', '')

        path.append(f"{comm}({current_pid})")
        ancestor_comms.append(comm)
        ancestor_pids.append(current_pid)

        is_external = (exe_path and exe_path not in SYSTEM_BASELINE_EXECS)

        # DO NOT count as untrusted if comm is system daemon (whitelisted)
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
    process_name = safe_str(event.comm)
    file_path = safe_str(event.fname)
    pid = getattr(event, 'pid', None)
    try:
        pid = int(pid)
    except Exception:
        print(f"[WARN] analyze_file_event: invalid pid '{pid}'")
        return

    if any(file_path.startswith(p) for p in WHITELIST_PATHS):
        return

    # Indicator-based rules (external JSON or defaults) would be processed earlier if present --
    # here we focus on the scoring path. If rule-based detection already triggered, this code won't run.

    # 1) trajectory info
    trajectory_score, trajectory_path, ancestor_comms, ancestor_pids = get_trajectory_score_and_path(pid)

    # 2) object score
    object_level = "L3"
    for pref, lvl in OBJECT_POLICY.items():
        if file_path.startswith(pref):
            object_level = lvl
            break
    object_score = LEVEL_SCORES.get(object_level, 1)

    # -----------------------------
    # 3) Determine action score **with improved trust checks**
    # -----------------------------
    worst_external_action_level = "L3"
    for anc_pid in ancestor_pids:
        if anc_pid not in process_tree:
            continue
        proc_info = process_tree[anc_pid]
        anc_comm = proc_info.get('comm', 'N/A')
        anc_exe = proc_info.get('exe_path', '')

        # --- NEW: skip if ancestor is a known system daemon (by comm) ---
        if anc_comm in SYSTEM_COMM_WHITELIST:
            # treat as trusted; do not escalate based on system daemon
            continue

        # --- NEW: skip if ancestor executable is in baseline (trusted) ---
        if anc_exe and anc_exe in SYSTEM_BASELINE_EXECS:
            continue

        # only now consider it an external candidate for raising action risk
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
    try:
        event_type = int(getattr(event, 'type', 0))
    except Exception:
        print("[WARN] process_event_from_kernel: event.type invalid, defaulting to 0")
        event_type = 0

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

    elif event_type in [0, 2, 3]:
        analyze_file_event(event)
