# ===============================================================
# AORM Engine (final patched version)
# ===============================================================
import json
import os
import time
import re
from profiler import HybridProfiler

# --- 0. 초기화 및 설정 ---
BASE_SCORE_THRESHOLD = 8.0
CRITICAL_THRESHOLD = 12.0
behavior_profiler = HybridProfiler(base_score_threshold=BASE_SCORE_THRESHOLD)

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

# --- 1. 베이스라인 / 정책 로딩 ---
SYSTEM_BASELINE_EXECS = set()
if os.path.exists('system_baseline.json'):
    try:
        with open('system_baseline.json', 'r') as f:
            SYSTEM_BASELINE_EXECS = set(json.load(f).keys())
    except Exception:
        SYSTEM_BASELINE_EXECS = set()

# Fallback: 시스템 바이너리 자동 등록
if not SYSTEM_BASELINE_EXECS:
    for base in ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/lib', '/usr/lib']:
        if os.path.exists(base):
            for root, dirs, files in os.walk(base):
                for fn in files:
                    SYSTEM_BASELINE_EXECS.add(os.path.join(root, fn))
    print(f"  [INFO] SYSTEM_BASELINE_EXECS auto-populated with {len(SYSTEM_BASELINE_EXECS)} paths.")
else:
    print(f"  [INFO] Loaded SYSTEM_BASELINE_EXECS with {len(SYSTEM_BASELINE_EXECS)} entries.")

# --- 2. 정책 / 매핑 정의 ---
WHITELIST_PATHS = (
    '/proc/', '/lib/', '/usr/lib/', '/etc/ld.so.cache',
    '/sys/', '/run/', '/dev/', '/proc/sys/', '/sys/fs/', '/var/run/',
    "/usr/libexec/coreutils/",
    "/usr/share/locale/",
    "/usr/share/locale-langpack/",
    "/usr/share/dpkg/",
    "/etc/apt/apt.conf.d/",
    "/etc/dpkg/",
    "/var/lib/dpkg/",
    "/var/lib/apt/",
    "/dev/null",
    "/tmp/"
)

OBJECT_POLICY = {
    "/etc/shadow": "L0", "/etc/passwd": "L0", "/etc/sudoers": "L0",
    "bin": "L1", "/usr/bin": "L1", "/sbin": "L1", "/root/": "L1",
    "/etc/": "L2", "/var/log/": "L3", "/tmp/": "L3",
}
ACTION_POLICY = {
    "bash": "L2", "cat": "L3", "sshd": "L1", "vim": "L2", "rm": "L1",
    "mv": "L1", "cp": "L1", "nano": "L2", "systemd": "L0", "sudo": "L0",
    "find": "L3", "python3": "L2", "perl": "L2", "gcc": "L2",
    "curl": "L2", "wget": "L2"
}
LEVEL_SCORES = {"L0": 10, "L1": 7, "L2": 4, "L3": 1}
LEVEL_NAMES = ["L0", "L1", "L2", "L3"]

SYSTEM_COMM_WHITELIST = set([
    "systemd", "init", "kthreadd", "rcu_sched", "kworker",
    "watchdog", "sshd", "systemd-oomd", "snapd", "containerd",
    "dbus-daemon", "irqbalance", "polkitd",
    "apt-config", "apt-get", "dpkg", "gpgconf", "gpg-connect-agent",
    "apt-key", "simulate_normal", "date", "sleep", "head", "rm"
])

INDICATOR_MIN_MATCHES = 2  # 최소 2개 인디케이터 일치 시 강제 ALERT

# --- 3. 헬퍼 함수 ---
def safe_str(v):
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode('utf-8', errors='replace')
    return str(v)

# --- 4. 트래젝토리 분석 ---
def get_trajectory_score_and_path(pid, max_depth=12):
    path, ancestor_comms, ancestor_pids = [], [], []
    current_pid = pid
    trajectory_score = 0.0
    untrusted_depth = None
    untrusted_count = 0

    for depth in range(max_depth):
        if current_pid not in process_tree:
            break
        proc = process_tree[current_pid]
        comm = proc.get('comm', 'N/A')
        exe = proc.get('exe_path', '')

        path.append(f"{comm}({current_pid})")
        ancestor_comms.append(comm)
        ancestor_pids.append(current_pid)

        if exe and exe not in SYSTEM_BASELINE_EXECS and comm not in SYSTEM_COMM_WHITELIST:
            untrusted_count += 1
            if untrusted_depth is None:
                untrusted_depth = depth

        current_pid = proc.get('ppid', 0)
        if not current_pid or current_pid == 0:
            break

    if untrusted_count > 0:
        base = 0.4
        count_factor = min(0.5, 0.12 * untrusted_count)
        proximity = 0.5 / (untrusted_depth + 1) if untrusted_depth is not None else 0.0
        trajectory_score = min(1.0, base + count_factor + proximity)

    return trajectory_score, " -> ".join(reversed(path)), list(reversed(ancestor_comms)), list(reversed(ancestor_pids))

# --- 5. 레벨 매핑 ---
def get_aorm_levels(proc, file):
    obj_level = "L3"
    for pref, lvl in OBJECT_POLICY.items():
        if file.startswith(pref):
            obj_level = lvl
            break
    act_level = ACTION_POLICY.get(proc, "L3")
    return f"[{act_level}, {obj_level}]"

# --- 6. 파일 이벤트 분석 ---
def analyze_file_event(event):
    process_name = safe_str(event.comm)
    file_path = safe_str(event.fname)
    pid = getattr(event, 'pid', None)

    try:
        pid = int(pid)
    except Exception:
        print(f"[WARN] Invalid pid '{pid}'")
        return

    if any(file_path.startswith(p) for p in WHITELIST_PATHS):
        return

    # 트래젝토리 스코어
    traj_score, traj_path, ancestor_comms, ancestor_pids = get_trajectory_score_and_path(pid)

    # 객체 점수
    obj_level = "L3"
    for pref, lvl in OBJECT_POLICY.items():
        if file_path.startswith(pref):
            obj_level = lvl
            break
    obj_score = LEVEL_SCORES.get(obj_level, 1)

    # 액션 점수
    worst_act_level = "L3"
    for anc_pid in ancestor_pids:
        if anc_pid not in process_tree:
            continue
        proc = process_tree[anc_pid]
        comm = proc.get('comm', 'N/A')
        exe = proc.get('exe_path', '')
        if comm in SYSTEM_COMM_WHITELIST or exe in SYSTEM_BASELINE_EXECS:
            continue
        lvl = ACTION_POLICY.get(comm, "L3")
        if int(lvl[1]) < int(worst_act_level[1]):
            worst_act_level = lvl
    act_score = LEVEL_SCORES.get(worst_act_level, 1)

    base_score = obj_score + act_score
    anomaly_score = behavior_profiler.process_event(process_name, file_path, base_score)
    final_score = base_score * (1 + anomaly_score) * (1 + traj_score)

    levels = get_aorm_levels(process_name, file_path)
    print(f"[Trajectory] {traj_path} => {process_name} opens {file_path} | Mapping to {levels}")
    print(f"  [Scoring] Base: {base_score:.1f} (Obj:{obj_level}, Act:{worst_act_level}), "
          f"Anomaly: {anomaly_score:.2f}, Trajectory: {traj_score:.2f} -> Final: {final_score:.1f}")

    SUPPORT = (anomaly_score >= 0.6) or (traj_score >= 0.6)
    if final_score >= CRITICAL_THRESHOLD and SUPPORT:
        print(f"🚨 ALERT! Suspicious Trajectory Detected. Final Score: {final_score:.1f}")

# --- 7. 커널 이벤트 처리 ---
def process_event_from_kernel(event):
    try:
        t = int(getattr(event, 'type', 0))
    except Exception:
        t = 0

    if t == 1:  # exec
        try:
            pid = int(getattr(event, 'pid', -1))
            ppid = int(getattr(event, 'ppid', 0))
        except Exception:
            return
        comm = safe_str(getattr(event, 'comm', ''))
        exe = safe_str(getattr(event, 'fname', ''))
        process_tree[pid] = {'ppid': ppid, 'comm': comm, 'exe_path': exe}
    elif t in [0, 2, 3]:
        analyze_file_event(event)
