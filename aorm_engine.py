# aorm_engine.py

import json
import os
from profiler import HybridProfiler

# --- 글로벌 변수 및 초기화 ---
BASE_SCORE_THRESHOLD = 8.0
behavior_profiler = HybridProfiler(base_score_threshold=BASE_SCORE_THRESHOLD)

# 프로세스 트리: {pid: {'ppid': ppid, 'comm': comm, 'exe_path': path}}
process_tree = {}

SYSTEM_BASELINE_EXECS = set()
if os.path.exists('system_baseline.json'):
    with open('system_baseline.json', 'r') as f:
        SYSTEM_BASELINE_EXECS = set(json.load(f).keys())

CRITICAL_THRESHOLD = 12.0
WHITELIST_PATHS = ('/proc/', '/lib/', '/usr/lib/', '/etc/ld.so.cache',)
OBJECT_POLICY = {"/etc/shadow": "L0", "/etc/passwd": "L0", "/etc/sudoers": "L0", "/root/": "L1", "/etc/": "L2", "/var/log/": "L3", "/tmp/": "L3",}
ACTION_POLICY = {"bash": "L2", "cat": "L3", "sshd": "L1", "vim": "L2", "rm": "L1",}
LEVEL_SCORES = {"L0": 10, "L1": 7, "L2": 4, "L3": 1}
LEVEL_NAMES = ["L0", "L1", "L2", "L3"]

# --- 핵심 분석 함수 ---

def get_trajectory_score_and_path(pid):
    """프로세스 트리를 재귀적으로 탐색하여 조상 경로와 궤적 점수를 반환합니다."""
    path = []
    current_pid = pid
    max_score = 0.1 # 기본 점수 (신뢰)

    # 최대 10단계까지만 조상 추적 (무한 루프 방지)
    for _ in range(10):
        if current_pid in process_tree:
            proc_info = process_tree[current_pid]
            comm = proc_info['comm']
            exe_path = proc_info['exe_path']
            
            path.append(f"{comm}({current_pid})")
            
            # 조상 중에 신뢰할 수 없는 출처가 하나라도 있으면 점수를 1.0으로 설정
            if exe_path not in SYSTEM_BASELINE_EXECS:
                max_score = 1.0

            current_pid = proc_info['ppid']
            if current_pid == 0: break
        else:
            break # 부모를 더 이상 추적할 수 없음
            
    return max_score, " -> ".join(reversed(path))


def get_aorm_levels(process_name, file_path):
    """AORM 레벨을 문자열로 반환합니다."""
    obj_level_idx = LEVEL_NAMES.index(OBJECT_POLICY.get(file_path, "L3"))
    act_level_idx = LEVEL_NAMES.index(ACTION_POLICY.get(process_name, "L3"))
    # 더 구체적인 정책 매칭 로직 (이전과 동일)
    for path, level in reversed(list(OBJECT_POLICY.items())):
        if file_path.startswith(path):
            obj_level_idx = LEVEL_NAMES.index(level)
            break
    return f"[L{act_level_idx}, L{obj_level_idx}]"


def analyze_file_open_event(event):
    """파일 접근 이벤트의 위험도를 종합적으로 분석합니다."""
    process_name = event.comm.decode('utf-8', 'replace')
    file_path = event.fname.decode('utf-8', 'replace')
    pid = event.pid

    if any(file_path.startswith(p) for p in WHITELIST_PATHS): return
    
    # 1. Base Score 계산
    object_level = OBJECT_POLICY.get(file_path, "L3")
    for path, level in reversed(list(OBJECT_POLICY.items())):
        if file_path.startswith(path): object_level = level; break
    action_level = ACTION_POLICY.get(process_name, "L3")
    aorm_base_score = LEVEL_SCORES.get(object_level, 1) + LEVEL_SCORES.get(action_level, 1)

    # 2. Anomaly Score 계산 (하이브리드 모델)
    anomaly_score = behavior_profiler.process_event(process_name, file_path, aorm_base_score)
    
    # 3. Trajectory Score 계산 (새로운 기능)
    trajectory_score, trajectory_path = get_trajectory_score_and_path(pid)
    
    # 4. 최종 위험도 산출 및 궤적 시각화
    final_risk_score = aorm_base_score * (1 + anomaly_score) * (1 + trajectory_score)

    # AORM 행렬 위에서의 궤적 시각화
    aorm_cell = get_aorm_levels(process_name, file_path)
    print(f"[Trajectory] {trajectory_path} => {process_name} opens {file_path} | Mapping to {aorm_cell}")
    print(f"  [Scoring] Base: {aorm_base_score:.1f}, Anomaly: {anomaly_score:.2f}, Trajectory: {trajectory_score:.1f} -> Final: {final_risk_score:.1f}")

    if final_risk_score >= CRITICAL_THRESHOLD:
        print(f"🚨 ALERT! Suspicious Trajectory Detected. Final Score: {final_risk_score:.1f}")

# --- 이벤트 처리기 ---

def process_event_from_kernel(event):
    """커널로부터 받은 이벤트를 종류에 따라 처리합니다."""
    
    # 이벤트 타입 (0: 파일 접근, 1: 프로세스 실행)
    event_type = event.type
    
    if event_type == 1: # EVENT_TYPE_EXEC
        # 프로세스 트리에 새로운 프로세스 정보 추가
        pid = event.pid
        ppid = event.ppid
        comm = event.comm.decode('utf-8', 'replace')
        exe_path = event.fname.decode('utf-8', 'replace')
        process_tree[pid] = {'ppid': ppid, 'comm': comm, 'exe_path': exe_path}
    
    elif event_type == 0: # EVENT_TYPE_FILE_OPEN
        # 파일 접근 이벤트 분석
        analyze_file_open_event(event)
