# aorm_engine.py

import json
import os
from profiler import StatisticalProfiler

behavior_profiler = StatisticalProfiler()

SYSTEM_BASELINE_EXECS = set()
if os.path.exists('system_baseline.json'):
    with open('system_baseline.json', 'r') as f:
        SYSTEM_BASELINE_EXECS = set(json.load(f).keys())

CRITICAL_THRESHOLD = 20.0
WHITELIST_PATHS = ('/proc/', '/lib/', '/usr/lib/', '/etc/ld.so.cache',)
OBJECT_POLICY = {"/etc/shadow": "L0", "/etc/passwd": "L0", "/etc/sudoers": "L0", "/root/": "L1", "/etc/": "L2", "/var/log/": "L3", "/tmp/": "L3",}
ACTION_POLICY = {"bash": "L2", "cat": "L3", "sshd": "L1", "vim": "L2", "rm": "L1",}
LEVEL_SCORES = {"L0": 10, "L1": 7, "L2": 4, "L3": 1}

def get_origin_score(pid):
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        return 0.1 if exe_path in SYSTEM_BASELINE_EXECS else 1.0
    except (FileNotFoundError, PermissionError):
        return 1.0

def get_object_level(file_path):
    for path, level in reversed(list(OBJECT_POLICY.items())):
        if file_path.startswith(path): return level
    return "L3"

def get_action_level(process_name):
    return ACTION_POLICY.get(process_name, "L3")

def calculate_aorm_score(event_data):
    process_name = event_data['process_name']
    file_path = event_data['file_path']
    pid = event_data['pid']

    if any(file_path.startswith(p) for p in WHITELIST_PATHS): return None
            
    anomaly_score = behavior_profiler.process_event(process_name, file_path)
    origin_score = get_origin_score(pid)
    
    aorm_base_score = LEVEL_SCORES.get(get_object_level(file_path), 1) + LEVEL_SCORES.get(get_action_level(process_name), 1)
    
    final_risk_score = aorm_base_score * (1 + anomaly_score) * (1 + origin_score)

    print(f"[DEBUG] Base: {aorm_base_score:.1f}, Anomaly: {anomaly_score:.2f}, Origin: {origin_score:.1f} -> Final: {final_risk_score:.1f}")

    if final_risk_score >= CRITICAL_THRESHOLD:
        print(f"🚨 ALERT! Proc: '{process_name}', File: '{file_path}'. Final Score: {final_risk_score:.1f}")
