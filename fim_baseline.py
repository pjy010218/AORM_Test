# fim_baseline.py

import os
import sys
import json
import hashlib

CONFIG = {
    "baseline_file": "fim_baseline.json",
    "monitored_dirs": ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"],
    "buffer_size": 65536
}

def get_file_hash(filepath):
    """파일의 SHA-256 해시를 계산합니다."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(CONFIG["buffer_size"])
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except (IOError, PermissionError):
        return None

def create_baseline():
    """모니터링 대상 디렉토리의 모든 파일에 대한 해시 기준선을 생성합니다."""
    print("[FIM] Creating a new integrity baseline...")
    baseline = {}
    for directory in CONFIG["monitored_dirs"]:
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if not os.path.exists(filepath) or os.path.isdir(filepath) or os.path.islink(filepath):
                    continue
                filehash = get_file_hash(filepath)
                if filehash:
                    baseline[filepath] = filehash
    
    with open(CONFIG["baseline_file"], 'w') as f:
        json.dump(baseline, f, indent=4)
    print(f"[FIM] ✅ Baseline created with {len(baseline)} files.")

def check_integrity():
    """현재 파일 시스템 상태를 기준선과 비교하여 변경 사항을 보고합니다."""
    if not os.path.exists(CONFIG["baseline_file"]):
        print("[FIM] ERROR: Baseline file not found.")
        return

    with open(CONFIG["baseline_file"], 'r') as f:
        baseline = json.load(f)

    checked_files = set()
    alerts = []

    for directory in CONFIG["monitored_dirs"]:
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if not os.path.exists(filepath) or os.path.isdir(filepath) or os.path.islink(filepath):
                    continue
                checked_files.add(filepath)
                
                current_hash = get_file_hash(filepath)
                if not current_hash:
                    continue

                if filepath not in baseline:
                    alerts.append(f"ALERT! File CREATED: {filepath}")
                elif baseline[filepath] != current_hash:
                    alerts.append(f"ALERT! File MODIFIED: {filepath}")

    deleted_files = set(baseline.keys()) - checked_files
    for filepath in deleted_files:
        alerts.append(f"ALERT! File DELETED: {filepath}")

    if alerts:
        print("[FIM] Integrity violations detected:")
        for alert in alerts:
            print(alert)
    else:
        print("[FIM] No integrity violations detected.")
    
if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['create', 'check']:
        print("Usage: sudo python3 fim_baseline.py [create|check]")
        sys.exit(1)
        
    mode = sys.argv[1]
    if mode == 'create':
        create_baseline()
    elif mode == 'check':
        check_integrity()