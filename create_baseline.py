# create_baseline.py

import json
import hashlib
import os

INPUT_FILE_LIST = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/etc"
]
OUTPUT_FILE = "system_baseline.json"
BUFFER_SIZE = 65536  # 64KB

def create_system_baseline():
    """
    주요 시스템 디렉토리를 스캔하여 각 파일의 경로와 해시를 system_baseline.json에 저장합니다.
    """
    print(f"Scanning system directories to create baseline...")
    baseline_data = {}
    
    filepaths = []
    for directory in INPUT_FILE_LIST:
        if os.path.isdir(directory):
            for dirpath, _, filenames in os.walk(directory):
                for filename in filenames:
                    filepaths.append(os.path.join(dirpath, filename))

    print(f"Found {len(filepaths)} potential files. Generating hashes...")

    for path in filepaths:
        if not os.path.exists(path) or os.path.isdir(path) or os.path.islink(path):
            continue
        
        sha256 = hashlib.sha256()
        try:
            with open(path, 'rb') as file_to_hash:
                while True:
                    data = file_to_hash.read(BUFFER_SIZE)
                    if not data:
                        break
                    sha256.update(data)
            
            baseline_data[path] = {'hash': sha256.hexdigest()}

        except (IOError, PermissionError):
            # 권한 없는 파일은 건너뜀
            continue

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(baseline_data, f, indent=4)

    print(f"✅ Successfully created '{OUTPUT_FILE}' with {len(baseline_data)} entries.")

if __name__ == "__main__":
    create_system_baseline()