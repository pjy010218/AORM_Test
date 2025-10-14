# profiler.py

import json
import os
import time

class HybridProfiler:
    def __init__(self, profile_path='behavior_profile.json', base_score_threshold=8.0):
        """
        [수정됨] 생성자에서 self.profile을 먼저 생성하여 'AttributeError'를 원천 차단합니다.
        """
        self.profile_path = profile_path
        self.base_score_threshold = base_score_threshold
        # 1. 어떤 경우에도 self.profile이 존재하도록 가장 먼저 빈 딕셔너리로 생성합니다.
        self.profile = {}
        # 2. 그 후에 파일을 읽어 내용을 덮어씁니다.
        self._load()

    def _load(self):
        """
        [수정됨] 이제 이 함수는 파일이 있을 경우 self.profile의 내용을 채우는 역할만 합니다.
        """
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, 'r') as f:
                    # 파일 내용이 비어있지 않은 경우에만 로드
                    content = f.read()
                    if content:
                        self.profile = json.loads(content)
                print(f"  [INFO] Behavior profile loaded from '{self.profile_path}'.")
            except (json.JSONDecodeError, IOError):
                print(f"  [WARN] Profile file '{self.profile_path}' is corrupted or unreadable. Starting fresh.")
                self.profile = {} # 문제가 생겨도 빈 딕셔너리로 초기화
        else:
            print("  [INFO] No existing profile found. Starting a new one.")
            # 파일이 없어도 self.profile은 __init__ 덕분에 이미 존재합니다.

    def _save(self):
        """이제 self.profile은 항상 존재하므로 이 함수는 안전합니다."""
        try:
            with open(self.profile_path, 'w') as f:
                json.dump(self.profile, f, indent=4)
        except IOError as e:
            print(f"  [ERROR] Failed to save profile to '{self.profile_path}': {e}")

    def save_profile(self):
        """프로필을 파일에 저장하는 공개 메서드."""
        print("  [INFO] Saving behavior profile to disk...")
        self._save()

    def process_event(self, process_name, file_path, base_score):
        """개선된 통계 계산"""
        if base_score >= self.base_score_threshold:
            return 1.0
    
        event_key = f"{process_name} {file_path}"
        current_time = time.time()
        
        if event_key not in self.profile:
            self.profile[event_key] = {
                'count': 0,
                'mean': 0,
                'M2': 0,  # Welford 알고리즘을 위한 제곱합
                'std_dev': 0,
                'last_seen': 0
            }
    
        stats = self.profile[event_key]
        
        # 첫 이벤트가 아닌 경우 interval 계산
        if stats['last_seen'] == 0:
            stats['last_seen'] = current_time
            stats['count'] = 1
            return 0.8  # 첫 등장은 높은 이상도
        
        interval = current_time - stats['last_seen']
        stats['count'] += 1
        
        # Welford's 온라인 알고리즘
        delta = interval - stats['mean']
        stats['mean'] += delta / stats['count']
        delta2 = interval - stats['mean']
        stats['M2'] += delta * delta2
        
        if stats['count'] >= 2:
            variance = stats['M2'] / (stats['count'] - 1)
            stats['std_dev'] = variance ** 0.5
        
        # Z-score 계산
        anomaly_score = 0.0
        if stats['count'] > 2 and stats['std_dev'] > 0:
            z_score = abs((interval - stats['mean']) / stats['std_dev'])
            anomaly_score = min(1.0, z_score / 3.0)
        elif stats['count'] > 1:
            anomaly_score = 1.0 if interval != stats['mean'] else 0.0
        
        stats['last_seen'] = current_time
        
        return anomaly_score
