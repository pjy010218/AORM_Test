# profiler.py

import json
import os
import time
from collections import deque
from statistics import mean, stdev

class HybridProfiler:
    def __init__(self, profile_path='behavior_profile.json', base_score_threshold=8.0):
        self.profile_path = profile_path
        self.MAX_TIMESTAMPS = 100
        self.profile_data = self._load()
        self.BASE_SCORE_THRESHOLD = base_score_threshold

    def _load(self):
        if not os.path.exists(self.profile_path): return {}
        with open(self.profile_path, 'r') as f:
            raw_data = json.load(f)
            for key, value in raw_data.items():
                value['timestamps'] = deque(value.get('timestamps', []), maxlen=self.MAX_TIMESTAMPS)
            return raw_data
        
    def _save(self):
        # 이 함수는 이제 save_profile()로 이름이 변경되어 외부에서 호출됩니다.
        with open(self.profile_path, 'w') as f:
            json.dump(self.profile, f, indent=4)

    def save_profile(self):
        """
        [수정됨] 프로필을 파일에 저장하는 공개 메서드.
        프로세스 종료 시 호출하기 위함.
        """
        print("  [INFO] Saving behavior profile to disk...")
        self._save()

    def _update_stats(self, event_key):
        timestamps = self.profile_data[event_key]['timestamps']
        if len(timestamps) < 2: return
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        if len(intervals) > 1:
            self.profile_data[event_key]['mean_interval'] = mean(intervals)
            self.profile_data[event_key]['std_dev_interval'] = stdev(intervals)
        elif len(intervals) == 1:
            self.profile_data[event_key]['mean_interval'] = intervals[0]

    def process_event(self, process_name, file_path, base_score):
        if base_score >= self.BASE_SCORE_THRESHOLD:
            return 1.0

        event_key = f"{process_name}|{file_path}"
        current_time = time.time()
        
        if event_key not in self.profile_data:
            self.profile_data[event_key] = { 'count': 1, 'timestamps': deque([current_time], maxlen=self.MAX_TIMESTAMPS), 'mean_interval': 0, 'std_dev_interval': 0 }
            self._save()
            return 1.0

        entry = self.profile_data[event_key]
        entry['count'] += 1
        last_event_time = entry['timestamps'][-1] if entry['timestamps'] else current_time
        entry['timestamps'].append(current_time)
        self._update_stats(event_key)
        
        anomaly_score = 0.0
        if entry.get('std_dev_interval', 0) > 0 and last_event_time != current_time:
            current_interval = current_time - last_event_time
            z_score = (current_interval - entry['mean_interval']) / entry['std_dev_interval']
            anomaly_score = min(abs(z_score) / 3.0, 1.0)

        self._save()
        return anomaly_score