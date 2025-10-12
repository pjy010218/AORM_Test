# profiler.py

import json
import os
import time
from collections import deque
from statistics import mean, stdev

class StatisticalProfiler:
    def __init__(self, profile_path='behavior_profile.json'):
        self.profile_path = profile_path
        self.MAX_TIMESTAMPS = 100
        self.profile_data = self._load()

    def _load(self):
        if os.path.exists(self.profile_path):
            data = {}
            with open(self.profile_path, 'r') as f:
                raw_data = json.load(f)
                for key, value in raw_data.items():
                    value['timestamps'] = deque(value.get('timestamps', []), maxlen=self.MAX_TIMESTAMPS)
                    data[key] = value
                return data
        return {}

    def _save(self):
        data_to_save = {}
        for key, value in self.profile_data.items():
            temp_value = value.copy()
            temp_value['timestamps'] = list(temp_value['timestamps'])
            data_to_save[key] = temp_value
        with open(self.profile_path, 'w') as f:
            json.dump(data_to_save, f, indent=4)

    def _update_stats(self, event_key):
        timestamps = self.profile_data[event_key]['timestamps']
        if len(timestamps) < 2: return
        intervals = [(timestamps[i] - timestamps[i-1]) for i in range(1, len(timestamps))]
        if len(intervals) > 1:
            self.profile_data[event_key]['mean_interval'] = mean(intervals)
            self.profile_data[event_key]['std_dev_interval'] = stdev(intervals)
        elif len(intervals) == 1:
            self.profile_data[event_key]['mean_interval'] = intervals[0]

    def process_event(self, process_name, file_path):
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
