# main.py

from bcc import BPF
from aorm_engine import calculate_aorm_score

bpf_program = """
#include <linux/sched.h>

struct data_t {
    u32 uid;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fname[256];
};
BPF_PERF_OUTPUT(events);

int trace_event(struct pt_regs *ctx, const char __user *filename) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 1000) {
        return 0;
    }
    struct data_t data = {};
    data.uid = uid;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

try:
    b = BPF(text=bpf_program)
    # openat과 openat2 syscall의 filename 인자에 프로브를 연결
    b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="trace_event")
    b.attach_kprobe(event=b.get_syscall_fnname("openat2"), fn_name="trace_event")
except Exception as e:
    print(f"BPF program failed to load: {e}")
    exit()

print("✅ AORM Agent is running.")
print("   Silently monitoring for events...")

def process_and_analyze(cpu, data, size):
    event = b["events"].event(data)
    event_data = {
        'process_name': event.comm.decode('utf-8', 'replace'),
        'file_path': event.fname.decode('utf-8', 'replace'),
        'pid': event.pid
    }
    if event_data['file_path']:
        calculate_aorm_score(event_data)

b["events"].open_perf_buffer(process_and_analyze)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n👋 AORM Agent stopped.")
