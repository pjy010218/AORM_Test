# main.py

from bcc import BPF
from aorm_engine import process_event_from_kernel

# eBPF C 코드에 'execve' 시스템 콜을 추적하는 부분이 추가됨
bpf_program = """
#include <linux/sched.h>

// 1. 이벤트 타입을 정의 (파일 접근 vs 프로세스 실행)
enum event_type {
    EVENT_TYPE_FILE_OPEN,
    EVENT_TYPE_EXEC,
};

// 2. 모든 종류의 이벤트를 담을 수 있는 공용 데이터 구조체
struct data_t {
    enum event_type type;
    u32 uid;
    u32 pid;
    u32 ppid; // Parent PID 추가
    char comm[TASK_COMM_LEN];
    char fname[256];
};
BPF_PERF_OUTPUT(events);

// 3. 파일 접근을 감시하는 함수 (기존과 유사)
int trace_open_event(struct pt_regs *ctx, const char __user *filename) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 1000) { return 0; }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    struct data_t data = {};
    data.type = EVENT_TYPE_FILE_OPEN;
    data.uid = uid;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 4. (신규) 프로세스 실행을 감시하는 함수
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 1000) { return 0; }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct data_t data = {};
    data.type = EVENT_TYPE_EXEC;
    data.uid = uid;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

try:
    b = BPF(text=bpf_program)
    b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="trace_open_event")
    b.attach_kprobe(event=b.get_syscall_fnname("openat2"), fn_name="trace_open_event")
except Exception as e:
    print(f"BPF program failed to load: {e}")
    exit()

print("✅ AORM Agent (Trajectory-Aware) is running.")
print("   Monitoring file access and process execution...")

def process_and_analyze(cpu, data, size):
    """커널로부터 받은 모든 이벤트를 aorm_engine으로 전달"""
    event = b["events"].event(data)
    process_event_from_kernel(event) # 분석 로직을 aorm_engine으로 위임

b["events"].open_perf_buffer(process_and_analyze)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n👋 AORM Agent stopped.")
