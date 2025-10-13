# main.py

from bcc import BPF
from aorm_engine import process_event_from_kernel

# BPF C 코드를 수정하여 스택 대신 BPF 맵을 사용
bpf_program = """
#include <linux/sched.h>

enum event_type {
    EVENT_TYPE_FILE_OPEN,
    EVENT_TYPE_EXEC,
    EVENT_TYPE_RENAME,
    EVENT_TYPE_UNLINK,
};

struct data_t {
    enum event_type type;
    u32 uid;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    char old_fname[256];
};

// ▼▼▼▼▼ 1. 스택 대신 사용할 BPF 맵 정의 ▼▼▼▼▼
BPF_PERCPU_ARRAY(data_map, struct data_t, 1);
BPF_PERF_OUTPUT(events);

static inline int trace_syscall_common(struct pt_regs *ctx, const char __user *filename, enum event_type event_type) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 1000) { return 0; }
    
    // ▼▼▼▼▼ 2. 맵에서 데이터 구조체 포인터를 가져옴 ▼▼▼▼▼
    int zero = 0;
    struct data_t *data = data_map.lookup(&zero);
    if (!data) { return 0; } // Should never happen
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // ▼▼▼▼▼ 3. 포인터를 통해 맵의 데이터에 접근 ▼▼▼▼▼
    data->type = event_type;
    data->uid = uid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), filename);
    
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

int trace_open_event(struct pt_regs *ctx, const char __user *filename) {
    return trace_syscall_common(ctx, filename, EVENT_TYPE_FILE_OPEN);
}

int trace_unlink_event(struct pt_regs *ctx, const char __user *pathname) {
    return trace_syscall_common(ctx, pathname, EVENT_TYPE_UNLINK);
}

int trace_rename_event(struct pt_regs *ctx, int olddfd, const char __user *oldname, int newdfd, const char __user *newname) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 1000) { return 0; }

    int zero = 0;
    struct data_t *data = data_map.lookup(&zero);
    if (!data) { return 0; }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    data->type = EVENT_TYPE_RENAME;
    data->uid = uid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->old_fname, sizeof(data->old_fname), oldname);
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), newname);
    
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 1000) { return 0; }

    int zero = 0;
    struct data_t *data = data_map.lookup(&zero);
    if (!data) { return 0; }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data->type = EVENT_TYPE_EXEC;
    data->uid = uid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), args->filename);

    events.perf_submit(args, data, sizeof(struct data_t));
    return 0;
}
"""

try:
    b = BPF(text=bpf_program)
    b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="trace_open_event")
    b.attach_kprobe(event=b.get_syscall_fnname("openat2"), fn_name="trace_open_event")
    b.attach_kprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="trace_unlink_event")
    b.attach_kprobe(event=b.get_syscall_fnname("renameat2"), fn_name="trace_rename_event")
except Exception as e:
    print(f"BPF program failed to load: {e}")
    exit()

print("✅ AORM Agent (Wide-Vision / Stack-Safe) is running.")
print("   Monitoring file open, exec, rename, and unlink...")

def process_and_analyze(cpu, data, size):
    event = b["events"].event(data)
    process_event_from_kernel(event)

b["events"].open_perf_buffer(process_and_analyze)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n👋 AORM Agent stopped.")