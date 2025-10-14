#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[수정됨] AORM Agent with stable BPF Tracepoint event capture
 - Captures kernel syscalls using stable tracepoints for reliability
 - Preserves the modular design of the AORM Engine integration
 - Implements graceful shutdown to ensure behavior profile is always saved
"""
from types import SimpleNamespace
import ctypes as ct
import time
import os
import sys
import signal
from bcc import BPF

# 🔹 AORM 엔진 불러오기
import aorm_engine

if os.geteuid() != 0:
    print("❌ Must run as root.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# BPF C 코드 (Tracepoint 기반으로 전면 재설계)
# ─────────────────────────────────────────────────────────────
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

enum event_type {
    EVENT_TYPE_FILE_OPEN, // 0
    EVENT_TYPE_EXEC,      // 1
    EVENT_TYPE_RENAME,    // 2
    EVENT_TYPE_UNLINK     // 3
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

BPF_PERCPU_ARRAY(data_map, struct data_t, 1);
BPF_PERF_OUTPUT(events);

// 원본 철학을 유지하는 공통 이벤트 제출 함수
static inline int submit_event(void *ctx, enum event_type t, const char __user *fname, const char __user *oldname) {
    int zero = 0;
    struct data_t *data = data_map.lookup(&zero);
    if (!data) return 0;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data->type = t;
    data->uid = uid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent ? task->real_parent->tgid : 0;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (fname) bpf_probe_read_user_str(&data->fname, sizeof(data->fname), fname);
    else data->fname[0] = 0;

    if (oldname) bpf_probe_read_user_str(&data->old_fname, sizeof(data->old_fname), oldname);
    else data->old_fname[0] = 0;

    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

// === 안정적인 Tracepoint 핸들러 ===
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    return submit_event(args, EVENT_TYPE_FILE_OPEN, (const char __user *)args->filename, NULL);
}
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    return submit_event(args, EVENT_TYPE_UNLINK, (const char __user *)args->pathname, NULL);
}
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    return submit_event(args, EVENT_TYPE_RENAME, (const char __user *)args->newname, (const char __user *)args->oldname);
}
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    return submit_event(args, EVENT_TYPE_EXEC, (const char __user *)args->filename, NULL);
}
"""

# ─────────────────────────────────────────────────────────────
# Python 구조체 정의 (기존과 동일)
# ─────────────────────────────────────────────────────────────
class DataEvent(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint), ("uid", ct.c_uint), ("pid", ct.c_uint),
        ("ppid", ct.c_uint), ("comm", ct.c_char * 16),
        ("fname", ct.c_char * 256), ("old_fname", ct.c_char * 256),
    ]

# ─────────────────────────────────────────────────────────────
# 이벤트 처리 함수: AORM 엔진 호출 (기존과 동일)
# ─────────────────────────────────────────────────────────────
def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DataEvent)).contents
    try:
        event_obj = SimpleNamespace(
            type=event.type, uid=event.uid, pid=event.pid, ppid=event.ppid,
            comm=event.comm, fname=event.fname, old_fname=event.old_fname,
        )
        aorm_engine.process_event_from_kernel(event_obj)
    except Exception as e:
        print(f"[AORM ERROR] Failed to process event: {e}")

# ─────────────────────────────────────────────────────────────
# 안전한 종료 핸들러 (재구현)
# ─────────────────────────────────────────────────────────────
keep_running = True
def handle_signal(sig, frame):
    global keep_running
    print("\n[INFO] Shutdown signal received, stopping agent gracefully...")
    keep_running = False

# ─────────────────────────────────────────────────────────────
# 메인 루프 (수정됨)
# ─────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("Loading BPF program with tracepoints...")
    try:
        b = BPF(text=bpf_program)
    except Exception as e:
        print(f"[FATAL] BPF program failed to load: {e}")
        print("Please ensure you have the correct kernel headers installed.")
        sys.exit(1)

    # Tracepoint는 BPF 코드 내에서 자동으로 attach되므로, attach_kprobe 호출이 불필요.
    
    b["events"].open_perf_buffer(handle_event)

    print("✅ AORM Agent is now monitoring kernel events via tracepoints...")
    
    try:
        while keep_running:
            b.perf_buffer_poll(timeout=1000)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred in the main loop: {e}")
    finally:
        # [중요] 정상 종료 시 프로파일을 저장하여 데이터 유실을 방지
        print("[INFO] Main loop exited. Saving final behavior profile...")
        if aorm_engine.behavior_profiler:
            aorm_engine.behavior_profiler.save_profile()
        print("\n👋 AORM Agent stopped gracefully.")

if __name__ == "__main__":
    main()
