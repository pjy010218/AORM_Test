#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AORM Agent with BPF event capture + AORM Engine integration
 - Captures kernel syscalls (open, unlink, rename, exec)
 - Sends each event to aorm_engine.process_event_from_kernel() for analysis
 - Prints ALERT and trajectory logs through aorm_engine
"""

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
# BPF C 코드
# ─────────────────────────────────────────────────────────────
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/limits.h>
#include <linux/types.h>

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

// 공통 이벤트 제출 함수
static inline int submit_event(struct pt_regs *ctx, enum event_type t, const char __user *fname, const char __user *oldname) {
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

    if (fname)
        bpf_probe_read_user_str(&data->fname, sizeof(data->fname), fname);
    else
        data->fname[0] = 0;

    if (oldname)
        bpf_probe_read_user_str(&data->old_fname, sizeof(data->old_fname), oldname);
    else
        data->old_fname[0] = 0;

    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

// 각 syscall별 핸들러
int probe_openat(struct pt_regs *ctx) {
    const char __user *filename = (const char __user *)PT_REGS_PARM2(ctx);
    return submit_event(ctx, EVENT_TYPE_FILE_OPEN, filename, NULL);
}
int probe_unlink(struct pt_regs *ctx) {
    const char __user *pathname = (const char __user *)PT_REGS_PARM1(ctx);
    return submit_event(ctx, EVENT_TYPE_UNLINK, pathname, NULL);
}
int probe_unlinkat(struct pt_regs *ctx) {
    const char __user *pathname = (const char __user *)PT_REGS_PARM2(ctx);
    return submit_event(ctx, EVENT_TYPE_UNLINK, pathname, NULL);
}
int probe_rename(struct pt_regs *ctx) {
    const char __user *oldname = (const char __user *)PT_REGS_PARM1(ctx);
    const char __user *newname = (const char __user *)PT_REGS_PARM2(ctx);
    return submit_event(ctx, EVENT_TYPE_RENAME, newname, oldname);
}
int probe_execve(struct pt_regs *ctx) {
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    return submit_event(ctx, EVENT_TYPE_EXEC, filename, NULL);
}
int probe_execveat(struct pt_regs *ctx) {
    const char __user *pathname = (const char __user *)PT_REGS_PARM2(ctx);
    return submit_event(ctx, EVENT_TYPE_EXEC, pathname, NULL);
}
"""

# ─────────────────────────────────────────────────────────────
# Python 구조체 정의
# ─────────────────────────────────────────────────────────────
class DataEvent(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint),
        ("uid", ct.c_uint),
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("fname", ct.c_char * 256),
        ("old_fname", ct.c_char * 256),
    ]

EVENT_TYPE_MAP = {0: "OPEN", 1: "EXEC", 2: "RENAME", 3: "UNLINK"}

# ─────────────────────────────────────────────────────────────
# 이벤트 처리 함수: AORM 엔진 호출
# ─────────────────────────────────────────────────────────────
def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DataEvent)).contents
    etype = event.type
    fname = event.fname.decode('utf-8', errors='replace').rstrip('\x00')
    oldname = event.old_fname.decode('utf-8', errors='replace').rstrip('\x00')
    comm = event.comm.decode('utf-8', errors='replace').rstrip('\x00')

    # AORM 엔진이 기대하는 형식으로 이벤트 dict 구성
    event_dict = {
        "type": etype,
        "uid": event.uid,
        "pid": event.pid,
        "ppid": event.ppid,
        "comm": comm,
        "fname": fname,
        "old_fname": oldname,
    }

    # 🔥 분석 실행 (이 함수 내부에서 ALERT / Trajectory 로그가 출력됨)
    try:
        aorm_engine.process_event_from_kernel(event_dict)
    except Exception as e:
        print(f"[AORM ERROR] Failed to process event: {e}")

# ─────────────────────────────────────────────────────────────
# 종료 핸들러
# ─────────────────────────────────────────────────────────────
def handle_signal(sig, frame):
    print("\n[INFO] Received signal, shutting down AORM agent...")
    sys.exit(0)

# ─────────────────────────────────────────────────────────────
# 메인 루프
# ─────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("Loading BPF program and attaching probes...")
    b = BPF(text=bpf_program)

    # Attach probes safely
    try:
        b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="probe_openat")
    except Exception as e:
        print(f"[WARN] openat attach failed: {e}")

    for fn_name, probe in [
        ("unlink", "probe_unlink"),
        ("unlinkat", "probe_unlinkat"),
        ("rename", "probe_rename"),
        ("execve", "probe_execve"),
        ("execveat", "probe_execveat"),
    ]:
        try:
            b.attach_kprobe(event=b.get_syscall_fnname(fn_name), fn_name=probe)
        except Exception:
            pass

    b["events"].open_perf_buffer(handle_event)

    print("✅ AORM Agent is now monitoring kernel events...")
    while True:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[WARN] perf poll error: {e}")
            time.sleep(0.5)

if __name__ == "__main__":
    main()
