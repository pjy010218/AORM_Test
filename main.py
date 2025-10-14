#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AORM agent: BPF program + Python user-space reader.

This file contains an embedded BPF C program (string bpf_program) that:
 - tracks file-related syscalls (openat, unlink, rename) and execve/execveat
 - fills a data_t structure and submits via perf events to user-space

User-space part registers a perf buffer callback and prints received events.
Requires: bcc (python-bcc), root privileges.
"""

import ctypes as ct
import time
import os
import sys
import signal
from bcc import BPF

# Ensure we have root
if os.geteuid() != 0:
    print("This script must be run as root.", file=sys.stderr)
    sys.exit(1)

# --- BPF C program ---
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

// constants for event types
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_UNLINK 2
#define EVENT_TYPE_RENAME 3
#define EVENT_TYPE_EXEC 4

struct data_t {
    u32 type;
    u32 uid;
    u32 pid;
    u32 ppid;
    char comm[16];
    char fname[256];
};

BPF_PERCPU_ARRAY(data_map, struct data_t, 1);
BPF_PERF_OUTPUT(events);
BPF_HASH(uid_filter_map, u32, u8);

// helper to decide whether to monitor (if uid_filter_map empty -> monitor all)
static inline int should_monitor(u32 uid) {
    u8 *val;
    u32 zero = 0;
    // if map is empty, return 1 (monitor all)
    // trying to lookup a '0' key as sentinel; if map is empty, fallback to monitor all
    val = uid_filter_map.lookup(&zero);
    if (!val) {
        return 1;
    }
    // if there is a specific key present as 1 for our uid, monitor; otherwise no
    u32 ukey = uid;
    val = uid_filter_map.lookup(&ukey);
    if (val && *val == 1) {
        return 1;
    }
    return 0;
}

// common routine to populate data and submit
static inline int trace_syscall_common(struct pt_regs *ctx, const char __user *filename, int event_type) {
    u32 uid_full = bpf_get_current_uid_gid();
    u32 uid = uid_full & 0xffffffff;

    if (!should_monitor(uid)) {
        return 0;
    }

    int idx = 0;
    struct data_t *data = data_map.lookup(&idx);
    if (!data) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data->type = event_type;
    data->uid = uid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    // guard access to real_parent
    if (task && task->real_parent) {
        data->ppid = task->real_parent->tgid;
    } else {
        data->ppid = 0;
    }

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    if (filename) {
        bpf_probe_read_user_str(&data->fname, sizeof(data->fname), filename);
    } else {
        data->fname[0] = 0;
    }

    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

// kprobe handlers
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    return trace_syscall_common(ctx, filename, EVENT_TYPE_OPEN);
}

int trace_unlink(struct pt_regs *ctx, const char __user *pathname) {
    return trace_syscall_common(ctx, pathname, EVENT_TYPE_UNLINK);
}

int trace_rename(struct pt_regs *ctx, const char __user *oldname, const char __user *newname) {
    // choose to report oldname (or could report both)
    return trace_syscall_common(ctx, oldname, EVENT_TYPE_RENAME);
}

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    return trace_syscall_common(ctx, filename, EVENT_TYPE_EXEC);
}

int trace_execveat(struct pt_regs *ctx, int dirfd, const char __user *filename,
                   const char __user *const __user *argv,
                   const char __user *const __user *envp, int flags) {
    return trace_syscall_common(ctx, filename, EVENT_TYPE_EXEC);
}
"""

# --- Python-side event structure mirrors C struct data_t ---
class DataEvent(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint),
        ("uid", ct.c_uint),
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("fname", ct.c_char * 256),
    ]

# pretty print helper
EVENT_TYPE_MAP = {
    1: "OPEN",
    2: "UNLINK",
    3: "RENAME",
    4: "EXEC",
}

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DataEvent)).contents
    etype = EVENT_TYPE_MAP.get(event.type, str(event.type))
    fname = event.fname.decode('utf-8', errors='replace').rstrip('\x00')
    comm = event.comm.decode('utf-8', errors='replace').rstrip('\x00')
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"{ts} | {etype} | uid={event.uid} pid={event.pid} ppid={event.ppid} comm={comm} file='{fname}'")

def handle_signal(sig, frame):
    print("\nReceived signal, exiting...")
    sys.exit(0)

def main():
    # allow clean ctrl-c
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("Loading BPF program...")
    b = BPF(text=bpf_program)

    # attach kprobes for syscalls (use helper to resolve correct syscall names)
    try:
        open_fn = b.get_syscall_fnname("openat")
        b.attach_kprobe(event=open_fn, fn_name="trace_openat")
    except Exception as e:
        print(f"Warning: could not attach openat kprobe: {e}")

    try:
        unlink_fn = b.get_syscall_fnname("unlink")
        b.attach_kprobe(event=unlink_fn, fn_name="trace_unlink")
    except Exception as e:
        # some systems use unlinkat; try that
        try:
            unlinkat_fn = b.get_syscall_fnname("unlinkat")
            b.attach_kprobe(event=unlinkat_fn, fn_name="trace_unlink")
        except Exception as ex:
            print(f"Warning: could not attach unlink kprobe: {ex}")

    try:
        rename_fn = b.get_syscall_fnname("rename")
        b.attach_kprobe(event=rename_fn, fn_name="trace_rename")
    except Exception as e:
        try:
            renameat_fn = b.get_syscall_fnname("renameat")
            b.attach_kprobe(event=renameat_fn, fn_name="trace_rename")
        except Exception as ex:
            print(f"Warning: could not attach rename kprobe: {ex}")

    # execve and execveat
    try:
        exec_fn = b.get_syscall_fnname("execve")
        b.attach_kprobe(event=exec_fn, fn_name="trace_execve")
    except Exception as e:
        print(f"Warning: could not attach execve kprobe: {e}")
    try:
        execat_fn = b.get_syscall_fnname("execveat")
        b.attach_kprobe(event=execat_fn, fn_name="trace_execveat")
    except Exception:
        # not fatal
        pass

    # open perf buffer
    b["events"].open_perf_buffer(print_event)

    print("BPF loaded and probes attached. Listening for events... (hit Ctrl-C to exit)")
    while True:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            print("Keyboard interrupt, exiting")
            break
        except Exception as e:
            # don't crash on transient errors; print and continue
            print(f"Warning: perf poll error: {e}")
            time.sleep(0.1)

if __name__ == "__main__":
    main()
