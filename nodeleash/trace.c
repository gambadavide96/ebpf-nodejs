//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ============================================================================
// EVENT STRUCTURE — mirrors SyscallInfo in main.go (20 bytes, no padding)
// ============================================================================
struct ebpf_syscall_info {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_id;
    int   stack_id;
};

// ============================================================================
// MAPS
// ============================================================================

// Process tree: root PID + all children spawned via fork.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240);
} target_pid_map SEC(".maps");


// User-space stack traces.
// 8192 entries handles real-world Node.js workloads without drops.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 8192);
} stack_map SEC(".maps");

// Ring buffer. 4MB handles event bursts on loaded servers.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} ring_buffer SEC(".maps");


// ============================================================================
// TRACEPOINT ARGUMENT STRUCTURES
// ============================================================================
struct sys_enter_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    long  id;
    unsigned long args[6];
};

// ============================================================================
// TRACEPOINTS
// ============================================================================

// Propagates tracking to child processes.
// Does NOT fire for thread creation — threads share parent TGID and are
// tracked automatically by trace_sys_enter.
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid  = ctx->child_pid;

    u32 *tracked = bpf_map_lookup_elem(&target_pid_map, &parent_pid);
    if (tracked) {
        u32 val = 1;
        bpf_map_update_elem(&target_pid_map, &child_pid, &val, BPF_ANY);
    }
    return 0;
}

// Removes a PROCESS (not a thread) from tracking on exit.
// For Node.js threads (libuv pool, V8 workers), TGID == main process PID —
// so every thread exit would delete the main process from the map,
// silently stopping all monitoring. Only delete when tid == pid (thread-group leader).
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid      = (__u32)(pid_tgid);        // Identify this specific thread, lowest 32 bit
    u32 pid      = (__u32)(pid_tgid >> 32);  // Identify the main thread, the process

    if (tid != pid)
        return 0; // thread exit — keep the process tracked

    bpf_map_delete_elem(&target_pid_map, &pid);
    return 0;
}

// Captures syscall events for tracked processes.
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
    u64 pid_tgid   = bpf_get_current_pid_tgid();
    u32 pid        = (__u32)(pid_tgid >> 32);
    u32 syscall_id = (__u32)ctx->id;

    // If the pid isn't in the map, we ignore it
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    //Get the current stack for the process that triggered sys_enter    
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    // Reserve 20 bytes in ring buffer
    struct ebpf_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    if (!info)
        return 0;

    info->timestamp_ns = bpf_ktime_get_ns();
    info->pid          = pid;
    info->syscall_id   = syscall_id;
    info->stack_id     = stack_id;

    bpf_ringbuf_submit(info, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
