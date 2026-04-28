//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ============================================================================
// SYSCALL NUMBERS (x86_64) — used for fd-lifecycle tracking
// ============================================================================
#define SYS_CLOSE    3
#define SYS_OPENAT   257
#define SYS_SOCKET   41
#define SYS_ACCEPT   43
#define SYS_ACCEPT4  288

static __always_inline bool is_fd_creating(__u32 id) {
    return id == SYS_OPENAT || id == SYS_SOCKET ||
           id == SYS_ACCEPT || id == SYS_ACCEPT4;
}

// ============================================================================
// EVENT STRUCTURE — mirrors SyscallInfo in main.go (24 bytes, no padding)
// ============================================================================
struct ebpf_syscall_info {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_id;
    int   stack_id;
    int   fd_owner_stack_id; // -1 if not available
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

// Kernel-side syscall allowlist. Populated at startup from syscallToCapability.
// Drops futex, epoll_wait, clock_gettime and all other infrastructure syscalls
// before they reach the ring buffer — zero cost to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // syscall ID
    __type(value, __u8);  // always 1 (set semantics)
    __uint(max_entries, 512);
} tracked_syscalls_map SEC(".maps");

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

// Drop counters for diagnosing silent data loss.
// Index 0: stack_map full. Index 1: ring_buffer full.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} drop_counters SEC(".maps");

#define DROP_STACK_FULL   0
#define DROP_RINGBUF_FULL 1

// Async attribution maps.
// tid → stack_id: temporary storage between sys_enter and sys_exit
// for fd-creating syscalls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240);
} pending_open_map SEC(".maps");

// (pid << 32 | fd) → stack_id: JS context active when the fd was created.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 65536);
} fd_owner_map SEC(".maps");

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

struct sys_exit_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    long  id;
    long  ret;
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
// Fix: the original approach used TGID for deletion. For Node.js threads
// (libuv pool, V8 workers), TGID == main process PID — so every thread
// exit would delete the main process from the map, silently stopping all
// monitoring. Fix: only delete when pid == tgid (thread-group leader).
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid);
    u32 tgid     = (__u32)(pid_tgid >> 32);

    if (pid != tgid)
        return 0; // thread exit — keep the process tracked

    bpf_map_delete_elem(&target_pid_map, &tgid);
    return 0;
}

// Captures syscall events for tracked processes.
// Two-stage filter: (1) PID tracked? (2) syscall relevant?
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
    u64 pid_tgid   = bpf_get_current_pid_tgid();
    u32 pid        = (__u32)(pid_tgid >> 32);
    u32 tid        = (__u32)(pid_tgid);
    u32 syscall_id = (__u32)ctx->id;

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // Cleanup closed fd from fd_owner_map.
    if (syscall_id == SYS_CLOSE) {
        u32 fd  = (__u32)ctx->args[0];
        u64 key = ((u64)pid << 32) | (u64)fd;
        bpf_map_delete_elem(&fd_owner_map, &key);
    }

    if (!bpf_map_lookup_elem(&tracked_syscalls_map, &syscall_id))
        return 0;

    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0) {
        u32 key = DROP_STACK_FULL;
        u64 *cnt = bpf_map_lookup_elem(&drop_counters, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    // Save stack for fd-creating syscalls so sys_exit can associate
    // the new fd with this JS context (async attribution mechanism).
    if (is_fd_creating(syscall_id)) {
        u32 sid = (__u32)stack_id;
        bpf_map_update_elem(&pending_open_map, &tid, &sid, BPF_ANY);
    }

    // Look up fd_owner context for async I/O attribution.
    int fd_owner_stack_id = -1;
    u32 fd  = (__u32)ctx->args[0];
    u64 key = ((u64)pid << 32) | (u64)fd;
    u32 *owner = bpf_map_lookup_elem(&fd_owner_map, &key);
    if (owner)
        fd_owner_stack_id = (int)*owner;

    struct ebpf_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    if (!info) {
        u32 k = DROP_RINGBUF_FULL;
        u64 *cnt = bpf_map_lookup_elem(&drop_counters, &k);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    info->timestamp_ns      = bpf_ktime_get_ns();
    info->pid               = pid;
    info->syscall_id        = syscall_id;
    info->stack_id          = stack_id;
    info->fd_owner_stack_id = fd_owner_stack_id;

    bpf_ringbuf_submit(info, 0);
    return 0;
}

// Associates a newly created fd with the JS context that created it.
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    u32 *saved = bpf_map_lookup_elem(&pending_open_map, &tid);
    if (!saved)
        return 0;

    u32 stack_id = *saved;
    bpf_map_delete_elem(&pending_open_map, &tid);

    if (ctx->ret >= 0) {
        u32 new_fd = (__u32)ctx->ret;
        u64 key    = ((u64)pid << 32) | (u64)new_fd;
        bpf_map_update_elem(&fd_owner_map, &key, &stack_id, BPF_ANY);
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
