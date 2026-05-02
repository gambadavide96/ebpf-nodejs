//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>  

// ============================================================================
// EVENT STRUCTURE — mirrors SyscallInfo in main.go (24 bytes, no padding)
// ============================================================================
struct ebpf_syscall_info {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_id;
    int   stack_id;
    int   async_stack_id; // -1 if not available, >= 0 if async context found via uprobes
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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 512);
} tracked_syscalls_map SEC(".maps");

// User-space stack traces.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 8192);
} stack_map SEC(".maps");

// Ring buffer.
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

// ============================================================================
// ASYNC ATTRIBUTION MAPS (uprobes)
//
// Two-step mechanism to bridge the JS context (main thread) with the
// syscall execution (worker thread):
//
//   Step 1 — uprobe uv__work_submit (main thread, JS frame visible):
//             uv_work_map[w_addr] = stack_id
//
//   Step 2 — uprobe uv__fs_work (worker thread, same w_addr as key):
//             tid_stack_map[worker_tid] = stack_id
//             delete uv_work_map[w_addr]
//
//   Step 3 — trace_sys_enter (worker thread):
//             async_stack_id = tid_stack_map[worker_tid]
//             delete tid_stack_map[worker_tid]
//
// The uv__work pointer (w_addr) is the bridge key — passed identically to
// both uv__work_submit and uv__fs_work, so no struct offset is needed.
// ============================================================================

// uv__work address → stack_id captured at scheduling time (main thread).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // address of uv__work struct
    __type(value, __u32); // stack_id captured in the main thread
    __uint(max_entries, 65536);
} uv_work_map SEC(".maps");

// Worker TID → stack_id transferred from uv_work_map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // worker thread TID
    __type(value, __u32); // stack_id from scheduling time
    __uint(max_entries, 1024);
} tid_stack_map SEC(".maps");

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

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid      = (__u32)(pid_tgid);
    u32 pid      = (__u32)(pid_tgid >> 32);

    if (tid != pid)
        return 0;

    bpf_map_delete_elem(&target_pid_map, &pid);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
    u64 pid_tgid   = bpf_get_current_pid_tgid();
    u32 pid        = (__u32)(pid_tgid >> 32);
    u32 tid        = (__u32)(pid_tgid);
    u32 syscall_id = (__u32)ctx->id;

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    if (!bpf_map_lookup_elem(&tracked_syscalls_map, &syscall_id))
        return 0;

    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0) {
        u32 key = DROP_STACK_FULL;
        u64 *cnt = bpf_map_lookup_elem(&drop_counters, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    // Check for async context registered by the uprobes.
    // If found, it means this syscall is being executed by a libuv worker
    // thread whose scheduling context was captured when the async op was queued.
    int async_stack_id = -1;
    u32 *async_sid = bpf_map_lookup_elem(&tid_stack_map, &tid);
    if (async_sid) {
        async_stack_id = (int)*async_sid;
        bpf_map_delete_elem(&tid_stack_map, &tid);
    }

    // Reserve 24 bytes in ring buffer
    struct ebpf_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    if (!info) {
        u32 k = DROP_RINGBUF_FULL;
        u64 *cnt = bpf_map_lookup_elem(&drop_counters, &k);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    info->timestamp_ns   = bpf_ktime_get_ns();
    info->pid            = pid;
    info->syscall_id     = syscall_id;
    info->stack_id       = stack_id;
    info->async_stack_id = async_stack_id;

    bpf_ringbuf_submit(info, 0);
    return 0;
}

// ============================================================================
// UPROBES — async attribution
// ============================================================================

// Step 1: uprobe on uv__work_submit.
// Called from the main thread immediately after uv_fs_read (and other async
// ops) to enqueue work in the thread pool. The JS call stack is visible here.
//
// Signature: void uv__work_submit(uv_loop_t *loop, struct uv__work *w, ...)
// PARM1 = loop, PARM2 = w (the uv__work pointer used as bridge key)
SEC("uprobe/uv__work_submit")
int trace_uv_work_submit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    u64 w_addr = PT_REGS_PARM2(ctx);

    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&uv_work_map, &w_addr, &sid, BPF_ANY);
    return 0;
}

// Step 2: uprobe on uv__fs_work.
// Called in the worker thread to execute the filesystem operation.
// PARM1 is the same uv__work pointer passed to uv__work_submit.
//
// Signature: static void uv__fs_work(struct uv__work *w)
// PARM1 = w
SEC("uprobe/uv__fs_work")
int trace_uv_fs_work(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    u64 w_addr = PT_REGS_PARM1(ctx);

    // Look up the stack saved at scheduling time using w_addr as key.
    u32 *sid = bpf_map_lookup_elem(&uv_work_map, &w_addr);
    if (!sid)
        return 0;

    // Transfer context from w_addr to worker TID so trace_sys_enter can find it.
    bpf_map_update_elem(&tid_stack_map, &tid, sid, BPF_ANY);
    bpf_map_delete_elem(&uv_work_map, &w_addr);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
