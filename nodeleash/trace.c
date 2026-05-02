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
    int   async_stack_id; // -1 if not available, >= 0 if captured via uprobes
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

// Kernel-side syscall allowlist.
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

// Drop counters. Index 0: stack_map full. Index 1: ring_buffer full.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} drop_counters SEC(".maps");

#define DROP_STACK_FULL   0
#define DROP_RINGBUF_FULL 1

// ============================================================================
// ASYNC ATTRIBUTION MAPS
//
// Two categories of async operations require different mechanisms:
//
// CATEGORY A — Thread pool (filesystem, DNS, crypto):
//   Uses two maps to bridge the thread context change:
//
//   Step 1 — uprobe uv__work_submit (main thread, JS visible):
//             uv_work_map[w_addr] = stack_id
//   Step 2 — uprobe uv__fs_work / uv__getaddrinfo_work (worker thread):
//             tid_stack_map[worker_tid] = stack_id
//             delete uv_work_map[w_addr]
//   Step 3 — trace_sys_enter (worker thread):
//             async_stack_id = tid_stack_map[tid]
//             delete tid_stack_map[tid]
//
// CATEGORY B — Event loop / main thread (TCP write, UDP send):
//   No thread change — uprobe writes directly to tid_stack_map.
//
//   Step 1 — uprobe uv_write / uv_udp_send (main thread, JS visible):
//             tid_stack_map[main_tid] = stack_id
//   Step 2 — trace_sys_enter (same thread, write/sendto syscall):
//             async_stack_id = tid_stack_map[tid]
//             delete tid_stack_map[tid]
// ============================================================================

// uv__work address → stack_id (bridge key for thread-pool ops).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // address of uv__work struct
    __type(value, __u32); // stack_id from main thread
    __uint(max_entries, 65536);
} uv_work_map SEC(".maps");

// TID → stack_id (used by both categories before trace_sys_enter).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // thread TID
    __type(value, __u32); // stack_id
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
// HELPERS
// ============================================================================

// Captures the current user-space stack and stores it in tid_stack_map.
// Used by Category B uprobes (main thread, no thread switch).
static __always_inline void save_stack_for_tid(struct pt_regs *ctx, u32 tid) {
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return;
    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&tid_stack_map, &tid, &sid, BPF_ANY);
}

// Captures the current stack and stores it in uv_work_map keyed by w_addr.
// Used by Category A uprobes (main thread, thread-pool handoff).
static __always_inline void save_stack_for_work(struct pt_regs *ctx, u64 w_addr) {
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return;
    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&uv_work_map, &w_addr, &sid, BPF_ANY);
}

// Transfers context from uv_work_map[w_addr] to tid_stack_map[tid].
// Used by worker-thread uprobes (Category A, Step 2).
static __always_inline void transfer_work_to_tid(u64 w_addr, u32 tid) {
    u32 *sid = bpf_map_lookup_elem(&uv_work_map, &w_addr);
    if (!sid)
        return;
    bpf_map_update_elem(&tid_stack_map, &tid, sid, BPF_ANY);
    bpf_map_delete_elem(&uv_work_map, &w_addr);
}

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

    // Retrieve async context if any uprobe registered one for this TID.
    int async_stack_id = -1;
    u32 *async_sid = bpf_map_lookup_elem(&tid_stack_map, &tid);
    if (async_sid) {
        async_stack_id = (int)*async_sid;
        bpf_map_delete_elem(&tid_stack_map, &tid);
    }

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
// CATEGORY A — Thread pool uprobes
// ============================================================================

// uv__work_submit — main thread scheduling point for ALL thread-pool ops.
// Captures the JS context before the work is handed off to a worker.
//
// Signature: void uv__work_submit(uv_loop_t *loop, struct uv__work *w, ...)
// PARM1 = loop, PARM2 = w
SEC("uprobe/uv__work_submit")
int trace_uv_work_submit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    u64 w_addr = PT_REGS_PARM2(ctx);
    save_stack_for_work(ctx, w_addr);
    return 0;
}

// uv__fs_work — worker thread entry for filesystem operations.
// Transfers context from uv_work_map to tid_stack_map using worker TID.
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
    transfer_work_to_tid(w_addr, tid);
    return 0;
}

// uv__getaddrinfo_work — worker thread entry for DNS lookup.
// Same pattern as uv__fs_work.
//
// Signature: static void uv__getaddrinfo_work(struct uv__work *w)
// PARM1 = w
SEC("uprobe/uv__getaddrinfo_work")
int trace_uv_getaddrinfo_work(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    u64 w_addr = PT_REGS_PARM1(ctx);
    transfer_work_to_tid(w_addr, tid);
    return 0;
}

// ============================================================================
// CATEGORY B — Main thread / event loop uprobes (no thread switch)
// ============================================================================

// uv_write — schedules a write on a TCP/pipe stream.
// Called from the main thread with JS still on the stack.
// The write() or writev() syscall follows on the same thread.
//
// Signature: int uv_write(uv_write_t *req, uv_stream_t *stream, ...)
// PARM1 = req (not used as key — same-thread so TID is sufficient)
SEC("uprobe/uv_write")
int trace_uv_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    save_stack_for_tid(ctx, tid);
    return 0;
}

// uv_read_start — registers a read callback on a TCP stream.
// Called when JS code calls socket.on('data', ...).
// Subsequent read() syscalls on the same fd are attributed to this context.
//
// Signature: int uv_read_start(uv_stream_t *stream, ...)
SEC("uprobe/uv_read_start")
int trace_uv_read_start(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    save_stack_for_tid(ctx, tid);
    return 0;
}

// uv__tcp_connect — initiates a TCP connection.
// Called from the main thread when JS calls net.connect() or http.request().
// The connect() syscall follows immediately on the same thread.
//
// Signature: int uv__tcp_connect(uv_connect_t *req, uv_tcp_t *handle, ...)
// PARM1 = req
SEC("uprobe/uv__tcp_connect")
int trace_uv_tcp_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    save_stack_for_tid(ctx, tid);
    return 0;
}

// uv_udp_send — sends a UDP datagram.
// Called from the main thread with JS on the stack.
// The sendto() syscall follows on the same thread.
//
// Signature: int uv_udp_send(uv_udp_send_t *req, uv_udp_t *handle, ...)
SEC("uprobe/uv_udp_send")
int trace_uv_udp_send(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    save_stack_for_tid(ctx, tid);
    return 0;
}

// uv_udp_recv_start — registers a receive callback on a UDP socket.
// Called from the main thread when JS code sets up a UDP receiver.
//
// Signature: int uv_udp_recv_start(uv_udp_t *handle, ...)
SEC("uprobe/uv_udp_recv_start")
int trace_uv_udp_recv_start(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    save_stack_for_tid(ctx, tid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
