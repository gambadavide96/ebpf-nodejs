//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// x86_64 syscall numbers — valid since main.go targets amd64 exclusively.
#define SYS_close    3
#define SYS_socket   41
#define SYS_accept   43
#define SYS_accept4  288

// ============================================================================
// EVENT STRUCTURE — mirrors SyscallInfo in main.go (24 bytes, no padding)
// ============================================================================
struct ebpf_syscall_info {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_id;
    int   stack_id;
    int   async_stack_id; // -1 if not available, >= 0 if async context found
};

// ============================================================================
// CORE MAPS
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
// ASYNC ATTRIBUTION — THREAD POOL
//
// Used for filesystem ops (uv__fs_work) and DNS lookups (uv__getaddrinfo_work).
//
// Flow:
//   1. uprobe uv__work_submit (main thread, JS on stack):
//        uv_work_map[w_addr] = stack_id
//   2. uprobe uv__fs_work / uv__getaddrinfo_work (worker thread):
//        tid_stack_map[worker_tid] = uv_work_map[w_addr]
//        delete uv_work_map[w_addr]
//   3. trace_sys_enter (worker thread, any tracked syscall):
//        async_stack_id = tid_stack_map[tid]   ← read but NOT deleted
//   4. uretprobe uv__fs_work / uv__getaddrinfo_work (worker thread, work done):
//        delete tid_stack_map[tid]              ← single cleanup point
//
// Keeping tid_stack_map alive for the full duration of the work item (steps
// 3–4) ensures ALL syscalls within a single work item are attributed, not
// just the first one.
// ============================================================================

// uv__work address → stack_id (bridge across the main→worker thread boundary).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // address of uv__work struct
    __type(value, __u32); // stack_id captured on main thread
    __uint(max_entries, 65536);
} uv_work_map SEC(".maps");

// TID → stack_id (active on worker threads during work item execution).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // thread TID
    __type(value, __u32); // stack_id
    __uint(max_entries, 1024);
} tid_stack_map SEC(".maps");

// ============================================================================
// ASYNC ATTRIBUTION — NETWORK (fd-scoped)
//
// Network syscalls (read/write/recv/send) execute on the main thread inside
// libuv's I/O polling loop, with no JS frame on the native stack. Attribution
// is preserved by tying the JS context captured at socket creation time to the
// socket file descriptor, which stays stable for the socket's entire lifetime.
//
// Flow:
//   1. trace_sys_enter for socket() (main thread, JS on stack):
//        stack_id is computed → pending_socket_map[tid] = stack_id
//   2. trace_sys_exit for socket() (same thread, fd now known via ctx->ret):
//        fd_attribution_map[fd] = pending_socket_map[tid]
//        delete pending_socket_map[tid]
//   3. trace_sys_enter for read/write/recv/send on that fd:
//        async_stack_id = fd_attribution_map[args[0]]  ← never deleted on read
//   4. trace_sys_enter for close(fd):
//        delete fd_attribution_map[fd]
//
// The same mechanism covers accept() / accept4(): the new fd inherits the
// stack_id of the accept() call if a JS frame was present (e.g. a synchronous
// accept in a test server). For production servers accept() is called from
// libuv's I/O polling with no JS frame, so pending_socket_map[tid] will be
// empty and the accepted fd remains unattributed (documented limitation).
// ============================================================================

// fd → stack_id (persistent across the socket's lifetime).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // file descriptor
    __type(value, __u32); // stack_id captured when socket was created
    __uint(max_entries, 65536);
} fd_attribution_map SEC(".maps");

// TID → stack_id (transient staging between sys_enter and sys_exit of socket()).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // TID of the thread calling socket()
    __type(value, __u32); // stack_id from the JS context at call time
    __uint(max_entries, 1024);
} pending_socket_map SEC(".maps");

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
// HELPERS
// ============================================================================

static __always_inline void save_stack_for_work(struct pt_regs *ctx, u64 w_addr) {
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return;
    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&uv_work_map, &w_addr, &sid, BPF_ANY);
}

static __always_inline void transfer_work_to_tid(u64 w_addr, u32 tid) {
    u32 *sid = bpf_map_lookup_elem(&uv_work_map, &w_addr);
    if (!sid)
        return;
    bpf_map_update_elem(&tid_stack_map, &tid, sid, BPF_ANY);
    bpf_map_delete_elem(&uv_work_map, &w_addr);
}

static __always_inline void cleanup_tid_stack(u32 tid) {
    bpf_map_delete_elem(&tid_stack_map, &tid);
}

// ============================================================================
// CORE TRACEPOINTS
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

// trace_sys_enter — main event capture.
//
// Async context priority:
//   1. tid_stack_map  — set by worker-thread uprobes (thread-pool path).
//                       Read but NOT deleted here; uretprobes handle cleanup
//                       so that every syscall in the work item is attributed.
//   2. fd_attribution_map — set by trace_sys_exit for socket()/accept().
//                       Read but NOT deleted; attribution persists for the
//                       socket's entire lifetime.
//
// Additional responsibilities:
//   • socket() — stages stack_id in pending_socket_map for trace_sys_exit.
//   • close()  — removes stale fd attribution from fd_attribution_map.
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

    // ---- Async context: thread pool (worker threads) ----
    // tid_stack_map[tid] is populated by uv__fs_work / uv__getaddrinfo_work.
    // It stays alive for the entire work item; the uretprobe on those functions
    // is the single cleanup point.
    int async_stack_id = -1;
    u32 *async_sid = bpf_map_lookup_elem(&tid_stack_map, &tid);
    if (async_sid)
        async_stack_id = (int)*async_sid;

    // ---- Async context: network fd-based (main thread) ----
    // Only consulted when no thread-pool context is present.
    // args[0] is the fd for read/write/recv/send/recvfrom/sendto/sendmsg/recvmsg.
    // For other syscalls the lookup simply returns NULL (no side effects).
    if (async_stack_id < 0) {
        u32 fd = (u32)ctx->args[0];
        u32 *fd_sid = bpf_map_lookup_elem(&fd_attribution_map, &fd);
        if (fd_sid)
            async_stack_id = (int)*fd_sid;
    }

    // ---- Stage socket()/accept() for sys_exit fd capture ----
    // When socket() is called with a JS frame on the stack (synchronous setup),
    // we need to carry the stack_id into trace_sys_exit where the new fd is
    // known. pending_socket_map[tid] is the staging area.
    if (syscall_id == SYS_socket || syscall_id == SYS_accept || syscall_id == SYS_accept4) {
        u32 sid = (u32)stack_id;
        bpf_map_update_elem(&pending_socket_map, &tid, &sid, BPF_ANY);
    }

    // ---- Cleanup on close() ----
    // Remove fd attribution when the socket is closed so that a future socket
    // reusing the same fd number does not inherit stale attribution.
    if (syscall_id == SYS_close) {
        u32 fd = (u32)ctx->args[0];
        bpf_map_delete_elem(&fd_attribution_map, &fd);
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

// trace_sys_exit — fd attribution for socket()/accept()/accept4().
//
// By the time sys_exit fires the kernel has assigned the new fd (ctx->ret).
// We retrieve the stack_id staged in pending_socket_map by trace_sys_enter
// and store it as a persistent per-fd entry in fd_attribution_map.
//
// This tracepoint is filtered to the three syscalls above in the first
// instruction, so its overhead on unrelated syscall exits is a single
// comparison and return.
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_args *ctx) {
    long id = ctx->id;
    if (id != SYS_socket && id != SYS_accept && id != SYS_accept4)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    u32 tid = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // Always clean up the staging entry — whether the syscall succeeded or not.
    u32 *sid = bpf_map_lookup_elem(&pending_socket_map, &tid);
    if (!sid) return 0;

    if (ctx->ret >= 0) {
        u32 fd = (u32)ctx->ret;
        bpf_map_update_elem(&fd_attribution_map, &fd, sid, BPF_ANY);
    }

    bpf_map_delete_elem(&pending_socket_map, &tid);
    return 0;
}

// ============================================================================
// THREAD POOL UPROBES — Category A
// ============================================================================

// uv__work_submit — main thread scheduling point for ALL thread-pool ops.
// JS frame is present here; captures the stack_id keyed by the uv__work
// struct address, which is stable across the main→worker thread boundary.
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
// Transfers context from uv_work_map to tid_stack_map using the worker TID.
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

// uretprobe on uv__fs_work — cleanup point for the worker thread context.
// Deletes tid_stack_map[tid] after ALL syscalls of the work item have fired,
// preventing the stale context from leaking into subsequent work items on
// the same worker thread.
SEC("uretprobe/uv__fs_work")
int trace_uv_fs_work_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;
    cleanup_tid_stack(tid);
    return 0;
}

// uv__getaddrinfo_work — worker thread entry for DNS lookups.
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

// uretprobe on uv__getaddrinfo_work — same cleanup role as uv__fs_work_ret.
SEC("uretprobe/uv__getaddrinfo_work")
int trace_uv_getaddrinfo_work_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;
    cleanup_tid_stack(tid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";