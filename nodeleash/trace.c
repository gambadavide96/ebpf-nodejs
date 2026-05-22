//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> 

// ============================================================================
// EVENT STRUCTURE — mirrors SyscallInfo in main.go (20 bytes, no padding)
// ============================================================================
struct ebpf_syscall_info {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_id;
    int   stack_id;
    int async_stack_id;
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

// Infrastructure syscall blocklist.
// Populated at startup from noiseSyscalls.go.
// Syscalls present in this map are dropped before reaching the ring buffer —
// they are pure Node.js/OS infrastructure with no attribution value:
// mutex ops (futex), event loop waits (epoll_wait, poll), scheduling (yield).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // syscall ID
    __type(value, __u8);  // always 1 (set semantics)
    __uint(max_entries, 256);
} noise_syscalls_map SEC(".maps");

//Category 1 — Filesystem
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // uv__work_t*
    __type(value, __u32); // stack_id
    __uint(max_entries, 4096);
} work_ptr_map SEC(".maps");

// Category 2a — DNS + TCP connect
// Key: &uv_getaddrinfo_t.work_req  (= arg1 di uv__getaddrinfo_done)
// OFFSET_GETADDRINFO_WORK_REQ:
// gdb $(which node) -batch -ex "p (long)&((uv_getaddrinfo_t*)0)->work_req" -ex quit
#ifndef OFFSET_GETADDRINFO_WORK_REQ
#define OFFSET_GETADDRINFO_WORK_REQ 72
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 512);
} getaddrinfo_map SEC(".maps");

// Category 2b — Direct TCP connect (IP without DNS)
// Key: uv_tcp_t* handle (stable from uv_tcp_connect to AfterConnect)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 512);
} tcp_connect_map SEC(".maps");

// Category 3 — Stream write (TCP/pipe)
// Key: uv_stream_t* (same handle passed by uv_write and receveid by uv__write)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 512);
} stream_write_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // tid
    __type(value, __u32); // stack_id saved on submission
    __uint(max_entries, 1024);
} tid_async_stack_map SEC(".maps");

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
    u32 tid        = (__u32)(pid_tgid);
    u32 syscall_id = (__u32)ctx->id;

    // If the pid isn't in the map, we ignore it
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

     // Drop infrastructure/noise syscalls before capturing the stack.
    // This avoids wasting stack_map entries and ring buffer space on
    // futex, epoll_wait, poll and other syscalls with no attribution value.
    if (bpf_map_lookup_elem(&noise_syscalls_map, &syscall_id))
        return 0;

    //Get the current stack for the process that triggered sys_enter    
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    //Get the async stack for the current thread if present
    int async_stack_id = -1;
    u32 *async_sid = bpf_map_lookup_elem(&tid_async_stack_map, &tid);
    if (async_sid)
        async_stack_id = (int)*async_sid;

    // Reserve 20 bytes in ring buffer
    struct ebpf_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    if (!info)
        return 0;

    info->timestamp_ns = bpf_ktime_get_ns();
    info->pid          = pid;
    info->syscall_id   = syscall_id;
    info->stack_id     = stack_id;
    info->async_stack_id = async_stack_id;

    bpf_ringbuf_submit(info, 0);
    return 0;
}

// ============================================================================
// UPROBES
// ============================================================================

// ============================================================================
// CATEGORY 1 — Filesystem
// ============================================================================

SEC("uprobe/uv__work_submit")
int uprobe_uv_work_submit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv__work_submit(uv_loop_t *loop, struct uv__work *w, ...)
    // arg2 = RSI = uv__work_t* w
    u64 work_ptr = PT_REGS_PARM2(ctx);
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&work_ptr_map, &work_ptr, &sid, BPF_ANY);
    return 0;
}

SEC("uprobe/uv__fs_work")
int uprobe_uv_fs_work(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    u32 tid = (__u32)(pid_tgid);
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv__fs_work(struct uv__work *w)
    // arg1 = RDI = uv__work_t* w
    u64 work_ptr = PT_REGS_PARM1(ctx);
    u32 *sid = bpf_map_lookup_elem(&work_ptr_map, &work_ptr);
    if (sid)
        bpf_map_update_elem(&tid_async_stack_map, &tid, sid, BPF_ANY);
    return 0;
}

SEC("uretprobe/uv__fs_work")
int uretprobe_uv_fs_work(struct pt_regs *ctx) {
    u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tid_async_stack_map, &tid);
    return 0;
}

// ============================================================================
// CATEGORY 2a — DNS resolution + TCP connect
// ============================================================================

SEC("uprobe/uv_getaddrinfo")
int uprobe_uv_getaddrinfo(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv_getaddrinfo(uv_loop_t *loop, uv_getaddrinfo_t *req, ...)
    // arg2 = RSI = uv_getaddrinfo_t* req
    // key: req + offset = &req->work_req
    // so in uv__getaddrinfo_done(uv__work_t* w) the lookup is correct

    u64 req_ptr  = PT_REGS_PARM2(ctx);  // RSI = uv_getaddrinfo_t* req
    u64 work_key = req_ptr + OFFSET_GETADDRINFO_WORK_REQ;

    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&getaddrinfo_map, &work_key, &sid, BPF_ANY);
    return 0;
}

SEC("uprobe/uv__getaddrinfo_done")
int uprobe_uv_getaddrinfo_done(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    u32 tid = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv__getaddrinfo_done(struct uv__work *w, int status)
    // arg1 = RDI = uv__work_t* w  (= &req->work_req, stessa chiave usata sopra)

    u64 work_ptr = PT_REGS_PARM1(ctx);  // RDI = uv__work_t* w
    u32 *sid = bpf_map_lookup_elem(&getaddrinfo_map, &work_ptr);
    if (sid)
        bpf_map_update_elem(&tid_async_stack_map, &tid, sid, BPF_ANY);
    return 0;
}

SEC("uretprobe/uv__getaddrinfo_done")
int uretprobe_uv_getaddrinfo_done(struct pt_regs *ctx) {
    u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tid_async_stack_map, &tid);
    return 0;
}

// ============================================================================
// CATEGORY 2b — Direct TCP connect with IP (without DNS)
// ============================================================================
//
// Covers the case: net.createConnection({ host: '1.2.3.4', port: 80 })
// where uv_getaddrinfo is not called because the host is already an IP.
//
// uv_tcp_connect is synchronous — the JS stack is present at the time of the probe.
// No TRANSFER/CLEANUP needed: the connect() syscall happens immediately.
// In the same call, trace_sys_enter captures it via tid_async_stack_map.

SEC("uprobe/uv_tcp_connect")
int uprobe_uv_tcp_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    u32 tid = (__u32)(pid_tgid);
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv_tcp_connect(uv_connect_t *req, uv_tcp_t *handle, ...)
    // arg2 = RSI = uv_tcp_t* handle
    // JS stack is present → save directly in tid_async_stack_map
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&tid_async_stack_map, &tid, &sid, BPF_ANY);
    return 0;
}

SEC("uretprobe/uv_tcp_connect")
int uretprobe_uv_tcp_connect(struct pt_regs *ctx) {
    u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tid_async_stack_map, &tid);
    return 0;
}


// ============================================================================
// CATEGORY 3 — Stream write (TCP/pipe)
// ============================================================================

SEC("uprobe/uv_write")
int uprobe_uv_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv_write(uv_write_t *req, uv_stream_t *handle, ...)
    // arg2 = RSI = uv_stream_t* handle
    u64 stream_ptr = PT_REGS_PARM2(ctx);
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0)
        return 0;

    u32 sid = (u32)stack_id;
    bpf_map_update_elem(&stream_write_map, &stream_ptr, &sid, BPF_ANY);
    return 0;
}

SEC("uprobe/uv__write")
int uprobe_uv_write_internal(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    u32 tid = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // uv__write(uv_stream_t *stream)
    // arg1 = RDI = uv_stream_t* stream
    u64 stream_ptr = PT_REGS_PARM1(ctx);
    
    u32 *sid = bpf_map_lookup_elem(&stream_write_map, &stream_ptr);
    if (sid)
        bpf_map_update_elem(&tid_async_stack_map, &tid, sid, BPF_ANY);
    return 0;
}

SEC("uretprobe/uv__write")
int uretprobe_uv_write_internal(struct pt_regs *ctx) {
    u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tid_async_stack_map, &tid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
