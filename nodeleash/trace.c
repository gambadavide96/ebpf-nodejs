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

// Infrastructure syscall blocklist.
// Populated at startup from noiseSyscalls.go.
// Syscalls present in this map are dropped before reaching the ring buffer —
// they are pure Node.js/OS infrastructure with no attribution value:
// mutex ops (futex), event loop waits (epoll_wait, poll), scheduling (yield) ecc..
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // syscall ID
    __type(value, __u8);  // always 1 (set semantics)
    __uint(max_entries, 256);
} noise_syscalls_map SEC(".maps");

// Ring buffer. 16MB handles event bursts on loaded servers.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); //16MB
} ring_buffer SEC(".maps");


//Category 1 — Thread Pool
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);   // uv__work_t*
    __type(value, __u32); // stack_id
    __uint(max_entries, 4096);
} work_ptr_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // tid
    __type(value, __u32); // stack_id saved on submission
    __uint(max_entries, 1024);
} tid_async_stack_map SEC(".maps");


// ============================================================================
// CATEGORY 1 — Thread pool async attribution — helpers
// ============================================================================


// Shared logic for all TRANSFER probes.
// Recovers the JS stack saved at submission time by looking up work_ptr_map
// using the uv__work_t* pointer received as arg1 (RDI), then stores it in
// tid_async_stack_map keyed by the worker thread TID so that trace_sys_enter
// can attribute all syscalls occurring during this work item's execution.
static __always_inline int handle_work_transfer(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (__u32)(pid_tgid >> 32);
    u32 tid = (__u32)(pid_tgid);
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;
    u64 work_ptr = PT_REGS_PARM1(ctx);
    u32 *sid = bpf_map_lookup_elem(&work_ptr_map, &work_ptr);
    if (sid)
        bpf_map_update_elem(&tid_async_stack_map, &tid, sid, BPF_ANY);
    return 0;
}

// Shared logic for all CLEANUP probes.
// Removes the async context from tid_async_stack_map when the work function
// returns, preventing the worker thread TID from being incorrectly attributed
// to subsequent unrelated operations when the thread is reused by the pool.
static __always_inline int handle_work_cleanup(struct pt_regs *ctx) {
    u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&tid_async_stack_map, &tid);
    return 0;
}


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
    //PID here is actually TGID (Thread Group ID)—that is, the main process identifier, 
    //shared by all threads. And is in the higher 32 bits.
    //TID is the individual thread identifier, and is the lower 32 bits.
    u64 pid_tgid   = bpf_get_current_pid_tgid();
    u32 pid        = (__u32)(pid_tgid >> 32);  //shift the right 32 bits → get the high 32 bits → PID
    u32 tid        = (__u32)(pid_tgid);       // cast to 32 bits → truncate the high 32 bits → TID
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

// When an uprobe fires, the kernel saves the state of all CPU registers
// into struct pt_regs, passed to the BPF program as ctx.
//
// On x86-64, the System V AMD64 ABI calling convention defines that
// integer arguments are passed in registers in this order:
//   arg1 → RDI,  arg2 → RSI,  arg3 → RDX,  arg4 → RCX
//
// PT_REGS_PARM2(ctx) reads ctx->si (= RSI) — the second argument
// of the hooked function at the time of the call.

// ============================================================================
// CATEGORY 1 — Thread pool async attribution
//
// Pattern: ENTRY (main thread, JS stack present) → TRANSFER (worker thread,
// JS stack absent) → CLEANUP (worker thread, operation complete).
//
// uv__work_submit is the single common entry point for ALL thread pool
// operations. Each specific work function receives the same uv__work_t*
// pointer as argument, allowing lookup of the stack captured at submission
// time. The same TRANSFER and CLEANUP logic applies to all work functions.
//
// Covered operations:
//   uv__fs_work          — filesystem (openat, read, write, close, stat)
//   uv__getaddrinfo_work — DNS forward lookup, covers c-ares worker syscalls
// ============================================================================


// ENTRY — fired on the main thread when any operation is submitted to the
// libuv thread pool. The JS call stack is still present at this point.
// Captures the stack and saves it in work_ptr_map keyed by uv__work_t* (RSI),
// which remains stable across the main thread → worker thread boundary.
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

// TRANSFER/CLEANUP — filesystem operations (fs.readFile, fs.writeFile, etc.)
// Syscalls attributed: openat, read, write, close, stat, mkdir, unlink, rename
// Note: only the first step of chained operations (e.g. fs.readFile open step)
// is attributed — subsequent steps are submitted from internal C callbacks
// where the JS stack is already gone.
SEC("uprobe/uv__fs_work")
int uprobe_uv__fs_work(struct pt_regs *ctx) {
    return handle_work_transfer(ctx);
}
SEC("uretprobe/uv__fs_work")
int uretprobe_uv__fs_work(struct pt_regs *ctx) {
    return handle_work_cleanup(ctx);
}

// TRANSFER/CLEANUP — DNS forward lookup (dns.lookup, net.createConnection)
// Syscalls attributed: socket, connect, sendto, recvfrom of c-ares on the
// worker thread. Without this probe these syscalls appear as unattributed
// noise indistinguishable from legitimate DNS resolution.
SEC("uprobe/uv__getaddrinfo_work")
int uprobe_uv__getaddrinfo_work(struct pt_regs *ctx) {
    return handle_work_transfer(ctx);
}
SEC("uretprobe/uv__getaddrinfo_work")
int uretprobe_uv__getaddrinfo_work(struct pt_regs *ctx) {
    return handle_work_cleanup(ctx);
}

// ============================================================================
// CATEGORY 2 — 
// ============================================================================


char __license[] SEC("license") = "Dual MIT/GPL";
