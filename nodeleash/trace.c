//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// ============================================================================
// SYSCALL NUMBERS (x86_64) — used for fd-lifecycle tracking
// ============================================================================
#define SYS_READ      0
#define SYS_WRITE     1
#define SYS_CLOSE     3
#define SYS_SOCKET    41
#define SYS_SENDTO    44
#define SYS_RECVFROM  45
#define SYS_SENDMSG   46
#define SYS_RECVMSG   47
#define SYS_ACCEPT    43
#define SYS_ACCEPT4   288
#define SYS_OPENAT    257

static __always_inline bool is_fd_creating(__u32 id) {
    return id == SYS_OPENAT || id == SYS_SOCKET ||
           id == SYS_ACCEPT || id == SYS_ACCEPT4;
}

// Solo per syscall che operano su fd come primo argomento
static __always_inline bool is_fd_io(__u32 id) {
    return id == SYS_READ     ||
           id == SYS_WRITE    ||
           id == SYS_SENDTO   ||
           id == SYS_RECVFROM ||
           id == SYS_SENDMSG  ||
           id == SYS_RECVMSG;
}

// ============================================================================
// EVENT STRUCTURE — mirrors SyscallInfo in main.go (24 bytes, no padding)
// ============================================================================
struct ebpf_syscall_info {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_id;
    int   stack_id;
    int   fd_async_stack_id; // -1 if not available
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
// before they reach the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // syscall ID
    __type(value, __u8);  // always 1 (set semantics)
    __uint(max_entries, 512);
} tracked_syscalls_map SEC(".maps");

// User-space stack traces.
// 8192 entries.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 8192);
} stack_map SEC(".maps");

// Ring buffer. 4MB handles event.
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
// For Node.js threads (libuv pool, V8 workers), TGID == main process PID —
// so every thread exit would delete the main process from the map, 
//silently stopping all monitoring. Fix: only delete when pid == tgid (thread-group leader).
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid      = (__u32)(pid_tgid);           //Identify this specific thread, lowest 32 bit
    u32 pid     = (__u32)(pid_tgid >> 32);     //Identify the main thread, the process

    if (tid != pid)
        return 0; // thread exit — keep the process tracked

    bpf_map_delete_elem(&target_pid_map, &pid);
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

    //If the pid isn't in the map, we ignore it
    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;


    // If this syscall is a close(fd), remove the entry associated 
    // with that fd from the fd_owner_map
    if (syscall_id == SYS_CLOSE) {
        u32 fd  = (__u32)ctx->args[0];              //Reading the file descriptor
        u64 key = ((u64)pid << 32) | (u64)fd;       //Reading the key for the fd_owner_map
        bpf_map_delete_elem(&fd_owner_map, &key);   //Removing from the map
    }

    //If the syscall isn't in syscallToCapability, we ignore it
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
        //Save the current stack (sid) with tid as a key in pending_open_map
        bpf_map_update_elem(&pending_open_map, &tid, &sid, BPF_ANY);
    }

    // Async attribution fallback: if this fd was opened with a visible JS stack,
    // include that context so userspace can attribute async I/O completions.
    int fd_async_stack_id = -1;
    if (is_fd_io(syscall_id)) {
        u32 fd  = (__u32)ctx->args[0];
        u64 key = ((u64)pid << 32) | (u64)fd;
        u32 *saved_stack_id = bpf_map_lookup_elem(&fd_owner_map, &key);
        if (saved_stack_id)
            fd_async_stack_id = (int)*saved_stack_id;
        }

    //Reserve 24 bytes in ringbuffer
    struct ebpf_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    //If the ringbuffer is full, we notify in  drop_counters
    if (!info) {
        u32 k = DROP_RINGBUF_FULL;
        u64 *cnt = bpf_map_lookup_elem(&drop_counters, &k);
        if (cnt) __sync_fetch_and_add(cnt, 1);  //Atomic increment of the counter
        return 0;
    }

    info->timestamp_ns      = bpf_ktime_get_ns();
    info->pid               = pid;
    info->syscall_id        = syscall_id;
    info->stack_id          = stack_id;
    info->fd_async_stack_id = fd_async_stack_id;

    bpf_ringbuf_submit(info, 0);
    return 0;
}

// Associates a newly created fd with the JS context that created it
// We store the stack_id on sys_exit : fd_owner_map[pid | fd] = stack_id
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = (__u32)(pid_tgid >> 32);
    u32 tid      = (__u32)(pid_tgid);

    if (!bpf_map_lookup_elem(&target_pid_map, &pid))
        return 0;

    // Only fd-creating syscalls (socket, openat, accept) have a pending entry.
    // If none exists, this sys_exit has nothing to do.
    u32 *saved = bpf_map_lookup_elem(&pending_open_map, &tid);
    if (!saved)
        return 0;

    u32 stack_id = *saved;
    bpf_map_delete_elem(&pending_open_map, &tid);

    // If the syscall went well, ret is the file descriptor
    // for socket,accept,openat ecc..
    if (ctx->ret >= 0) {
        u32 new_fd = (__u32)ctx->ret;   //Extract the number of file descriptor
        u64 key    = ((u64)pid << 32) | (u64)new_fd;    //Building the key
        bpf_map_update_elem(&fd_owner_map, &key, &stack_id, BPF_ANY); //Store stack_id
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
