//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// INFO STRUCTURE 
struct ebpf_syscall_info {
    __u64 timestamp_ns; // 8 byte
    __u32 pid;          // 4 byte 
    __u32 syscall_id;   // 4 byte
    int   stack_id;     // 4 byte
}; 

// HASH MAP FOR MAIN AND CHILDREN PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240); 
} target_pid_map SEC(".maps");

// STACK TRACE MAP
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 1024);
} stack_map SEC(".maps");

// RING BUFFER 
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 Kilobyte
} ring_buffer SEC(".maps");

// Structure for raw_syscalls/sys_enter 
struct sys_enter_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    long  id; // syscall ID
    unsigned long args[6];
};



// To caputure children processes
//If the parent is in the map, we add also the child
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;

    
    u32 *is_tracked = bpf_map_lookup_elem(&target_pid_map, &parent_pid);
    if (is_tracked) {
        
        u32 val = 1;
        bpf_map_update_elem(&target_pid_map, &child_pid, &val, BPF_ANY);
    }
    return 0;
}

// Garbage Collector for died processes
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Remove from the map died process
    bpf_map_delete_elem(&target_pid_map, &pid);
    return 0;
}


// To capture syscall event and related info structure
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // We look if current PID is in HASH map
    __u32 *is_tracked = bpf_map_lookup_elem(&target_pid_map, &pid);
    if (!is_tracked) {
        return 0; 
    }

    // We get stack id
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0) {
        return 0; 
    }

    // Reserving space in ring buffer (20 byte)
    struct ebpf_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    if (!info) {
        return 0; 
    }

    // Preparing data to send in User Space
    info->timestamp_ns = bpf_ktime_get_ns();
    info->pid = pid;                   
    info->syscall_id = (__u32)ctx->id;
    info->stack_id = stack_id;

    // Submit event in user space
    bpf_ringbuf_submit(info, 0);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";