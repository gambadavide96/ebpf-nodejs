//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


// 1. STRUTTURA PER IL RING BUFFER
// Mettendo il dato più grande (8 byte) per primo, e i due 
// da 4 byte dopo, raggiungiamo esattamente i 16 byte. Nessun "buco" di memoria!
struct my_syscall_info {
    __u64 timestamp_ns; // 8 byte
    __u32 syscall_id;   // 4 byte
    int   stack_id;     // 4 byte
}; 

// Mappa Array per filtrare il PID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} target_pid_map SEC(".maps");

// Mappa dedicata agli Stack Trace 
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 1024);
} stack_map SEC(".maps");

// 2. LA DEFINIZIONE DEL RING BUFFER
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Creiamo un buffer da 256 Kilobyte
} events SEC(".maps");

// Struttura fissa per raw_syscalls/sys_enter
struct sys_enter_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    long  id; // ID della syscall
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u32 array_key = 0;
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &array_key);
    if (!target_pid || *target_pid != pid) {
        return 0;
    }

    // Ricaviamo lo stack del processo Node, viene restituito uno stack id
    //e la riga corrispondente viene popolata con gli indirizzi
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0) {
        return 0; 
    }

    // 3. PRENOTIAMO LO SPAZIO NEL RING BUFFER
    // Chiediamo al kernel un blocco di 16 byte. Se il buffer è pieno, restituisce NULL.
    struct my_syscall_info *info = bpf_ringbuf_reserve(&events, sizeof(*info), 0);
    if (!info) {
        return 0; // Buffer temporaneamente pieno, evento scartato
    }

    // 4. POPOLIAMO I DATI
    info->timestamp_ns = bpf_ktime_get_ns();
    info->syscall_id = (__u32)ctx->id;
    info->stack_id = stack_id;

    // 5. INVIAMO L'EVENTO ALLO USER SPACE
    // Da questo momento, il programma Go viene "svegliato"
    bpf_ringbuf_submit(info, 0);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";