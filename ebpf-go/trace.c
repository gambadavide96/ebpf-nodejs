//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 1. INFO STRUCTURE AGGIORNATA
// Abbiamo aggiunto il PID. La struttura è ora di 20 byte totali 
// (8 + 4 + 4 + 4), mantenendo un allineamento in memoria perfetto.
struct my_syscall_info {
    __u64 timestamp_ns; // 8 byte
    __u32 pid;          // 4 byte <-- NUOVO: Identifica chi ha fatto la syscall
    __u32 syscall_id;   // 4 byte
    int   stack_id;     // 4 byte
}; 

// 2. HASH MAP PER I PID MULTIPLI
// Non è più un ARRAY di 1 elemento, ma un HASH table per contenere fino a 10.000 PID.
// La chiave sarà il PID stesso.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240); 
} target_pid_map SEC(".maps");

// STACK TRACE MAP (Invariata)
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 1024);
} stack_map SEC(".maps");

// RING BUFFER (Invariato)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 Kilobyte
} ring_buffer SEC(".maps");

// Structure for raw_syscalls/sys_enter (Invariata)
struct sys_enter_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    long  id; // syscall ID
    unsigned long args[6];
};

// -----------------------------------------------------------------------------
// NUOVI TRACEPOINT PER IL PROCESS TREE TRACKING
// -----------------------------------------------------------------------------

// 3. CATTURA LA NASCITA DEI FIGLI (FORK)
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;

    // Se il processo padre è nella nostra mappa dei sorvegliati...
    u32 *is_tracked = bpf_map_lookup_elem(&target_pid_map, &parent_pid);
    if (is_tracked) {
        // ...aggiungiamo automaticamente il figlio alla mappa!
        u32 val = 1;
        bpf_map_update_elem(&target_pid_map, &child_pid, &val, BPF_ANY);
    }
    return 0;
}

// 4. PULIZIA DEI FIGLI MORTI (EXIT) - Garbage Collector
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Se il processo che muore era tracciato, rimuoviamolo per liberare memoria
    bpf_map_delete_elem(&target_pid_map, &pid);
    return 0;
}

// -----------------------------------------------------------------------------
// TRACEPOINT DELLE SYSCALL
// -----------------------------------------------------------------------------

// 5. CATTURA DELLE SYSCALL AGGIORNATA
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Controllo dinamico: usiamo il PID come chiave per cercare nell'HASH map
    __u32 *is_tracked = bpf_map_lookup_elem(&target_pid_map, &pid);
    if (!is_tracked) {
        return 0; // Processo non di nostro interesse, ignora
    }

    // Ricaviamo lo stack id
    int stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    if (stack_id < 0) {
        return 0; 
    }

    // Prenotiamo spazio nel Ring Buffer (ora 20 byte)
    struct my_syscall_info *info = bpf_ringbuf_reserve(&ring_buffer, sizeof(*info), 0);
    if (!info) {
        return 0; 
    }

    // Popoliamo i dati da mandare allo User Space
    info->timestamp_ns = bpf_ktime_get_ns();
    info->pid = pid;                   // <-- INSERIAMO IL PID NELL'EVENTO
    info->syscall_id = (__u32)ctx->id;
    info->stack_id = stack_id;

    // Invio evento a Go
    bpf_ringbuf_submit(info, 0);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";