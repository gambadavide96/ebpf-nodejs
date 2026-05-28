package main

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// noiseSyscalls is the blocklist of infrastructure syscalls that NodeLeash
// drops before they reach the ring buffer. These syscalls are generated
// continuously by the Node.js runtime internals and have no attribution value:
// they never point to user-land package behaviour and would only pollute the
// policy with call-path hashes that change across runs.
//
// The list is intentionally conservative — only syscalls that are ALWAYS
// infrastructure are included.
var noiseSyscalls = []string{
	// -------------------------------------------------------------------------
	// Synchronization primitives — libuv thread pool, V8 garbage collector.
	// These are called millions of times per second and never point to
	// user-land package behaviour.
	// -------------------------------------------------------------------------
	"futex",
	"futex_time64",

	// -------------------------------------------------------------------------
	// Event loop waiting — epoll/poll/select are the heart of libuv's I/O loop.
	// Filtering only the *wait* variants — epoll_ctl is kept because it
	// tracks fd registration which has attribution value.
	// -------------------------------------------------------------------------
	"epoll_wait",
	"epoll_pwait",
	"epoll_pwait2",

	// -------------------------------------------------------------------------
	// Scheduling — pure CPU scheduling, no I/O or resource access
	// -------------------------------------------------------------------------
	"sched_yield",
	"nanosleep",
	"clock_nanosleep",

	// -------------------------------------------------------------------------
	// Signal handling — pure infrastructure, no user code involvement
	// -------------------------------------------------------------------------
	"rt_sigprocmask",
	"rt_sigaction",
	"rt_sigreturn",
	"sigaltstack",

	// -------------------------------------------------------------------------
	// NodeLeash self-noise — overhead of the probe mechanism itself.
	// syscall_335 appears attributed to user code but is an artifact of
	// NodeLeash's own uretprobe instrumentation, not real package behaviour.
	// -------------------------------------------------------------------------
	"uretprobe",
}

// populateNoiseSyscalls fills the kernel-side noise_syscalls_map from the
// blocklist above. Called once at startup after the eBPF objects are loaded.
// Syscalls in this map are dropped by trace_sys_enter before capturing the
// stack, saving stack_map entries and ring buffer space.
func populateNoiseSyscalls(objs traceObjects) error {
	val := uint8(1)

	key := uint32(335) // sys_uretprobe — kernel uretprobe mechanism, fired by NodeLeash itself
	if err := objs.NoiseSyscallsMap.Put(&key, &val); err != nil {
		return fmt.Errorf("inserting hardcoded noise syscall sys_uretprobe (335): %w", err)
	}
	for _, name := range noiseSyscalls {
		id, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			// Syscall may not exist on this kernel version — skip silently.
			continue
		}
		key := uint32(id)
		if err := objs.NoiseSyscallsMap.Put(&key, &val); err != nil {
			return fmt.Errorf("inserting noise syscall %s (id %d): %w", name, key, err)
		}
	}
	return nil
}
