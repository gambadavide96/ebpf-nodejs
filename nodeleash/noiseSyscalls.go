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

	/*

		// Synchronization primitives
		"futex",
		"futex_time64",

		// Event loop waiting
		"epoll_wait",
		"epoll_pwait",
		"epoll_pwait2",
		"poll",
		"ppoll",
		"select",
		"pselect6",

		// Scheduling
		"sched_yield",
		"nanosleep",
		"clock_nanosleep",

		// Signal handling
		"rt_sigprocmask",
		"rt_sigaction",
		"rt_sigreturn",
		"sigaltstack",

		// Time queries
		"clock_gettime",
		"gettimeofday",

		// Memory management
		"brk",
		"mmap",
		"mprotect",
		"munmap",
		"madvise",

		// Process identity
		"getpid",
	*/
	// NodeLeash self-noise
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
