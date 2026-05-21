package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf trace trace.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// SyscallInfo mirrors ebpf_syscall_info in trace.c.
// 20 bytes, naturally aligned — must match exactly (binary.Read is used).
type SyscallInfo struct {
	TimestampNs uint64
	Pid         uint32
	SyscallId   uint32
	StackId     int32
}

func getSyscallName(id uint32) string {
	name, err := seccomp.ScmpSyscall(id).GetName()
	if err != nil {
		return fmt.Sprintf("syscall_%d", id)
	}
	return name
}

// =========================================================================
// CLI
//
// Analyze mode — build a policy from a live Node.js process:
//   sudo ./nodeleash analyze <PID>
//
// Enforce mode — monitor against an existing policy and log violations:
//   sudo ./nodeleash enforce <PID> \
//       --policy       <path/to/nodeleash_policy_pid<N>_<ts>.json> \
//       --unattributed <path/to/nodeleash_unattributed_pid<N>_<ts>.json>
//
// Both modes share the same eBPF infrastructure (trace.c, Blazesym,
// ring buffer). The only difference is what happens per event:
//   analyze: record into Policy / UnattributedPolicy
//   enforce: check against EnforcementEngine, log violations to terminal
// =========================================================================

func printUsage() {
	fmt.Fprintf(os.Stderr, `NodeLeash — npm package-level syscall policy enforcement

ANALYZE MODE  (build policy from a running Node.js process):
  sudo ./nodeleash analyze <PID> 

ENFORCE MODE  (log policy violations from a running Node.js process):
  sudo ./nodeleash enforce <PID> \
      --policy       <nodeleash_policy_pid<N>_<ts>.json> \
      --unattributed <nodeleash_unattributed_pid<N>_<ts>.json>

  --policy        path to the attributed policy file (required)
  --unattributed  path to the unattributed policy file (required)

Violations are logged to stdout. The monitored process is never terminated.
`)
}

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1] // "analyze" or "enforce"
	pidStr := os.Args[2]

	targetPID, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		log.Fatalf("Invalid PID %q: %v", pidStr, err)
	}

	// Parse mode-specific flags from the remaining arguments.
	args := os.Args[3:]

	var (
		// enforce flags
		policyPath       string
		unattributedPath string
	)

	switch mode {
	case "analyze":
		//No flag to parse
	case "enforce":
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--policy":
				if i+1 < len(args) {
					policyPath = args[i+1]
					i++
				}
			case "--unattributed":
				if i+1 < len(args) {
					unattributedPath = args[i+1]
					i++
				}
			}
		}
		if policyPath == "" || unattributedPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --policy and --unattributed are required in enforce mode.")
			printUsage()
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown mode %q. Use 'analyze' or 'enforce'.\n", mode)
		printUsage()
		os.Exit(1)
	}

	// -------------------------------------------------------------------------
	// eBPF setup — identical for both modes
	// -------------------------------------------------------------------------
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Register root PID. trace.c propagates it to child processes via trace_fork.
	pidKey, pidVal := uint32(targetPID), uint32(1)
	if err := objs.TargetPidMap.Put(&pidKey, &pidVal); err != nil {
		log.Fatalf("Inserting PID: %v", err)
	}

	tpSysEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		log.Fatalf("sys_enter: %v", err)
	}
	defer tpSysEnter.Close()

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceFork, nil)
	if err != nil {
		log.Fatalf("fork: %v", err)
	}
	defer tpFork.Close()

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("exit: %v", err)
	}
	defer tpExit.Close()

	// -------------------------------------------------------------------------
	// Mode-specific state
	// -------------------------------------------------------------------------
	var (
		// Analyze mode
		policy             Policy
		unattributedPolicy *UnattributedPolicy
		rawTracker         map[string]map[string][]string

		// Enforce mode
		engine *EnforcementEngine
	)

	switch mode {
	case "analyze":
		policy = NewPolicy()
		unattributedPolicy = NewUnattributedPolicy()
		rawTracker = make(map[string]map[string][]string)
		fmt.Printf("🔍 NodeLeash [ANALYZE] — PID: %d\n", targetPID)

	case "enforce":
		engine, err = LoadEnforcementEngine(policyPath, unattributedPath)
		if err != nil {
			log.Fatalf("Loading enforcement engine: %v", err)
		}
		fmt.Printf("🛡️  NodeLeash [ENFORCE] — PID: %d\n", targetPID)
		fmt.Println("   Violations will be logged to stdout.")
	}

	symb := NewBlazeSymbolizer()

	// Boot time offset: convert eBPF CLOCK_MONOTONIC timestamps to wall clock.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("ClockGettime: %v", err)
	}
	bootTime := time.Now().Add(-time.Duration(uint64(ts.Sec)*1e9 + uint64(ts.Nsec)))

	// -------------------------------------------------------------------------
	// Ring buffer + shutdown
	// -------------------------------------------------------------------------
	rd, err := ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		log.Fatalf("Ring buffer reader: %v", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		fmt.Println("\n🛑 Signal received — flushing...")
		rd.Close()
	}()

	fmt.Println("Listening for syscall events...")

	// =========================================================================
	// EVENT LOOP
	//
	// Steps 1–5 are identical in both modes: decode the event, resolve symbols,
	// build the attributed stack. Step 6 branches on mode:
	//   analyze → record into policy structures
	//   enforce → check against EnforcementEngine, log violations
	// =========================================================================
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) ||
				errors.Is(err, os.ErrClosed) ||
				strings.Contains(err.Error(), "file already closed") {
				break
			}
			log.Printf("Ring buffer error: %v", err)
			continue
		}

		// Step 1: decode fixed-size event header from trace.c.
		var info SyscallInfo
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
			log.Printf("Decode error: %v", err)
			continue
		}

		// Step 2: retrieve current stack addresses from the eBPF stack map.
		var rawFrames [127]uint64
		if err := objs.StackMap.Lookup(&info.StackId, &rawFrames); err != nil {
			continue
		}
		var validIPs []uint64
		for _, ip := range rawFrames {
			if ip == 0 {
				break
			}
			validIPs = append(validIPs, ip)
		}
		if len(validIPs) == 0 {
			continue
		}

		syscallName := getSyscallName(info.SyscallId)

		// Step 3: resolve instruction pointers → ResolvedFrame{Name, Module}.
		// Name: from Blazesym (V8 perf map for JS, ELF for Node binary).
		// Module: from /proc/<pid>/maps — available even for unresolved symbols.
		// Requires Node.js started with --perf-basic-prof for JS frame names.
		resolvedFrames := symb.ResolveBatch(validIPs, info.Pid)

		// Step 4 (analyze only): record raw stack before any filtering.
		if mode == "analyze" {
			recordRawStack(rawTracker, syscallName, resolvedFrames)
		}

		// Step 5: classify frames, build call path, map syscall → capability.
		// Returns (event, true) for attributed events.
		// Returns (AnalyzedStack{Capability: cap}, false) for unattributed.
		// Attribution works only when the JS frame is present on the native
		// stack at the moment of the syscall (synchronous/quasi-synchronous
		// execution). Deferred async I/O via libuv or the worker thread pool
		// produces stacks with no user-land frames → UnattributedPolicy.
		event, ok := AnalyzeStack(syscallName, resolvedFrames)

		// Step 6: branch on mode.
		switch mode {
		case "analyze":
			if ok {
				policy.Record(event)
			} else if event.Syscall != "" {
				// Unattributed but Syscall known: feed the safety net.
				unattributedPolicy.Record(event.Syscall)
			}

			eventTime := bootTime.Add(time.Duration(info.TimestampNs))

			if ok {
				fmt.Printf("\n🕒 [%s] [PID:%d] %s → %s\n",
					eventTime.Format("15:04:05.000000"),
					info.Pid, event.Syscall, event.Responsible)
				fmt.Printf("   path: %s\n", strings.Join(event.CallPath, " → "))
			} else if event.Syscall != "" {
				fmt.Printf("\n🕒 [%s] [PID:%d] %s → [unattributed]\n",
					eventTime.Format("15:04:05.000000"),
					info.Pid, event.Syscall)
			}

			for i, f := range resolvedFrames {
				fmt.Printf("      [%2d] %s\n", i, f.Display())
			}

		case "enforce":
			// Pass the event to the engine regardless of attribution status.
			// Check() handles both cases: attributed events go through the
			// per-package policy; unattributed events go through the safety net.
			engine.Check(event, info.Pid, syscallName)
		}
	}

	// =========================================================================
	// SHUTDOWN & EXPORT
	// =========================================================================

	switch mode {
	case "analyze":
		policy.PrintSummary()
		unattributedPolicy.PrintSummary()
		printRawReport(rawTracker)
		exportRawReport(int(targetPID), rawTracker)

		if err := policy.Export(int(targetPID), "policy"); err != nil {
			log.Printf("Policy export error: %v", err)
		}
		if err := unattributedPolicy.Export(int(targetPID), "policy"); err != nil {
			log.Printf("Unattributed policy export error: %v", err)
		}

	case "enforce":
		engine.PrintViolationSummary()
	}
}
