package main

//Specific target for x86_64:
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace trace.c

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
// 24 bytes, naturally aligned — must match exactly (binary.Read is used).
type SyscallInfo struct {
	TimestampNs  uint64
	Pid          uint32
	SyscallId    uint32
	StackId      int32
	AsyncStackId int32 // -1 if no async context, >= 0 if uprobes captured a JS context
}

func getSyscallName(id uint32) string {
	name, err := seccomp.ScmpSyscall(id).GetName()
	if err != nil {
		return fmt.Sprintf("syscall_%d", id)
	}
	return name
}

// populateTrackedSyscalls fills the kernel-side tracked_syscalls_map from
// the capability taxonomy. Only these syscall IDs reach the ring buffer.
func populateTrackedSyscalls(objs traceObjects) error {
	val := uint8(1)
	for name := range syscallToCapability {
		id, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			continue
		}
		key := uint32(id)
		if err := objs.TrackedSyscallsMap.Put(&key, &val); err != nil {
			return fmt.Errorf("inserting syscall %s (id %d): %w", name, key, err)
		}
	}
	return nil
}

// attachUprobes attaches the two uprobes needed for async attribution:
//   - uv__work_submit: captures JS stack when async work is scheduled (main thread)
//   - uv__fs_work: transfers the context to the worker TID (worker thread)
//
// Both symbols must be present in the Node.js binary. If not found (stripped
// binary), uprobes are skipped and attribution falls back to UnattributedPolicy.
// Returns the list of links to defer-close in main.
func attachUprobes(pid uint32, objs traceObjects) []link.Link {
	nodePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Printf("⚠️  Cannot read node binary path: %v — uprobes disabled", err)
		return nil
	}

	ex, err := link.OpenExecutable(nodePath)
	if err != nil {
		log.Printf("⚠️  Cannot open executable %s: %v — uprobes disabled", nodePath, err)
		return nil
	}

	var links []link.Link

	upWorkSubmit, err := ex.Uprobe("uv__work_submit", objs.TraceUvWorkSubmit, nil)
	if err != nil {
		log.Printf("⚠️  uprobe uv__work_submit: %v — async attribution disabled", err)
		return nil
	}
	links = append(links, upWorkSubmit)
	fmt.Println("   uprobe attached: uv__work_submit")

	upFsWork, err := ex.Uprobe("uv__fs_work", objs.TraceUvFsWork, nil)
	if err != nil {
		log.Printf("⚠️  uprobe uv__fs_work: %v — async attribution disabled", err)
		upWorkSubmit.Close()
		return nil
	}
	links = append(links, upFsWork)
	fmt.Println("   uprobe attached: uv__fs_work")

	return links
}

// checkDropCounters warns if events were silently lost during the session.
func checkDropCounters(objs traceObjects) {
	var stackDrops, ringDrops uint64
	k0, k1 := uint32(0), uint32(1)
	objs.DropCounters.Lookup(&k0, &stackDrops)
	objs.DropCounters.Lookup(&k1, &ringDrops)
	if stackDrops > 0 || ringDrops > 0 {
		fmt.Printf("\n⚠️  Data loss during session:\n")
		fmt.Printf("   Stack map full:   %d events dropped\n", stackDrops)
		fmt.Printf("   Ring buffer full: %d events dropped\n", ringDrops)
		fmt.Printf("   Consider increasing max_entries in trace.c\n")
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `NodeLeash — npm package-level syscall policy enforcement

ANALYZE MODE  (build policy from a running Node.js process):
  sudo ./nodeleash analyze <PID> [--debug]

  --debug   print resolved stacks and save full call paths to JSON

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

	mode := os.Args[1]
	pidStr := os.Args[2]

	targetPID, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		log.Fatalf("Invalid PID %q: %v", pidStr, err)
	}

	args := os.Args[3:]

	var (
		debugMode        bool
		policyPath       string
		unattributedPath string
	)

	switch mode {
	case "analyze":
		for _, a := range args {
			if a == "--debug" {
				debugMode = true
			}
		}
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
	// eBPF setup
	// -------------------------------------------------------------------------
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	pidKey, pidVal := uint32(targetPID), uint32(1)
	if err := objs.TargetPidMap.Put(&pidKey, &pidVal); err != nil {
		log.Fatalf("Inserting PID: %v", err)
	}

	if err := populateTrackedSyscalls(objs); err != nil {
		log.Fatalf("Populating syscall filter: %v", err)
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

	// Attach uprobes for async attribution.
	// Graceful degradation: if the symbols are not found (stripped binary),
	// NodeLeash continues without async attribution.
	uprobeLinks := attachUprobes(uint32(targetPID), objs)
	for _, l := range uprobeLinks {
		defer l.Close()
	}
	asyncEnabled := len(uprobeLinks) == 2

	// -------------------------------------------------------------------------
	// Mode-specific state
	// -------------------------------------------------------------------------
	var (
		policy             Policy
		unattributedPolicy *UnattributedPolicy
		debugStore         callPathDebugStore
		rawTracker         map[string]map[string][]string
		engine             *EnforcementEngine
	)

	switch mode {
	case "analyze":
		policy = NewPolicy()
		unattributedPolicy = NewUnattributedPolicy()
		debugStore = make(callPathDebugStore)
		rawTracker = make(map[string]map[string][]string)
		fmt.Printf("🔍 NodeLeash [ANALYZE] — PID: %d\n", targetPID)
		if asyncEnabled {
			fmt.Println("   Async attribution: enabled (uprobes on libuv)")
		} else {
			fmt.Println("   Async attribution: disabled (symbols not found)")
		}
		if debugMode {
			fmt.Println("   [--debug: stacks printed, call paths saved to JSON]")
		}

	case "enforce":
		engine, err = LoadEnforcementEngine(policyPath, unattributedPath)
		if err != nil {
			log.Fatalf("Loading enforcement engine: %v", err)
		}
		fmt.Printf("🛡️  NodeLeash [ENFORCE] — PID: %d\n", targetPID)
		fmt.Println("   Violations will be logged to stdout.")
	}

	symb := NewBlazeSymbolizer()

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

		// Step 1: decode event.
		var info SyscallInfo
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
			log.Printf("Decode error: %v", err)
			continue
		}

		// Step 2: retrieve stack addresses.
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

		// Step 3: resolve symbols.
		resolvedFrames := symb.ResolveBatch(validIPs, info.Pid)

		// Step 4 (analyze only): record raw stack.
		if mode == "analyze" {
			recordRawStack(rawTracker, syscallName, resolvedFrames)
		}

		// Step 5: resolve async frames if uprobes captured a context.
		// async_stack_id >= 0 means the worker thread that executed this syscall
		// was previously registered by trace_uv_fs_work with a JS stack from
		// the scheduling point (uv__work_submit in the main thread).
		var asyncFrames []ResolvedFrame
		if info.AsyncStackId >= 0 {
			var asyncRaw [127]uint64
			asyncID := uint32(info.AsyncStackId)
			if err := objs.StackMap.Lookup(&asyncID, &asyncRaw); err == nil {
				var asyncIPs []uint64
				for _, ip := range asyncRaw {
					if ip == 0 {
						break
					}
					asyncIPs = append(asyncIPs, ip)
				}
				if len(asyncIPs) > 0 {
					asyncFrames = symb.ResolveBatch(asyncIPs, info.Pid)
				}
			}
		}

		// Step 6: attribute. Try direct stack first; fall back to async frames.
		event, ok := AnalyzeStack(syscallName, resolvedFrames)
		if !ok && len(asyncFrames) > 0 {
			event, ok = AnalyzeStack(syscallName, asyncFrames)
			if ok {
				// Mark the source of attribution for debug output
				event.Responsible = event.Responsible + " [async]"
			}
		}

		// Step 7: branch on mode.
		switch mode {
		case "analyze":
			if ok {
				// Strip the [async] marker before recording — it's only for debug
				responsible := strings.TrimSuffix(event.Responsible, " [async]")
				event.Responsible = responsible
				policy.Record(event)
			} else if event.Capability != "" {
				unattributedPolicy.Record(event.Capability)
			}

			if debugMode {
				eventTime := bootTime.Add(time.Duration(info.TimestampNs))

				if ok {
					asyncMarker := ""
					if len(asyncFrames) > 0 && info.AsyncStackId >= 0 &&
						strings.Contains(event.Responsible, "[async]") {
						asyncMarker = " [via uprobe]"
					}
					fmt.Printf("\n🕒 [%s] [PID:%d] %s → %s%s\n",
						eventTime.Format("15:04:05.000000"),
						info.Pid, event.Capability,
						strings.TrimSuffix(event.Responsible, " [async]"),
						asyncMarker)
					fmt.Printf("   path: %s\n", strings.Join(event.CallPath, " → "))
					debugStore.RecordDebug(event)
				} else if event.Capability != "" {
					fmt.Printf("\n🕒 [%s] [PID:%d] %s → [unattributed]\n",
						eventTime.Format("15:04:05.000000"),
						info.Pid, event.Capability)
				}

				fmt.Println("   --- current stack ---")
				for i, f := range resolvedFrames {
					fmt.Printf("      [%2d] %s\n", i, f.Display())
				}
				if len(asyncFrames) > 0 {
					fmt.Println("   --- async stack (from uprobe) ---")
					for i, f := range asyncFrames {
						fmt.Printf("      [%2d] %s\n", i, f.Display())
					}
				}
			}

		case "enforce":
			engine.Check(event, info.Pid, syscallName)
		}
	}

	// =========================================================================
	// SHUTDOWN & EXPORT
	// =========================================================================
	checkDropCounters(objs)

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
		if debugMode {
			debugStore.ExportDebug(int(targetPID), "policy")
		}

	case "enforce":
		engine.PrintViolationSummary()
	}
}
