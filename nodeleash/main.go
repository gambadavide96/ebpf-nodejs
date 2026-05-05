package main

// Specific target for x86_64:
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
	AsyncStackId int32 // -1 = no async context; >= 0 = stack_id from uprobe or fd map
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

// attachUprobes attaches all libuv uprobes for async attribution.
//
// Thread-pool probes (Category A — covers fs.*, dns.*):
//
//	uv__work_submit      uprobe    — captures JS context on main thread at submission
//	uv__fs_work          uprobe    — transfers context to worker thread (filesystem)
//	uv__fs_work          uretprobe — cleans up worker context after all I/O syscalls
//	uv__getaddrinfo_work uprobe    — transfers context to worker thread (DNS)
//	uv__getaddrinfo_work uretprobe — cleans up worker context after DNS syscalls
//
// Network attribution is handled entirely inside trace.c via the fd_attribution_map
// (trace_sys_enter stages on socket()/accept(), trace_sys_exit promotes to fd map)
// and requires no uprobes.
//
// Graceful degradation: if any symbol is absent the uprobe is skipped and a
// warning is printed. If uv__work_submit is attached but no worker uprobes are
// (e.g. stripped binary), an explicit warning is emitted because the uv_work_map
// would accumulate stale entries without the corresponding cleanup path.
func attachUprobes(pid uint32, objs traceObjects) ([]link.Link, int) {
	nodePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Printf("⚠️  Cannot read node binary path: %v — uprobes disabled", err)
		return nil, 0
	}

	ex, err := link.OpenExecutable(nodePath)
	if err != nil {
		log.Printf("⚠️  Cannot open executable: %v — uprobes disabled", err)
		return nil, 0
	}

	type entry struct {
		label  string
		attach func() (link.Link, error)
	}

	entries := []entry{
		// ---- thread pool: submission (main thread) ----
		{"uprobe:uv__work_submit", func() (link.Link, error) {
			return ex.Uprobe("uv__work_submit", objs.TraceUvWorkSubmit, nil)
		}},

		// ---- thread pool: filesystem worker (entry + exit) ----
		{"uprobe:uv__fs_work", func() (link.Link, error) {
			return ex.Uprobe("uv__fs_work", objs.TraceUvFsWork, nil)
		}},
		{"uretprobe:uv__fs_work", func() (link.Link, error) {
			return ex.Uretprobe("uv__fs_work", objs.TraceUvFsWorkRet, nil)
		}},

		// ---- thread pool: DNS worker (entry + exit) ----
		{"uprobe:uv__getaddrinfo_work", func() (link.Link, error) {
			return ex.Uprobe("uv__getaddrinfo_work", objs.TraceUvGetaddrinfoWork, nil)
		}},
		{"uretprobe:uv__getaddrinfo_work", func() (link.Link, error) {
			return ex.Uretprobe("uv__getaddrinfo_work", objs.TraceUvGetaddrinfoWorkRet, nil)
		}},
	}

	var links []link.Link
	attached := 0
	submitAttached := false
	workerEntryAttached := 0

	for _, e := range entries {
		l, err := e.attach()
		if err != nil {
			log.Printf("⚠️  %s not found: %v", e.label, err)
			continue
		}
		links = append(links, l)
		attached++
		fmt.Printf("   attached: %s\n", e.label)

		if e.label == "uprobe:uv__work_submit" {
			submitAttached = true
		}
		if e.label == "uprobe:uv__fs_work" || e.label == "uprobe:uv__getaddrinfo_work" {
			workerEntryAttached++
		}
	}

	// Warn when the thread-pool bridge is half-attached: uv__work_submit will
	// populate uv_work_map but nobody will ever drain it, causing the map to
	// fill up silently over time.
	if submitAttached && workerEntryAttached == 0 {
		log.Printf("⚠️  uv__work_submit attached but no worker uprobes found.")
		log.Printf("    Thread-pool attribution disabled (stripped binary?).")
		log.Printf("    uv_work_map entries will accumulate without cleanup.")
	}

	return links, attached
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
		log.Fatalf("sys_enter tracepoint: %v", err)
	}
	defer tpSysEnter.Close()

	// sys_exit is used exclusively to capture the fd returned by socket()/accept().
	// Its handler exits immediately for all other syscalls (single comparison).
	tpSysExit, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.TraceSysExit, nil)
	if err != nil {
		log.Fatalf("sys_exit tracepoint: %v", err)
	}
	defer tpSysExit.Close()

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceFork, nil)
	if err != nil {
		log.Fatalf("fork tracepoint: %v", err)
	}
	defer tpFork.Close()

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("exit tracepoint: %v", err)
	}
	defer tpExit.Close()

	// Attach thread-pool uprobes. Network attribution needs no uprobes
	// (handled entirely via sys_enter/sys_exit tracepoints in trace.c).
	uprobeLinks, attachedCount := attachUprobes(uint32(targetPID), objs)
	for _, l := range uprobeLinks {
		defer l.Close()
	}

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
		fmt.Printf("   Thread-pool attribution: %d/5 uprobes attached\n", attachedCount)
		fmt.Printf("   Network attribution: active (fd-based, no uprobes required)\n")
		if debugMode {
			fmt.Println("   [--debug: stacks printed, call paths saved to JSON]")
		}

	case "enforce":
		engine, err = LoadEnforcementEngine(policyPath, unattributedPath)
		if err != nil {
			log.Fatalf("Loading enforcement engine: %v", err)
		}
		fmt.Printf("🛡️  NodeLeash [ENFORCE] — PID: %d\n", targetPID)
		fmt.Printf("   Thread-pool attribution: %d/5 uprobes attached\n", attachedCount)
		fmt.Printf("   Network attribution: active (fd-based, no uprobes required)\n")
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
	//
	// Per-event steps:
	//   1. Decode the fixed-size event header from trace.c.
	//   2. Retrieve current stack addresses from the eBPF stack map.
	//   3. Resolve current stack symbols via Blazesym.
	//   4. (analyze only) Record raw stack for the raw report.
	//   5. If async_stack_id >= 0, resolve async stack symbols.
	//   6. Attribute: try current stack first (synchronous path),
	//      fall back to async stack (uprobe or fd-based path).
	//   7. Branch on mode: record into policy or check for violations.
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

		// Step 1: decode event header.
		var info SyscallInfo
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
			log.Printf("Decode error: %v", err)
			continue
		}

		// Step 2: retrieve current stack addresses.
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

		// Step 3: resolve current stack.
		resolvedFrames := symb.ResolveBatch(validIPs, info.Pid)

		// Step 4 (analyze only): record raw stack before filtering.
		if mode == "analyze" {
			recordRawStack(rawTracker, syscallName, resolvedFrames)
		}

		// Step 5: resolve async stack if trace.c found one.
		// async_stack_id >= 0 means either:
		//   - a thread-pool uprobe set tid_stack_map[worker_tid], or
		//   - a prior socket() call set fd_attribution_map[fd].
		// In both cases the async stack contains JS frames from the original
		// JS call site, which AnalyzeStack can attribute to a package.
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

		// Step 6: attribute.
		// Priority: synchronous stack > async stack > UnattributedPolicy.
		event, ok := AnalyzeStack(syscallName, resolvedFrames)
		fromAsync := false
		if !ok && len(asyncFrames) > 0 {
			event, ok = AnalyzeStack(syscallName, asyncFrames)
			fromAsync = ok
		}

		// Step 7: branch on mode.
		switch mode {
		case "analyze":
			if ok {
				policy.Record(event)
			} else if event.Capability != "" {
				unattributedPolicy.Record(event.Capability)
			}

			if debugMode {
				eventTime := bootTime.Add(time.Duration(info.TimestampNs))

				if ok {
					tag := ""
					if fromAsync {
						tag = " [async]"
					}
					fmt.Printf("\n🕒 [%s] [PID:%d] %s → %s%s\n",
						eventTime.Format("15:04:05.000000"),
						info.Pid, event.Capability, event.Responsible, tag)
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
					fmt.Println("   --- async stack ---")
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
