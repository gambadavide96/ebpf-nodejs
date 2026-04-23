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

// INFO STRUCTURE
type SyscallInfo struct {
	TimestampNs uint64
	Pid         uint32 // Identificatore del processo
	SyscallId   uint32
	StackId     int32
}

// getSyscallName use seccomp to translate syscall ID in syscall name
func getSyscallName(id uint32) string {
	scmpSyscall := seccomp.ScmpSyscall(id)
	name, err := scmpSyscall.GetName()
	if err != nil {
		return fmt.Sprintf("syscall_%d", id)
	}
	return name
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Correct use: sudo ./monitor <PID_NODEJS>")
	}

	targetPID, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		log.Fatalf("PID not valid: %v", err)
	}

	// Removes the lockable memory limit in RAM
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Loading eBPF objects
	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatalf("Error on loading objects: %v", err)
	}
	defer objs.Close()

	// Hash map Pids initialization
	pidKey := uint32(targetPID)
	pidVal := uint32(1)
	if err := objs.TargetPidMap.Put(&pidKey, &pidVal); err != nil {
		log.Fatalf("Error on insert PID in Hash map : %v", err)
	}

	// Setting Tracepoint
	tpSys, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		log.Fatalf("Trace_sys_enter hook error : %v", err)
	}
	defer tpSys.Close()

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TraceFork, nil)
	if err != nil {
		log.Fatalf("Trace_fork hook error: %v", err)
	}
	defer tpFork.Close()

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("Trace_exit hook error: %v", err)
	}
	defer tpExit.Close()

	fmt.Printf("🔍 Process Tree Monitoring started. Main PID: %d\n", targetPID)

	// HIERARCHICAL DATA STRUCTURE (Multi-PID)
	// Structure: map[PID]map[SyscallName]map[StackFingerprint][]StackFrames
	syscallStacksTracker := make(map[uint32]map[string]map[string][]string)

	// Blazesym initialization
	symb := NewBlazeSymbolizer()

	// Manage Time events
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("Unable to read system clock: %v", err)
	}
	uptimeNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	bootTime := time.Now().Add(-time.Duration(uptimeNs))

	// Ring Buffer reader
	rd, err := ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		log.Fatalf("Error on opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Intercepting closing signals (Ctrl+C)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n🛑 Interruption received.")
		rd.Close()
	}()

	fmt.Println("Waiting events...")

	for {
		//Reading data from ringbuffer
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) || strings.Contains(err.Error(), "file already closed") {
				break
			}
			log.Printf("Error reading ringbuf: %v", err)
			continue
		}

		// Decoding event
		var info SyscallInfo
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
			log.Printf("Error decoding event: %v", err)
			continue
		}

		// Retrieving addresses from the StackMap
		var stackFrames [127]uint64
		err = objs.StackMap.Lookup(&info.StackId, &stackFrames)
		if err != nil {
			continue
		}

		eventTime := bootTime.Add(time.Duration(info.TimestampNs))
		timeStr := eventTime.Format("15:04:05.000000")
		syscallName := getSyscallName(info.SyscallId)

		fmt.Printf("\n🕒 [%s] [PID: %d] 🔹 Syscall: %-15s (ID: %d) | Stack ID: %d\n",
			timeStr, info.Pid, syscallName, info.SyscallId, info.StackId)

		// ---------------------------------------------------------
		// SYMBOL RESOLUTION
		// ---------------------------------------------------------
		var validIPs []uint64
		for _, ip := range stackFrames {
			if ip == 0 {
				break
			}
			validIPs = append(validIPs, ip)
		}

		if len(validIPs) > 0 {
			// Passing PID and addresses to blazesym
			resolvedNames := symb.ResolveBatch(validIPs, info.Pid)

			for i, funcName := range resolvedNames {
				fmt.Printf("      [%2d] %s\n", i, funcName)
			}

			// Saving PID -> Syscall -> Stack in the map
			if syscallStacksTracker[info.Pid] == nil {
				syscallStacksTracker[info.Pid] = make(map[string]map[string][]string)
			}
			if syscallStacksTracker[info.Pid][syscallName] == nil {
				syscallStacksTracker[info.Pid][syscallName] = make(map[string][]string)
			}

			// Saving stack fingerprint
			stackFingerprint := strings.Join(resolvedNames, "|")

			if _, exists := syscallStacksTracker[info.Pid][syscallName][stackFingerprint]; !exists {
				syscallStacksTracker[info.Pid][syscallName][stackFingerprint] = resolvedNames
			}
		}
	}

	// Profile aggregation
	functionSyscallsProfile := BuildFunctionProfile(syscallStacksTracker)

	// JSON Syscall stack traces for each PID
	exportJSONSyscalls(syscallStacksTracker)

	// JSON function profile
	exportJSONFunctions(int(targetPID), functionSyscallsProfile)
}
