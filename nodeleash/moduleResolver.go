package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

type mapEntry struct {
	start  uint64
	end    uint64
	module string
}

// moduleResolver maps virtual addresses to the binary file they belong to
// by reading /proc/<pid>/maps.
//
// This is the foundation of NodeLeash's positive-whitelist frame classification.
// Instead of a fragile blacklist of symbol name prefixes, we ask:
// "which binary does this address come from?"
//
// Classification rules (applied in stackAnalyzer.go):
//   module ends with ".node"  → npm native addon  (positive match)
//   module is any other path  → Node.js infrastructure (node, libc, libuv)
//   module is empty           → anonymous mmap (V8 JIT region)
//                               identified via "JS:" name prefix instead
type moduleResolver struct {
	mu      sync.RWMutex
	pid     uint32
	entries []mapEntry
}

func newModuleResolver(pid uint32) (*moduleResolver, error) {
	r := &moduleResolver{pid: pid}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Resolve returns the binary path for a given virtual address.
// On miss, triggers a reload to handle addons loaded after startup.
func (r *moduleResolver) Resolve(addr uint64) string {
	r.mu.RLock()
	result := r.lookup(addr)
	r.mu.RUnlock()

	if result == "" {
		_ = r.reload()
		r.mu.RLock()
		result = r.lookup(addr)
		r.mu.RUnlock()
	}
	return result
}

func (r *moduleResolver) lookup(addr uint64) string {
	for _, e := range r.entries {
		if addr >= e.start && addr < e.end {
			return e.module
		}
	}
	return ""
}

func (r *moduleResolver) reload() error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", r.pid))
	if err != nil {
		return fmt.Errorf("reading /proc/%d/maps: %w", r.pid, err)
	}
	defer f.Close()

	var entries []mapEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if e, ok := parseMapsLine(scanner.Text()); ok {
			entries = append(entries, e)
		}
	}

	r.mu.Lock()
	r.entries = entries
	r.mu.Unlock()
	return scanner.Err()
}

// parseMapsLine parses one line from /proc/<pid>/maps.
// Format: "start-end perms offset dev ino [path]"
func parseMapsLine(line string) (mapEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return mapEntry{}, false
	}
	parts := strings.SplitN(fields[0], "-", 2)
	if len(parts) != 2 {
		return mapEntry{}, false
	}
	start, err1 := strconv.ParseUint(parts[0], 16, 64)
	end, err2 := strconv.ParseUint(parts[1], 16, 64)
	if err1 != nil || err2 != nil {
		return mapEntry{}, false
	}
	module := ""
	if len(fields) >= 6 {
		module = fields[5]
		if strings.HasPrefix(module, "[") {
			module = "" // skip [heap], [stack], [vdso]
		}
	}
	return mapEntry{start: start, end: end, module: module}, true
}
