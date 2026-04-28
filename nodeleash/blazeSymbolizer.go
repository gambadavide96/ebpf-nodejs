package main

import (
	"fmt"
	"log"

	blazesym "github.com/libbpf/blazesym/go"
)

// ResolvedFrame pairs a symbol name with the binary it belongs to.
//
// Both fields are needed for classification:
//   - Name identifies JS frames via the "JS:" prefix written by V8's perf map
//   - Module identifies native addon frames via the ".node" file suffix
//
// Module comes from /proc/<pid>/maps independently of Blazesym, so
// classification is correct even for frames Blazesym cannot resolve.
type ResolvedFrame struct {
	Name   string // "JS:funcName path:line" | "nativeFunc" | "0x7f..." (unresolved)
	Module string // "/app/node_modules/bcrypt/build/Release/bcrypt.node" | "" (anonymous JIT)
}

func (f ResolvedFrame) Display() string {
	if f.Name != "" {
		return f.Name
	}
	if f.Module != "" {
		return fmt.Sprintf("[unresolved@%s]", f.Module)
	}
	return "[unknown]"
}

type cacheKey struct {
	pid  uint32
	addr uint64
}

type BlazeSymbolizer struct {
	sym      *blazesym.Symbolizer
	cache    map[cacheKey]ResolvedFrame
	modCache map[uint32]*moduleResolver
}

func NewBlazeSymbolizer() *BlazeSymbolizer {
	sym, err := blazesym.NewSymbolizer()
	if err != nil {
		log.Fatalf("Cannot initialize Blazesym: %v", err)
	}
	return &BlazeSymbolizer{
		sym:      sym,
		cache:    make(map[cacheKey]ResolvedFrame),
		modCache: make(map[uint32]*moduleResolver),
	}
}

func (b *BlazeSymbolizer) getModuleResolver(pid uint32) *moduleResolver {
	if r, ok := b.modCache[pid]; ok {
		return r
	}
	r, err := newModuleResolver(pid)
	if err != nil {
		return nil
	}
	b.modCache[pid] = r
	return r
}

// ResolveBatch resolves instruction pointers to ResolvedFrame values.
// Cache misses are batched into a single Blazesym call.
func (b *BlazeSymbolizer) ResolveBatch(ips []uint64, pid uint32) []ResolvedFrame {
	results := make([]ResolvedFrame, len(ips))
	resolver := b.getModuleResolver(pid)

	var missIdx []int
	var missIPs []uint64

	for i, ip := range ips {
		if f, ok := b.cache[cacheKey{pid, ip}]; ok {
			results[i] = f
		} else {
			missIdx = append(missIdx, i)
			missIPs = append(missIPs, ip)
		}
	}

	if len(missIPs) == 0 {
		return results
	}

	symbols, err := b.sym.SymbolizeProcessAbsAddrs(
		missIPs, pid,
		blazesym.ProcessSourceWithPerfMap(true),
	)

	for j, idx := range missIdx {
		ip := missIPs[j]

		name := fmt.Sprintf("0x%x", ip)
		if err == nil && j < len(symbols) && symbols[j].Name != "" {
			name = symbols[j].Name
		}

		module := ""
		if resolver != nil {
			module = resolver.Resolve(ip)
		}

		f := ResolvedFrame{Name: name, Module: module}
		results[idx] = f
		b.cache[cacheKey{pid, ip}] = f
	}

	return results
}
