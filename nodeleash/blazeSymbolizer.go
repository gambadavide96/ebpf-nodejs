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

// Produces a readable string for printing the frame,
// managing the three possible resolution states
func (f ResolvedFrame) Display() string {
	if f.Name != "" {
		return f.Name
	}
	if f.Module != "" {
		return fmt.Sprintf("[unresolved@%s]", f.Module)
	}
	return "[unknown]"
}

type BlazeSymbolizer struct {
	sym      *blazesym.Symbolizer
	modCache map[uint32]*moduleResolver //Cache for module resolution: modCache[pid].Resolve(ip)
}

func NewBlazeSymbolizer() *BlazeSymbolizer {
	sym, err := blazesym.NewSymbolizer()
	if err != nil {
		log.Fatalf("Cannot initialize Blazesym: %v", err)
	}
	return &BlazeSymbolizer{
		sym:      sym,
		modCache: make(map[uint32]*moduleResolver),
	}
}

// Return or create a module resolver per pid
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

// ResolveBatch resolves all addresses in a single call to Blazesym.
// No cache — each call always queries Blazesym and /proc/<pid>/maps.
func (b *BlazeSymbolizer) ResolveBatch(ips []uint64, pid uint32) []ResolvedFrame {
	results := make([]ResolvedFrame, len(ips))
	resolver := b.getModuleResolver(pid)

	symbols, err := b.sym.SymbolizeProcessAbsAddrs(
		ips, pid,
		blazesym.ProcessSourceWithPerfMap(true),
	)

	for i, ip := range ips {
		name := fmt.Sprintf("0x%x", ip)
		if err == nil && i < len(symbols) && symbols[i].Name != "" {
			name = symbols[i].Name
		}
		//TO DO: Possibile semplificazione usare symbols.module
		//al posto che moduleResolver? Da testare
		module := ""
		if resolver != nil {
			module = resolver.Resolve(ip)
		}

		results[i] = ResolvedFrame{Name: name, Module: module}
	}

	return results
}
