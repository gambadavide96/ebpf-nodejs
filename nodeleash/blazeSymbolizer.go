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
	sym *blazesym.Symbolizer
}

func NewBlazeSymbolizer() *BlazeSymbolizer {
	sym, err := blazesym.NewSymbolizer()
	if err != nil {
		log.Fatalf("Cannot initialize Blazesym: %v", err)
	}
	return &BlazeSymbolizer{
		sym: sym,
	}
}

// ResolveBatch resolves all addresses in a single call to Blazesym.
func (b *BlazeSymbolizer) ResolveBatch(ips []uint64, pid uint32) []ResolvedFrame {
	results := make([]ResolvedFrame, len(ips))

	symbols, err := b.sym.SymbolizeProcessAbsAddrs(
		ips, pid,
		blazesym.ProcessSourceWithPerfMap(true),
	)

	for i, ip := range ips {
		name := fmt.Sprintf("0x%x", ip)
		module := ""

		if err == nil && i < len(symbols) {
			if symbols[i].Name != "" {
				name = symbols[i].Name
			}
			if symbols[i].Module != "" {
				module = symbols[i].Module
			}
		}

		results[i] = ResolvedFrame{Name: name, Module: module}
	}

	return results
}
