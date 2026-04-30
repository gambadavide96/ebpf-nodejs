package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// AnalyzedStack is the unit of information produced per eBPF event.
// Returned by AnalyzeStack for both attributed and unattributed events.
// When ok=false, only Capability is populated — callers use it for
// the UnattributedPolicy safety net.
type AnalyzedStack struct {
	Capability   string
	Responsible  string   // package that triggered the syscall ("" if unattributed)
	CallPath     []string // [outermost_caller, ..., Responsible]
	CallPathHash string
}

type FrameKind int

const (
	KindInfrastructure FrameKind = iota
	KindNPM
	KindLocal
	KindNativeAddon
)

type classifiedFrame struct {
	Kind        FrameKind
	PackageName string
}

// -----------------------------------------------------------------------
// Frame classification — positive whitelist
//
// Two positive rules replace the old blacklist of symbol name prefixes:
//
//   Rule 1: Name has prefix "JS:"    → V8 JIT frame (from perf map)
//   Rule 2: Module ends with ".node" → npm native addon
//   Default: everything else         → infrastructure (skip)
//
// This is robust across Node.js version updates: new libuv or V8 symbols
// are automatically infrastructure because they have no ".node" module
// and no "JS:" prefix.
// -----------------------------------------------------------------------

func classifyFrame(frame ResolvedFrame) classifiedFrame {
	if strings.HasPrefix(frame.Name, "JS:") {
		return classifyJSFrame(frame.Name)
	}
	if strings.HasSuffix(frame.Module, ".node") {
		return classifiedFrame{
			Kind:        KindNativeAddon,
			PackageName: extractNativeAddonPackage(frame.Module),
		}
	}
	return classifiedFrame{Kind: KindInfrastructure}
}

func classifyJSFrame(raw string) classifiedFrame {
	if strings.Contains(raw, " node:") {
		return classifiedFrame{Kind: KindInfrastructure}
	}

	clean := strings.TrimLeft(strings.TrimPrefix(raw, "JS:"), "~^*")

	if strings.Contains(clean, "-liftoff") || strings.Contains(clean, "-turbofan") {
		return classifiedFrame{Kind: KindNPM, PackageName: "WASM_MODULE"}
	}

	parts := strings.SplitN(clean, " ", 2)
	funcName := parts[0]
	path := "unknown"
	if len(parts) > 1 {
		path = parts[1]
	}

	// Anonymous function mitigation.
	// V8 emits frames with empty function name for arrow functions and
	// callbacks, but always includes the source path:line:col.
	// We synthesize a positional name so the frame contributes to the
	// call path. The package is extracted from the path, which is always
	// available regardless of function anonymity.
	if funcName == "" {
		if path == "unknown" {
			return classifiedFrame{Kind: KindInfrastructure}
		}
		funcName = "<anon@" + anonLabel(path) + ">"
	}

	pkgName := extractJSPackageName(path)

	if strings.Contains(path, "node_modules") {
		return classifiedFrame{Kind: KindNPM, PackageName: pkgName}
	}
	return classifiedFrame{Kind: KindLocal, PackageName: pkgName}
}

func extractNativeAddonPackage(modulePath string) string {
	idx := strings.Index(modulePath, "node_modules/")
	if idx == -1 {
		return filepath.Base(modulePath)
	}
	sub := modulePath[idx+len("node_modules/"):]
	parts := strings.SplitN(sub, "/", 3)
	if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func extractJSPackageName(rawPath string) string {
	clean := strings.TrimPrefix(rawPath, "file://")
	if idx := strings.Index(clean, ":"); idx > 1 {
		clean = clean[:idx]
	}
	clean = filepath.Clean(clean)

	if idx := strings.Index(clean, "node_modules/"); idx != -1 {
		sub := clean[idx+len("node_modules/"):]
		parts := strings.SplitN(sub, "/", 3)
		if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
			return parts[0] + "/" + parts[1]
		}
		return parts[0]
	}

	if clean == "" || clean == "." || clean == "unknown" {
		return "LOCAL/unknown"
	}
	fileName := filepath.Base(clean)
	parentDir := filepath.Base(filepath.Dir(clean))
	if parentDir == "." || parentDir == "/" {
		return fmt.Sprintf("LOCAL/%s", fileName)
	}
	return fmt.Sprintf("LOCAL/%s/%s", parentDir, fileName)
}

func anonLabel(path string) string {
	clean := strings.TrimPrefix(path, "file://")
	parts := strings.Split(clean, ":")
	base := filepath.Base(parts[0])
	if len(parts) > 1 {
		return base + ":" + parts[1]
	}
	return base
}

// -----------------------------------------------------------------------
// Call path construction
// -----------------------------------------------------------------------

// Responsibile: The userspace responsible of the syscall
// callPath: The userspace path that lead to the syscall
func buildCallPath(frames []ResolvedFrame) (responsible string, callPath []string, found bool) {
	var packages []string
	seen := make(map[string]bool)

	for _, frame := range frames {
		cf := classifyFrame(frame)
		//If the frame is noise, we ignore it
		if cf.Kind == KindInfrastructure || cf.PackageName == "" {
			continue
		}
		//We find the syscall responsible
		if responsible == "" {
			responsible = cf.PackageName
			found = true
		}
		//If we haven't seen this package, we add to the call path
		if !seen[cf.PackageName] {
			packages = append(packages, cf.PackageName)
			seen[cf.PackageName] = true
		}
	}

	if !found {
		return "", nil, false
	}
	return responsible, reverseStringSlice(packages), true
}

// -----------------------------------------------------------------------
// Main entry point
// -----------------------------------------------------------------------

// AnalyzeStack processes a single eBPF event.
//
// Returns (event, true) when attribution succeeds.
// Returns (AnalyzedStack{Capability: cap}, false) when attribution fails
// but the capability is known — callers record it in UnattributedPolicy.
//
// Attribution works for syscalls executed synchronously or quasi-synchronously,
// i.e. while the JS frame is still physically present on the native stack.
// Asynchronous I/O (deferred by libuv or the worker thread pool) produces
// stacks with no user-land JS frames and ends up in UnattributedPolicy.
func AnalyzeStack(syscallName string, frames []ResolvedFrame) (AnalyzedStack, bool) {
	//Assigning capability
	cap := MapToCapability(syscallName)
	if cap == CapUnknown {
		return AnalyzedStack{}, false
	}

	responsible, callPath, found := buildCallPath(frames)

	//If we haven't found the responsible
	//we pass the capability to assign it in unattributed fallback
	if !found {
		return AnalyzedStack{Capability: cap}, false
	}

	return AnalyzedStack{
		Capability:   cap,
		Responsible:  responsible,
		CallPath:     callPath,
		CallPathHash: hashCallPath(callPath),
	}, true
}

func hashCallPath(path []string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(path, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

func reverseStringSlice(s []string) []string {
	r := make([]string, len(s))
	for i, v := range s {
		r[len(s)-1-i] = v
	}
	return r
}
