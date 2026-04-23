package main

import (
	"strings"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// FuncInfo represents a stack frame identified as a User function (not Node interna noise)
type FuncInfo struct {
	Name string
	Type string
	Path string
}

const (
	TypeJSLocal   = "JS_FUNC"
	TypeNPM       = "NPM" //external module
	TypeWASM      = "WASM"
	TypeNativeCPP = "NATIVE_ADDON" //Native library
)

// Declarative lists of prefixes for noise filtering (Node internals)
var noisePrefixes = []string{
	"__", "_start", "uv_", "node::", "v8::", "Builtins_",
	"void node", "pthread", "_IO_", "0x", "int node", "std::",
	"cxxabiv1::",
}

// Declarative lists of keywords for noise filtering (Node internals)
var noiseKeyWords = []string{
	"LINUX_2.6", "{virtual override thunk", "\u003c",
}

// isLibcWrapper uses libseccomp to dynamically check whether the name
// matches a Linux system call.
func isLibcWrapper(name string) bool {
	_, err := seccomp.GetSyscallFromName(name)
	return err == nil
}

// isNoise verify if the current frame is Node noise
func isNoise(raw string) bool {
	for _, prefix := range noisePrefixes {
		if strings.HasPrefix(raw, prefix) {
			return true
		}
	}
	for _, keywords := range noiseKeyWords {
		if strings.Contains(raw, keywords) {
			return true
		}
	}
	return isLibcWrapper(raw)
}

// parseV8Frame extracts and classifies JavaScript/WASM-specific information
func parseV8Frame(raw string) (FuncInfo, bool) {
	// Ignoring Node core modules (es. node:fs)
	if strings.Contains(raw, " node:") {
		return FuncInfo{}, false
	}

	// Clean V8 prefixes (~, ^, *)
	cleanString := strings.TrimLeft(strings.TrimPrefix(raw, "JS:"), "~^*")
	parts := strings.SplitN(cleanString, " ", 2)

	funcName := parts[0]

	// Discards anonymous functions
	if funcName == "" {
		return FuncInfo{}, false
	}

	path := "unknown"
	if len(parts) > 1 {
		path = parts[1] // Es: /app/index.js:10:5
	}

	// WASM identification
	if strings.Contains(funcName, "-liftoff") || strings.Contains(funcName, "-turbofan") {
		cleanWasmName := strings.Split(funcName, "-")[0]
		return FuncInfo{Name: cleanWasmName, Type: TypeWASM, Path: "wasm-module"}, true
	}

	//Identification npm module or local js function
	if strings.Contains(path, "node_modules") {
		return FuncInfo{Name: funcName, Type: TypeNPM, Path: path}, true
	}

	return FuncInfo{Name: funcName, Type: TypeJSLocal, Path: path}, true
}

// classifyFrame analyzes a single line of the stack trace to determine
// whether it belongs to the user and which technology it corresponds to.
func classifyFrame(raw string) (FuncInfo, bool) {

	if isNoise(raw) {
		return FuncInfo{}, false
	}

	// 2. V8 code (JS or Wasm)
	if strings.HasPrefix(raw, "JS:") {
		return parseV8Frame(raw)
	}

	// 3. Native addons (C/C++)
	return FuncInfo{Name: raw, Type: TypeNativeCPP, Path: "native-module"}, true
}

// BuildFunctionProfile takes as input all stacks traced by eBPF (divided by PID)
// and returns a single global aggregate map: Function -> SyscallName -> StackHash -> bool
func BuildFunctionProfile(tracker map[uint32]map[string]map[string][]string) map[FuncInfo]map[string]map[string]bool {

	// Function -> Syscalls map
	functionProfile := make(map[FuncInfo]map[string]map[string]bool)

	// Iterate over all intercepted PIDs (Parent + any Children)
	for _ /*pid*/, pidTracker := range tracker {

		// Iterate over the syscalls of that specific process
		for syscallName, hashStackTrace := range pidTracker {

			// Iterate over the stack traces
			for stackHash, stackFrames := range hashStackTrace {

				// Iterate over each frame to find the responsibile for the syscall
				for _, frame := range stackFrames {

					if info, isUserLand := classifyFrame(frame); isUserLand {

						if functionProfile[info] == nil {
							functionProfile[info] = make(map[string]map[string]bool)
						}
						if functionProfile[info][syscallName] == nil {
							functionProfile[info][syscallName] = make(map[string]bool)
						}

						// Assigning to the info function the syscallName with his stackHash
						functionProfile[info][syscallName][stackHash] = true

						break
					}
				}
			}
		}
	}

	return functionProfile
}
