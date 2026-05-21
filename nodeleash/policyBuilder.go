package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// -----------------------------------------------------------------------
// Policy — per-package attributed enforcement
// -----------------------------------------------------------------------

// Policy: Package → Syscall → CallPathHash.
type Policy map[string]map[string]map[string]bool

type PackageEntry struct {
	Package  string          `json:"package"`
	Syscalls []SyscallsEntry `json:"syscalls"`
}

type SyscallsEntry struct {
	Syscall        string   `json:"syscall"`
	CallPathHashes []string `json:"call_path_hashes"`
}

func NewPolicy() Policy { return make(Policy) }

func (p Policy) Record(event AnalyzedStack) {
	pkg, sys, hash := event.Responsible, event.Syscall, event.CallPathHash
	if p[pkg] == nil {
		p[pkg] = make(map[string]map[string]bool)
	}
	if p[pkg][sys] == nil {
		p[pkg][sys] = make(map[string]bool)
	}
	p[pkg][sys][hash] = true
}

// CheckViolation returns true if the event violates the policy.
// All three of (package, syscall, call_path_hash) must match.
func (p Policy) CheckViolation(event AnalyzedStack) bool {
	syscalls, ok := p[event.Responsible]
	if !ok {
		return true
	}
	hashes, ok := syscalls[event.Syscall]
	if !ok {
		return true
	}
	return !hashes[event.CallPathHash]
}

func (p Policy) Export(targetPID int, outputDir string) error {
	if len(p) == 0 {
		fmt.Println("⚠️  No attributed policy data collected.")
		return nil
	}
	var entries []PackageEntry
	for pkgName, syscalls := range p {
		e := PackageEntry{Package: pkgName}
		for sysName, hashes := range syscalls {
			se := SyscallsEntry{Syscall: sysName}
			for h := range hashes {
				se.CallPathHashes = append(se.CallPathHashes, h)
			}
			e.Syscalls = append(e.Syscalls, se)
		}
		entries = append(entries, e)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding policy: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0777); err != nil {
		return fmt.Errorf("creating dir: %w", err)
	}
	ts := time.Now().Format("20060102_150405")
	path := filepath.Join(outputDir,
		fmt.Sprintf("nodeleash_policy_pid%d_%s.json", targetPID, ts))
	if err := os.WriteFile(path, data, 0666); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}
	fmt.Printf("📁 Policy saved to: %s\n", path)
	fmt.Printf("   Packages: %d\n", len(p))
	fmt.Printf("   Syscalls: %d unique\n", countUniqueSyscalls(p))
	return nil
}

func (p Policy) PrintSummary() {
	if len(p) == 0 {
		fmt.Println("Attributed policy is empty.")
		return
	}
	fmt.Printf("\n%s\n  POLICY SUMMARY — %d packages\n%s\n",
		strings.Repeat("═", 60), len(p), strings.Repeat("═", 60))
	for pkg, syscalls := range p {
		fmt.Printf("\n  📦 %s\n", pkg)
		for sys, hashes := range syscalls {
			fmt.Printf("     %-32s %d path(s)\n", sys, len(hashes))
		}
	}
}

func countUniqueSyscalls(p Policy) int {
	seen := make(map[string]bool)
	for _, syscalls := range p {
		for s := range syscalls {
			seen[s] = true
		}
	}
	return len(seen)
}

// -----------------------------------------------------------------------
// UnattributedPolicy — process-level safety net
// -----------------------------------------------------------------------

// UnattributedPolicy records syscalls seen in events that NodeLeash
// could not attribute to any package (async completion, worker thread pool).
type UnattributedPolicy struct {
	Syscalls map[string]bool `json:"unattributed_syscalls"`
}

func NewUnattributedPolicy() *UnattributedPolicy {
	return &UnattributedPolicy{Syscalls: make(map[string]bool)}
}

func (u *UnattributedPolicy) Record(syscall string) {
	if syscall != "" {
		u.Syscalls[syscall] = true
	}
}

func (u *UnattributedPolicy) CheckViolation(syscall string) bool {
	if syscall == "" {
		return false
	}
	return !u.Syscalls[syscall]
}

func (u *UnattributedPolicy) Export(targetPID int, outputDir string) error {
	if len(u.Syscalls) == 0 {
		return nil
	}
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding unattributed policy: %w", err)
	}
	if err := os.MkdirAll(outputDir, 0777); err != nil {
		return fmt.Errorf("creating dir: %w", err)
	}
	ts := time.Now().Format("20060102_150405")
	path := filepath.Join(outputDir,
		fmt.Sprintf("nodeleash_unattributed_pid%d_%s.json", targetPID, ts))
	if err := os.WriteFile(path, data, 0666); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}
	fmt.Printf("📁 Unattributed policy saved to: %s\n", path)
	fmt.Printf("   Unattributed syscalls: %d\n", len(u.Syscalls))
	return nil
}

func (u *UnattributedPolicy) PrintSummary() {
	fmt.Printf("\n%s\n  UNATTRIBUTED SYSCALLS — safety net\n%s\n",
		strings.Repeat("─", 60), strings.Repeat("─", 60))
	if len(u.Syscalls) == 0 {
		fmt.Println("  None — all syscalls were attributed to a package.")
		return
	}
	fmt.Println("  Observed in syscalls whose JS context was not recoverable.")
	fmt.Println("  In enforcement: any NEW syscall here = violation.\n")
	for sys := range u.Syscalls {
		fmt.Printf("  • %s\n", sys)
	}
}

// -----------------------------------------------------------------------
// callPathDebugStore — human-readable call paths
// -----------------------------------------------------------------------

type callPathDebugStore map[string]map[string]map[string][]string

func (s callPathDebugStore) RecordDebug(event AnalyzedStack) {
	pkg, sys, hash := event.Responsible, event.Syscall, event.CallPathHash
	if s[pkg] == nil {
		s[pkg] = make(map[string]map[string][]string)
	}
	if s[pkg][sys] == nil {
		s[pkg][sys] = make(map[string][]string)
	}
	if _, exists := s[pkg][sys][hash]; !exists {
		s[pkg][sys][hash] = event.CallPath
	}
}

func (s callPathDebugStore) ExportDebug(targetPID int, outputDir string) {
	if len(s) == 0 {
		return
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		log.Printf("⚠️  debug JSON error: %v", err)
		return
	}
	if err := os.MkdirAll(outputDir, 0777); err != nil {
		return
	}
	path := filepath.Join(outputDir,
		fmt.Sprintf("nodeleash_callpaths_pid%d.json", targetPID))
	if err := os.WriteFile(path, data, 0666); err != nil {
		log.Printf("⚠️  debug write error: %v", err)
		return
	}
	fmt.Printf("🔍 Debug call paths saved to: %s\n", path)
}
