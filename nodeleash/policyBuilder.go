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

// Policy: Package → Capability → CallPathHash.
// Mirrors GoLeash's formal allowlist: A = { (Pi, { (Cij, T_ij) }) }
// where T_ij is stored as a set of call path hashes.
//
// Call path hashes enable context-aware enforcement (confused deputy defense):
// the same (package, capability) is allowed only when the full call context
// also matches a previously observed trusted path.
type Policy map[string]map[string]map[string]bool

type PackageEntry struct {
	Package  string          `json:"package"`
	Syscalls []SyscallsEntry `json:"syscalls"`
}

type SyscallsEntry struct {
	Syscall        string   `json:"syscalls"`
	CallPathHashes []string `json:"call_path_hashes"`
}

func NewPolicy() Policy { return make(Policy) }

func (p Policy) Record(event AnalyzedStack) {
	pkg, cap, hash := event.Responsible, event.Syscall, event.CallPathHash
	if p[pkg] == nil {
		p[pkg] = make(map[string]map[string]bool)
	}
	if p[pkg][cap] == nil {
		p[pkg][cap] = make(map[string]bool)
	}
	p[pkg][cap][hash] = true
}

// CheckViolation returns true if the event violates the policy.
// All three of (package, capability, call_path_hash) must match.
func (p Policy) CheckViolation(event AnalyzedStack) bool {
	caps, ok := p[event.Responsible]
	if !ok {
		return true
	}
	hashes, ok := caps[event.Syscall]
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
	for pkgName, caps := range p {
		e := PackageEntry{Package: pkgName}
		for sysName, hashes := range caps {
			ce := SyscallsEntry{Syscall: sysName}
			for h := range hashes {
				ce.CallPathHashes = append(ce.CallPathHashes, h)
			}
			e.Syscalls = append(e.Syscalls, ce)
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
	fmt.Printf("   Packages:    %d\n", len(p))
	fmt.Printf("   Capabilities: %d unique\n", countUniqueCaps(p))
	return nil
}

func (p Policy) PrintSummary() {
	if len(p) == 0 {
		fmt.Println("Attributed policy is empty.")
		return
	}
	fmt.Printf("\n%s\n  POLICY SUMMARY — %d packages\n%s\n",
		strings.Repeat("═", 60), len(p), strings.Repeat("═", 60))
	for pkg, caps := range p {
		fmt.Printf("\n  📦 %s\n", pkg)
		for cap, hashes := range caps {
			fmt.Printf("     %-32s %d path(s)\n", cap, len(hashes))
		}
	}
}

func countUniqueCaps(p Policy) int {
	seen := make(map[string]bool)
	for _, caps := range p {
		for c := range caps {
			seen[c] = true
		}
	}
	return len(seen)
}

// -----------------------------------------------------------------------
// UnattributedPolicy — process-level safety net
// -----------------------------------------------------------------------

// UnattributedPolicy records capabilities seen in syscalls that NodeLeash
// could not attribute to any package (async completion, worker thread pool).
//
// In enforcement: a capability that was NEVER seen unattributed during
// analysis but appears unattributed during enforcement is a violation —
// something is using a new capability through an opaque execution path.
type UnattributedPolicy struct {
	Capabilities map[string]bool `json:"unattributed_capabilities"`
}

func NewUnattributedPolicy() *UnattributedPolicy {
	return &UnattributedPolicy{Capabilities: make(map[string]bool)}
}

func (u *UnattributedPolicy) Record(capability string) {
	if capability != CapUnknown {
		u.Capabilities[capability] = true
	}
}

func (u *UnattributedPolicy) CheckViolation(capability string) bool {
	if capability == CapUnknown {
		return false
	}
	return !u.Capabilities[capability]
}

func (u *UnattributedPolicy) Export(targetPID int, outputDir string) error {
	if len(u.Capabilities) == 0 {
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
	fmt.Printf("   Unattributed capabilities: %d\n", len(u.Capabilities))
	return nil
}

func (u *UnattributedPolicy) PrintSummary() {
	fmt.Printf("\n%s\n  UNATTRIBUTED CAPABILITIES — safety net\n%s\n",
		strings.Repeat("─", 60), strings.Repeat("─", 60))
	if len(u.Capabilities) == 0 {
		fmt.Println("  None — all syscalls were attributed to a package.")
		return
	}
	fmt.Println("  Observed in syscalls whose JS context was not recoverable.")
	fmt.Println("  In enforcement: any NEW capability here = violation.\n")
	for cap := range u.Capabilities {
		fmt.Printf("  • %s\n", cap)
	}
}

// -----------------------------------------------------------------------
// callPathDebugStore — human-readable call paths (--debug only)
// -----------------------------------------------------------------------

type callPathDebugStore map[string]map[string]map[string][]string

func (s callPathDebugStore) RecordDebug(event AnalyzedStack) {
	pkg, cap, hash := event.Responsible, event.Capability, event.CallPathHash
	if s[pkg] == nil {
		s[pkg] = make(map[string]map[string][]string)
	}
	if s[pkg][cap] == nil {
		s[pkg][cap] = make(map[string][]string)
	}
	if _, exists := s[pkg][cap][hash]; !exists {
		s[pkg][cap][hash] = event.CallPath
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
