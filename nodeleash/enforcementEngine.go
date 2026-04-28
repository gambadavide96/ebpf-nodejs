package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Violation represents a single detected policy breach.
type Violation struct {
	Time        time.Time
	Pid         uint32
	Syscall     string
	Capability  string
	Package     string   // "[unattributed]" when the event had no attribution
	CallPath    []string // empty for unattributed violations
	FromFdOwner bool
}

func (v Violation) String() string {
	path := strings.Join(v.CallPath, " → ")
	if path == "" {
		path = "<unattributed>"
	}
	fdOwnerTag := ""
	if v.FromFdOwner {
		fdOwnerTag = " [fd_owner]"
	}
	return fmt.Sprintf(
		"[%s] 🚨 VIOLATION  pid=%-6d  cap=%-28s  pkg=%s%s  path=%s",
		v.Time.Format("15:04:05.000000"),
		v.Pid, v.Capability, v.Package, fdOwnerTag, path,
	)
}

// EnforcementEngine holds the loaded policy and logs violations to terminal.
//
// In this implementation the enforcement action is always logging: when a
// violation is detected the engine prints a warning to stdout and records it
// internally for the end-of-session summary. The application is not terminated.
// This is the safest deployment model for an initial enforcement run and
// mirrors the "forensics" mode described in GoLeash Section 4.7.
type EnforcementEngine struct {
	policy             Policy
	unattributedPolicy *UnattributedPolicy
	violations         []Violation
}

// LoadEnforcementEngine reads the two policy JSON files produced by analysis
// mode and constructs an engine ready for enforcement.
//
// policyPath:       nodeleash_policy_pid<N>_<ts>.json
// unattributedPath: nodeleash_unattributed_pid<N>_<ts>.json
func LoadEnforcementEngine(policyPath, unattributedPath string) (*EnforcementEngine, error) {
	p, err := loadPolicy(policyPath)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	u, err := loadUnattributedPolicy(unattributedPath)
	if err != nil {
		return nil, fmt.Errorf("loading unattributed policy: %w", err)
	}

	fmt.Printf("📋 Policy loaded: %d packages\n", len(p))
	fmt.Printf("📋 Unattributed capabilities: %d\n", len(u.Capabilities))

	return &EnforcementEngine{
		policy:             p,
		unattributedPolicy: u,
	}, nil
}

// Check evaluates a single eBPF event against the loaded policy.
//
// Two checks run in parallel:
//
//  1. Attributed check (per-package policy):
//     If the event was attributed to a specific package, verify that
//     (package, capability, call_path_hash) all appear in the approved policy.
//     This is the primary enforcement layer — equivalent to GoLeash's model.
//
//  2. Unattributed check (safety net):
//     If attribution failed (async path, worker thread pool), verify that
//     this capability was seen unattributed during analysis. A capability
//     that was never part of the legitimate "async noise floor" but suddenly
//     appears unattributed in enforcement is a strong anomaly signal.
func (e *EnforcementEngine) Check(event AnalyzedStack, pid uint32, syscallName string) {
	if event.Responsible != "" {
		// Primary check: attributed event.
		if e.policy.CheckViolation(event) {
			e.logViolation(Violation{
				Time:        time.Now(),
				Pid:         pid,
				Syscall:     syscallName,
				Capability:  event.Capability,
				Package:     event.Responsible,
				CallPath:    event.CallPath,
				FromFdOwner: event.FromFdOwner,
			})
		}
		return
	}

	// Safety net check: unattributed event.
	if event.Capability != "" && e.unattributedPolicy.CheckViolation(event.Capability) {
		e.logViolation(Violation{
			Time:       time.Now(),
			Pid:        pid,
			Syscall:    syscallName,
			Capability: event.Capability,
			Package:    "[unattributed]",
		})
	}
}

// logViolation prints the violation to stdout and appends it to the internal
// list for the end-of-session summary.
func (e *EnforcementEngine) logViolation(v Violation) {
	fmt.Println(v.String())
	e.violations = append(e.violations, v)
}

// PrintViolationSummary prints a grouped summary of all violations detected
// during the enforcement session. Called at shutdown.
func (e *EnforcementEngine) PrintViolationSummary() {
	fmt.Printf("\n%s\n  ENFORCEMENT SUMMARY\n%s\n",
		strings.Repeat("═", 60), strings.Repeat("═", 60))

	if len(e.violations) == 0 {
		fmt.Println("  ✅ No violations detected.")
		return
	}

	fmt.Printf("  🚨 %d violation(s) detected\n\n", len(e.violations))

	// Group by package for readability.
	byPkg := make(map[string]map[string]int) // pkg → cap → count
	for _, v := range e.violations {
		if byPkg[v.Package] == nil {
			byPkg[v.Package] = make(map[string]int)
		}
		byPkg[v.Package][v.Capability]++
	}

	for pkg, caps := range byPkg {
		fmt.Printf("  📦 %s\n", pkg)
		for cap, count := range caps {
			fmt.Printf("     %-32s ×%d\n", cap, count)
		}
	}
}

// -----------------------------------------------------------------------
// JSON deserialization
// -----------------------------------------------------------------------

// loadPolicy reads the JSON written by Policy.Export() and reconstructs
// the in-memory Policy map.
func loadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var entries []PackageEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing policy JSON: %w", err)
	}
	p := NewPolicy()
	for _, entry := range entries {
		for _, ce := range entry.Capabilities {
			if p[entry.Package] == nil {
				p[entry.Package] = make(map[string]map[string]bool)
			}
			if p[entry.Package][ce.Capability] == nil {
				p[entry.Package][ce.Capability] = make(map[string]bool)
			}
			for _, h := range ce.CallPathHashes {
				p[entry.Package][ce.Capability][h] = true
			}
		}
	}
	return p, nil
}

// loadUnattributedPolicy reads the JSON written by UnattributedPolicy.Export().
func loadUnattributedPolicy(path string) (*UnattributedPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	u := NewUnattributedPolicy()
	if err := json.Unmarshal(data, u); err != nil {
		return nil, fmt.Errorf("parsing unattributed policy JSON: %w", err)
	}
	return u, nil
}
