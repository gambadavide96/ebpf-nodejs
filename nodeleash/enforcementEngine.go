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
	Time     time.Time
	Pid      uint32
	Syscall  string
	Package  string   // "[unattributed]" when the event had no attribution
	CallPath []string // empty for unattributed violations
}

func (v Violation) String() string {
	path := strings.Join(v.CallPath, " → ")
	if path == "" {
		path = "<unattributed>"
	}
	return fmt.Sprintf(
		"[%s] 🚨 VIOLATION  pid=%-6d  syscall=%-28s  pkg=%s  path=%s",
		v.Time.Format("15:04:05.000000"),
		v.Pid, v.Syscall, v.Package, path,
	)
}

// EnforcementEngine holds the loaded policy and logs violations to terminal.
type EnforcementEngine struct {
	policy             Policy
	unattributedPolicy *UnattributedPolicy
	violations         []Violation
}

// LoadEnforcementEngine reads the two policy JSON files produced by analysis
// mode and constructs an engine ready for enforcement.
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
	fmt.Printf("📋 Unattributed syscalls: %d\n", len(u.Syscalls))

	return &EnforcementEngine{
		policy:             p,
		unattributedPolicy: u,
	}, nil
}

// Check evaluates a single eBPF event against the loaded policy.
func (e *EnforcementEngine) Check(event AnalyzedStack, pid uint32, syscallName string) {
	if event.Responsible != "" {
		// Primary check: attributed event.
		if e.policy.CheckViolation(event) {
			e.logViolation(Violation{
				Time:     time.Now(),
				Pid:      pid,
				Syscall:  syscallName,
				Package:  event.Responsible,
				CallPath: event.CallPath,
			})
		}
		return
	}

	// Safety net check: unattributed event.
	if event.Syscall != "" && e.unattributedPolicy.CheckViolation(event.Syscall) {
		e.logViolation(Violation{
			Time:    time.Now(),
			Pid:     pid,
			Syscall: syscallName,
			Package: "[unattributed]",
		})
	}
}

func (e *EnforcementEngine) logViolation(v Violation) {
	fmt.Println(v.String())
	e.violations = append(e.violations, v)
}

// PrintViolationSummary prints a grouped summary of all violations.
func (e *EnforcementEngine) PrintViolationSummary() {
	fmt.Printf("\n%s\n  ENFORCEMENT SUMMARY\n%s\n",
		strings.Repeat("═", 60), strings.Repeat("═", 60))

	if len(e.violations) == 0 {
		fmt.Println("  ✅ No violations detected.")
		return
	}

	fmt.Printf("  🚨 %d violation(s) detected\n\n", len(e.violations))

	// Group by package for readability.
	byPkg := make(map[string]map[string]int) // pkg → syscall → count
	for _, v := range e.violations {
		if byPkg[v.Package] == nil {
			byPkg[v.Package] = make(map[string]int)
		}
		byPkg[v.Package][v.Syscall]++
	}

	for pkg, syscalls := range byPkg {
		fmt.Printf("  📦 %s\n", pkg)
		for sys, count := range syscalls {
			fmt.Printf("     %-32s ×%d\n", sys, count)
		}
	}
}

// -----------------------------------------------------------------------
// JSON deserialization
// -----------------------------------------------------------------------

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
		for _, se := range entry.Syscalls {
			if p[entry.Package] == nil {
				p[entry.Package] = make(map[string]map[string]bool)
			}
			if p[entry.Package][se.Syscall] == nil {
				p[entry.Package][se.Syscall] = make(map[string]bool)
			}
			for _, h := range se.CallPathHashes {
				p[entry.Package][se.Syscall][h] = true
			}
		}
	}
	return p, nil
}

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
