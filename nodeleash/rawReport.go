package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func recordRawStack(tracker map[string]map[string][]string, syscallName string, frames []ResolvedFrame) {
	if tracker[syscallName] == nil {
		tracker[syscallName] = make(map[string][]string)
	}
	names := framesToStrings(frames)
	hash := hashRawFrames(names)
	if _, exists := tracker[syscallName][hash]; !exists {
		tracker[syscallName][hash] = names
	}
}

func framesToStrings(frames []ResolvedFrame) []string {
	out := make([]string, len(frames))
	for i, f := range frames {
		out[i] = f.Display()
	}
	return out
}

func hashRawFrames(frames []string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join(frames, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

func printRawReport(tracker map[string]map[string][]string) {
	if len(tracker) == 0 {
		fmt.Println("\n⚠️  No raw stacks collected.")
		return
	}

	syscalls := make([]string, 0, len(tracker))
	for sc := range tracker {
		syscalls = append(syscalls, sc)
	}
	sort.Strings(syscalls)

	fmt.Printf("\n%s\n  RAW REPORT — Syscall → Stack Traces (%d syscalls)\n%s\n",
		strings.Repeat("═", 60), len(tracker), strings.Repeat("═", 60))

	for _, sc := range syscalls {
		stacks := tracker[sc]
		fmt.Printf("\n🔹 %-20s (%d unique stack(s))\n", sc, len(stacks))
		i := 1
		for _, frames := range stacks {
			fmt.Printf("   Stack #%d:\n", i)
			for j, f := range frames {
				fmt.Printf("      [%2d] %s\n", j, f)
			}
			i++
		}
	}
	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
}

func exportRawReport(targetPID int, tracker map[string]map[string][]string) {
	if len(tracker) == 0 {
		return
	}
	flat := make(map[string][][]string, len(tracker))
	for sc, stacks := range tracker {
		for _, frames := range stacks {
			flat[sc] = append(flat[sc], frames)
		}
	}
	data, err := json.MarshalIndent(flat, "", "  ")
	if err != nil {
		log.Printf("⚠️  raw report encode error: %v", err)
		return
	}
	reportDir := "report"
	if err := os.MkdirAll(reportDir, 0777); err != nil {
		log.Printf("⚠️  mkdir error: %v", err)
		return
	}
	ts := time.Now().Format("20060102_150405")
	path := filepath.Join(reportDir,
		fmt.Sprintf("raw_stacks_pid%d_%s.json", targetPID, ts))
	if err := os.WriteFile(path, data, 0666); err != nil {
		log.Printf("⚠️  raw report write error: %v", err)
		return
	}
	fmt.Printf("✅ Raw stacks report saved to: %s\n", path)
}
