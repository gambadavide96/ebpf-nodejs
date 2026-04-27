package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Defines the structure of the final JSON at the function level
type FunctionProfileOutput struct {
	Type     string `json:"type"` // Es: "NPM", "NATIVE_ADDON", "JS_LOCAL"
	Function string `json:"function"`
	Path     string `json:"path"`
	// Syscall -> HashPath -> Exists
	Syscalls map[string]map[string]bool `json:"syscalls"`
}

// Defines the structure of the final JSON for the package policy
type PackageProfileOutput struct {
	Package  string                     `json:"package"`  // Es: "express", "APP_LOCAL"
	Syscalls map[string]map[string]bool `json:"syscalls"` // Syscall -> HashPath -> true
}

// Gnerate the report Syscall -> Stack Trace
func exportJSONSyscalls(tracker map[uint32]map[string]map[string][]string) {
	if len(tracker) == 0 {
		fmt.Println("\n⚠️ No data intercepted")
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	reportDir := "report"

	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Error creating folder '%s': %v", reportDir, err)
	}

	// Iterate over the processes (PID) registered by the Kernel
	for pid, pidTracker := range tracker {
		finalExportData := make(map[string][][]string)

		for syscall, uniqueStacks := range pidTracker {
			var allStacksForSyscall [][]string
			for _, stack := range uniqueStacks {
				allStacksForSyscall = append(allStacksForSyscall, stack)
			}

			if len(allStacksForSyscall) > 0 {
				finalExportData[syscall] = allStacksForSyscall
			}
		}

		if len(finalExportData) > 0 {
			filename := fmt.Sprintf("stacks_report_pid%d_%s.json", pid, timestamp)
			fullPath := filepath.Join(reportDir, filename)

			fileData, err := json.MarshalIndent(finalExportData, "", "  ")
			if err != nil {
				log.Printf("⚠️ Error while encoding JSON for PID %d: %v", pid, err)
				continue
			}

			if err := os.WriteFile(fullPath, fileData, 0644); err != nil {
				log.Printf("⚠️ Error writing JSON file for PID %d: %v", pid, err)
				continue
			}

			fmt.Printf("✅ Exported Stacks Report for PID %d in: %s\n", pid, fullPath)
		}
	}
}

// Return a report: Function -> Syscall -> HashPath
func exportJSONFunctions(targetPID int, profile map[FuncInfo]map[string]map[string]bool) {
	var outputData []FunctionProfileOutput

	for funcInfo, syscallsMap := range profile {
		outputData = append(outputData, FunctionProfileOutput{
			Type:     funcInfo.Type,
			Function: funcInfo.Name,
			Path:     funcInfo.Path,
			Syscalls: syscallsMap,
		})
	}

	if len(outputData) == 0 {
		fmt.Println("⚠️ No function profile processed.")
		return
	}

	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		log.Fatalf("Error generating JSON file: %v", err)
	}

	reportDir := "functionsProfiling"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Error creating folder '%s': %v", reportDir, err)
	}

	fileName := fmt.Sprintf("global_functions_profile_root%d.json", targetPID)
	fullPath := filepath.Join(reportDir, fileName)

	err = os.WriteFile(fullPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("File saving error %s: %v", fileName, err)
	}

	fmt.Printf("\n📁 Saved Functions Behavioral Profile in: %s\n", fullPath)
}

// Return a report: Package -> Syscall -> HashPath
func exportJSONPackages(targetPID int, profile PackageProfile) {
	var outputData []PackageProfileOutput

	for pkgName, syscallsMap := range profile {
		outputData = append(outputData, PackageProfileOutput{
			Package:  pkgName,
			Syscalls: syscallsMap,
		})
	}

	if len(outputData) == 0 {
		fmt.Println("⚠️ No package profile processed.")
		return
	}

	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		log.Fatalf("Error generating JSON Packages: %v", err)
	}

	reportDir := "packagesProfiling"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Error creating folder '%s': %v", reportDir, err)
	}

	fileName := fmt.Sprintf("global_packages_policy_root%d.json", targetPID)
	fullPath := filepath.Join(reportDir, fileName)

	err = os.WriteFile(fullPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Error File Saving %s: %v", fileName, err)
	}

	fmt.Printf("\n📁Saved Package Policy in: %s\n", fullPath)
}
