package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// FunctionProfileOutput definisce la struttura del JSON finale per il profiling globale
type FunctionProfileOutput struct {
	Type     string   `json:"type"`     // Es: "NPM", "NODE_INTERNAL", "JS_LOCAL"
	Function string   `json:"function"` // Il nome della funzione
	Path     string   `json:"path"`     // Percorso del file
	Syscalls []string `json:"syscalls"` // La lista aggregata delle syscall invocate
}

// exportJSONSyscalls genera UN FILE SEPARATO per ogni processo (PID) intercettato.
// In questo modo manteniamo la tracciabilità esatta (es. Node vs Bash vs Curl).
func exportJSONSyscalls(tracker map[uint32]map[string]map[string][]string) {
	if len(tracker) == 0 {
		fmt.Println("\n⚠️ Nessun dato intercettato, file JSON RAW non creati.")
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	reportDir := "report"

	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Errore durante la creazione della cartella '%s': %v", reportDir, err)
	}

	// Iteriamo sui processi (PID) registrati dal Kernel
	for pid, pidTracker := range tracker {
		// Struttura finale per il singolo PID: map[SyscallName]ArrayDiStack
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

		// Se questo processo ha fatto chiamate valide, generiamo il suo file
		if len(finalExportData) > 0 {
			filename := fmt.Sprintf("stacks_report_pid%d_%s.json", pid, timestamp)
			fullPath := filepath.Join(reportDir, filename)

			fileData, err := json.MarshalIndent(finalExportData, "", "  ")
			if err != nil {
				log.Printf("⚠️ Errore durante la codifica JSON per il PID %d: %v", pid, err)
				continue
			}

			if err := os.WriteFile(fullPath, fileData, 0644); err != nil {
				log.Printf("⚠️ Errore durante la scrittura del file JSON per il PID %d: %v", pid, err)
				continue
			}

			fmt.Printf("✅ Report Stacks RAW esportato per PID %d in: %s\n", pid, fullPath)
		}
	}
}

// exportJSONFunctions trasforma il profilo comportamentale in un JSON leggibile e aggregato
func exportJSONFunctions(targetPID int, profile map[FuncInfo]map[string]bool) {
	var outputData []FunctionProfileOutput

	for funcInfo, syscallsMap := range profile {
		var syscallList []string

		// Trasforma il set (mappa booleana) in un array di stringhe
		for sysName := range syscallsMap {
			syscallList = append(syscallList, sysName)
		}

		outputData = append(outputData, FunctionProfileOutput{
			Type:     funcInfo.Type,
			Function: funcInfo.Name,
			Path:     funcInfo.Path,
			Syscalls: syscallList,
		})
	}

	if len(outputData) == 0 {
		fmt.Println("⚠️ Nessun profilo funzione elaborato.")
		return
	}

	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		log.Fatalf("Errore durante la generazione del JSON Functions: %v", err)
	}

	reportDir := "functionsProfiling"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Errore durante la creazione della cartella '%s': %v", reportDir, err)
	}

	// Creiamo un nome file che indichi la natura globale (Root PID)
	fileName := fmt.Sprintf("global_functions_profile_root%d.json", targetPID)
	fullPath := filepath.Join(reportDir, fileName)

	err = os.WriteFile(fullPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Errore salvataggio file %s: %v", fileName, err)
	}

	fmt.Printf("\n📁 Salvato Profilo Comportamentale Globale in: %s\n", fullPath)
}
