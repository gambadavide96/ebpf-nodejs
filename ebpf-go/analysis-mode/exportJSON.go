package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// FunctionProfileOutput definisce la struttura del JSON finale a livello di funzione
type FunctionProfileOutput struct {
	Type     string `json:"type"`     // Es: "NPM", "NATIVE_ADDON", "JS_LOCAL"
	Function string `json:"function"` // Il nome della funzione
	Path     string `json:"path"`     // Percorso del file
	// Syscalls non è più un array piatto, ma una mappa 3D: Syscall -> HashPath -> Esiste
	Syscalls map[string]map[string]bool `json:"syscalls"`
}

// PackageProfileOutput definisce la struttura del JSON finale per la policy di pacchetto
type PackageProfileOutput struct {
	Package  string                     `json:"package"`  // Es: "express", "APP_LOCAL"
	Syscalls map[string]map[string]bool `json:"syscalls"` // Syscall -> HashPath -> true
}

// exportJSONSyscalls rimane invariata (genera i file RAW separati per processo)
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
// AGGIORNATO: Ora riceve in input la mappa a 3 dimensioni
func exportJSONFunctions(targetPID int, profile map[FuncInfo]map[string]map[string]bool) {
	var outputData []FunctionProfileOutput

	for funcInfo, syscallsMap := range profile {
		// Ottimizzazione: Assegniamo direttamente la syscallsMap alla struct!
		// Non c'è più bisogno di scorrere e creare array di stringhe.
		outputData = append(outputData, FunctionProfileOutput{
			Type:     funcInfo.Type,
			Function: funcInfo.Name,
			Path:     funcInfo.Path,
			Syscalls: syscallsMap,
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

	fileName := fmt.Sprintf("global_functions_profile_root%d.json", targetPID)
	fullPath := filepath.Join(reportDir, fileName)

	err = os.WriteFile(fullPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Errore salvataggio file %s: %v", fileName, err)
	}

	fmt.Printf("\n📁 Salvato Profilo Comportamentale Globale (GoLeash-Ready) in: %s\n", fullPath)
}

func exportJSONPackages(targetPID int, profile PackageProfile) {
	var outputData []PackageProfileOutput

	for pkgName, syscallsMap := range profile {
		outputData = append(outputData, PackageProfileOutput{
			Package:  pkgName,
			Syscalls: syscallsMap,
		})
	}

	if len(outputData) == 0 {
		fmt.Println("⚠️ Nessun profilo pacchetto elaborato.")
		return
	}

	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		log.Fatalf("Errore durante la generazione del JSON Packages: %v", err)
	}

	reportDir := "packagesProfiling" // Una nuova cartella per tenere le cose ordinate
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Errore durante la creazione della cartella '%s': %v", reportDir, err)
	}

	fileName := fmt.Sprintf("global_packages_policy_root%d.json", targetPID)
	fullPath := filepath.Join(reportDir, fileName)

	err = os.WriteFile(fullPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Errore salvataggio file %s: %v", fileName, err)
	}

	fmt.Printf("\n🛡️ Salvata Policy di Pacchetto (GoLeash-Style) in: %s\n", fullPath)
}
