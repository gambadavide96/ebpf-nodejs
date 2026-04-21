package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Struttura che definisce come apparirà ogni blocco nel JSON finale
type FunctionProfileOutput struct {
	Type     string   `json:"type"`     // Es: "NPM", "WASM", "JS_LOCAL"
	Function string   `json:"function"` // Il nome della funzione
	Path     string   `json:"path"`     // Percorso
	Syscalls []string `json:"syscalls"` // La lista delle syscall invocate
}

// Funzione helper per preparare la struttura syscall -> stack trace ed esportare il file JSON
func exportJSONSyscalls(pid int, tracker map[string]map[string][]string) {
	// Struttura finale per il JSON: map[SyscallName]ArrayDiStack(ArrayDiStringhe)
	finalExportData := make(map[string][][]string)

	for syscall, uniqueStacks := range tracker {
		var allStacksForSyscall [][]string
		for _, stack := range uniqueStacks {
			allStacksForSyscall = append(allStacksForSyscall, stack)
		}

		if len(allStacksForSyscall) > 0 {
			finalExportData[syscall] = allStacksForSyscall
		}
	}

	if len(finalExportData) == 0 {
		fmt.Println("\n⚠️ Nessun dato intercettato, file JSON non creato.")
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("stacks_report_pid%d_%s.json", pid, timestamp)

	// MarshalIndent crea un JSON leggibile (pretty print)
	fileData, err := json.MarshalIndent(finalExportData, "", "  ")
	if err != nil {
		log.Fatalf("Errore durante la codifica del JSON: %v", err)
	}

	reportDir := "report"

	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Errore durante la creazione della cartella '%s': %v", reportDir, err)
	}

	fullPath := filepath.Join(reportDir, filename)

	if err := os.WriteFile(fullPath, fileData, 0644); err != nil {
		log.Fatalf("Errore durante la scrittura del file JSON: %v", err)
	}

	fmt.Printf("\n✅ Report completo esportato con successo in: %s\n", fullPath)
}

// exportJSONFunctions trasforma la mappa interna in un JSON leggibile e lo salva su disco
func exportJSONFunctions(pid int, profile map[FuncInfo]map[string]bool) {
	var outputData []FunctionProfileOutput

	// Convertiamo la Mappa complessa in un Array di strutture
	for funcInfo, syscallsMap := range profile {
		var syscallList []string

		// Estraiamo le chiavi dal "Set" (i nomi delle syscall)
		for sysName := range syscallsMap {
			syscallList = append(syscallList, sysName)
		}

		// Creiamo l'oggetto finale per questa funzione
		outputData = append(outputData, FunctionProfileOutput{
			Type:     funcInfo.Type,
			Function: funcInfo.Name,
			Path:     funcInfo.Path,
			Syscalls: syscallList,
		})
	}

	// Trasformiamo l'array in JSON formattato con indentazione (Pretty Print)
	jsonData, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		log.Fatalf("Errore durante la generazione del JSON Functions: %v", err)
	}

	reportDir := "functionsProfiling"

	if err := os.MkdirAll(reportDir, 0755); err != nil {
		log.Fatalf("Errore durante la creazione della cartella '%s': %v", reportDir, err)
	}

	// Creiamo il nome del file
	fileName := fmt.Sprintf("functions_profile_%d.json", pid)
	fullPath := filepath.Join(reportDir, fileName)

	// Scriviamo su disco
	err = os.WriteFile(fullPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Errore salvataggio file %s: %v", fileName, err)
	}

	fmt.Printf("📁 Salvato Profilo Comportamentale: %s\n", fileName)
}
