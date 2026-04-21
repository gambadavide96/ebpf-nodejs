package main

import (
	"strings"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// FuncInfo rappresenta un frame dello stack identificato come User-Land
type FuncInfo struct {
	Name string
	Type string
	Path string
}

// Costanti per i tipi di funzioni (evita stringhe magiche hardcoded)
const (
	TypeJSLocal   = "JS_FUNC"
	TypeNPM       = "NPM"
	TypeWASM      = "WASM"
	TypeNativeCPP = "NATIVE_C++"
)

// Liste dichiarative per il filtraggio del rumore
var noisePrefixes = []string{
	"__", "_start", "uv_", "node::", "v8::", "Builtins_",
	"void node", "pthread", "_IO_", "0x", "int node", "std::",
	"cxxabiv1::",
}

var noiseContains = []string{
	"LINUX_2.6", "{virtual override thunk", "\u003c",
}

// libcNoise contiene funzioni standard del C che non sono system call dirette,
// ma che fungono da wrapper di alto livello (e che quindi vogliamo ignorare).
var libcNoise = []string{
	"fseek", "fopen", "fclose", "fread", "fwrite", "fflush",
	"malloc", "calloc", "realloc", "free",
	"printf", "fprintf", "sprintf", "puts",
}

// isNoise verifica se il frame corrisponde a logiche interne da ignorare
func isNoise(raw string) bool {
	for _, prefix := range noisePrefixes {
		if strings.HasPrefix(raw, prefix) {
			return true
		}
	}
	for _, sub := range noiseContains {
		if strings.Contains(raw, sub) {
			return true
		}
	}
	return isLibcWrapper(raw)
}

// isLibcWrapper usa libseccomp per verificare dinamicamente se il nome
// corrisponde a una System Call di Linux.
func isLibcWrapper(name string) bool {
	_, err := seccomp.GetSyscallFromName(name)
	return err == nil
}

// parseV8Frame estrae e classifica le informazioni specifiche di JavaScript/WASM
func parseV8Frame(raw string) (FuncInfo, bool) {
	// Ignoriamo i moduli core di Node (es. node:fs)
	if strings.Contains(raw, " node:") {
		return FuncInfo{}, false
	}

	// Pulizia prefissi V8 (~, ^, *)
	cleanString := strings.TrimLeft(strings.TrimPrefix(raw, "JS:"), "~^*")
	parts := strings.SplitN(cleanString, " ", 2)

	funcName := parts[0]
	// Filtro radicale: scartiamo subito le funzioni anonime o vuote
	if funcName == "" {
		return FuncInfo{}, false
	}

	path := "unknown"
	if len(parts) > 1 {
		path = parts[1] // Es: /app/index.js:10:5
	}

	// Identificazione WASM
	if strings.Contains(funcName, "-liftoff") || strings.Contains(funcName, "-turbofan") {
		cleanWasmName := strings.Split(funcName, "-")[0]
		return FuncInfo{Name: cleanWasmName, Type: TypeWASM, Path: "wasm-memory"}, true
	}

	// Identificazione modulo NPM vs JS Locale
	if strings.Contains(path, "node_modules") {
		return FuncInfo{Name: funcName, Type: TypeNPM, Path: path}, true
	}

	return FuncInfo{Name: funcName, Type: TypeJSLocal, Path: path}, true
}

// classifyFrame analizza una singola riga dello stack trace per capire
// se appartiene all'utente e a quale tecnologia corrisponde.
func classifyFrame(raw string) (FuncInfo, bool) {
	// 1. FILTRO RUMORE AVANZATO
	if isNoise(raw) {
		return FuncInfo{}, false
	}

	// 2. ANALISI CODICE V8 (JS e Wasm)
	if strings.HasPrefix(raw, "JS:") {
		return parseV8Frame(raw)
	}

	// 3. ADDON NATIVI (C/C++)
	return FuncInfo{Name: raw, Type: TypeNativeCPP, Path: "native-binary"}, true
}

// BuildFunctionProfile prende in input tutti gli stack tracciati da eBPF
// e restituisce la mappa pulita: Funzione -> Syscalls
func BuildFunctionProfile(syscallStacksTracker map[string]map[string][]string) map[FuncInfo]map[string]bool {
	// Manteniamo la struttura dati richiesta per compatibilità con l'esportazione JSON
	functionProfile := make(map[FuncInfo]map[string]bool)

	for syscallName, fingerprints := range syscallStacksTracker {
		for _, stackFrames := range fingerprints {
			for _, frame := range stackFrames {

				// Sfruttiamo l'inizializzazione inline dell'if tipica di Go
				if info, isUserLand := classifyFrame(frame); isUserLand {

					if functionProfile[info] == nil {
						functionProfile[info] = make(map[string]bool)
					}

					functionProfile[info][syscallName] = true
				}
			}
		}
	}

	return functionProfile
}
