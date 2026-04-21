package main

import (
	"strings"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// FuncInfo rappresenta un frame dello stack identificato come User-Land
type FuncInfo struct {
	Name string
	Type string // "JS_LOCAL", "NPM", "WASM", "NATIVE_C++"
	Path string
}

// isLibcWrapper usa libseccomp per verificare dinamicamente se il nome
// corrisponde a una System Call di Linux (es. read, write, mmap).
func isLibcWrapper(name string) bool {
	// Se libseccomp riconosce il nome, è una syscall (quindi scartiamo il frame)
	_, err := seccomp.GetSyscallFromName(name)
	return err == nil
}

// classifyFrame analizza una singola riga dello stack trace per capire
// se appartiene all'utente e a quale tecnologia corrisponde.
func classifyFrame(raw string) (funcInfo FuncInfo, isUserLand bool) {
	// 1. FILTRO RUMORE AVANZATO
	if strings.HasPrefix(raw, "__") ||
		strings.HasPrefix(raw, "_start") ||
		strings.HasPrefix(raw, "uv_") ||
		strings.HasPrefix(raw, "node::") ||
		strings.HasPrefix(raw, "v8::") ||
		strings.HasPrefix(raw, "Builtins_") ||
		strings.HasPrefix(raw, "void node") ||
		strings.HasPrefix(raw, "pthread") ||
		strings.HasPrefix(raw, "_IO_") ||
		strings.HasPrefix(raw, "0x") || // Indirizzi di memoria non risolti
		strings.HasPrefix(raw, "int node") || // Firme C++ demangled con tipo di ritorno
		strings.Contains(raw, "LINUX_2.6") || // Stub VDSO del kernel legacy
		strings.Contains(raw, "{virtual override thunk") ||
		strings.Contains(raw, "\u003c") ||
		isLibcWrapper(raw) { // Funzioni dirette libc (read, ioctl...)
		return FuncInfo{}, false
	}

	// 2. ANALISI CODICE V8 (JS e Wasm)
	if strings.HasPrefix(raw, "JS:") {
		if strings.Contains(raw, " node:") {
			return FuncInfo{}, false
		}

		// Pulizia prefissi V8
		cleanString := strings.TrimLeft(strings.TrimPrefix(raw, "JS:"), "~^*")

		// Dividiamo tra nome funzione e percorso (separati dal primo spazio)
		parts := strings.SplitN(cleanString, " ", 2)
		funcName := parts[0]
		if funcName == "" {
			funcName = "<anonymous>"
		}

		path := "unknown"
		if len(parts) > 1 {
			path = parts[1] // Qui abbiamo il path ES: /app/index.js:10:5
		}

		// Identificazione tipo
		if strings.Contains(funcName, "-liftoff") || strings.Contains(funcName, "-turbofan") {
			cleanWasmName := strings.Split(funcName, "-")[0]
			return FuncInfo{Name: cleanWasmName, Type: "WASM", Path: "wasm-memory"}, true
		}

		if strings.Contains(path, "node_modules") {
			return FuncInfo{Name: funcName, Type: "NPM", Path: path}, true
		}

		return FuncInfo{Name: funcName, Type: "JS_LOCAL", Path: path}, true
	}

	// 3. ADDON NATIVI
	// Per i moduli C++, la location spesso non è presente nella stringa grezza
	// a meno che non sia stata risolta esplicitamente come file .so
	return FuncInfo{Name: raw, Type: "NATIVE_C++", Path: "native-binary"}, true
}

// BuildFunctionProfile prende in input tutti gli stack tracciati da eBPF
// e restituisce la mappa pulita: Funzione -> Syscalls
func BuildFunctionProfile(syscallStacksTracker map[string]map[string][]string) map[FuncInfo]map[string]bool {
	functionProfile := make(map[FuncInfo]map[string]bool)

	// Iteriamo su tutta la mole di dati raccolta
	for syscallName, fingerprints := range syscallStacksTracker {
		for _, stackFrames := range fingerprints {
			// Analizziamo lo stack dall'alto verso il basso
			for _, frame := range stackFrames {
				info, isUserLand := classifyFrame(frame)

				if isUserLand {
					// Inizializza il Set se non esiste
					if functionProfile[info] == nil {
						functionProfile[info] = make(map[string]bool)
					}
					// Associa la syscall a questa funzione
					functionProfile[info][syscallName] = true
				}
			}
		}
	}

	return functionProfile
}
