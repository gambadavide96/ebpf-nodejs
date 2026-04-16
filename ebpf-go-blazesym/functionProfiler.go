package main

import "strings"

// FuncInfo rappresenta un frame dello stack identificato come User-Land
type FuncInfo struct {
	Name string
	Type string // "JS_LOCAL", "NPM", "WASM", "NATIVE_C++"
}

// classifyFrame analizza una singola riga dello stack trace per capire
// se appartiene all'utente e a quale tecnologia corrisponde.
func classifyFrame(raw string) (funcInfo FuncInfo, isUserLand bool) {
	// 1. FILTRO RUMORE (Escludiamo Kernel, Libuv, V8 e Node C++ Core)
	if strings.HasPrefix(raw, "__") || strings.HasPrefix(raw, "uv_") ||
		strings.HasPrefix(raw, "node::") || strings.HasPrefix(raw, "v8::") ||
		strings.HasPrefix(raw, "Builtins_") || strings.Contains(raw, "{virtual override thunk") {
		return FuncInfo{}, false
	}

	// 2. ANALISI CODICE GESTITO DA V8 (JS e Wasm)
	if strings.HasPrefix(raw, "JS:") {
		if strings.Contains(raw, " node:") {
			return FuncInfo{}, false
		}

		cleanString := strings.TrimLeft(strings.TrimPrefix(raw, "JS:"), "~^*")
		parts := strings.SplitN(cleanString, " ", 2)
		funcName := parts[0]
		if funcName == "" {
			funcName = "<anonymous>"
		}

		if strings.Contains(funcName, "-liftoff") || strings.Contains(funcName, "-turbofan") {
			cleanWasmName := strings.Split(funcName, "-")[0]
			return FuncInfo{Name: cleanWasmName, Type: "WASM"}, true
		}

		if len(parts) > 1 && strings.Contains(parts[1], "node_modules") {
			return FuncInfo{Name: funcName, Type: "NPM"}, true
		}

		return FuncInfo{Name: funcName, Type: "JS_LOCAL"}, true
	}

	// 3. ANALISI ADDON NATIVI C++ (.node)
	return FuncInfo{Name: raw, Type: "NATIVE_C++"}, true
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

					// Interrompiamo il ciclo per questo stack
					break
				}
			}
		}
	}

	return functionProfile
}
