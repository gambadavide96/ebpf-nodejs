package main

import (
	"strings"
)

// PackageProfile rappresenta la policy aggregata a livello di pacchetto (Stile GoLeash)
// Struttura: map[NomePacchetto]map[Syscall]map[CallPathHash]bool
type PackageProfile map[string]map[string]map[string]bool

// extractPackageName è la funzione euristica che estrae il nome del pacchetto NPM
// o assegna una categoria semantica in base al percorso del file.
func extractPackageName(info FuncInfo) string {
	// 1. Moduli Nativi C/C++
	if info.Type == TypeNativeCPP {
		return "NATIVE_ADDON"
	}

	// 2. Moduli WASM
	if info.Type == TypeWASM {
		return "WASM_MODULE"
	}

	// 3. Moduli Esterni (NPM / node_modules)
	if info.Type == TypeNPM {
		// Esempio di info.Path: "/percorso/app/node_modules/express/lib/router/index.js:42:15"
		// Vogliamo estrarre solo "express"
		parts := strings.Split(info.Path, "node_modules/")
		if len(parts) > 1 {
			// Prendi tutto ciò che c'è dopo "node_modules/"
			subPath := parts[1]
			// Dividi per la barra (/) per isolare il nome della cartella del pacchetto
			pkgParts := strings.SplitN(subPath, "/", 2)
			if len(pkgParts) > 0 {
				pkgName := pkgParts[0]

				// Gestione degli scoped packages di NPM (es. "@types/node")
				if strings.HasPrefix(pkgName, "@") && len(pkgParts) > 1 {
					// Ricostruisce lo scope: "@types" + "/" + "node"
					scopedParts := strings.SplitN(pkgParts[1], "/", 2)
					if len(scopedParts) > 0 {
						return pkgName + "/" + scopedParts[0]
					}
				}
				return pkgName
			}
		}
		return "UNKNOWN_NPM_MODULE" // Fallback di sicurezza
	}

	// 4. Codice Applicativo Locale (JS scritto dallo sviluppatore)
	// Se il path non contiene node_modules, assumiamo sia codice sorgente diretto
	if info.Type == TypeJSLocal {
		return "APP_LOCAL"
	}

	return "UNKNOWN_PACKAGE"
}

// BuildPackageProfile aggrega il profilo delle funzioni in un profilo di pacchetto,
// mantenendo però l'hash dei Call Path per garantire la protezione "Confused Deputy".
func BuildPackageProfile(funcProfile map[FuncInfo]map[string]map[string]bool) PackageProfile {

	pkgProfile := make(PackageProfile)

	// Itera sull'output estremamente granulare di BuildFunctionProfile
	for funcInfo, syscallsMap := range funcProfile {

		// 1. Determina il Pacchetto di appartenenza della funzione
		packageName := extractPackageName(funcInfo)

		// Inizializza la mappa per il pacchetto se è la prima volta che lo incontriamo
		if pkgProfile[packageName] == nil {
			pkgProfile[packageName] = make(map[string]map[string]bool)
		}

		// 2. Fai il "merge" (unione) delle syscall e dei relativi hash
		for syscallName, hashesMap := range syscallsMap {

			// Inizializza la mappa per la syscall se necessario
			if pkgProfile[packageName][syscallName] == nil {
				pkgProfile[packageName][syscallName] = make(map[string]bool)
			}

			// Aggiungi tutti gli hash dei Call Path validi per questa combinazione
			for hash := range hashesMap {
				pkgProfile[packageName][syscallName][hash] = true
			}
		}
	}

	return pkgProfile
}
