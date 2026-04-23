package main

import (
	"strings"
)

// Represents the aggregated package-level policy
// Structure: map[namePackage]map[SyscallName]map[StackHash]bool
type PackageProfile map[string]map[string]map[string]bool

//	Extracts the NPM package name or assigns a
//
// semantic category based on the file path.
func extractPackageName(info FuncInfo) string {

	// 1. Native Modules
	if info.Type == TypeNativeCPP {
		return "NATIVE_ADDON"
	}

	// 2. Wasm Module
	if info.Type == TypeWASM {
		return "WASM_MODULE"
	}

	// 3. External modules (NPM / node_modules)
	if info.Type == TypeNPM {
		// Example: "/node_modules/express/lib/router/index.js:42:15"
		// We want extract only router

		parts := strings.Split(info.Path, "node_modules/")
		if len(parts) > 1 {
			// Take everything after "node_modules/"
			subPath := parts[1]
			// Divide by slash (/) to isolate the package folder name
			// The first slice is package name
			pkgParts := strings.SplitN(subPath, "/", 2)
			if len(pkgParts) > 0 {
				pkgName := pkgParts[0]

				// Managing NPM scoped packages (es. "@nestjs/core")
				if strings.HasPrefix(pkgName, "@") && len(pkgParts) > 1 {
					// Rebuilds the scope: "@nestjs" + "/" + "core"
					scopedParts := strings.SplitN(pkgParts[1], "/", 2)
					if len(scopedParts) > 0 {
						return pkgName + "/" + scopedParts[0]
					}
				}
				return pkgName
			}
		}
		return "UNKNOWN_NPM_MODULE"
	}

	// 4. Local JS Code
	if info.Type == TypeJSLocal {
		return "LOCAL"
	}

	return "UNKNOWN_PACKAGE"
}

// Aggregates the function profile into a package profile,
// preserving the call path hash.
func BuildPackageProfile(funcProfile map[FuncInfo]map[string]map[string]bool) PackageProfile {

	pkgProfile := make(PackageProfile)

	// Iterate on function information
	for funcInfo, syscallsMap := range funcProfile {

		// 1. Determina il Pacchetto di appartenenza della funzione
		packageName := extractPackageName(funcInfo)

		// Initialize the map for the package if this is the first time we encounter it
		if pkgProfile[packageName] == nil {
			pkgProfile[packageName] = make(map[string]map[string]bool)
		}

		// 2. Merging syscall and relative hashes
		for syscallName, hashesMap := range syscallsMap {

			// Initialize map for syscall if is needed
			if pkgProfile[packageName][syscallName] == nil {
				pkgProfile[packageName][syscallName] = make(map[string]bool)
			}

			// Add all stack hashes for this combination
			for hash := range hashesMap {
				pkgProfile[packageName][syscallName][hash] = true
			}
		}
	}

	return pkgProfile
}
