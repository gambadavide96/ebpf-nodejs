package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ianlancetaylor/demangle"
)

/*
Per tradurre un indirizzo C++, Symbolizer deve capire a quale file appartiene (es. /usr/lib/libc.so.6), aprirlo dal disco fisso,
decodificare il suo formato binario (che su Linux si chiama ELF - Executable and Linkable Format)
e cercare nella sua tabella dei simboli.
*/

// MemoryRegion rappresenta una riga di /proc/<PID>/maps
//Per risolvere i simboli del codice nativo (binario node e librerie di sistema)

// ES: 7f8a9b000000-7f8a9b200000 r-xp 00000000 08:01 123456 /usr/lib/libc.so.6
type MemoryRegion struct {
	Start  uint64
	End    uint64
	Offset uint64
	Path   string
}

// JITSymbol rappresenta una funzione JavaScript presa da /tmp/perf-<PID>.map

// ES: 3fbd8a1000 250 LazyCompile:*app.get /var/www/app.js
type JITSymbol struct {
	Start uint64
	End   uint64
	Name  string
}

type Symbolizer struct {
	pid        int                  //Per costruire i percorsi dei file da leggere (es. /proc/1234/maps e /tmp/perf-1234.map).
	regions    []MemoryRegion       //Contiene le mappe delle librerie C/C++
	jitSymbols []JITSymbol          //Contiene le funzioni javascript JIT
	elfCache   map[string]*elf.File //Salva nella mappa i file ELF aperti per accesso veloce (come una cache)
	symCache   map[uint64]string    // MODIFICARE:Cache per non ricalcolare IP solo per funzioni C/C++ (Oppure togliere)
}

// Costruttore dell'oggetto symbolizer, restituisce un puntatore allla struct
func NewSymbolizer(pid int) *Symbolizer {
	sym := &Symbolizer{
		pid:      pid,
		elfCache: make(map[string]*elf.File), //con make alloca lo spazio per le due mappe
		symCache: make(map[uint64]string),
	}
	sym.loadProcMaps() //chiamo i due metodi per riempire gli array delle funzioni C/C++ e JS
	sym.loadPerfMap()
	return sym
}

// 1. Carica la mappa della memoria di Linux
func (s *Symbolizer) loadProcMaps() {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", s.pid))
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue // Ignoriamo le regioni di memoria anonime senza percorso
		}

		addrs := strings.Split(fields[0], "-")
		start, _ := strconv.ParseUint(addrs[0], 16, 64)
		end, _ := strconv.ParseUint(addrs[1], 16, 64)
		offset, _ := strconv.ParseUint(fields[2], 16, 64)

		s.regions = append(s.regions, MemoryRegion{
			Start: start, End: end, Offset: offset, Path: fields[5],
		})
	}
}

// 2. Carica la mappa delle funzioni JIT di Node.js (JavaScript)
func (s *Symbolizer) loadPerfMap() {

	// Per svuotare la lista prima di aggiornarla
	s.jitSymbols = nil

	file, err := os.Open(fmt.Sprintf("/tmp/perf-%d.map", s.pid))
	if err != nil {
		return // Node non è stato avviato con --perf-basic-prof
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Formato: <indirizzo_esadecimale> <dimensione_esadecimale> <NomeFunzione>
		parts := strings.SplitN(scanner.Text(), " ", 3)
		if len(parts) < 3 {
			continue
		}
		start, _ := strconv.ParseUint(parts[0], 16, 64)
		size, _ := strconv.ParseUint(parts[1], 16, 64)

		s.jitSymbols = append(s.jitSymbols, JITSymbol{
			Start: start, End: start + size, Name: parts[2],
		})
	}
}

// 3. LA FUNZIONE PRINCIPALE: Traduce l'indirizzo esadecimale in una stringa leggibile
func (s *Symbolizer) Resolve(ip uint64) string {
	// Controlliamo la cache prima di fare sforzi
	if name, ok := s.symCache[ip]; ok {
		return name
	}

	result := fmt.Sprintf("0x%x [Sconosciuto]", ip) // Fallback di default

	// A) Cerchiamo se è una funzione JavaScript JIT
	for _, jit := range s.jitSymbols {
		if ip >= jit.Start && ip < jit.End {
			result = fmt.Sprintf("[JS] %s", jit.Name)
			s.symCache[ip] = result
			return result
		}
	}

	// B) Cerchiamo se è in una libreria nativa C/C++
	for _, region := range s.regions {
		if ip >= region.Start && ip < region.End {
			// Calcoliamo l'offset relativo all'interno del file ELF
			fileOffset := ip - region.Start + region.Offset

			// Apriamo il file ELF solo se non l'abbiamo già aperto
			elfFile, ok := s.elfCache[region.Path]
			if !ok {
				var err error
				elfFile, err = elf.Open(region.Path)
				if err == nil {
					s.elfCache[region.Path] = elfFile
				}
			}

			if elfFile != nil {
				// Leggiamo i simboli (sia quelli standard che quelli dinamici .so)
				symbols, _ := elfFile.Symbols()
				dynSymbols, _ := elfFile.DynamicSymbols()
				symbols = append(symbols, dynSymbols...)

				for _, sym := range symbols {
					// Attenzione: per i file condivisi (.so), sym.Value è l'offset dal base address
					if fileOffset >= sym.Value && fileOffset < sym.Value+sym.Size {
						// Trovato! Estrarre solo il nome base del file (es. libc.so.6)
						libName := region.Path[strings.LastIndex(region.Path, "/")+1:]

						// Usiamo NoParams per rimuovere i lunghi argomenti delle funzioni C++ e tenere solo il nome
						demangledName, err := demangle.ToString(sym.Name, demangle.NoParams)
						if err != nil {
							// Se il demangling fallisce (ad esempio se è una funzione C standard come "__open64"
							// che non è mangled), teniamo semplicemente il nome originale.
							demangledName = sym.Name
						}

						result = fmt.Sprintf("[C/C++] %s (%s)", demangledName, libName)
						break
					}
				}
			}
			// Se non trova il simbolo nell'ELF, stampa almeno il nome della libreria
			if result == fmt.Sprintf("0x%x [Sconosciuto]", ip) {
				libName := region.Path[strings.LastIndex(region.Path, "/")+1:]
				result = fmt.Sprintf("0x%x [%s]", ip, libName)
			}
			break
		}
	}

	s.symCache[ip] = result
	return result
}
