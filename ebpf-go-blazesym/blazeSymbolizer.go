package main

import (
	"fmt"
	"log"

	blazesym "github.com/libbpf/blazesym/go"
)

type BlazeSymbolizer struct {
	sym *blazesym.Symbolizer
	pid uint32
}

func NewBlazeSymbolizer(pid int) *BlazeSymbolizer {
	sym, err := blazesym.NewSymbolizer()
	if err != nil {
		log.Fatalf("Errore critico: impossibile inizializzare Blazesym: %v", err)
	}

	return &BlazeSymbolizer{
		sym: sym,
		pid: uint32(pid),
	}
}

// Funzione Resolve per risolvere gli indirizzi ip uno alla volta
func (b *BlazeSymbolizer) Resolve(ip uint64) string {

	//SymbolizeProcessAbsAddrs symbolizes a list of process absolute addresses.
	//Passiamo un unico indirizzo ip da risolvere, ma lo incartiamo dentro un array
	symbols, err := b.sym.SymbolizeProcessAbsAddrs([]uint64{ip}, b.pid, blazesym.ProcessSourceWithPerfMap(true))

	// 2. Controllo errori e risultati vuoti
	if err != nil || len(symbols) == 0 {
		return fmt.Sprintf("[Sconosciuto] 0x%x", ip)
	}

	// 3. Estraiamo il primo (e unico, dato che abbiamo passato un solo IP) risultato
	sym := symbols[0]

	// 4. Stampiamo solo il nome, senza prefissi fuorvianti!
	return fmt.Sprintf("%s", sym.Name)
}

// ResolveBatch risolve un intero array di indirizzi in una singola chiamata a Blazesym
func (b *BlazeSymbolizer) ResolveBatch(ips []uint64) []string {
	// Prepariamo l'array dei risultati della stessa lunghezza degli IP in ingresso
	results := make([]string, len(ips))

	// 1. L'Esecuzione Batch: passiamo l'intero array "ips" al motore Rust
	symbols, err := b.sym.SymbolizeProcessAbsAddrs(ips, b.pid, blazesym.ProcessSourceWithPerfMap(true))

	// 2. Se c'è un errore, riempiamo i risultati con gli indirizzi raw
	if err != nil || len(symbols) == 0 {
		for i, ip := range ips {
			results[i] = fmt.Sprintf("[Sconosciuto] 0x%x", ip)
		}
		return results
	}

	// 3. Mappiamo i risultati
	// Blazesym ci restituisce un array "symbols" parallelo al nostro array "ips"
	for i, ip := range ips {

		sym := symbols[i]

		// Se incontriamo un indirizzo non risolto, stampiamo l'indirizzo al suo posto
		if sym.Name == "" {
			results[i] = fmt.Sprintf("0x%x", ip)
		} else {
			results[i] = sym.Name
		}
	}

	return results
}
