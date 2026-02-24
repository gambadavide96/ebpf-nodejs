package main

import (
	"fmt"
	"log"

	// L'import corretto dal tuo esempio
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

func (b *BlazeSymbolizer) Resolve(ip uint64) string {

	// 1. Chiamiamo il metodo specifico per i processi, passando un ARRAY di indirizzi
	// (Esattamente come faceva l'esempio con []uint64{0x2000200})
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
