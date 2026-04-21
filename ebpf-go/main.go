package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf trace trace.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// RINGBUFFER INFO STRUCTURE
type SyscallInfo struct {
	TimestampNs uint64
	SyscallId   uint32
	StackId     int32
}

// traduce dinamicamente l'ID della syscall nel suo nome
// interrogando il Kernel tramite libseccomp
func getSyscallName(id uint32) string {
	scmpSyscall := seccomp.ScmpSyscall(id)

	name, err := scmpSyscall.GetName()
	if err != nil {
		// Se la syscall non esiste o non è
		// riconosciuta su questa architettura, stampa il numero grezzo.
		return fmt.Sprintf("syscall_%d", id)
	}

	return name
}

func main() {
	//os.Args array di stringhe passate in input, 0 è il nome del programma e 1 il PID
	if len(os.Args) < 2 {
		log.Fatalf("Correct use: sudo ./monitor <PID_NODEJS>")
	}

	//conversione PID da stringa a intero
	targetPID, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		log.Fatalf("PID non valido: %v", err)
	}

	//Removes the limit on the amount of memory the current process can lock into RAM
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := traceObjects{}
	//Inietta nel kernel il bytecode eBPF compilato, crea le mappe e valida il programma
	//poi inserisce in objs i file descriptor che collegano Go al programma ebpf nel kernel.
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatalf("Errore caricamento oggetti: %v", err)
	}
	defer objs.Close()

	//Inserisco nella mappa eBPF il target PID passato dall'utente
	key := uint32(0)
	val := uint32(targetPID)
	objs.TargetPidMap.Put(&key, &val)

	//Aggagancia la funzione trace_sys_enter definita in trace.c a sysenter
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		log.Fatalf("Errore aggancio tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Printf("🔍 Monitoraggio stack trace per PID %d avviato.\n", targetPID)

	// INIZIALIZZAZIONE STRUTTURA DATI PER IL TRACKING
	// Struttura: map[NomeSyscall]map[ChiaveStackUnica]ArrayDiFunzioni
	syscallStacksTracker := make(map[string]map[string][]string)

	//INIZIALIZZAZIONE BLAZESYM
	symb := NewBlazeSymbolizer(int(targetPID))

	//CALCOLO ISTANTE ESATTO
	var ts unix.Timespec
	//Riempe ts con i secondi ed i nanosecondi da quando la macchina è accesa
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("Impossibile leggere il clock di sistema: %v", err)
	}
	//Tempo totale di accensione in nanosecondi
	uptimeNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	//Calcolo istante esatto(data e ora) di accensione della macchina
	bootTime := time.Now().Add(-time.Duration(uptimeNs))

	// 1. INIZIALIZZIAMO IL LETTORE DEL RING BUFFER
	rd, err := ringbuf.NewReader(objs.RingBuffer) // "RingBuffer" is the ring buffer defined in C
	if err != nil {
		log.Fatalf("Error on opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	//Creiamo stopper per ricevere messaggi di tipo os.Signal
	stopper := make(chan os.Signal, 1)
	//se l'utente preme Ctrl+C (os.Interrupt) o cerca di interrompere il processo (SIGTERM)
	//prendi quel segnale e mettilo in stopper
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n🛑 Interruzione ricevuta. Generazione report JSON in corso...")
		// Rimosso os.Exit(0). Chiudiamo il reader per sbloccare il ciclo for.
		rd.Close()
	}()

	fmt.Println("In attesa di eventi...")

	// 2. CICLO INFINITO BLOCCANTE
	for {
		// Il programma si "addormenta" qui finché il kernel non invia un evento
		//ogni volta che arriva un evento nel buffer, viene messo in record
		record, err := rd.Read()
		if err != nil {
			// Se l'errore è dovuto alla chiusura del file (da parte di Ctrl+C), usciamo in silenzio
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) || strings.Contains(err.Error(), "file already closed") {
				break
			}
			log.Printf("Errore lettura ringbuf: %v", err)
			continue
		}

		// 3. DECODIFICA BINARIA
		// Trasformiamo i 16 byte grezzi (record.RawSample) nella nostra Go SyscallInfo
		var info SyscallInfo
		//Read taglia i byte letti in 8+4+4 e li assegna alla struct info che abbiamo definito
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
			log.Printf("Errore decodifica evento: %v", err)
			continue
		}

		// Andiamo a ripescare i dettagli dello stack tramite lo stack id (nella mappa StackMap)
		var stackFrames [127]uint64
		err = objs.StackMap.Lookup(&info.StackId, &stackFrames)
		if err != nil {
			continue
		}

		//Ricavo data ed ora esatta in cui si è verificato l'evento
		//aggiungendo al tempo di boot i nanosecondi in cui si è verificato l'evento
		eventTime := bootTime.Add(time.Duration(info.TimestampNs))
		timeStr := eventTime.Format("15:04:05.000000")
		syscallName := getSyscallName(info.SyscallId)
		fmt.Printf("\n🕒 [%s] 🔹 Syscall: %-15s (ID: %d) | Stack ID: %d\n",
			timeStr, syscallName, info.SyscallId, info.StackId)

		// ---------------------------------------------------------
		// RISOLUZIONE BATCH (one call to BlazeSym)
		// ---------------------------------------------------------

		// 1. Estraiamo solo gli IP (instructions pointers) validi (interrompiamo al primo 0)
		var validIPs []uint64
		for _, ip := range stackFrames {
			if ip == 0 {
				break
			}
			validIPs = append(validIPs, ip)
		}

		// 2. Se ci sono IP da risolvere, li passiamo in una sola chiamata a Blazesym
		if len(validIPs) > 0 {
			resolvedNames := symb.ResolveBatch(validIPs)

			// 3. Stampiamo i risultati formattati
			for i, funcName := range resolvedNames {
				fmt.Printf("      [%2d] %s\n", i, funcName)
			}

			// 4. CREAZIONE MAPPA SYSCALL - STACK TRACE
			// Se non esiste una chiave per la syscall intercettata, la creo.
			if syscallStacksTracker[syscallName] == nil {
				syscallStacksTracker[syscallName] = make(map[string][]string)
			}

			// Uniamo l'intero stack in una stringa usando un delimitatore speciale
			// Questa stringa serve impronta digitale (hash) univoca per lo stack
			stackFingerprint := strings.Join(resolvedNames, "|")

			// Per evitare duplicati, inseriamo lo stack catturato nella mappa solo se la sua firma non esiste già.
			if _, exists := syscallStacksTracker[syscallName][stackFingerprint]; !exists {
				syscallStacksTracker[syscallName][stackFingerprint] = resolvedNames
			}

		}
	}

	//5. COSTRUZIONE MAPPA FUNZIONE -> SYSCALL
	functionSyscallsProfile := BuildFunctionProfile(syscallStacksTracker)

	// 6. ESPORTAZIONE DEI FILE JSON
	exportJSONSyscalls(int(targetPID), syscallStacksTracker)
	exportJSONFunctions(int(targetPID), functionSyscallsProfile)

}
