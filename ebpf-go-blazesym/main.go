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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Struttura gemella. Nota l'ordine: Timestamp per primo!
// Essendo 8 + 4 + 4 byte = 16 byte precisi, non ci serve il padding ("_ uint32").
type SyscallInfo struct {
	TimestampNs uint64
	SyscallId   uint32
	StackId     int32
}

var syscallNames = map[uint32]string{
	0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
	9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 14: "rt_sigprocmask",
	16: "ioctl", 17: "pread64", 20: "writev", 21: "access", 22: "pipe",
	24: "sched_yield", 28: "madvise", 41: "socket", 42: "connect", 44: "sendto", 228: "clock_gettime",
	257: "openat", 262: "fstatat", 281: "epoll_wait", 293: "pipe2", 318: "getrandom",
}

func getSyscallName(id uint32) string {
	if name, ok := syscallNames[id]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", id)
}

func main() {
	//os.Args array di stringhe passate in input, 0 è il nome del programma e 1 il PID
	if len(os.Args) < 2 {
		log.Fatalf("Uso corretto: sudo ./monitor <PID_NODEJS>")
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
	//poi inserisce in objs i file descriptor che collegano Go al programma ebpf nel kernel
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

	fmt.Printf("🔍 Monitoraggio stack trace per PID %d avviato (RING BUFFER).\n", targetPID)

	symb := NewBlazeSymbolizer(int(targetPID))

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
	rd, err := ringbuf.NewReader(objs.Events) // "Events" è il ring buffer definito in C
	if err != nil {
		log.Fatalf("Errore apertura ringbuf reader: %v", err)
	}
	defer rd.Close()

	//Creiamo stopper per ricevere messaggi di tipo os.Signal
	stopper := make(chan os.Signal, 1)
	//se l'utente preme Ctrl+C (os.Interrupt) o cerca di interrompere il processo (SIGTERM)
	//prendi quel segnale e mettilo in stopper
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Goroutine per uscire puliti quando premiamo Ctrl+C
	//Il comando go avvia una goroutine parallela, se legge qualcosa da stopper significa che
	//c'è un segnale di interruzione del processo, chiude il reader del ringbuffer e chiude il programma
	go func() {
		<-stopper
		fmt.Println("\n🛑 Uscita in corso...")
		rd.Close() // Chiudendo il reader sblocchiamo il for sottostante
		os.Exit(0)
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
				return
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

		fmt.Printf("\n🕒 [%s] 🔹 Syscall: %-15s (ID: %d) | Stack ID: %d\n",
			timeStr, getSyscallName(info.SyscallId), info.SyscallId, info.StackId)

		// ---------------------------------------------------------
		// RISOLUZIONE BATCH (una sola chiamata a BlazeSym)
		// ---------------------------------------------------------

		// 1. Estraiamo solo gli IP validi (interrompiamo al primo 0)
		var validIPs []uint64
		for _, ip := range stackFrames {
			if ip == 0 {
				break
			}
			validIPs = append(validIPs, ip)
		}

		// 2. Se ci sono IP da risolvere, li passiamo tutti insieme a Blazesym
		if len(validIPs) > 0 {
			resolvedNames := symb.ResolveBatch(validIPs)

			// 3. Stampiamo i risultati formattati
			for i, funcName := range resolvedNames {
				fmt.Printf("      [%2d] %s\n", i, funcName)
			}
		}
	}
}
