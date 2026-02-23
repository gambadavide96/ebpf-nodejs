# eBPF Node.js Syscall Tracer & Profiler

A powerful observability and security tool written in **Go** and **eBPF** to trace real-time system calls made by Node.js applications. It captures and decodes the entire stack trace, bridging the gap between User Space execution and Kernel Space system calls.



## 🌟 What is this project?

This project demonstrates how to use eBPF to build a continuous profiler and a low-overhead Intrusion Detection System (IDS). Unlike traditional tracers that only tell you *which* syscall was executed, this tool answers the most critical question: **Which exact line of JavaScript code or internal C++ function triggered this system operation?**

It solves two of the most complex challenges in modern observability:
1. **The "Blind Spot" of JIT-compiled languages:** It translates raw memory addresses into actual JavaScript functions compiled Just-In-Time by the V8 engine.
2. **High-Performance Streaming:** It uses eBPF `RingBuffer` maps to guarantee 100% event capture in real-time with zero data loss (no overwriting) and near-zero CPU overhead in User Space.

## ✨ Key Features

* 🕵️‍♂️ **Real-Time Syscall Tracing:** Hooks into the `raw_syscalls/sys_enter` kernel tracepoint.
* 📚 **Stack Trace Extraction (User Space):** Captures up to 127 memory frames of the target application.
* 🧩 **Advanced Symbolization:**
  * **JavaScript JIT:** Reads Node.js `perf-map` files to resolve JS functions dynamically in real-time.
  * **Native C/C++:** Dynamically parses ELF binaries and memory maps (`/proc/<PID>/maps`) to resolve internal Node.js and `libc` calls.
  * **C++ Demangling:** Translates heavily mangled V8 internal functions (e.g., `_ZN2v8...`) into clean, human-readable C++ signatures.
* ⏱️ **Monotonic Timestamps:** Synchronizes Kernel uptime with User Space clocks to provide a flawless, nanosecond-precision event timeline.
* 🚀 **Zero-Loss Streaming:** Event-driven architecture powered by **eBPF Ring Buffer**.

## 🛠️ Prerequisites

* **Linux Kernel:** Version 5.8 or higher (required for BPF RingBuffer and `bpf2go` support).
* **Go:** Version 1.20+ installed.
* **Clang/LLVM:** Required to compile C code into eBPF bytecode (`sudo apt install clang llvm`).
* **Root Privileges:** Required to load eBPF programs into the kernel.

## 🚀 How to Run

### 1. Prepare the Node.js Application
For the V8 engine to expose the map of JIT-compiled functions (which is essential to resolve JavaScript symbols), you must start your Node.js application with the `--perf-basic-prof` flag:

```bash
node --perf-basic-prof app.js
