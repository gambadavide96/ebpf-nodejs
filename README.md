# NodeLeash

NodeLeash is a kernel-level security system for Node.js that uses eBPF to intercept syscalls and attribute them to the responsible npm package. It builds a per-package allowlist policy during an analysis phase and enforces it at runtime, logging any violations to the terminal.

It is inspired by [GoLeash](https://github.com/chains-project/goleash) and adapted to the specific characteristics of the Node.js runtime.

---

## How It Works

NodeLeash attaches eBPF tracepoints to `sys_enter` and captures the native user-space stack of the Node.js process at the moment each relevant syscall is executed. Using V8's perf map (`--perf-basic-prof`),(`--interpreted-native-stack`)  and ELF symbol tables (via Blazesym), it resolves raw instruction pointer addresses into symbolic frame names and identifies which npm package originated the syscall.

It operates in two modes:

- **analyze** — observes a running process and builds a JSON policy
- **enforce** — monitors a running process against an existing policy and logs violations to stdout

---

## Architecture

```
Node.js process
      │
      │ syscall
      ▼
  sys_enter  (eBPF tracepoint)
      │
      │  stack_id → ring buffer → userspace
      ▼
  Blazesym + /proc/<pid>/maps
      │
      │  ResolvedFrame { Name, Module }
      ▼
  stackAnalyzer.go
  ├── classifyFrame()    positive whitelist: "JS:" prefix | ".node" module suffix
  ├── buildCallPath()    extracts the npm package sequence from the call stack
  └── AnalyzeStack()     maps syscall → capability → responsible package
         │
         ▼
  analyze mode                     enforce mode
  ├── Policy                        └── EnforcementEngine
  │   └── package → capability          └── logs violations to stdout
  │       → call_path_hash
  └── UnattributedPolicy
      └── capability safety net
```

---

## Policy Model

### Attributed policy (`nodeleash_policy_pid<N>_<ts>.json`)

Maps each npm package to the capabilities it is allowed to exercise, qualified by call path hash:

```json
[
  {
    "package": "express",
    "capabilities": [
      {
        "capability": "CAP_WRITE_FILE",
        "call_path_hashes": ["a3f9c2e1..."]
      }
    ]
  }
]
```

The call path hash is SHA-256 of the ordered sequence of npm packages observed in the stack (infrastructure filtered out). This enables **confused deputy detection**: the same `(package, capability)` pair is allowed only when the full call context also matches a previously observed trusted path.

### Unattributed policy (`nodeleash_unattributed_pid<N>_<ts>.json`)

A safety net of capabilities observed in syscalls that NodeLeash could not attribute to any package (async I/O completions, worker thread pool operations). In enforcement, a capability that was never part of the legitimate "async noise floor" but suddenly appears unattributed is flagged as a violation.

---

## Attribution: What Works and What Doesn't

NodeLeash attributes a syscall if and only if **at the exact moment the syscall is executed by the kernel**, the native stack contains at least one JS frame belonging to user code.

| Case | Example | Stack at syscall time | Attribution |
|------|---------|----------------------|-------------|
| Synchronous syscall | `fs.writeFileSync` | JS frame visible | ✅ Direct |
| Callback + immediate syscall | `onConnect` + `write` via `uv__try_write` | JS frame visible | ✅ Direct |
| Deferred async I/O | `socket.on('data')` read completion | Pure libuv | ❌ UnattributedPolicy |
| Worker thread pool | `fs.readFile` | Pure libuv worker | ❌ UnattributedPolicy |

The fundamental limitation is structural to the Node.js runtime: asynchronous operations are executed by libuv or its worker thread pool after the originating JS frame has already left the stack. This is the key difference from Go, where goroutines block their native stack during syscalls, keeping the originating context always present.

---

## Process Tree Tracking

NodeLeash tracks child processes automatically. When Node.js spawns a child via `child_process.spawn()`, the kernel fires `sched_process_fork`, which NodeLeash intercepts and adds the child PID to `target_pid_map`. Tracking propagates recursively — grandchildren are tracked through the same mechanism. Child processes that replace their image via `execve` (e.g. `/bin/sh`) remain tracked at the PID level but their syscalls become unattributable, as their stack contains no Node.js frames.

---

## Capability Taxonomy

NodeLeash maps syscalls to a set of high-level capabilities:

| Capability | Example syscalls |
|-----------|-----------------|
| `CAP_READ_FILE` | `read`, `openat`, `stat` |
| `CAP_WRITE_FILE` | `write`, `truncate`, `fallocate` |
| `CAP_CREATE_FILE` | `mkdir`, `rename`, `link` |
| `CAP_DELETE_FILE` | `unlink`, `rmdir` |
| `CAP_CONNECT_REMOTE` | `socket`, `connect` |
| `CAP_LISTEN_LOCAL` | `bind`, `listen`, `accept4` |
| `CAP_SEND_DATA` | `sendto`, `sendmsg` |
| `CAP_RECEIVE_DATA` | `recvfrom`, `recvmsg` |
| `CAP_EXEC` | `execve`, `clone`, `fork` |
| `CAP_MEMORY_MANIPULATION` | `mmap`, `mprotect`, `brk` |
| `CAP_DIRECT_IO` | `ioctl` |

---

## Prerequisites

| Dependency | Purpose |
|-----------|---------|
| Linux kernel ≥ 5.7 | Ring buffer eBPF map type |
| clang / llvm | Compile `trace.c` to eBPF bytecode |
| libbpf-dev | eBPF helpers (`bpf_helpers.h`) |
| bpftool | Generate `vmlinux.h` from kernel BTF |
| libseccomp-dev | Translate syscall IDs to names |
| libelf-dev / zlib1g-dev | Transitive libbpf dependencies |
| Go 1.22+ | Build userspace binary |
| Rust / Cargo | Build Blazesym (CGO dependency) |
| Node.js 20 LTS | Target process for testing |

---

## Installation

```bash
# 1. System dependencies
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev \
    zlib1g-dev libseccomp-dev linux-tools-$(uname -r) pkg-config git

# 2. Go 1.22+
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

# 3. Rust (required by Blazesym)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 4. Generate vmlinux.h from the running kernel's BTF
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 5. Go module setup
go mod init nodeleash
go get github.com/cilium/ebpf@latest
go get github.com/libbpf/blazesym/go@latest
go get github.com/seccomp/libseccomp-golang
go get golang.org/x/sys/unix

# 6. Generate eBPF bindings from trace.c
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go generate ./...

# 7. Build
CGO_ENABLED=1 go build -o nodeleash .
```

---

## Usage

### Analyze mode

Start Node.js with perf map support, then run NodeLeash:

```bash
node --perf-basic-prof --interpreted-frames-native-stack app.js &
NODE_PID=$!

sudo ./nodeleash analyze $NODE_PID [--debug]
```

Output files (written to `policy/` and `report/` on Ctrl+C):

```
policy/
  nodeleash_policy_pid<N>_<ts>.json         # attributed per-package policy
  nodeleash_unattributed_pid<N>_<ts>.json   # unattributed capability safety net
report/
  raw_stacks_pid<N>_<ts>.json               # raw stack traces for inspection
```

The `--debug` flag prints resolved stacks to stdout and saves call path details to `policy/nodeleash_callpaths_pid<N>.json`.

### Enforce mode

```bash
node --perf-basic-prof --interpreted-frames-native-stack app.js &
NODE_PID=$!

sudo ./nodeleash enforce $NODE_PID \
    --policy       policy/nodeleash_policy_pid<N>_<ts>.json \
    --unattributed policy/nodeleash_unattributed_pid<N>_<ts>.json
```

Violations are printed to stdout as they occur. The monitored process is **never terminated**. A summary is printed on Ctrl+C.

### Example violation output

```
🛡️  NodeLeash [ENFORCE] — PID: 5678
📋 Policy loaded: 4 packages
📋 Unattributed capabilities: 3
Listening for syscall events...

[15:04:05.123456] 🚨 VIOLATION  pid=5678  cap=CAP_CONNECT_REMOTE  pkg=malicious-pkg  path=LOCAL/app.js → malicious-pkg

════════════════════════════════════════════════
  ENFORCEMENT SUMMARY
════════════════════════════════════════════════
  🚨 1 violation(s) detected

  📦 malicious-pkg
     CAP_CONNECT_REMOTE               ×1
```

---

## Building a Reliable Policy

The policy must be built over a workload that exercises all expected code paths. A policy built on a partial workload produces false positives in enforcement.

**Recommended analysis procedure:**

1. Start NodeLeash analysis before or immediately after starting Node.js, to capture startup operations.
2. Exercise all application routes and features during the analysis session.
3. Exercise all application routes and features during the analysis session,
  including all code paths that use sensitive capabilities (file access,
  network connections, child process spawning). A capability that never
  appears during analysis will be flagged as a violation in enforcement
  even if it is legitimate.
4. Terminate NodeLeash with Ctrl+C to export the policy.

---

## Project Structure

```
nodeleash/
├── trace.c               # eBPF kernel program: syscall capture, stack map
├── main.go               # Entry point: analyze | enforce modes, event loop
├── blazeSymbolizer.go    # Blazesym wrapper: addr → ResolvedFrame{Name, Module}
├── moduleResolver.go     # /proc/<pid>/maps reader: addr → binary path
├── stackAnalyzer.go      # Frame classification, call path, AnalyzeStack()
├── capabilities.go       # Syscall → capability taxonomy
├── policyBuilder.go      # Policy, UnattributedPolicy, JSON export
├── enforcementEngine.go  # Policy loader, Check(), violation logger
└── rawReport.go          # Raw stack report for debug inspection
```

---

## Known Limitations

**Async attribution** — syscalls executed by libuv after the JS frame has left the stack (deferred I/O, worker thread pool) cannot be attributed to a specific package and are recorded in `UnattributedPolicy` only.

**JIT address instability** — V8 writes function mappings to the perf map lazily after JIT compilation. If eBPF captures a stack frame in the window between compilation and perf map write, Blazesym cannot resolve the address and the frame is discarded as unresolved infrastructure. The syscall may then appear unattributable even though the correct JS frame was present on the stack. This race is inherent to the perf map mechanism and cannot be eliminated without modifying the V8 runtime.

**exec after fork** — child processes that replace their image via `execve` remain tracked at the PID level but their syscalls are unattributable.

**Policy warm-up** — the policy must be built with a representative workload. An incomplete analysis session produces false positives in enforcement.