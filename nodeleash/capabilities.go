package main

const (
	CapFile             = "CAP_FILE"
	CapReadFile         = "CAP_READ_FILE"
	CapWriteFile        = "CAP_WRITE_FILE"
	CapCreateFile       = "CAP_CREATE_FILE"
	CapDeleteFile       = "CAP_DELETE_FILE"
	CapFileMetadata     = "CAP_FILE_METADATA"
	CapConnectRemote    = "CAP_CONNECT_REMOTE"
	CapListenLocal      = "CAP_LISTEN_LOCAL"
	CapSendData         = "CAP_SEND_DATA"
	CapReceiveData      = "CAP_RECEIVE_DATA"
	CapExec             = "CAP_EXEC"
	CapTerminate        = "CAP_TERMINATE_PROCESS"
	CapReadSystemState  = "CAP_READ_SYSTEM_STATE"
	CapWriteSystemState = "CAP_WRITE_SYSTEM_STATE"
	CapResourceLimits   = "CAP_RESOURCE_LIMITS"
	CapMemory           = "CAP_MEMORY_MANIPULATION"
	CapDirectIO         = "CAP_DIRECT_IO"
	CapUnknown          = "CAP_UNKNOWN"
)

// syscallToCapability is the single source of truth for the capability taxonomy.
// Used by MapToCapability (analysis/enforcement) and populateTrackedSyscalls
// (kernel-side filter at startup).
var syscallToCapability = map[string]string{
	"read": CapReadFile, "pread64": CapReadFile, "readv": CapReadFile,
	"open": CapReadFile, "openat": CapReadFile, "openat2": CapReadFile,
	"stat": CapReadFile, "fstat": CapReadFile, "lstat": CapReadFile,
	"newfstatat": CapReadFile, "statx": CapReadFile,
	"access": CapReadFile, "faccessat": CapReadFile,
	"getdents64": CapReadFile, "readlink": CapReadFile, "readlinkat": CapReadFile,

	"write": CapWriteFile, "pwrite64": CapWriteFile, "writev": CapWriteFile,
	"truncate": CapWriteFile, "ftruncate": CapWriteFile,
	"fallocate": CapWriteFile, "copy_file_range": CapWriteFile,

	"mkdir": CapCreateFile, "mkdirat": CapCreateFile, "creat": CapCreateFile,
	"link": CapCreateFile, "linkat": CapCreateFile,
	"symlink": CapCreateFile, "symlinkat": CapCreateFile,
	"rename": CapCreateFile, "renameat": CapCreateFile, "renameat2": CapCreateFile,

	"unlink": CapDeleteFile, "unlinkat": CapDeleteFile, "rmdir": CapDeleteFile,

	"close": CapFile, "dup": CapFile, "dup2": CapFile, "dup3": CapFile,
	"poll": CapFile, "ppoll": CapFile,
	"epoll_wait": CapFile, "epoll_pwait": CapFile,
	"epoll_ctl": CapFile, "epoll_create1": CapFile,
	"select": CapFile, "pselect6": CapFile,
	"fcntl": CapFile, "pipe": CapFile, "pipe2": CapFile,

	"chmod": CapFileMetadata, "fchmod": CapFileMetadata,
	"chown": CapFileMetadata, "fchown": CapFileMetadata, "lchown": CapFileMetadata,
	"utimes": CapFileMetadata, "utimensat": CapFileMetadata,

	"socket": CapConnectRemote, "connect": CapConnectRemote, "socketpair": CapConnectRemote,

	"bind": CapListenLocal, "listen": CapListenLocal,
	"accept": CapListenLocal, "accept4": CapListenLocal,

	"send": CapSendData, "sendto": CapSendData,
	"sendmsg": CapSendData, "sendmmsg": CapSendData,

	"recv": CapReceiveData, "recvfrom": CapReceiveData,
	"recvmsg": CapReceiveData, "recvmmsg": CapReceiveData,

	"execve": CapExec, "execveat": CapExec,
	"clone": CapExec, "clone3": CapExec, "fork": CapExec, "vfork": CapExec,

	"exit": CapTerminate, "exit_group": CapTerminate,
	"kill": CapTerminate, "tgkill": CapTerminate, "tkill": CapTerminate,

	"getpid": CapReadSystemState, "getppid": CapReadSystemState,
	"getuid": CapReadSystemState, "geteuid": CapReadSystemState,
	"getgid": CapReadSystemState, "getegid": CapReadSystemState,
	"uname": CapReadSystemState, "getcwd": CapReadSystemState,
	"clock_gettime": CapReadSystemState, "gettimeofday": CapReadSystemState,
	"getrusage": CapReadSystemState, "sysinfo": CapReadSystemState,

	"setuid": CapWriteSystemState, "setgid": CapWriteSystemState,
	"chdir": CapWriteSystemState, "fchdir": CapWriteSystemState,
	"setsid": CapWriteSystemState, "prctl": CapWriteSystemState,

	"setrlimit": CapResourceLimits, "prlimit64": CapResourceLimits, "getrlimit": CapResourceLimits,

	"mmap": CapMemory, "munmap": CapMemory, "mprotect": CapMemory,
	"mremap": CapMemory, "madvise": CapMemory, "brk": CapMemory,

	"ioctl": CapDirectIO,
}

func MapToCapability(syscallName string) string {
	if cap, ok := syscallToCapability[syscallName]; ok {
		return cap
	}
	return CapUnknown
}
