#include <node_api.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

// --- FUNZIONE 1: Syscall WRITE ---
napi_value TriggerWriteSyscall(napi_env env, napi_callback_info info) {
    const char* msg = "\n[C++] Syscall write diretta da Addon\n";
    write(1, msg, strlen(msg));

    napi_value result;
    napi_create_string_utf8(env, "Syscall WRITE completata!", NAPI_AUTO_LENGTH, &result);
    return result;
}

// --- FUNZIONE 2: Syscall OPENAT ---
napi_value TriggerOpenSyscall(napi_env env, napi_callback_info info) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd != -1) {
        write(fd, "test", 4);
        close(fd);
    }

    napi_value result;
    napi_create_string_utf8(env, "Syscall OPEN completata!", NAPI_AUTO_LENGTH, &result);
    return result;
}

// --- INIZIALIZZAZIONE DEL MODULO ---
napi_value Init(napi_env env, napi_value exports) {
    napi_value fnWrite, fnOpen;

    // Creiamo ed esportiamo la prima funzione (eseguiWrite)
    napi_create_function(env, nullptr, 0, TriggerWriteSyscall, nullptr, &fnWrite);
    napi_set_named_property(env, exports, "eseguiWrite", fnWrite);

    // Creiamo ed esportiamo la seconda funzione (eseguiOpen)
    napi_create_function(env, nullptr, 0, TriggerOpenSyscall, nullptr, &fnOpen);
    napi_set_named_property(env, exports, "eseguiOpen", fnOpen);

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)