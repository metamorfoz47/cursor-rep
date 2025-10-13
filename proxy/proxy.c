#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#pragma comment(lib, "ws2_32.lib")

// Global state
static HMODULE g_selfModule = NULL;
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logLock;
static volatile LONG g_loggerReady = 0;
static HANDLE g_hookThread = NULL;
static HMODULE g_astraOriginal = NULL; // astra_.dll

// Original function pointers
typedef int (WSAAPI *send_ptr)(SOCKET s, const char *buf, int len, int flags);
typedef int (WSAAPI *recv_ptr)(SOCKET s, char *buf, int len, int flags);
typedef int (WSAAPI *connect_ptr)(SOCKET s, const struct sockaddr *name, int namelen);

static send_ptr   g_real_send   = NULL;
static recv_ptr   g_real_recv   = NULL;
static connect_ptr g_real_connect = NULL;

// Small helpers
static void get_module_dir_w(HMODULE module, wchar_t *outDir, DWORD outLen) {
    if (outDir == NULL || outLen == 0) return;
    DWORD n = GetModuleFileNameW(module, outDir, outLen);
    if (n == 0 || n >= outLen) {
        outDir[0] = L'\0';
        return;
    }
    // Trim to directory
    for (DWORD i = n; i > 0; --i) {
        if (outDir[i] == L'\\' || outDir[i] == L'/') {
            outDir[i] = L'\0';
            break;
        }
    }
}

static void ensure_logger_initialized(void) {
    if (InterlockedCompareExchange(&g_loggerReady, 0, 0) != 0) {
        return;
    }

    InitializeCriticalSection(&g_logLock);

    wchar_t dir[MAX_PATH];
    get_module_dir_w(g_selfModule, dir, MAX_PATH);

    wchar_t logPath[MAX_PATH];
    wsprintfW(logPath, L"%s\\log.txt", dir);

    g_logFile = CreateFileW(
        logPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_logFile != INVALID_HANDLE_VALUE) {
        InterlockedExchange(&g_loggerReady, 1);
    }
}

static void log_write_raw(const char *data, DWORD len) {
    if (g_logFile == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(g_logFile, data, len, &written, NULL);
}

static void log_printf(const char *fmt, ...) {
    ensure_logger_initialized();
    if (InterlockedCompareExchange(&g_loggerReady, 0, 0) == 0) return;

    char buffer[4096];
    SYSTEMTIME st; GetLocalTime(&st);
    int prefix = _snprintf(
        buffer, sizeof(buffer),
        "%04u-%02u-%02u %02u:%02u:%02u.%03u ",
        (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds
    );
    if (prefix < 0) prefix = 0;

    va_list args; va_start(args, fmt);
    int n = _vsnprintf(buffer + prefix, sizeof(buffer) - (size_t)prefix, fmt, args);
    va_end(args);
    if (n < 0) n = (int)(sizeof(buffer) - (size_t)prefix - 1);

    EnterCriticalSection(&g_logLock);
    log_write_raw(buffer, (DWORD)strlen(buffer));
    static const char crlf[] = "\r\n";
    log_write_raw(crlf, 2);
    LeaveCriticalSection(&g_logLock);
}

static void log_hex(const void *data, size_t len) {
    ensure_logger_initialized();
    if (InterlockedCompareExchange(&g_loggerReady, 0, 0) == 0) return;

    const size_t maxDump = 64 * 1024; // cap to avoid giant logs
    if (len > maxDump) len = maxDump;

    const uint8_t *p = (const uint8_t *)data;
    char line[128];

    EnterCriticalSection(&g_logLock);
    for (size_t i = 0; i < len; i += 16) {
        int n = _snprintf(line, sizeof(line), "%08zx  ", i);
        if (n < 0) n = 0;
        size_t pos = (size_t)n;

        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) {
                pos += (size_t)_snprintf(line + pos, sizeof(line) - pos, "%02x ", p[i + j]);
            } else {
                pos += (size_t)_snprintf(line + pos, sizeof(line) - pos, "   ");
            }
        }

        pos += (size_t)_snprintf(line + pos, sizeof(line) - pos, " ");
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) {
                uint8_t c = p[i + j];
                line[pos++] = (c >= 32 && c <= 126) ? (char)c : '.';
                if (pos >= sizeof(line)) break;
            }
        }
        if (pos > sizeof(line) - 3) pos = sizeof(line) - 3;
        line[pos++] = '\r';
        line[pos++] = '\n';
        line[pos] = '\0';

        log_write_raw(line, (DWORD)pos);
    }
    LeaveCriticalSection(&g_logLock);
}

// IAT hooker (by name) for a given module
static BOOL iat_hook_by_name(HMODULE module, const char *importDllLower, const char *funcName, void *newFunc, void **origOut) {
    if (!module || !importDllLower || !funcName || !newFunc) return FALSE;

    BYTE *base = (BYTE *)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_DATA_DIRECTORY impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) return FALSE;

    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + impDir.VirtualAddress);
    for (; desc->Name != 0; ++desc) {
        const char *dllName = (const char *)(base + desc->Name);
        if (!dllName) continue;

        // lowercase compare
        char dllLower[128];
        size_t k = 0; for (; dllName[k] && k < sizeof(dllLower) - 1; ++k) {
            char c = dllName[k];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            dllLower[k] = c;
        }
        dllLower[k] = '\0';

        if (_stricmp(dllLower, importDllLower) != 0) {
            // also accept without trailing .dll
            size_t len = strlen(dllLower);
            if (!(len > 4 && strcmp(dllLower + (len - 4), ".dll") == 0 && _strnicmp(dllLower, importDllLower, len - 4) == 0)) {
                continue;
            }
        }

        IMAGE_THUNK_DATA *origThunk = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *firstThunk = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
        for (; origThunk && origThunk->u1.AddressOfData != 0; ++origThunk, ++firstThunk) {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                continue; // ordinal import, skip
            }
            IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + origThunk->u1.AddressOfData);
            if (!ibn) continue;
            const char *name = (const char *)ibn->Name;
            if (!name) continue;
            if (strcmp(name, funcName) == 0) {
                DWORD oldProtect;
                if (origOut) *origOut = (void *)(uintptr_t)firstThunk->u1.Function;
                if (VirtualProtect(&firstThunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect)) {
                    firstThunk->u1.Function = (ULONGLONG)(uintptr_t)newFunc;
                    DWORD tmp; VirtualProtect(&firstThunk->u1.Function, sizeof(void *), oldProtect, &tmp);
                    FlushInstructionCache(GetCurrentProcess(), &firstThunk->u1.Function, sizeof(void *));
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

// Hook targets
static void initialize_real_functions(void) {
    HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("WS2_32.dll");
    if (hWs2) {
        g_real_send = (send_ptr)(void *)GetProcAddress(hWs2, "send");
        g_real_recv = (recv_ptr)(void *)GetProcAddress(hWs2, "recv");
        g_real_connect = (connect_ptr)(void *)GetProcAddress(hWs2, "connect");
    }
}

static void hook_ws2_functions_for_astra(void) {
    if (!g_astraOriginal) return;
    initialize_real_functions();

    BOOL ok1 = iat_hook_by_name(g_astraOriginal, "ws2_32.dll", "send",  (void *)(uintptr_t)(&send),  (void **)(void *)&g_real_send);
    BOOL ok2 = iat_hook_by_name(g_astraOriginal, "ws2_32.dll", "recv",  (void *)(uintptr_t)(&recv),  (void **)(void *)&g_real_recv);
    BOOL ok3 = iat_hook_by_name(g_astraOriginal, "ws2_32.dll", "connect", (void *)(uintptr_t)(&connect), (void **)(void *)&g_real_connect);

    log_printf("IAT hook results: send=%d recv=%d connect=%d", ok1, ok2, ok3);
}

// Address helpers for printing endpoints
static void describe_sockaddr(const struct sockaddr *name, int namelen, char *out, size_t outLen) {
    if (!out || outLen == 0) return;
    out[0] = '\0';
    if (!name) return;

    if (name->sa_family == AF_INET && namelen >= (int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)name;
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        unsigned short port = ntohs(in->sin_port);
        _snprintf(out, outLen, "%s:%hu", ip[0] ? ip : "0.0.0.0", port);
        return;
    }
#ifdef AF_INET6
    if (name->sa_family == AF_INET6 && namelen >= (int)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)name;
        char ip[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
        unsigned short port = ntohs(in6->sin6_port);
        _snprintf(out, outLen, "[%s]:%hu", ip[0] ? ip : "::", port);
        return;
    }
#endif
    _snprintf(out, outLen, "fam=%d len=%d", (int)name->sa_family, (int)namelen);
}

// Hook implementations
int WSAAPI connect(SOCKET s, const struct sockaddr *name, int namelen) {
    if (!g_real_connect) initialize_real_functions();

    char addr[128];
    describe_sockaddr(name, namelen, addr, sizeof addr);
    log_printf("connect(s=%p, addr=%s)", (void *)(uintptr_t)s, addr);

    int rc = g_real_connect ? g_real_connect(s, name, namelen) : SOCKET_ERROR;
    log_printf("connect -> %d (err=%d)", rc, (int)WSAGetLastError());
    return rc;
}

int WSAAPI send(SOCKET s, const char *buf, int len, int flags) {
    if (!g_real_send) initialize_real_functions();
    log_printf("send(s=%p, len=%d, flags=0x%x)", (void *)(uintptr_t)s, len, (unsigned)flags);
    if (buf && len > 0) log_hex(buf, (size_t)len);
    int rc = g_real_send ? g_real_send(s, buf, len, flags) : SOCKET_ERROR;
    log_printf("send -> %d (err=%d)", rc, (int)WSAGetLastError());
    return rc;
}

int WSAAPI recv(SOCKET s, char *buf, int len, int flags) {
    if (!g_real_recv) initialize_real_functions();
    int rc = g_real_recv ? g_real_recv(s, buf, len, flags) : SOCKET_ERROR;
    log_printf("recv(s=%p, len=%d, flags=0x%x) -> %d (err=%d)", (void *)(uintptr_t)s, len, (unsigned)flags, rc, (int)WSAGetLastError());
    if (rc > 0 && buf) log_hex(buf, (size_t)rc);
    return rc;
}

static DWORD WINAPI HookThreadProc(LPVOID) {
    // Determine path to astra_.dll next to us and load it so its IAT can be patched
    wchar_t dir[MAX_PATH]; get_module_dir_w(g_selfModule, dir, MAX_PATH);
    wchar_t target[MAX_PATH]; wsprintfW(target, L"%s\\astra_.dll", dir);

    g_astraOriginal = LoadLibraryW(target);
    if (!g_astraOriginal) {
        log_printf("LoadLibraryW failed for: %S (err=%lu)", target, GetLastError());
        return 0;
    }

    hook_ws2_functions_for_astra();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_selfModule = hModule;
        DisableThreadLibraryCalls(hModule);
        ensure_logger_initialized();
        log_printf("astra proxy loaded (pid=%lu)", GetCurrentProcessId());
        g_hookThread = CreateThread(NULL, 0, HookThreadProc, NULL, 0, NULL);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        log_printf("astra proxy unloading");
        if (g_hookThread) {
            WaitForSingleObject(g_hookThread, 2000);
            CloseHandle(g_hookThread);
            g_hookThread = NULL;
        }
        if (g_logFile != INVALID_HANDLE_VALUE) {
            CloseHandle(g_logFile);
            g_logFile = INVALID_HANDLE_VALUE;
        }
        DeleteCriticalSection(&g_logLock);
    }
    return TRUE;
}
#else
int main(void) { return 0; }
#endif
