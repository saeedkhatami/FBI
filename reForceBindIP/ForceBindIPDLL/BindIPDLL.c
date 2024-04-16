#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#include <winsock2.h>

#define WHOAMI "BindIP DLL"
#include "picocrt.h"

#define WSA_WANTED
#include "ForceBindIPHelpers.h"

#define WINAPI_PROLOGUE_SIZE 5

typedef struct BindIP_HookData_S {
    const TCHAR *const moduleName;
    const CHAR *const funcName;
    LPVOID funcPtr;
    UINT_PTR hookPtr;
    BYTE origData[WINAPI_PROLOGUE_SIZE];
    BYTE hookedData[WINAPI_PROLOGUE_SIZE];
    PROC trampoline;
} BindIP_HookData;

#define DECLARE_HOOK(module, func, hook)                                                                                       \
    { .moduleName = _T(module), .funcName = (func), .hookPtr = (UINT_PTR)(hook) }

typedef int(WSAAPI *funcDecl_sendto)(
    _In_ SOCKET s, _In_reads_bytes_(len) const char FAR *buf, _In_ int len, _In_ int flags,
    _In_reads_bytes_(tolen) const struct sockaddr FAR *to, _In_ int tolen
);
int WINAPI funcHook_sendto(SOCKET s, const char *buf, int len, int flags, const SOCKADDR *to, int tolen);

typedef enum {
    Hook_sendto,
} BindIP_HookList;

BindIP_HookData hookData[] = {
    [Hook_sendto] = DECLARE_HOOK("WS2_32", "sendto", funcHook_sendto),
};

static DWORD ipAddr_GlobalVar = 0;
HANDLE hMutex = INVALID_HANDLE_VALUE;

int WINAPI funcHook_sendto(SOCKET s, const char *buf, int len, int flags, const SOCKADDR *to, int tolen) {
    SOCKADDR_IN sockname = {0};
    int salen = sizeof(sockname);
    int rv = 0;
    if (getsockname(s, (SOCKADDR *)&sockname, &salen) == SOCKET_ERROR) {
        rv = WSAGetLastError();
    }
    switch (rv) {
        case 0:
        case WSAEINVAL: /* Can occur on the first sendto() without prior bind() */ {
            switch (to->sa_family) {
                case AF_INET: {
                    if (rv == WSAEINVAL || ((CONST SOCKADDR_IN *)&sockname)->sin_addr.S_un.S_addr == INADDR_ANY) {
                        const SOCKADDR_IN sb = {.sin_family = AF_INET, .sin_addr.S_un.S_addr = ipAddr_GlobalVar, .sin_port = 0};
                        wsacall(bind(s, (CONST SOCKADDR *)&sb, sizeof(sb)));
                    }
                    break;
                }
                case AF_INET6: {
                    /* TODO */
                    DebugBreak();
                    break;
                }
                default: {
                }
            }
            break;
        }
        default: {
        }
    }

    return ((funcDecl_sendto)hookData[Hook_sendto].trampoline)(s, buf, len, flags, to, tolen);
}

/* DONE: implement trampolines
 * https://medium.com/geekculture/basic-windows-api-hooking-acb8d275e9b8
 * https://stackoverflow.com/a/45061320/1543625
 */
static int SetupHooks(void) {
#define IPADDR_MAX 64
    TCHAR ipAddrFromEnvVar[IPADDR_MAX];
    CHAR ipAddrString[IPADDR_MAX];

    if (GetEnvironmentVariable(_T("FORCEDIP"), ipAddrFromEnvVar, countof(ipAddrFromEnvVar)) == 0 ||
        ipAddrFromEnvVar[0] == '\0') {
        return 0;
    }

#if !defined(UNICODE)
    lstrcpy(ipAddrString, ipAddrFromEnvVar);
#else
    WideCharToMultiByte(CP_UTF8, 0, ipAddrFromEnvVar, -1, ipAddrString, countof(ipAddrString), 0, 0);
#endif

    ipAddr_GlobalVar = inet_addr(ipAddrString);

    for (unsigned i = 0; i < countof(hookData); ++i) {
        BindIP_HookData *d = &hookData[i];
        const HANDLE hModule = GetModuleHandle(d->moduleName);
        if (hModule == NULL) {
            return FALSE;
        }
        const HANDLE hProcess = GetCurrentProcess();
        const LPVOID funcPtr = (LPVOID)GetProcAddress(hModule, d->funcName);
        if (ReadProcessMemory(hProcess, funcPtr, d->origData, sizeof(d->origData), NULL) != TRUE) {
            return FALSE;
        }

        d->funcPtr = funcPtr;
        UINT_PTR trampolineEnd = (UINT_PTR)funcPtr + WINAPI_PROLOGUE_SIZE;

        CONST SIZE_T trampolineSize = 11;
        BYTE *trampolineStart = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT, PAGE_READWRITE);
        if (trampolineStart == NULL) {
            return FALSE;
        }
        memcpy(trampolineStart, d->origData, sizeof(d->origData));
        trampolineStart[WINAPI_PROLOGUE_SIZE] = 0x68; /* push funcPtr + WINAPI_PROLOGUE_SIZE */
        memcpy(&trampolineStart[6], &trampolineEnd, sizeof(trampolineEnd));
        trampolineStart[10] = 0xC3; /* ret */
        DWORD oldProtect;
        if (VirtualProtect(trampolineStart, trampolineSize, PAGE_EXECUTE_READ, &oldProtect) != TRUE) {
            return FALSE;
        }
        d->trampoline = (PROC)trampolineStart;

        UINT_PTR relativeOffset = d->hookPtr - trampolineEnd;
        d->hookedData[0] = 0xE9; /* jmp */
        memcpy(&d->hookedData[1], &relativeOffset, sizeof(relativeOffset));
        if (WriteProcessMemory(hProcess, funcPtr, d->hookedData, sizeof(d->hookedData), NULL) != TRUE) {
            return FALSE;
        }
    }

    return TRUE;
}

/* 0 is failure, 1 is success */
int WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH: {
#if 0
            MessageBox(NULL, _T("DllMain, DLL_PROCESS_ATTACH"), _T("BindIPDLL"), MB_OK);
#endif
            return SetupHooks();
        }
        case DLL_THREAD_ATTACH: /* NOLINT(bugprone-branch-clone) */
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH: {
            return TRUE;
        }
        default: {
            MessageBox(NULL, _T("DllMain, unknown op"), _T("BindIPDLL"), MB_OK);
            return FALSE; /* F A I L */
        }
    }
}
