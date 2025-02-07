#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tchar.h>

#define WHOAMI "BindIP DLL"
#include "picocrt.h"

#define WSA_WANTED
#include "helper.h"

#ifdef _WIN64
#define WINAPI_PROLOGUE_SIZE 12
typedef struct BindIP_HookData64_S
{
    BYTE origData[WINAPI_PROLOGUE_SIZE];
    BYTE hookedData[WINAPI_PROLOGUE_SIZE];
    PROC trampoline;
    UINT_PTR padding;
} BindIP_HookData64;
#else
#define WINAPI_PROLOGUE_SIZE 5
typedef struct BindIP_HookData32_S
{
    BYTE origData[WINAPI_PROLOGUE_SIZE];
    BYTE hookedData[WINAPI_PROLOGUE_SIZE];
    PROC trampoline;
} BindIP_HookData32;
#endif

typedef struct BindIP_HookData_S
{
    const TCHAR *const moduleName;
    const CHAR *const funcName;
    LPVOID funcPtr;
    UINT_PTR hookPtr;
#ifdef _WIN64
    BindIP_HookData64 platform;
#else
    BindIP_HookData32 platform;
#endif
} BindIP_HookData;

#define DECLARE_HOOK(module, func, hook) {.moduleName = _T(module), .funcName = (func), .hookPtr = (UINT_PTR)(hook)}

static DWORD g_preferred_addr = 0;
static IN6_ADDR g_preferred_addr6 = {0};
static HANDLE g_sync_handle = INVALID_HANDLE_VALUE;
static BOOL g_is_disabled = FALSE;

static BOOL check_operation_status(void)
{
    TCHAR killSwitch[8];
    return GetEnvironmentVariable(_T("FORCEDIP_DISABLE"), killSwitch, countof(killSwitch)) > 0;
}

typedef enum
{
    Hook_network_op,
    Hook_connect_op,
    Hook_bind_op,
    Hook_getsockname_op,
} NetworkHookList;

typedef int(WSAAPI *fn_network_op)(
    _In_ SOCKET s, _In_reads_bytes_(len) const char FAR *buf, _In_ int len, _In_ int flags,
    _In_reads_bytes_(tolen) const struct sockaddr FAR *to, _In_ int tolen);

typedef int(WSAAPI *fn_connect_op)(
    _In_ SOCKET s,
    _In_reads_bytes_(namelen) const struct sockaddr FAR *name,
    _In_ int namelen);

typedef int(WSAAPI *fn_bind_op)(
    _In_ SOCKET s,
    _In_reads_bytes_(namelen) const struct sockaddr FAR *name,
    _In_ int namelen);

typedef int(WSAAPI *fn_getsockname_op)(
    _In_ SOCKET s,
    _Out_writes_bytes_to_(*namelen, *namelen) struct sockaddr FAR *name,
    _Inout_ int FAR *namelen);

static void system_network_initialize(void) {}
static void network_cleanup_routine(void) {}

int WINAPI network_packet_handler(SOCKET s, const char *buf, int len, int flags, const SOCKADDR *to, int tolen);
int WINAPI network_connect_handler(SOCKET s, const struct sockaddr *name, int namelen);
int WINAPI network_bind_handler(SOCKET s, const struct sockaddr *name, int namelen);
int WINAPI network_getsockname_handler(SOCKET s, struct sockaddr *name, int *namelen);

static BindIP_HookData hookData[] = {
    [Hook_network_op] = DECLARE_HOOK("WS2_32", "sendto", network_packet_handler),
    [Hook_connect_op] = DECLARE_HOOK("WS2_32", "connect", network_connect_handler),
    [Hook_bind_op] = DECLARE_HOOK("WS2_32", "bind", network_bind_handler),
    [Hook_getsockname_op] = DECLARE_HOOK("WS2_32", "getsockname", network_getsockname_handler),
};

static BOOL enforce_binding(SOCKET s, int family)
{
    SOCKADDR_STORAGE bind_addr = {0};
    int bind_len;

    int sock_type;
    int optlen = sizeof(sock_type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&sock_type, &optlen) == SOCKET_ERROR)
    {
        return FALSE;
    }

    if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM)
    {
        return TRUE;
    }

    switch (family)
    {
    case AF_INET:
    {
        if (g_preferred_addr == 0)
            return TRUE;
        SOCKADDR_IN *addr4 = (SOCKADDR_IN *)&bind_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = g_preferred_addr;
        addr4->sin_port = 0;
        bind_len = sizeof(SOCKADDR_IN);
        break;
    }
    case AF_INET6:
    {
        if (IN6_IS_ADDR_UNSPECIFIED(&g_preferred_addr6))
            return TRUE;
        SOCKADDR_IN6 *addr6 = (SOCKADDR_IN6 *)&bind_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = g_preferred_addr6;
        addr6->sin6_port = 0;
        bind_len = sizeof(SOCKADDR_IN6);
        break;
    }
    default:
        return TRUE;
    }

    return bind(s, (SOCKADDR *)&bind_addr, bind_len) == 0;
}

int WINAPI network_packet_handler(SOCKET s, const char *buf, int len, int flags, const SOCKADDR *to, int tolen)
{
    if (check_operation_status())
    {
        return ((fn_network_op)hookData[Hook_network_op].platform.trampoline)(s, buf, len, flags, to, tolen);
    }

    SOCKADDR_STORAGE sockname = {0};
    int salen = sizeof(sockname);
    int rv = 0;
    if (getsockname(s, (SOCKADDR *)&sockname, &salen) == SOCKET_ERROR)
    {
        rv = WSAGetLastError();
    }
    switch (rv)
    {
    case 0:
    case WSAEINVAL:
    {
        switch (to->sa_family)
        {
        case AF_INET:
        {
            if (rv == WSAEINVAL || ((CONST SOCKADDR_IN *)&sockname)->sin_addr.S_un.S_addr == INADDR_ANY)
            {
                const SOCKADDR_IN sb = {.sin_family = AF_INET, .sin_addr.S_un.S_addr = g_preferred_addr, .sin_port = 0};
                wsacall(bind(s, (CONST SOCKADDR *)&sb, sizeof(sb)));
            }
            break;
        }
        case AF_INET6:
        {
            if (rv == WSAEINVAL || IN6_IS_ADDR_UNSPECIFIED(&((CONST SOCKADDR_IN6 *)&sockname)->sin6_addr))
            {
                SOCKADDR_IN6 sb = {0};
                sb.sin6_family = AF_INET6;
                sb.sin6_addr = g_preferred_addr6;
                wsacall(bind(s, (CONST SOCKADDR *)&sb, sizeof(sb)));
            }
            break;
        }
        default:
        {
        }
        }
        break;
    }
    default:
    {
    }
    }

    return ((fn_network_op)hookData[Hook_network_op].platform.trampoline)(s, buf, len, flags, to, tolen);
}

int WINAPI network_connect_handler(SOCKET s, const struct sockaddr *name, int namelen)
{
    if (!check_operation_status())
    {
        enforce_binding(s, name->sa_family);
    }
    return ((fn_connect_op)hookData[Hook_connect_op].platform.trampoline)(s, name, namelen);
}

int WINAPI network_bind_handler(SOCKET s, const struct sockaddr *name, int namelen)
{
    if (!check_operation_status())
    {
        switch (name->sa_family)
        {
        case AF_INET:
        {
            if (g_preferred_addr != 0)
            {
                SOCKADDR_IN bind_addr = {0};
                bind_addr.sin_family = AF_INET;
                bind_addr.sin_addr.s_addr = g_preferred_addr;
                bind_addr.sin_port = ((SOCKADDR_IN *)name)->sin_port;
                return ((fn_bind_op)hookData[Hook_bind_op].platform.trampoline)(
                    s, (SOCKADDR *)&bind_addr, sizeof(bind_addr));
            }
            break;
        }
        case AF_INET6:
        {
            if (!IN6_IS_ADDR_UNSPECIFIED(&g_preferred_addr6))
            {
                SOCKADDR_IN6 bind_addr = {0};
                bind_addr.sin6_family = AF_INET6;
                bind_addr.sin6_addr = g_preferred_addr6;
                bind_addr.sin6_port = ((SOCKADDR_IN6 *)name)->sin6_port;
                return ((fn_bind_op)hookData[Hook_bind_op].platform.trampoline)(
                    s, (SOCKADDR *)&bind_addr, sizeof(bind_addr));
            }
            break;
        }
        }
    }
    return ((fn_bind_op)hookData[Hook_bind_op].platform.trampoline)(s, name, namelen);
}

int WINAPI network_getsockname_handler(SOCKET s, struct sockaddr *name, int *namelen)
{
    int ret = ((fn_getsockname_op)hookData[Hook_getsockname_op].platform.trampoline)(s, name, namelen);
    if (ret == 0 && !check_operation_status())
    {
        switch (name->sa_family)
        {
        case AF_INET:
        {
            if (g_preferred_addr != 0)
            {
                ((SOCKADDR_IN *)name)->sin_addr.s_addr = g_preferred_addr;
            }
            break;
        }
        case AF_INET6:
        {
            if (!IN6_IS_ADDR_UNSPECIFIED(&g_preferred_addr6))
            {
                ((SOCKADDR_IN6 *)name)->sin6_addr = g_preferred_addr6;
            }
            break;
        }
        }
    }
    return ret;
}

static BOOL setup_hook_x86(BindIP_HookData *d, UINT_PTR endpoint)
{
    CONST SIZE_T trampolineSize = 11;
    BYTE *trampolineStart = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT, PAGE_READWRITE);
    if (trampolineStart == NULL)
        return FALSE;

    memcpy(trampolineStart, d->platform.origData, WINAPI_PROLOGUE_SIZE);
    trampolineStart[WINAPI_PROLOGUE_SIZE] = 0x68;
    memcpy(&trampolineStart[6], &endpoint, sizeof(endpoint));
    trampolineStart[10] = 0xC3;

    DWORD oldProtect;
    if (VirtualProtect(trampolineStart, trampolineSize, PAGE_EXECUTE_READ, &oldProtect) != TRUE)
    {
        VirtualFree(trampolineStart, 0, MEM_RELEASE);
        return FALSE;
    }

    d->platform.trampoline = (PROC)trampolineStart;
    UINT_PTR relativeOffset = d->hookPtr - endpoint;
    d->platform.hookedData[0] = 0xE9;
    memcpy(&d->platform.hookedData[1], &relativeOffset, sizeof(relativeOffset));
    return TRUE;
}

static BOOL setup_hook_x64(BindIP_HookData *d, UINT_PTR endpoint)
{
    CONST SIZE_T trampolineSize = 32;
    BYTE *trampolineStart = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT, PAGE_READWRITE);
    if (trampolineStart == NULL)
        return FALSE;

    memcpy(trampolineStart, d->platform.origData, WINAPI_PROLOGUE_SIZE);

    trampolineStart[WINAPI_PROLOGUE_SIZE + 0] = 0x48;
    trampolineStart[WINAPI_PROLOGUE_SIZE + 1] = 0xB8;
    *((UINT_PTR *)&trampolineStart[WINAPI_PROLOGUE_SIZE + 2]) = endpoint;

    trampolineStart[WINAPI_PROLOGUE_SIZE + 10] = 0xFF;
    trampolineStart[WINAPI_PROLOGUE_SIZE + 11] = 0xE0;

    DWORD oldProtect;
    if (VirtualProtect(trampolineStart, trampolineSize, PAGE_EXECUTE_READ, &oldProtect) != TRUE)
    {
        VirtualFree(trampolineStart, 0, MEM_RELEASE);
        return FALSE;
    }

    d->platform.trampoline = (PROC)trampolineStart;
    d->platform.hookedData[0] = 0xFF;
    d->platform.hookedData[1] = 0x25;
    d->platform.hookedData[2] = 0x00;
    d->platform.hookedData[3] = 0x00;
    d->platform.hookedData[4] = 0x00;
    d->platform.hookedData[5] = 0x00;
    *((UINT_PTR *)&d->platform.hookedData[6]) = d->hookPtr;
    return TRUE;
}

static BOOL setup_hook(BindIP_HookData *d, UINT_PTR endpoint) {
#ifdef _WIN64
    return setup_hook_x64(d, endpoint);
#else
    return setup_hook_x86(d, endpoint);
#endif
}

static int initialize_network_hooks(void)
{
#define IPADDR_MAX 64
    TCHAR ipAddrFromEnvVar[IPADDR_MAX];
    CHAR ipAddrString[IPADDR_MAX];

    if (check_operation_status())
    {
        g_is_disabled = TRUE;
        return TRUE;
    }

    if (GetEnvironmentVariable(_T("FORCEDIP"), ipAddrFromEnvVar, countof(ipAddrFromEnvVar)) == 0 ||
        ipAddrFromEnvVar[0] == '\0')
    {
        return 0;
    }

#if !defined(UNICODE)
    lstrcpy(ipAddrString, ipAddrFromEnvVar);
#else
    WideCharToMultiByte(CP_UTF8, 0, ipAddrFromEnvVar, -1, ipAddrString, countof(ipAddrString), 0, 0);
#endif

    if (strchr(ipAddrString, ':') != NULL)
    {

        if (inet_pton(AF_INET6, ipAddrString, &g_preferred_addr6) != 1)
        {
            return FALSE;
        }
        g_preferred_addr = 0;
    }
    else
    {

        if (inet_pton(AF_INET, ipAddrString, &g_preferred_addr) != 1)
        {
            return FALSE;
        }
        memset(&g_preferred_addr6, 0, sizeof(g_preferred_addr6));
    }

    for (unsigned i = 0; i < countof(hookData); ++i)
    {
        BindIP_HookData *d = &hookData[i];
        const HANDLE hModule = GetModuleHandle(d->moduleName);
        if (hModule == NULL)
        {
            return FALSE;
        }
        const HANDLE hProcess = GetCurrentProcess();
        const LPVOID funcPtr = (LPVOID)GetProcAddress(hModule, d->funcName);
        if (ReadProcessMemory(hProcess, funcPtr, d->platform.origData, WINAPI_PROLOGUE_SIZE, NULL) != TRUE)
        {
            return FALSE;
        }

        d->funcPtr = funcPtr;
        UINT_PTR trampolineEnd = (UINT_PTR)funcPtr + WINAPI_PROLOGUE_SIZE;

        if (!setup_hook(d, trampolineEnd)) {
            return FALSE;
        }

        if (WriteProcessMemory(hProcess, funcPtr, d->platform.hookedData, WINAPI_PROLOGUE_SIZE, NULL) != TRUE)
        {
            return FALSE;
        }
    }

    return TRUE;
}

int WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule; (void)reserved; // Silence warnings C4100

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        system_network_initialize();
        g_is_disabled = check_operation_status();
#if defined(DEBUG)
        if (g_is_disabled)
        {
            MessageBox(NULL, _T("ForceBindIP is disabled via kill switch"), _T("BindIPDLL"), MB_OK);
        }
#endif
        return initialize_network_hooks();
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
    {
        network_cleanup_routine();
        return TRUE;
    }
    default:
    {
        MessageBox(NULL, _T("DllMain, unknown op"), _T("BindIPDLL"), MB_OK);
        return FALSE;
    }
    }
}
