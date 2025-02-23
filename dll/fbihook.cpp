#include "pch.h"
#include "MinHook.h"

static DWORD g_preferred_addr = 0;
static IN6_ADDR g_preferred_addr6 = {0};

typedef SOCKET(WSAAPI *pSocket)(int af, int type, int protocol);
typedef int(WSAAPI *pBind)(SOCKET s, const struct sockaddr *addr, int namelen);
typedef int(WSAAPI *pConnect)(SOCKET s, const struct sockaddr *name, int namelen);
typedef int(WSAAPI *pSendTo)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
typedef int(WSAAPI *pGetSockName)(SOCKET s, struct sockaddr *name, int *namelen);

static pSocket original_socket = nullptr;
static pBind original_bind = nullptr;
static pConnect original_connect = nullptr;
static pSendTo original_sendto = nullptr;
static pGetSockName original_getsockname = nullptr;

void parse_preferred_ip()
{
    TCHAR buffer[256];
    GetEnvironmentVariable(_T("PREFERRED_IP"), buffer, 256);
    std::basic_string<TCHAR> pref_ip(buffer);

    if (pref_ip.find(_T("IPv4:")) == 0)
    {
        std::basic_string<TCHAR> ip_str = pref_ip.substr(5);
        struct in_addr addr;
        if (InetPton(AF_INET, ip_str.c_str(), &addr) == 1)
        {
            g_preferred_addr = addr.s_addr;
        }
    }
    else if (pref_ip.find(_T("IPv6:")) == 0)
    {
        std::basic_string<TCHAR> ip_str = pref_ip.substr(5);
        InetPton(AF_INET6, ip_str.c_str(), &g_preferred_addr6);
    }
}

static BOOL enforce_binding(SOCKET s, int family)
{
    SOCKADDR_STORAGE bind_addr = {0};
    int bind_len;
    int sock_type;
    int optlen = sizeof(sock_type);

    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&sock_type, &optlen) == SOCKET_ERROR)
        return FALSE;

    if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM)
        return TRUE;

    if (family == AF_INET && g_preferred_addr != 0)
    {
        ((SOCKADDR_IN *)&bind_addr)->sin_family = AF_INET;
        ((SOCKADDR_IN *)&bind_addr)->sin_addr.s_addr = g_preferred_addr;
        bind_len = sizeof(SOCKADDR_IN);
    }
    else if (family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&g_preferred_addr6))
    {
        ((SOCKADDR_IN6 *)&bind_addr)->sin6_family = AF_INET6;
        ((SOCKADDR_IN6 *)&bind_addr)->sin6_addr = g_preferred_addr6;
        bind_len = sizeof(SOCKADDR_IN6);
    }
    else
    {
        return TRUE;
    }

    return original_bind(s, (SOCKADDR *)&bind_addr, bind_len) == 0;
}

SOCKET WSAAPI hooked_socket(int af, int type, int protocol)
{
    SOCKET s = original_socket(af, type, protocol);
    if (s != INVALID_SOCKET)
    {
        enforce_binding(s, af);
    }
    return s;
}

int WSAAPI hooked_bind(SOCKET s, const struct sockaddr *addr, int namelen)
{
    return original_bind(s, addr, namelen);
}

int WSAAPI hooked_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    enforce_binding(s, name->sa_family);
    return original_connect(s, name, namelen);
}

int WSAAPI hooked_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
    return original_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI hooked_getsockname(SOCKET s, struct sockaddr *name, int *namelen)
{
    return original_getsockname(s, name, namelen);
}

static BOOL initialize_hooks()
{
    HMODULE ws2_32 = GetModuleHandle(_T("WS2_32"));
    if (!ws2_32)
        return FALSE;

    FARPROC socket_addr = GetProcAddress(ws2_32, "socket");
    FARPROC bind_addr = GetProcAddress(ws2_32, "bind");
    FARPROC connect_addr = GetProcAddress(ws2_32, "connect");
    FARPROC sendto_addr = GetProcAddress(ws2_32, "sendto");
    FARPROC getsockname_addr = GetProcAddress(ws2_32, "getsockname");

    if (!socket_addr || !bind_addr || !connect_addr || !sendto_addr || !getsockname_addr)
        return FALSE;

    if (MH_CreateHook(socket_addr, &hooked_socket, (LPVOID *)&original_socket) != MH_OK ||
        MH_CreateHook(bind_addr, &hooked_bind, (LPVOID *)&original_bind) != MH_OK ||
        MH_CreateHook(connect_addr, &hooked_connect, (LPVOID *)&original_connect) != MH_OK ||
        MH_CreateHook(sendto_addr, &hooked_sendto, (LPVOID *)&original_sendto) != MH_OK ||
        MH_CreateHook(getsockname_addr, &hooked_getsockname, (LPVOID *)&original_getsockname) != MH_OK)
    {
        return FALSE;
    }

    return MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        parse_preferred_ip();
        if (MH_Initialize() != MH_OK)
            return FALSE;
        return initialize_hooks();

    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        return TRUE;

    default:
        return TRUE;
    }
}