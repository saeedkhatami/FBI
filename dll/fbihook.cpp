#include "pch.h"
#include "MinHook.h"
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

static DWORD g_preferred_ipv4_addr = 0;
static IN6_ADDR g_preferred_ipv6_addr = { 0 };
static DWORD g_interface_index = 0;
static bool g_use_interface = false;

typedef SOCKET(WSAAPI* pSocket)(int af, int type, int protocol);
typedef int(WSAAPI* pBind)(SOCKET s, const struct sockaddr* addr, int namelen);
typedef int(WSAAPI* pConnect)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int(WSAAPI* pSendTo)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
typedef int(WSAAPI* pGetSockName)(SOCKET s, struct sockaddr* name, int* namelen);

static pSocket original_socket = nullptr;
static pBind original_bind = nullptr;
static pConnect original_connect = nullptr;
static pSendTo original_sendto = nullptr;
static pGetSockName original_getsockname = nullptr;

void parse_preferred_binding()
{
    TCHAR buffer[256];
    if (GetEnvironmentVariable(_T("PREFERRED_IP"), buffer, 256) > 0)
    {
        std::basic_string<TCHAR> pref_ip(buffer);
        if (pref_ip.find(_T("IPv4:")) == 0)
        {
            std::basic_string<TCHAR> ip_str = pref_ip.substr(5);
            struct in_addr addr;
            if (InetPton(AF_INET, ip_str.c_str(), &addr) == 1)
            {
                g_preferred_ipv4_addr = addr.s_addr;
            }
        }
        else if (pref_ip.find(_T("IPv6:")) == 0)
        {
            std::basic_string<TCHAR> ip_str = pref_ip.substr(5);
            InetPton(AF_INET6, ip_str.c_str(), &g_preferred_ipv6_addr);
        }
    }
    else if (GetEnvironmentVariable(_T("PREFERRED_INTERFACE"), buffer, 256) > 0)
    {
        std::basic_string<TCHAR> guid_str(buffer);
        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (!pAddresses) return;

        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            if (!pAddresses) return;
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        }

        if (dwRetVal == NO_ERROR)
        {
            for (PIP_ADAPTER_ADDRESSES pAdapter = pAddresses; pAdapter != NULL; pAdapter = pAdapter->Next)
            {
                std::basic_string<TCHAR> adapterName;
#ifdef _UNICODE
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, pAdapter->AdapterName, -1, NULL, 0);
                std::wstring wstr(size_needed - 1, 0);
                MultiByteToWideChar(CP_UTF8, 0, pAdapter->AdapterName, -1, &wstr[0], size_needed);
                adapterName = wstr;
#else
                adapterName = std::string(pAdapter->AdapterName);
#endif
                if (adapterName == guid_str)
                {
                    g_interface_index = pAdapter->IfIndex;
                    g_use_interface = true;
                    for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next)
                    {
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                            g_preferred_ipv4_addr = sa_in->sin_addr.s_addr;
                            break;
                        }
                    }
                    break;
                }
            }
        }
        free(pAddresses);
    }
}

static BOOL enforce_binding(SOCKET s, int family)
{
    SOCKADDR_STORAGE bind_addr = { 0 };
    int bind_len;
    int sock_type;
    int optlen = sizeof(sock_type);

    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &optlen) == SOCKET_ERROR)
        return FALSE;

    if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM)
        return TRUE;

    if (family == AF_INET && g_preferred_ipv4_addr != 0)
    {
        ((SOCKADDR_IN*)&bind_addr)->sin_family = AF_INET;
        ((SOCKADDR_IN*)&bind_addr)->sin_addr.s_addr = g_preferred_ipv4_addr;
        bind_len = sizeof(SOCKADDR_IN);
    }
    else if (family == AF_INET6)
    {
        if (g_use_interface && g_interface_index != 0)
        {
            ((SOCKADDR_IN6*)&bind_addr)->sin6_family = AF_INET6;
            ((SOCKADDR_IN6*)&bind_addr)->sin6_addr = in6addr_any;
            ((SOCKADDR_IN6*)&bind_addr)->sin6_scope_id = g_interface_index;
            bind_len = sizeof(SOCKADDR_IN6);
        }
        else if (!IN6_IS_ADDR_UNSPECIFIED(&g_preferred_ipv6_addr))
        {
            ((SOCKADDR_IN6*)&bind_addr)->sin6_family = AF_INET6;
            ((SOCKADDR_IN6*)&bind_addr)->sin6_addr = g_preferred_ipv6_addr;
            bind_len = sizeof(SOCKADDR_IN6);
        }
        else
        {
            return TRUE;
        }
    }
    else
    {
        return TRUE;
    }

    return original_bind(s, (SOCKADDR*)&bind_addr, bind_len) == 0;
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

int WSAAPI hooked_bind(SOCKET s, const struct sockaddr* addr, int namelen)
{
    return original_bind(s, addr, namelen);
}

int WSAAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    enforce_binding(s, name->sa_family);
    if (name->sa_family == AF_INET6 && g_use_interface && g_interface_index != 0)
    {
        sockaddr_in6* addr6 = (sockaddr_in6*)name;
        if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && addr6->sin6_scope_id == 0)
        {
            sockaddr_in6 modified_addr = *addr6;
            modified_addr.sin6_scope_id = g_interface_index;
            return original_connect(s, (sockaddr*)&modified_addr, namelen);
        }
    }
    return original_connect(s, name, namelen);
}

int WSAAPI hooked_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    return original_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI hooked_getsockname(SOCKET s, struct sockaddr* name, int* namelen)
{
    return original_getsockname(s, name, namelen);
}

static BOOL initialize_hooks()
{
    HMODULE ws2_32 = GetModuleHandle(_T("WS2_32"));
    if (!ws2_32) return FALSE;

    FARPROC socket_addr = GetProcAddress(ws2_32, "socket");
    FARPROC bind_addr = GetProcAddress(ws2_32, "bind");
    FARPROC connect_addr = GetProcAddress(ws2_32, "connect");
    FARPROC sendto_addr = GetProcAddress(ws2_32, "sendto");
    FARPROC getsockname_addr = GetProcAddress(ws2_32, "getsockname");

    if (!socket_addr || !bind_addr || !connect_addr || !sendto_addr || !getsockname_addr)
        return FALSE;

    if (MH_CreateHook(socket_addr, &hooked_socket, (LPVOID*)&original_socket) != MH_OK ||
        MH_CreateHook(bind_addr, &hooked_bind, (LPVOID*)&original_bind) != MH_OK ||
        MH_CreateHook(connect_addr, &hooked_connect, (LPVOID*)&original_connect) != MH_OK ||
        MH_CreateHook(sendto_addr, &hooked_sendto, (LPVOID*)&original_sendto) != MH_OK ||
        MH_CreateHook(getsockname_addr, &hooked_getsockname, (LPVOID*)&original_getsockname) != MH_OK)
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
        parse_preferred_binding();
        if (MH_Initialize() != MH_OK) return FALSE;
        return initialize_hooks();

    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        return TRUE;

    default:
        return TRUE;
    }
}