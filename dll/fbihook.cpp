#include "pch.h"
#include "MinHook.h"

static bool verbose = false;
static SOCKADDR_IN g_preferred_ipv4_addr = {0};
static SOCKADDR_IN6 g_preferred_ipv6_addr = {0};
static DWORD g_interface_index = 0;
static bool g_use_interface = false;
static bool g_bind_tcp = false;
static bool g_bind_udp = false;
static int g_bind_port = 0;
static HANDLE log_file = INVALID_HANDLE_VALUE;

typedef SOCKET(WSAAPI *pSocket)(int af, int type, int protocol);
typedef int(WSAAPI *pBind)(SOCKET s, const struct sockaddr *addr, int namelen);
typedef int(WSAAPI *pConnect)(SOCKET s, const struct sockaddr *name, int namelen);
typedef int(WSAAPI *pSendTo)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
typedef int(WSAAPI *pGetSockName)(SOCKET s, struct sockaddr *name, int *namelen);
typedef SOCKET(WSAAPI *pWSASocket)(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo, GROUP g, DWORD dwFlags);
typedef int(WSAAPI *pWSAConnect)(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

static pSocket original_socket = nullptr;
static pBind original_bind = nullptr;
static pConnect original_connect = nullptr;
static pSendTo original_sendto = nullptr;
static pGetSockName original_getsockname = nullptr;
static pWSASocket original_WSAsocket = nullptr;
static pWSAConnect original_WSAConnect = nullptr;

void log_message(const TCHAR *format, ...)
{
    va_list args;
    va_start(args, format);
    int len = _vscwprintf(format, args) + 1;
    TCHAR *buffer = new TCHAR[len];
    _vstprintf_s(buffer, len, format, args);
    va_end(args);

    if (log_file != INVALID_HANDLE_VALUE)
    {
        int mb_len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
        char *mb_buffer = new char[mb_len];
        WideCharToMultiByte(CP_UTF8, 0, buffer, -1, mb_buffer, mb_len, NULL, NULL);
        DWORD written;
        WriteFile(log_file, mb_buffer, mb_len - 1, &written, NULL);
        delete[] mb_buffer;
    }

    if (verbose)
    {
        OutputDebugString(buffer);
    }

    delete[] buffer;
}

std::basic_string<TCHAR> standardize_guid(const std::basic_string<TCHAR> &guid)
{
    std::basic_string<TCHAR> clean_guid = guid;
    if (!clean_guid.empty() && clean_guid.front() == _T('{') && clean_guid.back() == _T('}'))
    {
        clean_guid = clean_guid.substr(1, clean_guid.length() - 2);
    }
    return clean_guid;
}

void parse_preferred_binding()
{
    TCHAR buffer[256];

    if (GetEnvironmentVariable(_T("VERBOSE"), buffer, 256) > 0)
    {
        verbose = (_tcscmp(buffer, _T("1")) == 0);
        if (verbose)
            log_message(_T("Verbose mode enabled in DLL\n"));
    }

    TCHAR bind_tcp[2];
    if (GetEnvironmentVariable(_T("BIND_TCP"), bind_tcp, 2) > 0 && _tcscmp(bind_tcp, _T("1")) == 0)
        g_bind_tcp = true;

    TCHAR bind_udp[2];
    if (GetEnvironmentVariable(_T("BIND_UDP"), bind_udp, 2) > 0 && _tcscmp(bind_udp, _T("1")) == 0)
        g_bind_udp = true;

    TCHAR bind_port[6];
    if (GetEnvironmentVariable(_T("BIND_PORT"), bind_port, 6) > 0)
    {
        g_bind_port = _ttoi(bind_port);
        if (verbose)
            log_message(_T("Set binding port to %d\n"), g_bind_port);
    }

    if (GetEnvironmentVariable(_T("PREFERRED_IP"), buffer, 256) > 0)
    {
        std::basic_string<TCHAR> pref_ip(buffer);
        if (pref_ip.find(_T("IPv4:")) == 0)
        {
            std::basic_string<TCHAR> ip_str = pref_ip.substr(5);
            if (InetPton(AF_INET, ip_str.c_str(), &g_preferred_ipv4_addr.sin_addr) == 1)
            {
                g_preferred_ipv4_addr.sin_family = AF_INET;
                if (verbose)
                    log_message(_T("Set preferred IPv4 address: %s\n"), ip_str.c_str());
            }
        }
        else if (pref_ip.find(_T("IPv6:")) == 0)
        {
            std::basic_string<TCHAR> ip_str = pref_ip.substr(5);
            if (InetPton(AF_INET6, ip_str.c_str(), &g_preferred_ipv6_addr.sin6_addr) == 1)
            {
                g_preferred_ipv6_addr.sin6_family = AF_INET6;
                if (verbose)
                    log_message(_T("Set preferred IPv6 address: %s\n"), ip_str.c_str());
            }
        }
    }

    else if (GetEnvironmentVariable(_T("PREFERRED_INTERFACE"), buffer, 256) > 0)
    {
        std::basic_string<TCHAR> guid_str = standardize_guid(buffer);
        if (verbose)
            log_message(_T("Standardized GUID: %s\n"), guid_str.c_str());

        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
        if (!pAddresses)
            return;

        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
            if (!pAddresses)
                return;
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        }

        if (dwRetVal == NO_ERROR)
        {
            for (PIP_ADAPTER_ADDRESSES pAdapter = pAddresses; pAdapter; pAdapter = pAdapter->Next)
            {
                int len = MultiByteToWideChar(CP_ACP, 0, pAdapter->AdapterName, -1, NULL, 0);
                std::wstring adapterName(len, 0);
                MultiByteToWideChar(CP_ACP, 0, pAdapter->AdapterName, -1, &adapterName[0], len);
                adapterName.resize(len - 1);

                if (adapterName == guid_str)
                {
                    g_interface_index = pAdapter->IfIndex;
                    g_use_interface = true;
                    if (verbose)
                        log_message(_T("Set interface index: %lu\n"), g_interface_index);

                    for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next)
                    {
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            sockaddr_in *sa_in = (sockaddr_in *)pUnicast->Address.lpSockaddr;
                            g_preferred_ipv4_addr.sin_addr = sa_in->sin_addr;
                            g_preferred_ipv4_addr.sin_family = AF_INET;
                            if (verbose)
                            {
                                TCHAR ip_str[INET_ADDRSTRLEN];
                                InetNtop(AF_INET, &sa_in->sin_addr, ip_str, INET_ADDRSTRLEN);
                                log_message(_T("Set preferred IPv4 from interface: %s\n"), ip_str);
                            }
                        }
                        else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                        {
                            sockaddr_in6 *sa_in6 = (sockaddr_in6 *)pUnicast->Address.lpSockaddr;
                            g_preferred_ipv6_addr.sin6_addr = sa_in6->sin6_addr;
                            g_preferred_ipv6_addr.sin6_family = AF_INET6;
                            if (verbose)
                            {
                                TCHAR ip_str[INET6_ADDRSTRLEN];
                                InetNtop(AF_INET6, &sa_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
                                log_message(_T("Set preferred IPv6 from interface: %s\n"), ip_str);
                            }
                        }
                    }
                    break;
                }
            }
        }
        free(pAddresses);
    }

    TCHAR log_path[MAX_PATH];
    if (GetEnvironmentVariable(_T("LOG_FILE"), log_path, MAX_PATH) > 0 && log_path[0] != _T('\0'))
    {
        log_file = CreateFile(log_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (log_file != INVALID_HANDLE_VALUE)
        {
            const char bom[] = "\xEF\xBB\xBF";
            DWORD written;
            WriteFile(log_file, bom, sizeof(bom) - 1, &written, NULL);
            log_message(_T("Logging started for process %lu\n"), GetCurrentProcessId());
        }
    }
    else
    {
        log_file = INVALID_HANDLE_VALUE;
    }
}

static BOOL enforce_binding(SOCKET s, int family, const struct sockaddr *target)
{
    SOCKADDR_STORAGE bind_addr = {0};
    int bind_len;

    if (family == AF_INET && g_preferred_ipv4_addr.sin_addr.s_addr != 0)
    {
        SOCKADDR_IN *sin = (SOCKADDR_IN *)&bind_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = g_preferred_ipv4_addr.sin_addr.s_addr;
        sin->sin_port = (g_bind_port != 0) ? htons((u_short)g_bind_port) : 0;
        bind_len = sizeof(SOCKADDR_IN);
    }
    else if (family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&g_preferred_ipv6_addr.sin6_addr))
    {
        SOCKADDR_IN6 *sin6 = (SOCKADDR_IN6 *)&bind_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = g_preferred_ipv6_addr.sin6_addr;
        sin6->sin6_port = (g_bind_port != 0) ? htons((u_short)g_bind_port) : 0;
        bind_len = sizeof(SOCKADDR_IN6);
    }
    else
    {
        if (verbose)
            log_message(_T("No preferred address for family %d\n"), family);
        return TRUE;
    }

    int bind_result = original_bind(s, (SOCKADDR *)&bind_addr, bind_len);
    if (bind_result != 0)
    {
        if (verbose)
            log_message(_T("Binding failed: %d\n"), WSAGetLastError());
        return FALSE;
    }

    if (verbose)
    {
        SOCKADDR_STORAGE local_addr;
        int addr_len = sizeof(local_addr);
        if (original_getsockname(s, (SOCKADDR *)&local_addr, &addr_len) == 0)
        {
            TCHAR ip_str[INET6_ADDRSTRLEN];
            if (local_addr.ss_family == AF_INET)
            {
                SOCKADDR_IN *sin = (SOCKADDR_IN *)&local_addr;
                InetNtop(AF_INET, &sin->sin_addr, ip_str, INET_ADDRSTRLEN);
                log_message(_T("Bound to IPv4: %s:%d\n"), ip_str, ntohs(sin->sin_port));
            }
            else if (local_addr.ss_family == AF_INET6)
            {
                SOCKADDR_IN6 *sin6 = (SOCKADDR_IN6 *)&local_addr;
                InetNtop(AF_INET6, &sin6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
                log_message(_T("Bound to IPv6: %s:%d\n"), ip_str, ntohs(sin6->sin6_port));
            }
        }
    }
    return TRUE;
}

SOCKET WSAAPI hooked_socket(int af, int type, int protocol)
{
    SOCKET s = original_socket(af, type, protocol);
    if (verbose)
        log_message(_T("Socket %d created: af=%d, type=%d, protocol=%d\n"), s, af, type, protocol);
    return s;
}

int WSAAPI hooked_bind(SOCKET s, const struct sockaddr *addr, int namelen)
{
    TCHAR ip_str[INET6_ADDRSTRLEN];
    if (addr->sa_family == AF_INET)
    {
        SOCKADDR_IN *sin = (SOCKADDR_IN *)addr;
        InetNtop(AF_INET, &sin->sin_addr, ip_str, INET_ADDRSTRLEN);
        log_message(_T("Bind called on socket %d to IP: %s, port: %d\n"), s, ip_str, ntohs(sin->sin_port));
    }
    else if (addr->sa_family == AF_INET6)
    {
        SOCKADDR_IN6 *sin6 = (SOCKADDR_IN6 *)addr;
        InetNtop(AF_INET6, &sin6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        log_message(_T("Bind called on socket %d to IP: %s, port: %d\n"), s, ip_str, ntohs(sin6->sin6_port));
    }
    return original_bind(s, addr, namelen);
}

int WSAAPI hooked_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    int sock_type;
    int optlen = sizeof(sock_type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&sock_type, &optlen) == SOCKET_ERROR)
    {
        if (verbose)
            log_message(_T("Failed to get socket type: %d\n"), WSAGetLastError());
        return SOCKET_ERROR;
    }

    if (g_bind_tcp && sock_type == SOCK_STREAM)
    {
        if (!enforce_binding(s, name->sa_family, name))
        {
            if (verbose)
                log_message(_T("Failed to enforce binding for TCP socket %d\n"), s);
            return SOCKET_ERROR;
        }
    }

    int result = original_connect(s, name, namelen);
    if (verbose && result != 0)
        log_message(_T("Connect failed: %d\n"), WSAGetLastError());
    if (result == 0 && verbose)
    {
        SOCKADDR_STORAGE local_addr;
        int addr_len = sizeof(local_addr);
        if (original_getsockname(s, (SOCKADDR *)&local_addr, &addr_len) == 0)
        {
            TCHAR ip_str[INET6_ADDRSTRLEN];
            if (local_addr.ss_family == AF_INET && g_preferred_ipv4_addr.sin_addr.s_addr != 0)
            {
                SOCKADDR_IN *sin = (SOCKADDR_IN *)&local_addr;
                InetNtop(AF_INET, &sin->sin_addr, ip_str, INET_ADDRSTRLEN);
                if (sin->sin_addr.s_addr == g_preferred_ipv4_addr.sin_addr.s_addr)
                {
                    log_message(_T("TCP socket %d connected and bound to preferred IP: %s\n"), s, ip_str);
                }
                else
                {
                    log_message(_T("Warning: TCP socket %d connected but not bound to preferred IP (using %s instead)\n"), s, ip_str);
                }
            }
            else if (local_addr.ss_family == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&g_preferred_ipv6_addr.sin6_addr))
            {
                SOCKADDR_IN6 *sin6 = (SOCKADDR_IN6 *)&local_addr;
                InetNtop(AF_INET6, &sin6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
                if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &g_preferred_ipv6_addr.sin6_addr))
                {
                    log_message(_T("TCP socket %d connected and bound to preferred IP: %s\n"), s, ip_str);
                }
                else
                {
                    log_message(_T("Warning: TCP socket %d connected but not bound to preferred IP (using %s instead)\n"), s, ip_str);
                }
            }
        }
    }
    return result;
}

int WSAAPI hooked_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
    int sock_type;
    int optlen = sizeof(sock_type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&sock_type, &optlen) == 0 && sock_type == SOCK_DGRAM)
    {
        if (g_bind_udp)
        {
            sockaddr_storage addr;
            int addr_len = sizeof(addr);
            if (original_getsockname(s, (sockaddr *)&addr, &addr_len) == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL)
            {
                if (!enforce_binding(s, to->sa_family, to))
                {
                    if (verbose)
                        log_message(_T("Failed to enforce binding for UDP socket %d\n"), s);
                    return SOCKET_ERROR;
                }
            }
        }
    }
    return original_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI hooked_getsockname(SOCKET s, struct sockaddr *name, int *namelen)
{
    return original_getsockname(s, name, namelen);
}
SOCKET WSAAPI hooked_WSAsocket(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo, GROUP g, DWORD dwFlags)
{
    SOCKET s = original_WSAsocket(af, type, protocol, lpProtocolInfo, g, dwFlags);
    log_message(_T("WSASocket %d created: af=%d, type=%d, protocol=%d\n"), s, af, type, protocol);
    return s;
}

int WSAAPI hooked_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
{
    int sock_type;
    int optlen = sizeof(sock_type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&sock_type, &optlen) == SOCKET_ERROR)
    {
        log_message(_T("Failed to get socket type in WSAConnect: %d\n"), WSAGetLastError());
        return SOCKET_ERROR;
    }

    if (g_bind_tcp && sock_type == SOCK_STREAM)
    {
        SOCKADDR_STORAGE local_addr;
        int addr_len = sizeof(local_addr);
        if (original_getsockname(s, (SOCKADDR *)&local_addr, &addr_len) != 0 ||
            (local_addr.ss_family == AF_INET && ((SOCKADDR_IN *)&local_addr)->sin_addr.s_addr == INADDR_ANY) ||
            (local_addr.ss_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&((SOCKADDR_IN6 *)&local_addr)->sin6_addr)))
        {
            if (!enforce_binding(s, name->sa_family, name))
            {
                log_message(_T("Failed to enforce binding for TCP socket %d in WSAConnect\n"), s);
                return SOCKET_ERROR;
            }
        }
        else
        {
            log_message(_T("Socket %d already bound, skipping enforce_binding\n"), s);
        }
    }

    int result = original_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    if (result == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK)
        {
            log_message(_T("WSAConnect on socket %d is in progress (non-blocking)\n"), s);

            return result;
        }
        else
        {
            log_message(_T("WSAConnect failed: %d\n"), error);
            return SOCKET_ERROR;
        }
    }
    else
    {
        log_message(_T("WSAConnect succeeded for socket %d\n"), s);
    }
    return result;
}

static BOOL initialize_hooks()
{
    HMODULE ws2_32 = GetModuleHandle(_T("WS2_32"));
    if (!ws2_32)
        return FALSE;

    original_socket = (pSocket)GetProcAddress(ws2_32, "socket");
    original_bind = (pBind)GetProcAddress(ws2_32, "bind");
    original_connect = (pConnect)GetProcAddress(ws2_32, "connect");
    original_sendto = (pSendTo)GetProcAddress(ws2_32, "sendto");
    original_getsockname = (pGetSockName)GetProcAddress(ws2_32, "getsockname");
    original_WSAsocket = (pWSASocket)GetProcAddress(ws2_32, "WSASocketW");
    original_WSAConnect = (pWSAConnect)GetProcAddress(ws2_32, "WSAConnect");

    if (!original_socket || !original_bind || !original_connect || !original_sendto || !original_getsockname)
        return FALSE;

    if (MH_CreateHook((LPVOID)original_socket, &hooked_socket, (LPVOID *)&original_socket) != MH_OK ||
        MH_CreateHook((LPVOID)original_bind, &hooked_bind, (LPVOID *)&original_bind) != MH_OK ||
        MH_CreateHook((LPVOID)original_connect, &hooked_connect, (LPVOID *)&original_connect) != MH_OK ||
        MH_CreateHook((LPVOID)original_sendto, &hooked_sendto, (LPVOID *)&original_sendto) != MH_OK ||
        MH_CreateHook((LPVOID)original_getsockname, &hooked_getsockname, (LPVOID *)&original_getsockname) != MH_OK ||
        MH_CreateHook((LPVOID)original_WSAsocket, &hooked_WSAsocket, (LPVOID *)&original_WSAsocket) != MH_OK ||
        MH_CreateHook((LPVOID)original_WSAConnect, &hooked_WSAConnect, (LPVOID *)&original_WSAConnect) != MH_OK)
    {
        return FALSE;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        return FALSE;
    if (verbose)
        log_message(_T("Hooks initialized successfully\n"));
    return TRUE;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        if (MH_Initialize() != MH_OK)
            return FALSE;
        parse_preferred_binding();
        return initialize_hooks();
    case DLL_PROCESS_DETACH:
        if (log_file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(log_file);
            log_file = INVALID_HANDLE_VALUE;
        }
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        return TRUE;
    default:
        return TRUE;
    }
}