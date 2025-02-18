#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h> // Added for printf and freopen_s
#include <tchar.h> // Added for TCHAR and _T()
#define WHOAMI "ForceBindIP"
#include "picocrt.h"
#define WINIFACE_WANTED
#include "helper.h"

typedef _Success_(return != FALSE) BOOL(WINAPI *fn_mem_write)(
    _In_ HANDLE h, _In_ LPVOID addr, _In_reads_bytes_(n) LPCVOID buf, _In_ SIZE_T n,
    _Out_opt_ SIZE_T *written);

typedef _Ret_maybenull_ HANDLE(WINAPI *fn_thread_create)(
    _In_ HANDLE h, _In_opt_ LPSECURITY_ATTRIBUTES attr, _In_ SIZE_T stack,
    _In_ LPTHREAD_START_ROUTINE start, _In_opt_ LPVOID param, _In_ DWORD flags,
    _Out_opt_ LPDWORD tid);

#ifdef UNICODE
typedef _Ret_maybenull_ HMODULE(WINAPI *fn_load_lib)(_In_ LPCWSTR name);
static const TCHAR sz_load_lib[] = _T("LoadLibraryW");
#else
typedef _Ret_maybenull_ HMODULE(WINAPI *fn_load_lib)(_In_ LPCSTR name);
static const CHAR sz_load_lib[] = "LoadLibraryA";
#endif

static const CHAR sz_create_thread[] = "CreateRemoteThread";
static const CHAR sz_write_mem[] = "WriteProcessMemory";

typedef _Success_(return != FALSE) BOOL(WINAPI *funcDecl_WriteProcessMemory)(
    _In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_reads_bytes_(nSize) LPCVOID lpBuffer, _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T *lpNumberOfBytesWritten);

typedef _Ret_maybenull_ HANDLE(WINAPI *funcDecl_CreateRemoteThread)(
    _In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId);

#ifdef UNICODE
typedef _Ret_maybenull_ HMODULE(WINAPI *funcDecl_LoadLibrary)(_In_ LPCWSTR lpLibFileName);
static const CHAR funcName_LoadLibrary[] = "LoadLibraryW";
#else
typedef _Ret_maybenull_ HMODULE(WINAPI *funcDecl_LoadLibrary)(_In_ LPCSTR lpLibFileName);
static const CHAR funcName_LoadLibrary[] = "LoadLibraryA";
#endif

static const CHAR funcName_CreateRemoteThread[] = "CreateRemoteThread";
static const CHAR funcName_WriteProcessMemory[] = "WriteProcessMemory";

PTCHAR lstrrchr(PTCHAR str, TCHAR c)
{
    (void)c;
    for (PTCHAR p = str + lstrlen(str); p >= str; --p)
    {
        if (*p == '\\')
        {
            return p;
        }
    }
    return NULL;
}

#define ResolveFunctionOnStack(hModule, funcName, funcType, funcAddr) \
    do                                                                \
    {                                                                 \
        (funcAddr) = (funcType)GetProcAddress(hModule, funcName);     \
    } while (0)

TCHAR *LTrimCommandLine(TCHAR *cmdLine)
{
    TCHAR *ptr = cmdLine;
    if (*ptr != '"')
    {
        while (*ptr > ' ')
        {
            ++ptr;
        }
    }
    else
    {
        ++ptr;
        while (*ptr != '\0' && *ptr != '"')
        {
            ++ptr;
        }
        if (*ptr == '"')
        {
            ++ptr;
        }
    }
    while (*ptr != '\0' && *ptr <= ' ')
    {
        ++ptr;
    }
    return ptr;
}

static BOOL IsProcess64Bit(HANDLE hProcess)
{
    (void)hProcess;
    BOOL isWow64 = FALSE;
    BOOL is64BitOS = FALSE;
    typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process =
        (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(_T("KERNEL32")), "IsWow64Process");
    if (fnIsWow64Process)
    {
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
        {
            is64BitOS = isWow64 || sizeof(void *) == 8;
            if (is64BitOS)
            {
                isWow64 = FALSE;
                if (fnIsWow64Process(hProcess, &isWow64))
                {
                    return !isWow64;
                }
            }
        }
    }
    return sizeof(void *) == 8;
}

static BOOL GetDllPath(HANDLE hProcess, LPTSTR dllPath, DWORD maxLen)
{
    (void)hProcess;
    if (GetModuleFileName(NULL, dllPath, maxLen) == 0)
    {
        return FALSE;
    }
    LPTSTR lastDelimiter = lstrrchr(dllPath, '\\');
    if (lastDelimiter == NULL)
    {
        return FALSE;
    }
    lstrcpy(lastDelimiter + 1, _T("BindIP.dll"));
    return GetFileAttributes(dllPath) != INVALID_FILE_ATTRIBUTES;
}

static void system_initialize(void) {}
static void cleanup_resources(void) {}

typedef struct
{
    BOOL ipv4_mode;
    BOOL ipv6_mode;
    BOOL delayed_injection;
    BOOL show_help;
    DWORD delay_ms;
} ProgramOptions;

static void print_usage(void)
{
    printf("ForceBindIP v2.0 - Force TCP/IP applications to use specific network interfaces\n\n"
           "Usage: ForceBindIP [options] <IP Address> <Program>\n"
           "Options:\n"
           "  -4    Force IPv4 mode\n"
           "  -6    Force IPv6 mode\n"
           "  -d    Delayed injection mode with specified delay in milliseconds\n"
           "  -h    Show this help message\n"
           "\n"
           "Examples:\n"
           "  ForceBindIP -4 192.168.1.100 notepad.exe\n"
           "  ForceBindIP -6 fe80::1234:5678:9abc:def0%%2 chrome.exe\n"
           "  ForceBindIP -d 5000 192.168.1.100 spotify.exe    # Wait 5 seconds before injection\n"
           "\n"
           "Notes:\n"
           "  - For IPv6 link-local addresses, use %% to escape the interface scope ID\n"
           "  - If no IP version is specified (-4/-6), it will be auto-detected\n"
           "  - Use -d for programs that initialize network after startup\n"
           "\n"
           "Network Adapter Usage:\n"
           "  ForceBindIP {adapter-guid} program.exe\n"
           "  Example: ForceBindIP {92418c82-090a-433f-94ba-a0f99194b5c1} chrome.exe\n");
    ExitProcess(0);
}

static BOOL parse_options(TCHAR *cmdline, ProgramOptions *opts, TCHAR *ipaddr, TCHAR **program)
{
    TCHAR *ptr = cmdline;
    BOOL found_ip = FALSE;
    memset(opts, 0, sizeof(ProgramOptions));
    *program = NULL;
    while (*ptr)
    {
        if (*ptr == '-')
        {
            ptr++;
            switch (*ptr)
            {
            case '4':
                opts->ipv4_mode = TRUE;
                break;
            case '6':
                opts->ipv6_mode = TRUE;
                break;
            case 'd':
            {
                opts->delayed_injection = TRUE;
                ptr++;
                while (*ptr == ' ')
                    ptr++;
                if (*ptr < '0' || *ptr > '9')
                {
                    printf("Error: -d requires a numeric delay value in milliseconds\n");
                    return FALSE;
                }
                opts->delay_ms = 0;
                while (*ptr >= '0' && *ptr <= '9')
                {
                    opts->delay_ms = opts->delay_ms * 10 + (*ptr - '0');
                    ptr++;
                }
                ptr--;
                break;
            }
            case 'h':
                opts->show_help = TRUE;
                return TRUE;
            default:
                printf("Error: Unknown option '-%c'\n", *ptr);
                return FALSE;
            }
            ptr++;
            while (*ptr == ' ')
                ptr++;
            continue;
        }
        if (!found_ip)
        {
            int idx = 0;
            while (*ptr && *ptr != ' ')
            {
                ipaddr[idx++] = *ptr++;
            }
            ipaddr[idx] = '\0';
            found_ip = TRUE;
        }
        else
        {
            *program = ptr;
            break;
        }
        while (*ptr == ' ')
            ptr++;
    }
    if (!found_ip || !*program)
    {
        printf("Error: Missing IP address or program\n");
        return FALSE;
    }
    return TRUE;
}

static BOOL validate_ip_address(const TCHAR *ip, BOOL *is_ipv6)
{
    CHAR ipstr[256];
    IN_ADDR ipv4;
    IN6_ADDR ipv6;
#ifdef UNICODE
    WideCharToMultiByte(CP_UTF8, 0, ip, -1, ipstr, sizeof(ipstr), NULL, NULL);
#else
    lstrcpyA(ipstr, ip);
#endif
    if (ip[0] == '{')
        return TRUE;
    if (inet_pton(AF_INET, ipstr, &ipv4) == 1)
    {
        *is_ipv6 = FALSE;
        return TRUE;
    }
    if (inet_pton(AF_INET6, ipstr, &ipv6) == 1)
    {
        *is_ipv6 = TRUE;
        return TRUE;
    }
    printf("Error: Invalid IP address format: %s\n", ipstr);
    return FALSE;
}

static void usage(void)
{
    print_usage();
    return;
}

static BOOL inject_dll(HANDLE hProcess, LPCTSTR dllPath)
{
    BOOL is64BitTarget = IsProcess64Bit(hProcess);
#ifdef _WIN64
    if (!is64BitTarget)
    {
        MessageBox_Show("Cannot inject 64-bit DLL into 32-bit process");
        return FALSE;
    }
#else
    if (is64BitTarget)
    {
        MessageBox_Show("Cannot inject 32-bit DLL into 64-bit process");
        return FALSE;
    }
#endif
    HMODULE module_kernel32 = GetModuleHandle(_T("KERNEL32"));
    if (module_kernel32 == NULL)
    {
        MessageBox_ShowError("Unable to get KERNEL32 handle");
        return FALSE;
    }
    funcDecl_LoadLibrary func_LoadLibrary;
    ResolveFunctionOnStack(module_kernel32, funcName_LoadLibrary, funcDecl_LoadLibrary, func_LoadLibrary);
    if (func_LoadLibrary == NULL)
    {
        MessageBox_ShowError("Unable to resolve LoadLibrary");
        return FALSE;
    }
    LPVOID remoteBuf = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuf == NULL)
    {
        MessageBox_ShowError("Unable to allocate remote memory");
        return FALSE;
    }
    funcDecl_WriteProcessMemory func_WriteProcessMemory;
    ResolveFunctionOnStack(module_kernel32, funcName_WriteProcessMemory, funcDecl_WriteProcessMemory, func_WriteProcessMemory);
    if (func_WriteProcessMemory == NULL)
    {
        MessageBox_ShowError("Unable to resolve WriteProcessMemory");
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    SIZE_T bytesWritten;
#ifdef UNICODE
    if (func_WriteProcessMemory(hProcess, remoteBuf, dllPath, (lstrlenW(dllPath) + 1) * sizeof(WCHAR), &bytesWritten) != TRUE)
#else
    if (func_WriteProcessMemory(hProcess, remoteBuf, dllPath, (lstrlenA(dllPath) + 1) * sizeof(CHAR), &bytesWritten) != TRUE)
#endif
    {
        MessageBox_ShowError("Unable to write remote memory");
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    funcDecl_CreateRemoteThread func_CreateRemoteThread;
    ResolveFunctionOnStack(module_kernel32, funcName_CreateRemoteThread, funcDecl_CreateRemoteThread, func_CreateRemoteThread);
    if (func_CreateRemoteThread == NULL)
    {
        MessageBox_ShowError("Unable to resolve CreateRemoteThread");
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    HANDLE remoteThread = func_CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)func_LoadLibrary, remoteBuf, 0, NULL);
    if (remoteThread == NULL)
    {
        MessageBox_ShowError("Unable to create remote thread");
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    if (WaitForSingleObject(remoteThread, INFINITE) != WAIT_OBJECT_0)
    {
        MessageBox_ShowError("Error waiting for remote thread");
        CloseHandle(remoteThread);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    DWORD exitCode;
    if (!GetExitCodeThread(remoteThread, &exitCode) || exitCode == 0)
    {
        MessageBox_ShowError("DLL injection failed");
        CloseHandle(remoteThread);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    CloseHandle(remoteThread);
    VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
    return TRUE;
}

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, TCHAR *lpCmdLine, int nShowCmd)
{
    (void)hInstance;
    (void)hPrevInstance;
    (void)nShowCmd;
    system_initialize();
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup failed\n");
        return 1;
    }
    ProgramOptions opts;
    TCHAR ipaddr[256];
    TCHAR *program;
    BOOL is_ipv6;
    AllocConsole();
    FILE *fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    if (!parse_options(LTrimCommandLine(GetCommandLine()), &opts, ipaddr, &program))
    {
        print_usage();
        return 1;
    }
    if (opts.show_help)
    {
        print_usage();
        return 0;
    }
    if (!validate_ip_address(ipaddr, &is_ipv6))
    {
        return 1;
    }
    if (opts.ipv4_mode && opts.ipv6_mode)
    {
        printf("Error: Cannot specify both -4 and -6\n");
        return 1;
    }
    if (opts.ipv4_mode)
        is_ipv6 = FALSE;
    if (opts.ipv6_mode)
        is_ipv6 = TRUE;
    HMODULE module_kernel32;
    funcDecl_WriteProcessMemory func_WriteProcessMemory;
    funcDecl_CreateRemoteThread func_CreateRemoteThread;
    funcDecl_LoadLibrary func_LoadLibrary;
    STARTUPINFO StartupInfo = {0};
    PROCESS_INFORMATION pInfo = {0};
    LPVOID remoteBuf;
    HANDLE remoteThread;
    DWORD creationFlags = 0;
    TCHAR dllName[MAX_PATH];
    IP_ADAPTER_INFO AdapterInfo[16];
    TCHAR ipAddrToBind[countof(_T("{92418c82-090a-433f-94ba-a0f99194b5c1}"))];
    dllName[0] = '\0';
    if (GetModuleFileName(NULL, dllName, countof(dllName)) == 0)
    {
        MessageBox_ShowError("ForceBindIP could not locate itself");
        return 1;
    }
    LPTSTR lastDelimiter;
    if ((lastDelimiter = lstrrchr(dllName, '\\')) == NULL)
    {
        MessageBox_Show("BindIP.dll path cannot be detected");
        return 1;
    }
    lstrcpy(lastDelimiter + 1, _T("BindIP.dll"));
    if (GetFileAttributes(dllName) == INVALID_FILE_ATTRIBUTES)
    {
        MessageBox_ShowError("BindIP.dll not found");
        return 1;
    }
    PTSTR ptr = lpCmdLine;
    BOOL delayedInjection = opts.delayed_injection;
    int idx = 0;
    while (TRUE)
    {
        if (*ptr == '\0' || *ptr == ' ')
        {
            break;
        }
        ipAddrToBind[idx++] = *ptr++;
    }
    ipAddrToBind[idx] = '\0';
    if (ipAddrToBind[0] - '0' < 0 || ipAddrToBind[0] - '0' > 9)
    {
        usage();
        return 1;
    }
    if (ipAddrToBind[0] == '{')
    {
        ULONG SizePointer = sizeof(AdapterInfo);
        if (GetAdaptersInfo(AdapterInfo, &SizePointer))
        {
            MessageBox_ShowError("Error querying network adapters");
            return 1;
        }
        PIP_ADAPTER_INFO p_AdapterInfo = &AdapterInfo[0];
        while (TRUE)
        {
            if (p_AdapterInfo == NULL)
            {
                MessageBox_Show("Couldn't find named adapter");
                return 1;
            }
            PTCHAR wAdapterName = p_AdapterInfo->AdapterName;
            if (lstrcmp(ipAddrToBind, wAdapterName) == 0)
            {
                lstrcpyn(ipAddrToBind, p_AdapterInfo->IpAddressList.IpAddress.String, countof(ipAddrToBind));
                break;
            }
            p_AdapterInfo = p_AdapterInfo->Next;
        }
    }
    if (*ptr == '\0')
    {
        usage();
        return 1;
    }
    while (*ptr == ' ')
    {
        ++ptr;
    }
    SetEnvironmentVariable(_T("FORCEDIP"), ipAddrToBind);
    StartupInfo.cb = sizeof(StartupInfo);
    if (!delayedInjection)
    {
        creationFlags = CREATE_SUSPENDED;
    }
    if (!CreateProcess(NULL, ptr, NULL, NULL, TRUE, creationFlags, NULL, NULL, &StartupInfo, &pInfo))
    {
        MessageBox_ShowError("ForceBindIP was unable to start the target program");
        return 1;
    }
    if (opts.delayed_injection)
    {
        printf("Waiting %lu milliseconds before injection...\n", opts.delay_ms);
        Sleep(opts.delay_ms);
        WaitForInputIdle(pInfo.hProcess, INFINITE);
    }
    if (!inject_dll(pInfo.hProcess, dllName))
    {
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }
    module_kernel32 = GetModuleHandle(_T("KERNEL32"));
    ResolveFunctionOnStack(module_kernel32, funcName_LoadLibrary, funcDecl_LoadLibrary, func_LoadLibrary);
    if (func_LoadLibrary == NULL)
    {
        MessageBox_ShowError("Unable to resolve LoadLibrary");
        return 1;
    }
    remoteBuf = VirtualAllocEx(pInfo.hProcess, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuf == NULL)
    {
        MessageBox_ShowError("Unable to allocate remote memory");
        return 1;
    }
    ResolveFunctionOnStack(module_kernel32, funcName_WriteProcessMemory, funcDecl_WriteProcessMemory, func_WriteProcessMemory);
    if (func_WriteProcessMemory == NULL)
    {
        MessageBox_ShowError("Unable to resolve WriteProcessMemory");
        return 1;
    }
    SIZE_T bytesWritten;
#ifdef UNICODE
    WCHAR dllNameW[MAX_PATH];
    lstrcpyW(dllNameW, dllName);
    if (func_WriteProcessMemory(pInfo.hProcess, remoteBuf, dllNameW, (lstrlenW(dllNameW) + 1) * sizeof(WCHAR), &bytesWritten) != TRUE)
#else
    CHAR dllNameA[MAX_PATH];
    lstrcpyA(dllNameA, dllName);
    if (func_WriteProcessMemory(pInfo.hProcess, remoteBuf, dllNameA, (lstrlenA(dllNameA) + 1) * sizeof(CHAR), &bytesWritten) != TRUE)
#endif
    {
        MessageBox_ShowError("Unable to write remote memory");
        return 1;
    }
    ResolveFunctionOnStack(module_kernel32, funcName_CreateRemoteThread, funcDecl_CreateRemoteThread, func_CreateRemoteThread);
    if (func_CreateRemoteThread == NULL)
    {
        MessageBox_ShowError("Unable to resolve CreateRemoteThread");
        return 1;
    }
    remoteThread = func_CreateRemoteThread(
        pInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)func_LoadLibrary, remoteBuf, CREATE_SUSPENDED, NULL);
    if (remoteThread == INVALID_HANDLE_VALUE)
    {
        MessageBox_ShowError("Unable to inject DLL");
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }
    ResumeThread(remoteThread);
    if (WaitForSingleObject(remoteThread, INFINITE) != WAIT_OBJECT_0)
    {
        MessageBox_ShowError("Unable to run DLL");
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }
    DWORD exitCode;
    if (GetExitCodeThread(remoteThread, &exitCode) == FALSE || exitCode == 0)
    {
        MessageBox_ShowError("Failed to run DllMain");
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }
    if (!delayedInjection)
    {
        ResumeThread(pInfo.hThread);
    }
    CloseHandle(pInfo.hThread);
    CloseHandle(pInfo.hProcess);
    cleanup_resources();
    WSACleanup();
    return 0;
}

#if defined(NDEBUG)
void DECLSPEC_NORETURN WINAPI EntryPoint(void)
{
    ExitProcess(_tWinMain(NULL, NULL, LTrimCommandLine(GetCommandLine()), SW_SHOWDEFAULT));
}
#endif