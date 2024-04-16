#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <tchar.h>

#define WHOAMI "ForceBindIP"
#include "picocrt.h"

#define WINIFACE_WANTED
#include "ForceBindIPHelpers.h"

typedef _Success_(return != FALSE) BOOL(WINAPI *funcDecl_WriteProcessMemory)(
    _In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_reads_bytes_(nSize) LPCVOID lpBuffer, _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T *lpNumberOfBytesWritten
);

typedef _Ret_maybenull_ HANDLE(WINAPI *funcDecl_CreateRemoteThread)(
    _In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId
);

typedef _Ret_maybenull_ HMODULE(WINAPI *funcDecl_LoadLibrary)(_In_ LPCSTR lpLibFileName);

static const CHAR funcName_CreateRemoteThread[] = "Zk|xm|K|tvm|Mqk|x}";
static const CHAR funcName_WriteProcessMemory[] = "Nkpm|Ikvz|jjT|tvk`";
static const CHAR funcName_LoadLibrary[] = STRINGIZE(LoadLibrary);

PTCHAR lstrrchr(PTCHAR str, TCHAR c) {
    for (PTCHAR p = str + lstrlen(str); p >= str; --p) {
        if (*p == '\\') {
            return p;
        }
    }
    return NULL;
}

static void DecryptFunctionName(BYTE *data, BYTE *out) {
    while (*data != '\0') {
        *out++ = *data++ ^ 0x19U;
    }
    *out = '\0';
}

#define ResolveFunctionOnStack(hModule, funcName, funcType, funcAddr)                                                          \
    do {                                                                                                                       \
        CHAR funcNameDecrypted[sizeof(funcName)];                                                                              \
        DecryptFunctionName((BYTE *)(funcName), (BYTE *)funcNameDecrypted);                                                    \
        (funcAddr) = (funcType)GetProcAddress(hModule, funcNameDecrypted);                                                     \
        RtlZeroMemory(funcNameDecrypted, sizeof(funcNameDecrypted));                                                           \
    } while (0)

TCHAR *LTrimCommandLine(TCHAR *cmdLine) {
    TCHAR *ptr = cmdLine;

    if (*ptr != '"') {
        while (*ptr > ' ') {
            ++ptr;
        }
    } else {
        ++ptr;
        while (*ptr != '\0' && *ptr != '"') {
            ++ptr;
        }

        if (*ptr == '"') {
            ++ptr;
        }
    }

    while (*ptr != '\0' && *ptr <= ' ') {
        ++ptr;
    }

    return ptr;
}

static int usage(void) { return MessageBox_Show2("Usage", "ForceBindIP usage"); }

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, TCHAR *lpCmdLine, int nShowCmd) {
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
    TCHAR ipAddrToBind[countof(_T("{92418c82-090a-433f-94ba-a0f99194b5c1}"))]; // adapter name or IP address

    dllName[0] = '\0';
    if (GetModuleFileName(NULL, dllName, countof(dllName)) == 0) {
        MessageBox_ShowError("ForceBindIP could not locate itself");
        return 1;
    }
    LPTSTR lastDelimiter;
    if ((lastDelimiter = lstrrchr(dllName, '\\')) == NULL) {
        MessageBox_Show("BindIP.dll path cannot be detected");
        return 1;
    }
    lstrcpy(lastDelimiter + 1, _T("BindIP.dll"));
    if (GetFileAttributes(dllName) == INVALID_FILE_ATTRIBUTES) {
        MessageBox_ShowError("BindIP.dll not found");
        return 1;
    }

    PTSTR ptr = lpCmdLine;

    BOOL delayedInjection = FALSE;
    if (*ptr == '-' && *(ptr + 1) == 'i') {
        ptr += countof(_T("-i"));
        delayedInjection = TRUE;
    }

    int idx = 0;
    while (TRUE) {
        if (*ptr == '\0' || *ptr == ' ') {
            break;
        }
        ipAddrToBind[idx++] = *ptr++;
    }
    ipAddrToBind[idx] = '\0';

    if (ipAddrToBind[0] - '0' < 0 || ipAddrToBind[0] - '0' > 9) {
        usage();
        return 1;
    }

    if (ipAddrToBind[0] == '{') {
        ULONG SizePointer = sizeof(AdapterInfo);
        if (GetAdaptersInfo(AdapterInfo, &SizePointer)) {
            MessageBox_ShowError("Error querying network adapters");
            return 1;
        }
        PIP_ADAPTER_INFO p_AdapterInfo = &AdapterInfo[0];
        while (TRUE) {
            if (p_AdapterInfo == NULL) {
                MessageBox_Show("Couldn't find named adapter");
                return 1;
            }
#if !defined(UNICODE)
            PTCHAR wAdapterName = p_AdapterInfo->AdapterName;
#else
            TCHAR wAdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
            MultiByteToWideChar(CP_UTF8, 0, p_AdapterInfo->AdapterName, -1, wAdapterName, countof(wAdapterName));
#endif

            if (lstrcmp(ipAddrToBind, wAdapterName) == 0) {
#if !defined(UNICODE)
                lstrcpyn(ipAddrToBind, p_AdapterInfo->IpAddressList.IpAddress.String, sizeof(ipAddrToBind));
#else
                MultiByteToWideChar(
                    CP_UTF8, 0, p_AdapterInfo->IpAddressList.IpAddress.String, -1, ipAddrToBind, countof(ipAddrToBind)
                );
#endif
                break;
            }
            p_AdapterInfo = p_AdapterInfo->Next;
        }
    }

    if (*ptr == '\0') {
        usage();
        return 1;
    }

    while (*ptr == ' ') {
        ++ptr;
    }

    /* Pass to DLL. */
    SetEnvironmentVariable(_T("FORCEDIP"), ipAddrToBind);

    StartupInfo.cb = sizeof(StartupInfo);
    if (!delayedInjection) {
        creationFlags = CREATE_SUSPENDED;
    }
    if (!CreateProcess(NULL, ptr, NULL, NULL, TRUE, creationFlags, NULL, NULL, &StartupInfo, &pInfo)) {
        MessageBox_ShowError("ForceBindIP was unable to start the target program");
        return 1;
    }
    if (delayedInjection) {
        WaitForInputIdle(pInfo.hProcess, INFINITE);
    }

    /* Do the alchemy. */
    module_kernel32 = GetModuleHandle(_T("KERNEL32"));

    remoteBuf = VirtualAllocEx(pInfo.hProcess, NULL, 4096 /* page size on x86 */, MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuf == NULL) {
        MessageBox_ShowError("Unable to allocate remote memory");
        return 1;
    }

    ResolveFunctionOnStack(module_kernel32, funcName_WriteProcessMemory, funcDecl_WriteProcessMemory, func_WriteProcessMemory);
    SIZE_T bytesWritten;
    if (func_WriteProcessMemory(pInfo.hProcess, remoteBuf, dllName, (lstrlen(dllName) + 1) * sizeof(TCHAR), &bytesWritten) !=
        TRUE) {
        MessageBox_ShowError("Unable to write remote memory");
        return 1;
    }

#if defined(DEBUG)
    VOID *mem = LocalAlloc(0, 4096);
    ReadProcessMemory(pInfo.hProcess, remoteBuf, mem, 4096, NULL);
#endif

    ResolveFunctionOnStack(module_kernel32, funcName_CreateRemoteThread, funcDecl_CreateRemoteThread, func_CreateRemoteThread);
    func_LoadLibrary = (funcDecl_LoadLibrary)GetProcAddress(module_kernel32, funcName_LoadLibrary);
    remoteThread = func_CreateRemoteThread(
        pInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)func_LoadLibrary, remoteBuf, CREATE_SUSPENDED, NULL
    );
    if (remoteThread == INVALID_HANDLE_VALUE) {
        MessageBox_ShowError("Unable to inject DLL");
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }

    ResumeThread(remoteThread);
    if (WaitForSingleObject(remoteThread, INFINITE) != WAIT_OBJECT_0) {
        MessageBox_ShowError("Unable to run DLL");
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }

    /* DONE: check if LoadLibrary succeeded! */
    DWORD exitCode;
    if (GetExitCodeThread(remoteThread, &exitCode) == FALSE || exitCode == 0) {
        MessageBox_ShowError("Failed to run DllMain");
        TerminateProcess(pInfo.hProcess, 1);
        return 1;
    }

    if (!delayedInjection) {
        ResumeThread(pInfo.hThread);
    }

    CloseHandle(pInfo.hThread);
    CloseHandle(pInfo.hProcess);
    return 0;
}

/* Entrypoint is overriden for Release builds (no CRT at all) in project settings */
#if defined(NDEBUG)
void DECLSPEC_NORETURN WINAPI EntryPoint(void) {
    /* Ignore parent nShowCmd for simplicity.
     * See https://in4k.untergrund.net/various%20web%20articles/Creating_Small_Win32_Executables_-_Fast_Builds.htm for more
     * details.
     */
    ExitProcess(_tWinMain(/*GetModuleHandle(NULL)*/ NULL, NULL, LTrimCommandLine(GetCommandLine()), SW_SHOWDEFAULT));
}
#endif
