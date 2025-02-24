#include "helper.h"
#include <tlhelp32.h>
#include <string>
#include <cstring>

bool inject_dll(HANDLE hProcess, const TCHAR* dllPath)
{
    SIZE_T pathSize = (_tcslen(dllPath) + 1) * sizeof(TCHAR);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem)
    {
        _tprintf(_T("Failed to allocate memory in target process.\n"));
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, NULL))
    {
        _tprintf(_T("Failed to write DLL path to target process.\n"));
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel32 = GetModuleHandle(_T("kernel32"));
    if (!kernel32)
    {
        _tprintf(_T("Failed to get kernel32 module.\n"));
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    FARPROC loadLib = GetProcAddress(kernel32, "LoadLibraryW");
    if (!loadLib)
    {
        _tprintf(_T("Failed to get LoadLibrary address.\n"));
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);
    if (!thread)
    {
        _tprintf(_T("Failed to create remote thread.\n"));
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    return exitCode != 0;
}

int _tmain(int argc, TCHAR* argv[])
{
    if (argc < 3)
    {
        _tprintf(_T("Usage: injector.exe <interface> <program> [args...]\n"));
        return 1;
    }

    TCHAR* interface_str = argv[1];

    if (interface_str[0] == _T('{'))
    {
        SetEnvironmentVariable(_T("PREFERRED_INTERFACE"), interface_str);
    }
    else
    {
        std::basic_string<TCHAR> pref_ip;
        if (_tcschr(interface_str, _T(':')))
        {
            pref_ip = _T("IPv6:") + std::basic_string<TCHAR>(interface_str);
        }
        else
        {
            pref_ip = _T("IPv4:") + std::basic_string<TCHAR>(interface_str);
        }
        SetEnvironmentVariable(_T("PREFERRED_IP"), pref_ip.c_str());
    }

    std::basic_string<TCHAR> cmdline;
    for (int i = 2; i < argc; i++)
    {
        if (i > 2) cmdline += _T(" ");
        cmdline += argv[i];
    }

    TCHAR dllPath[MAX_PATH];
    GetModuleFileName(NULL, dllPath, MAX_PATH);
    TCHAR* dirEnd = _tcsrchr(dllPath, '\\');
    if (dirEnd)
    {
        *dirEnd = '\0';
        _tcscat_s(dllPath, MAX_PATH, _T("\\forcebindipdll.dll"));
    }
    else
    {
        _tprintf(_T("Failed to determine DLL path.\n"));
        return 1;
    }

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(NULL, &cmdline[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        _tprintf(_T("Failed to create process: %s\n"), cmdline.c_str());
        return 1;
    }

    if (!inject_dll(pi.hProcess, dllPath))
    {
        _tprintf(_T("DLL injection failed.\n"));
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    _tprintf(_T("DLL injected successfully with interface: %s\n"), interface_str);
    return 0;
}