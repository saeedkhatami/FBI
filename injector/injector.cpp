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
    if (argc < 2)
    {
        _tprintf(_T("Usage: injector.exe [-4 <IPv4> | -6 <IPv6> | -i <GUID>] <program> [args...]\n"));
        return 1;
    }

    std::string injection_type;
    int program_index = -1;

    for (int i = 1; i < argc; )
    {
        if (_tcscmp(argv[i], _T("-4")) == 0)
        {
            if (!injection_type.empty())
            {
                _tprintf(_T("Error: Multiple injection methods specified\n"));
                return 1;
            }
            if (i + 1 >= argc || argv[i + 1][0] == _T('-'))
            {
                _tprintf(_T("Error: -4 requires an IPv4 address\n"));
                return 1;
            }
            std::basic_string<TCHAR> ipv4_addr = argv[i + 1];
            SetEnvironmentVariable(_T("PREFERRED_IP"), (_T("IPv4:") + ipv4_addr).c_str());
            injection_type = "ipv4";
            i += 2;
        }
        else if (_tcscmp(argv[i], _T("-6")) == 0)
        {
            if (!injection_type.empty())
            {
                _tprintf(_T("Error: Multiple injection methods specified\n"));
                return 1;
            }
            if (i + 1 >= argc || argv[i + 1][0] == _T('-'))
            {
                _tprintf(_T("Error: -6 requires an IPv6 address\n"));
                return 1;
            }
            std::basic_string<TCHAR> ipv6_addr = argv[i + 1];
            SetEnvironmentVariable(_T("PREFERRED_IP"), (_T("IPv6:") + ipv6_addr).c_str());
            injection_type = "ipv6";
            i += 2;
        }
        else if (_tcscmp(argv[i], _T("-i")) == 0)
        {
            if (!injection_type.empty())
            {
                _tprintf(_T("Error: Multiple injection methods specified\n"));
                return 1;
            }
            if (i + 1 >= argc || argv[i + 1][0] == _T('-'))
            {
                _tprintf(_T("Error: -i requires a GUID\n"));
                return 1;
            }
            std::basic_string<TCHAR> guid = argv[i + 1];
            std::basic_string<TCHAR> formatted_guid = _T("{") + guid + _T("}");
            SetEnvironmentVariable(_T("PREFERRED_INTERFACE"), formatted_guid.c_str());
            injection_type = "interface";
            i += 2;
        }
        else if (argv[i][0] != _T('-'))
        {
            program_index = i;
            break;
        }
        else
        {
            _tprintf(_T("Unknown option: %s\n"), argv[i]);
            return 1;
        }
    }

    if (program_index == -1)
    {
        _tprintf(_T("Error: No program specified\n"));
        return 1;
    }

    std::basic_string<TCHAR> cmdline;
    for (int i = program_index; i < argc; i++)
    {
        if (i > program_index)
            cmdline += _T(" ");
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

    if (injection_type == "ipv4")
    {
        _tprintf(_T("DLL injected successfully with IPv4: %s\n"), argv[2]);
    }
    else if (injection_type == "ipv6")
    {
        _tprintf(_T("DLL injected successfully with IPv6: %s\n"), argv[2]);
    }
    else if (injection_type == "interface")
    {
        _tprintf(_T("DLL injected successfully with interface GUID: %s\n"), argv[2]);
    }
    else
    {
        _tprintf(_T("DLL injected successfully with default settings\n"));
    }

    return 0;
}