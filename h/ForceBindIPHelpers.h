#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>

#if defined(WSA_WANTED)
#include <winsock2.h>
#endif

#ifndef WHOAMI
#define WHOAMI __FILE__
#endif

#define countof(a) (sizeof(a) / sizeof((a)[0]))

#define htobe16(x) ((((x) & 0xff) << 8) | ((x) >> 8))
#define be16toh htobe16

#define STRINGIZE(s) STRINGIZE2(s)
#define STRINGIZE2(s) #s

#if defined(WINIFACE_WANTED)

#define MessageBox_Show(text) MessageBox(NULL, _T(text), _T(WHOAMI), MB_ICONEXCLAMATION)
#define MessageBox_Show2(caption, text) MessageBox(NULL, _T(text), _T(caption), MB_ICONEXCLAMATION)

static void MessageBox_ShowError(TCHAR *text) {
    TCHAR buf[256];
    DWORD rv = GetLastError();
    int printed = wsprintf(buf, _T("%s\r\n\r\nWindows Error %u - "), text, rv);
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        rv,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf + printed,
        countof(buf) - printed,
        NULL
    );
    MessageBox(NULL, buf, _T(WHOAMI), MB_ICONERROR);
}

/* Hide some complexity. */
#define MessageBox_ShowError(textA) MessageBox_ShowError(_T(textA))

#endif /* WINIFACE_WANTED */

#if defined(WSA_WANTED)

static void WSAErrorHandler(
    const int rv, const TCHAR *file, const int line
#if defined(VERBOSE)
    , const TCHAR *op
#endif
) {
    int rc = WSAGetLastError();
    TCHAR *s;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&s,
        0,
        NULL
    );
    lprintf("%s:%d: rv = %d, WSA error %d - %s\r\n", file, line, rv, rc, s);
#if defined(VERBOSE)
    lprintf("    %s\r\n", op);
#endif
    LocalFree(s);
    DebugBreak();
}

/* clang-format off */
#if !defined(VERBOSE)
#define wsacall(op) do { int _rv = (int)(op); if (_rv < 0) { WSAErrorHandler(_rv, _T(WHOAMI), __LINE__); } } while (0)
#else
#define wsacall(op) do { int _rv = (int)(op); if (_rv < 0) { WSAErrorHandler(_rv, _T(WHOAMI), __LINE__, #op); } } while (0)
#endif
/* clang-format on */

static inline void EnableKillSwitch(void) {
    SetEnvironmentVariable(_T("FORCEDIP_DISABLE"), _T("1"));
}

static inline void DisableKillSwitch(void) {
    SetEnvironmentVariable(_T("FORCEDIP_DISABLE"), NULL);
}

#endif /* WSA_WANTED */

#if defined(_WIN64)
    #define HOOK_PROLOGUE_SIZE 12
#else
    #define HOOK_PROLOGUE_SIZE 5
#endif

typedef struct {
    BYTE origCode[HOOK_PROLOGUE_SIZE];
    BYTE hookCode[HOOK_PROLOGUE_SIZE];
    PROC trampoline;
#if defined(_WIN64)
    UINT_PTR padding;
#endif
} HookData;
