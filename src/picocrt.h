#pragma once

#ifndef WHOAMI
#define WHOAMI __FILE__
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>

#if defined(NDEBUG) && !defined(USE_CRT)

#if !defined(_MSC_VER) || defined(_CRTBLD)
#pragma function(memset)
void *__cdecl memset(void *ptr, int c, size_t len) {
    BYTE *p = ptr;
    for (SIZE_T i = 0; i < len; ++i) {
        *p++ = (BYTE)c;
    }
    return ptr;
}

#pragma function(memcpy)
void *__cdecl memcpy(void *dst, const void *src, size_t size) {
    void *start = dst;
    BYTE *bdst = dst;
    CONST BYTE *bsrc = src;
    while (size > 0) {
        *bdst++ = *bsrc++;
        --size;
    }
    return start;
}
#endif

#endif

#if defined(__RESHARPER__)
    #if !defined(UNICODE)
[[rscpp::format(printf, 1, 2)]]
    #else
[[rscpp::format(wprintf, 1, 2)]]
    #endif
#endif
int lprintf(TCHAR *fmt, ...) {
    TCHAR buf[256];
    va_list v1;
    va_start(v1, fmt);
    int len = wvsprintf(buf, fmt, v1);
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL);
    va_end(v1);
    return len;
}

/* Hide some complexity. */
#define lprintf(fmtA, ...) lprintf(_T(fmtA), ##__VA_ARGS__)
