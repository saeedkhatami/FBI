#pragma once
#include <windows.h>
#include <tchar.h>

#define lprintf(fmt, ...) _tprintf(_T(fmt), ##__VA_ARGS__)
