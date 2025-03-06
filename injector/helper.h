#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <tlhelp32.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <cwctype>
#include <conio.h>
#include <iostream>

#include <windows.h>
#include <tchar.h>



#define lprintf(fmt, ...) _tprintf(_T(fmt), ##__VA_ARGS__)
