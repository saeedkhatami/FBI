#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <tchar.h>

#define WHOAMI "TestAppNative"
#include "picocrt.h"

#define WSA_WANTED
#include "ForceBindIPHelpers.h"

static void TestCase1(void) {
    SOCKET s;
    wsacall(s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    const int broadcastEnable = 1;
    wsacall(setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char *)&broadcastEnable, sizeof(broadcastEnable)));

    SOCKADDR_IN sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.S_un.S_addr = 0xffffffffU;
    sin.sin_port = htobe16(62900);
    wsacall(sendto(s, (const char *)&s, sizeof(s), 0, (const SOCKADDR *)&sin, sizeof(sin)));

    int namelen = sizeof(sin);
    wsacall(getsockname(s, (SOCKADDR *)&sin, &namelen));

    lprintf(
        "Local IPv4 socket address is %d.%d.%d.%d:%u\n",
        sin.sin_addr.S_un.S_un_b.s_b1,
        sin.sin_addr.S_un.S_un_b.s_b2,
        sin.sin_addr.S_un.S_un_b.s_b3,
        sin.sin_addr.S_un.S_un_b.s_b4,
        be16toh(sin.sin_port)
    );
}

int __cdecl _tmain(void) {
    WSADATA wsaData;

    wsacall(WSAStartup(MAKEWORD(2, 2), &wsaData));

    {
        TestCase1();
    }

    wsacall(WSACleanup());

    lprintf("Press any key to continue ... ");
    const HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    FlushConsoleInputBuffer(hStdin);
    while (TRUE) {
        INPUT_RECORD ir;
        DWORD read;
        if (ReadConsoleInput(hStdin, &ir, 1, &read)) {
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                break;
            }
        }
    }

    return 0;
}

/* Entrypoint is overriden for Release builds (no CRT at all) in project settings */
#if defined(NDEBUG)
void DECLSPEC_NORETURN WINAPI EntryPoint(void) { ExitProcess(_tmain()); }
#endif
