#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

void print_socket_info(SOCKET sock)
{
    char ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_storage addr;
    int addr_len = sizeof(addr);

    if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == 0)
    {

        printf("Address Family: %s\n",
               addr.ss_family == AF_INET ? "IPv4" : addr.ss_family == AF_INET6 ? "IPv6"
                                                                               : "Unknown");

        if (addr.ss_family == AF_INET)
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, ip_str, sizeof(ip_str));
            printf("Local IP: %s\n", ip_str);
            printf("Local Port: %d\n", ntohs(ipv4->sin_port));
        }
        else if (addr.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_str, sizeof(ip_str));
            printf("Local IP: %s\n", ip_str);
            printf("Local Port: %d\n", ntohs(ipv6->sin6_port));
            printf("Scope ID: %lu\n", ipv6->sin6_scope_id);
        }
    }
    else
    {
        printf("Error getting socket info: %d\n", WSAGetLastError());
    }
}

void test_connection(int family)
{
    SOCKET sock;
    struct addrinfo hints = {0}, *result;

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        return;
    }

    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rv = getaddrinfo(family == AF_INET ? "8.8.8.8" : "2001:4860:4860::8888",
                         "53", &hints, &result);
    if (rv != 0)
    {
        printf("getaddrinfo failed: %d\n", rv);
        closesocket(sock);
        return;
    }

    printf("\n[%s] Attempting %s connection...\n",
           GetCommandLine(),
           family == AF_INET ? "IPv4" : "IPv6");

    printf("Before connect:\n");
    print_socket_info(sock);

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) < 0)
    {
        printf("Connect failed: %d\n", WSAGetLastError());
    }
    else
    {
        printf("After connect:\n");
        print_socket_info(sock);
        printf("Connection successful!\n");
    }

    freeaddrinfo(result);
    closesocket(sock);
}

int main()
{
    WSADATA wsa;

    printf("ForceBindIP Test Application\n");

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    while (1)
    {

        test_connection(AF_INET);
        test_connection(AF_INET6);
        Sleep(2000);
    }

    WSACleanup();
    return 0;
}