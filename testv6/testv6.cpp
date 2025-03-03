#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <conio.h>

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in6 serverAddr = { 0 };
    serverAddr.sin6_family = AF_INET6;
    serverAddr.sin6_port = htons(80);
    InetPton(AF_INET6, L"2001:4860:4860::8888", &serverAddr.sin6_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connect failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    sockaddr_in6 localAddr = { 0 };
    int addrLen = sizeof(localAddr);
    getsockname(sock, (sockaddr*)&localAddr, &addrLen);

    WCHAR ipStr[INET6_ADDRSTRLEN];
    InetNtopW(AF_INET6, &localAddr.sin6_addr, ipStr, INET6_ADDRSTRLEN);
    std::wcout << L"Connected from local IP: " << ipStr << std::endl;

    closesocket(sock);
    WSACleanup();

    std::cout << "Please enter a key to exit the application..." << std::endl;
    int a = _getch();

    return 0;
}