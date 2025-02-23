#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed" << std::endl;
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80);
    inet_pton(AF_INET, "142.250.190.78", &serverAddr.sin_addr);

    if (connect(sock, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connect failed" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    sockaddr_in localAddr;
    int addrLen = sizeof(localAddr);
    getsockname(sock, (sockaddr *)&localAddr, &addrLen);

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &localAddr.sin_addr, ipStr, sizeof(ipStr));
    std::cout << "Connected from local IP: " << ipStr << std::endl;

    closesocket(sock);
    WSACleanup();
    return 0;
}