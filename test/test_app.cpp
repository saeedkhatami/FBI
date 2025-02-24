#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "iphlpapi.lib")

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

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connect failed" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    sockaddr_in localAddr;
    int addrLen = sizeof(localAddr);
    getsockname(sock, (sockaddr*)&localAddr, &addrLen);

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &localAddr.sin_addr, ipStr, sizeof(ipStr));
    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);

    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == NO_ERROR)
    {
        PIP_ADAPTER_ADDRESSES pCurrent = pAddresses;
        while (pCurrent)
        {
            std::wcout << L"\nInterface Name: " << pCurrent->FriendlyName << std::endl;
            std::wcout << L"Interface GUID: " << pCurrent->AdapterName << std::endl;
            std::wcout << L"Description: " << pCurrent->Description << std::endl;

            if (pCurrent->OperStatus == IfOperStatusUp)
                std::cout << "Status: Up" << std::endl;
            else
                std::cout << "Status: Down" << std::endl;

            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrent->FirstUnicastAddress;
            while (pUnicast)
            {
                sockaddr_in* addr = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                char currentIp[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, currentIp, sizeof(currentIp));
                std::cout << "IP Address: " << currentIp << std::endl;
                pUnicast = pUnicast->Next;
            }
            pCurrent = pCurrent->Next;
        }
    }

    std::cout << "Connected from local IP: " << ipStr << std::endl;

    free(pAddresses);

    closesocket(sock);
    WSACleanup();
    return 0;
}