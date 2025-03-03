#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <conio.h>

int main()
{
    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);

    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == NO_ERROR)
    {
        PIP_ADAPTER_ADDRESSES pCurrent = pAddresses;
        while (pCurrent)
        {
            if (pCurrent->OperStatus == IfOperStatusUp)
            {
                std::wcout << L"\nInterface Name: " << pCurrent->FriendlyName << std::endl;
                std::wcout << L"Interface GUID: " << pCurrent->AdapterName << std::endl;
                std::wcout << L"Description: " << pCurrent->Description << std::endl;
                std::cout << "Status: Up" << std::endl;

                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrent->FirstUnicastAddress;
                while (pUnicast)
                {
                    sockaddr_in* addr = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    char currentIp[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr->sin_addr, currentIp, sizeof(currentIp));
                    std::cout << "IP Address: " << currentIp << std::endl;
                    pUnicast = pUnicast->Next;
                }
            }
            pCurrent = pCurrent->Next;
        }
    }

    free(pAddresses);

    std::cout << "Please enter a key to exit the application..." << std::endl;
    int b = _getch();

    return 0;
}
