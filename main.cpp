#include "Proxy.h"
#include <iostream>

int main() {
	WSADATA wsaData;
	int r = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (r != 0)
	{
		Log("WSAStartup failed: " + std::to_string(r));
		return 1;
	}
	StartProxyServer();
	WSACleanup();
	return 0;
}