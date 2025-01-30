#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <string>

#include <vector>

#pragma comment(lib, "ws2_32.lib")

static constexpr int LISTEN_PORT = 3307;
static constexpr int SERVER_PORT = 3306;
static const char* SERVER_HOST = "127.0.0.1";
static constexpr int usefulLoad = 5;
static constexpr char COM_QUERY = 0x03;
//Overlapped buffer size for a single call of WSASend/WSARecv
static constexpr int BUFFER_SIZE = 4096;

enum class IOOperationType {

	Accept,
	ReadClient,
	WriteClient,
	ReadServer,
	WriteServer
};

// OVERLAPPED-context for operation
struct IO_CONTEXT {
	OVERLAPPED overlapped;
	SOCKET socket;
	WSABUF wsabuf;
	std::vector<char> buffer;
	IOOperationType operation;
	DWORD TransferredData;

	IO_CONTEXT() : socket(INVALID_SOCKET), operation(IOOperationType::ReadClient), TransferredData(0) {
		buffer.resize(BUFFER_SIZE);
		wsabuf.buf = buffer.data();
		wsabuf.len = static_cast<ULONG>(buffer.size());
	}
};

//Context of a single connection
struct CONNECTION_CONTEXT {
	SOCKET ClientSocket = INVALID_SOCKET;
	SOCKET ServerSocket = INVALID_SOCKET;

	IO_CONTEXT ClientReadContext;
	IO_CONTEXT ServerReadContext;
	IO_CONTEXT ClientWriteContext;
	IO_CONTEXT ServerWriteContext;

	bool closed = false;

	std::vector<char> clientBuff;
	std::vector<char> serverBuff;
};

//logging

void Log(const std::string& msg);

bool StartProxyServer();

void CloseConnection(CONNECTION_CONTEXT* connCont);