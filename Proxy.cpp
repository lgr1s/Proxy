#include "Proxy.h"
#include <thread>
#include <mutex>
#include <iostream>

static constexpr int WORKER_THREAD_COUNT = 4;

std::mutex g_logMutex;
void Log(const std::string& msg) {
	std::lock_guard<std::mutex> lk(g_logMutex);
	std::cout << msg << std::endl;
}

HANDLE CompletionPort = INVALID_HANDLE_VALUE;

void InitializeContext(IO_CONTEXT& ctx, IOOperationType op, SOCKET s) {

	ctx.operation = op;
	ctx.socket = s;
	ctx.wsabuf.buf = ctx.buffer.data();
	ctx.wsabuf.len = ctx.buffer.size();
	ctx.TransferredData = 0;
}

bool SocketToCP(SOCKET s, ULONG_PTR completionKey) {
	HANDLE h = CreateIoCompletionPort((HANDLE)s, CompletionPort, completionKey, 0);
	if (!h)
	{
		Log("CreateIoCompletionPort failed");
		return false;
	}
	return true;
}

bool Send(IO_CONTEXT& ctx, const char* data, int len) {
	DWORD flags = 0;
	DWORD bytesSent = 0;

	ctx.wsabuf.buf = (CHAR*)data;
	ctx.wsabuf.len = len;

	if (WSASend(ctx.socket, &ctx.wsabuf, 1, &bytesSent, flags, &ctx.overlapped, NULL) == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING && err != 0)
		{
			Log("WSASend failed: " + std::to_string(err));
			return false;
		}
	}
	return true;
	//ctx.buffer.clear();
}

bool Receive(IO_CONTEXT& ctx) {
	
	DWORD flags = 0;
	DWORD bytesRecvd = 0;
	ctx.wsabuf.buf = ctx.buffer.data();
	ctx.wsabuf.len = ctx.buffer.size();

	if (WSARecv(ctx.socket, &ctx.wsabuf, 1, &bytesRecvd, &flags, &ctx.overlapped, NULL) == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING && err != 0)
		{
			Log("WSARecieve failed: " + std::to_string(err));
			return false;
		}
	}
	return true;
	//ctx.buffer.clear();
}

void CloseConnection(CONNECTION_CONTEXT* connCont)
{
	if (!connCont->closed) {

		connCont->closed = true;

		shutdown(connCont->ClientSocket, SD_BOTH);
		closesocket(connCont->ClientSocket);
		connCont->ClientSocket = INVALID_SOCKET;

		shutdown(connCont->ServerSocket, SD_BOTH);
		closesocket(connCont->ServerSocket);
		connCont->ServerSocket = INVALID_SOCKET;

		delete connCont;
	}
}

static const size_t MySqlHeaderSize = 4; // 3 bytes of len, 1 byte of seq

//Parser
void SendToServer(CONNECTION_CONTEXT* connCont, std::vector<char>& packet) {

	IO_CONTEXT& serverWrite = connCont->ServerWriteContext;
	InitializeContext(serverWrite, IOOperationType::WriteServer, connCont->ServerSocket);

	if (serverWrite.buffer.size() < packet.size()) {
		serverWrite.buffer.resize(packet.size());
	}

	memcpy(serverWrite.buffer.data(), packet.data(), packet.size());
	if (!Send(serverWrite, serverWrite.buffer.data(), static_cast<int>(packet.size()))) {
		CloseConnection(connCont);
	}
}

void ProcessClientBuffer(CONNECTION_CONTEXT* connCont) {
	auto& data = connCont->clientBuff;
	while (true) {
		if (data.size() < MySqlHeaderSize) return;
		unsigned int packetLen = (static_cast<unsigned char>(data[0])) |
			(static_cast<unsigned char>(data[1]) << 8) |
			(static_cast<unsigned char>(data[2]) << 16);

		unsigned int totalLen = MySqlHeaderSize + packetLen;
		if (data.size() < totalLen) {
			return; //Packet is not full. Waiting for the rest
		}

		std::vector<char> packet(data.begin(), data.begin() + totalLen);
		if (packet.size() >= usefulLoad) {
			unsigned char command = static_cast<unsigned char>(packet[4]);
			if (command == COM_QUERY) {
				unsigned int sqlLen = packetLen - 1;
				if (sqlLen > 0 && (MySqlHeaderSize + 1 + sqlLen) <= packet.size()) {
					std::string sql(packet.data() + usefulLoad, packet.data() + usefulLoad + sqlLen);
					Log("SQL Query: " + sql);
				}
			}
		}
		SendToServer(connCont, packet);
		data.erase(data.begin(), data.begin() + totalLen);
	}
}

void SendToClient(CONNECTION_CONTEXT* connCont, std::vector<char>& packet) {

	IO_CONTEXT& clientWrite = connCont->ClientWriteContext;
	InitializeContext(clientWrite, IOOperationType::WriteClient, connCont->ClientSocket);

	if (clientWrite.buffer.size() < packet.size()) {
		clientWrite.buffer.resize(packet.size());
	}

	memcpy(clientWrite.buffer.data(), packet.data(), packet.size());
	if (!Send(clientWrite, clientWrite.buffer.data(), static_cast<int>(packet.size()))) {
		CloseConnection(connCont);
	}
}

void ProcessServerBuffer(CONNECTION_CONTEXT* connCont) {

	auto& data = connCont->serverBuff;
	while (true) {
		if (data.size() < MySqlHeaderSize) return;
		unsigned int packetLen = (static_cast<unsigned char>(data[0])) |
			(static_cast<unsigned char>(data[1]) << 8) |
			(static_cast<unsigned char>(data[2]) << 16);

		unsigned int totalLen = MySqlHeaderSize + packetLen;
		if (data.size() < totalLen) {
			return; //Packet is not full. Waiting for the rest
		}

		std::vector<char> packet(data.begin(), data.begin() + totalLen);

		SendToClient(connCont, packet);
		data.erase(data.begin(), data.begin() + totalLen);
	}
}

/*std::string ParseQuery(const char* data, int len) {
	//4th byte - type of request
	//5th byte - request
	if (len < 5) return "";

	unsigned int packetLen = (static_cast<unsigned char>(data[0])) |
		(static_cast<unsigned char>(data[1]) << 8) |
		(static_cast<unsigned char>(data[2]) << 16);

	unsigned char command = static_cast<unsigned char>(data[4]);
	if (command != 0x03) return ""; //COM_QUERY

	int queryLen = packetLen - 1;

	return std::string(data + 5, queryLen);
}*/

void WorkerThread() {

	while (true) {
		DWORD bytesTransferred = 0;
		ULONG_PTR completionKey = 0;
		LPOVERLAPPED overlapped = nullptr;

		GetQueuedCompletionStatus(CompletionPort, &bytesTransferred, &completionKey, &overlapped, INFINITE);

		CONNECTION_CONTEXT* connCont = reinterpret_cast<CONNECTION_CONTEXT*>(completionKey);
		IO_CONTEXT* IOCont = reinterpret_cast<IO_CONTEXT*>(overlapped); // IO_CONTEXT address correlates with LPOVERLAPPED as Overlapped is the fires field in the IO_CONEXT structure



		IOCont->TransferredData = bytesTransferred;

		switch (IOCont->operation) {

		case IOOperationType::ReadClient: {

			connCont->clientBuff.insert(connCont->clientBuff.end(), IOCont->buffer.data(), IOCont->buffer.data() + bytesTransferred);
			ProcessClientBuffer(connCont);

			InitializeContext(connCont->ClientReadContext, IOOperationType::ReadClient, connCont->ClientSocket);

			Receive(connCont->ClientReadContext);
			break;
		}
		case IOOperationType::WriteServer: {
			break;
		}
		case IOOperationType::ReadServer: {

			//resend server response to client
			connCont->serverBuff.insert(connCont->serverBuff.end(), IOCont->buffer.data(), IOCont->buffer.data() + bytesTransferred);
			ProcessServerBuffer(connCont);
			InitializeContext(connCont->ServerReadContext, IOOperationType::ReadServer, connCont->ServerSocket);
			Receive(connCont->ServerReadContext);
			break;
		}
		case IOOperationType::WriteClient: {
			break;
		}

		default:
			break;
		}
	}
}

SOCKET ServerConnection(const char* host, int port) {

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		Log("Socket creation failed");
		return INVALID_SOCKET;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &serverAddr.sin_addr);
	if (connect(s, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		Log("connection failed");
		closesocket(s);
		return INVALID_SOCKET;
	}
	return s;
}


bool StartProxyServer() {

	CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, WORKER_THREAD_COUNT);
	if (!CompletionPort) {
		Log("Cretion of IOCP has failed");
		return false;
	}

	for (int i = 0; i < WORKER_THREAD_COUNT; ++i) {
		std::thread(WorkerThread).detach();
	}

	SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenSock == INVALID_SOCKET) {
		Log("Socket has failed!");
		return false;
	}

	sockaddr_in localAddr;
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(LISTEN_PORT);

	if (bind(listenSock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
		Log("Bind has failed!");
		closesocket(listenSock);
		return false;
	}
	if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
		Log("Listen has failed!");
		return false;
	}
	Log("Proxy listening on port " + std::to_string(LISTEN_PORT));

	while (true) {
		sockaddr_in clientAddr;
		int addrLen = sizeof(clientAddr);
		SOCKET clientSock = accept(listenSock, (sockaddr*)&clientAddr, &addrLen);
		if (clientSock == INVALID_SOCKET)
		{
			int error = WSAGetLastError();
			if (error == WSAEWOULDBLOCK)
			{
				Sleep(50);
				continue;
			}
			else
			{
				Log("accept() failed: " + std::to_string(error));
				continue;
			}
		}
		SOCKET serverSock = ServerConnection(SERVER_HOST, SERVER_PORT);
		if (serverSock == INVALID_SOCKET)
		{
			Log("Server Connection has failed!");
			closesocket(clientSock);
			continue;
		}
		CONNECTION_CONTEXT* connCont = new CONNECTION_CONTEXT();
		connCont->ClientSocket = clientSock;
		connCont->ServerSocket = serverSock;

		if (!SocketToCP(clientSock, (ULONG_PTR)connCont) || !SocketToCP(serverSock, (ULONG_PTR)connCont)) {
			Log("Associating socket with IOCP has faied!");
			CloseConnection(connCont);
		}

		InitializeContext(connCont->ClientReadContext, IOOperationType::ReadClient, clientSock);
		InitializeContext(connCont->ClientWriteContext, IOOperationType::WriteClient, clientSock);
		InitializeContext(connCont->ServerReadContext, IOOperationType::ReadServer, serverSock);
		InitializeContext(connCont->ServerWriteContext, IOOperationType::WriteServer, serverSock);

		if (!Receive(connCont->ClientReadContext)) {
			CloseConnection(connCont);
			continue;
		}
		if (!Receive(connCont->ServerReadContext)) {
			CloseConnection(connCont);
			continue;
		}

		//log connection
		char ip[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &clientAddr.sin_addr, ip, sizeof(ip));
		Log(std::string("Client connection: ") + ip);

	}
	closesocket(listenSock);
	return true;
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
