#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32")

#include <iostream>
#include <string>
#include <WinSock2.h>
#include <random>
using namespace std;

#define SERVERPORT 9050
#define BUFSIZE 512

#define C1 2021
#define C2 411

random_device rd;
mt19937 gen(rd());
uniform_int_distribution<int> dis(30000, 60000);

bool Encrypt(int _key, char* _source, char* _encrypt, unsigned long _front, unsigned long _length)
{
	unsigned long index;
	int key = _key;

	if (!_source || !_encrypt || _length <= 0)
		return false;

	for (index = _front; index < _length; index++)
	{
		_encrypt[index] = _source[index] ^ key >> 8;
		key = (_encrypt[index] + key) * C1 + C2;
	}
	return true;
}

bool Decrypt(int _key, char* _encrypt, char* _decrypt, unsigned long _front, unsigned long _length)
{
	unsigned long index;
	char previousblock;
	int key = _key;

	if (!_encrypt || !_decrypt || _length <= 0)
		return false;

	for (index = _front; index < _length; index++)
	{
		previousblock = _encrypt[index];
		_decrypt[index] = _encrypt[index] ^ key >> 8;
		key = (previousblock + key) * C1 + C2;
	}

	return true;
}

bool Packing(char* _buf, char* _data, int& _size)
{
	char* ptr = _buf + sizeof(int);
	_size = 0;
	int key = dis(gen);
	int len = strlen(_data);

	memcpy(ptr, &key, sizeof(key));
	ptr = ptr + sizeof(int);
	_size = _size + sizeof(key);

	memcpy(ptr, &len, sizeof(int));
	ptr = ptr + sizeof(int);
	_size = _size + sizeof(int);

	memcpy(ptr, _data, len);
	_size = _size + len;

	ptr = _buf;
	memcpy(ptr, &_size, sizeof(_size));
	_size = _size + sizeof(_size);

	// 암호화 구문
	char Encry[BUFSIZE + 1];
	ZeroMemory(Encry, sizeof(Encry));

	memcpy(Encry, ptr, _size);	// 현재 버퍼 정보 Encry 데이터에 복사
	if (!Encrypt(key, _buf, Encry, sizeof(int) * 2, _size))	// Encry 데이터 암호화
		return false;
	
	memcpy(_buf, Encry, _size);	// 암호화 된 Encry 데이터를 버퍼에 복사
	return true;
}

bool UnPacking(char* _buf, char* _data, int _size)
{
	char* ptr = _buf;

	int key = 0;
	memcpy(&key, ptr, sizeof(key));

	// 복호화 구문
	char Decry[BUFSIZE + 1];
	ZeroMemory(Decry, sizeof(Decry));

	if (!Decrypt(key, _buf, Decry, sizeof(int), _size)) // 암호화 되어 있는 버퍼를 복호화 하여 Decry 에 저장
		return false;

	memcpy(ptr, Decry, _size);	// 복호화 된 Decry 데이터를 버퍼에 저장
	ptr = ptr + sizeof(int);	// 버퍼 위치 이동	

	int len = 0;
	memcpy(&len, ptr, sizeof(int));
	ptr = ptr + sizeof(int);

	memcpy(_data, ptr, len);
	return true;
}

void error_quit(const char* msg);
void error_display(const char* msg);

int main()
{
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

	SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock == INVALID_SOCKET) error_quit("socket()");

	SOCKADDR_IN addr;
	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(SERVERPORT);
	int retval = bind(listen_sock, (SOCKADDR*)&addr, sizeof(addr));
	if (retval == SOCKET_ERROR) error_quit("bind()");

	retval = listen(listen_sock, SOMAXCONN);
	if (retval == SOCKET_ERROR) error_quit("listen()");

	SOCKET sock;
	SOCKADDR_IN clientaddr;
	int addrlen;
	char buf[BUFSIZE + 1];
	char msg[128];
	int size = 0;

	while (true)
	{
		addrlen = sizeof(clientaddr);
		sock = accept(listen_sock, (SOCKADDR*)&clientaddr, &addrlen);
		if (sock == INVALID_SOCKET)
		{
			error_display("accept()");
			break;
		}

		cout << "\n[TCP Server] Client Connet\nIP : " << inet_ntoa(clientaddr.sin_addr) << "\nPROT : " << ntohs(clientaddr.sin_port) << endl;

		while (true)
		{
			retval = recv(sock, (char*)&size, sizeof(int), 0);
			if (retval == SOCKET_ERROR)
			{
				error_display("recv()");
				break;
			}
			else if (retval == 0)
				break;

			retval = recv(sock, buf, size, 0);
			if (retval == SOCKET_ERROR)
			{
				error_display("recv()");
				break;
			}
			else if (retval == 0)
				break;

			ZeroMemory(msg, sizeof(msg));
			UnPacking(buf, msg, size);

			cout << "[TCP " << inet_ntoa(clientaddr.sin_addr) << ":" << ntohs(clientaddr.sin_port) << "] " << msg << endl;

			Packing(buf, msg, size);

			retval = send(sock, buf, size, 0);
			if (retval == SOCKET_ERROR)
			{
				error_display("send()");
				break;
			}			
		}

		cout << "[DisConnected]\n";
	}

	closesocket(listen_sock);
	WSACleanup();
	return 0;
}

void error_quit(const char* msg)
{
	void* lpmsgbuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpmsgbuf, 0, NULL);
	MessageBox(NULL, (LPCTSTR)lpmsgbuf, msg, MB_ICONERROR);
	LocalFree(lpmsgbuf);
	exit(1);
}

void error_display(const char* msg)
{
	void* lpmsgbuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpmsgbuf, 0, NULL);
	MessageBox(NULL, (LPCTSTR)lpmsgbuf, msg, MB_ICONERROR);
	LocalFree(lpmsgbuf);
}