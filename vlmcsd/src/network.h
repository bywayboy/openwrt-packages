#ifndef INCLUDED_NETWORK_H
#define INCLUDED_NETWORK_H

#define _GNU_SOURCE

#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif
#include "shared_globals.h"
#include "getopt.h"
#include "types.h"
#include "helpers.h"

BOOL sendrecv(int sock, BYTE *data, int len, int do_send);

#define _recv(s, d, l)  sendrecv(s, (BYTE *)d, l,  0)
#define _send(s, d, l)  sendrecv(s, (BYTE *)d, l, !0)

#ifndef NO_SOCKETS

void CloseAllListeningSockets();
int SetupListeningSockets(const uint_fast8_t maxsockets);

#endif // NO_SOCKETS

int RunServer();
SOCKET ConnectToAddress(const char *const addr, const int AddressFamily);
int IsDisconnected(const SOCKET s);

#endif // INCLUDED_NETWORK_H
