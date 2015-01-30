#ifndef INCLUDED_NETWORK_H
#define INCLUDED_NETWORK_H

#ifndef CONFIG
#define CONFIG "config.h"
#endif // CONFIG
#include CONFIG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "types.h"


#ifndef NO_DNS
typedef struct
{
	uint32_t random_weight;
	uint16_t priority;
	uint16_t weight;
	char serverName[72];
}  kms_server_dns_t, *kms_server_dns_ptr;

typedef struct
{
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	unsigned char name[1];
} dns_srv_record_t, *dns_srv_record_ptr;
#endif // NO_DNS


BOOL sendrecv(int sock, BYTE *data, int len, int do_send);

#define _recv(s, d, l)  sendrecv(s, (BYTE *)d, l,  0)
#define _send(s, d, l)  sendrecv(s, (BYTE *)d, l, !0)

#ifndef NO_SOCKETS

void closeAllListeningSockets();
BOOL addListeningSocket(const char *const addr);
__pure int_fast8_t checkProtocolStack(const int addressfamily);

#endif // NO_SOCKETS

int runServer();
SOCKET connectToAddress(const char *const addr, const int AddressFamily, int_fast8_t showHostName);
int_fast8_t isDisconnected(const SOCKET s);

#ifndef NO_DNS
int getKmsServerList(kms_server_dns_ptr** serverlist, const char *restrict query);
void sortSrvRecords(kms_server_dns_ptr* serverlist, const int answers);
#endif // NO_DNS

#endif // INCLUDED_NETWORK_H
