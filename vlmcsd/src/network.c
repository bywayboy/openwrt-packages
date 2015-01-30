#ifndef CONFIG
#define CONFIG "config.h"
#endif // CONFIG
#include CONFIG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
//#ifndef DNS_PARSER_INTERNAL
#if __ANDROID__
#include <netinet/in.h>
#include "nameser.h"
#include "resolv.h"
#else // other Unix non-Android
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif // other Unix non-Android
//#endif // DNS_PARSER_INTERNAL
#else // WIN32
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
#endif // WIN32

#include "network.h"
#include "endian.h"
#include "output.h"
#include "vlmcs.h"
#include "helpers.h"
#include "shared_globals.h"
#include "rpc.h"

#if defined(DNS_PARSER_INTERNAL) && !defined(_WIN32) && !defined(NO_DNS)

#include "ns_name.h"
#include "ns_parse.h"
#undef ns_msg
#undef ns_initparse
#undef ns_parserr
#undef ns_rr
#undef ns_name_uncompress
#undef ns_msg_base
#undef ns_msg_end
#undef ns_rr_rdata
#undef ns_rr_type
#undef ns_msg_count
#undef ns_rr_class
#undef ns_s_an
#define ns_msg ns_msg_vlmcsd
#define ns_initparse ns_initparse_vlmcsd
#define ns_parserr ns_parserr_vlmcsd
#define ns_rr ns_rr_vlmcsd
#define ns_name_uncompress ns_name_uncompress_vlmcsd
#define ns_msg_base ns_msg_base_vlmcsd
#define ns_msg_end ns_msg_end_vlmcsd
#define ns_rr_rdata ns_rr_rdata_vlmcsd
#define ns_rr_type ns_rr_type_vlmcsd
#define ns_msg_count ns_msg_count_vlmcsd
#define ns_rr_class ns_rr_class_vlmcsd
#define ns_s_an ns_s_an_vlmcsd

#ifndef NS_MAXLABEL
#define NS_MAXLABEL 63
#endif

#endif // defined(DNS_PARSER_INTERNAL) && !defined(_WIN32)





// Send or receive a fixed number of bytes regardless if received in one or more chunks
BOOL sendrecv(int sock, BYTE *data, int len, int do_send)
{
	int n;
	SENDRECV_T( f ) = do_send
			? (SENDRECV_T()) send
			: (SENDRECV_T()) recv;

	do
	{
			n = f(sock, data, len, 0);
	}
	while (
			( n < 0 && socket_errno == VLMCSD_EINTR ) || ( n > 0 && ( data += n, (len -= n) > 0 ) ));

	return ! len;
}


static int_fast8_t ip2str(char *restrict result, const size_t resultlen, const struct sockaddr *const restrict sa, const socklen_t socklen)
{
	static const char *const fIPv4 = "%s:%s";
	static const char *const fIPv6 = "[%s]:%s";
	char addr[64], serv[8];

	if (getnameinfo(sa, socklen, addr, sizeof(addr), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) return FALSE;
	if ((unsigned int)snprintf(result, resultlen, sa->sa_family == AF_INET6 ? fIPv6 : fIPv4, addr, serv) > resultlen) return FALSE;
	return TRUE;
}


static int_fast8_t getSocketList(struct addrinfo **saList, const char *const addr, const int flags, const int AddressFamily)
{
	int rc;

	size_t len = strlen(addr) + 1;

	// Don't alloca too much
	if (len > 256) return FALSE;

	char *addrcopy = (char*)alloca(len);

	memcpy(addrcopy, addr, len);

	char *szHost = addrcopy;
	const char *szPort = defaultport;

	char *lastcolon = strrchr(addrcopy, ':');
	char *firstcolon = strchr(addrcopy, ':');
	char *closingbracket = strrchr(addrcopy, ']');

	if (*addrcopy == '[' && closingbracket) //Address in brackets
	{
		*closingbracket = 0;
		szHost++;

		if (closingbracket[1] == ':')
			szPort = closingbracket + 2;
	}
	else if (firstcolon && firstcolon == lastcolon) //IPv4 address or hostname with port
	{
		*firstcolon = 0;
		szPort = firstcolon + 1;
	}

	struct addrinfo hints;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AddressFamily;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = flags;

	if ((rc = getaddrinfo(szHost, szPort, &hints, saList)))
	{
		printerrorf("Warning: %s: %s\n", addr, gai_strerror(rc));
		return FALSE;
	}

	return TRUE;
}


static int_fast8_t setBlockingEnabled(SOCKET fd, int_fast8_t blocking)
{
	if (fd < 0) return FALSE;

	#ifdef _WIN32

	unsigned long mode = blocking ? 0 : 1;
	return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? TRUE : FALSE;

	#else // POSIX

	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0) return FALSE;

	flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
	return (fcntl(fd, F_SETFL, flags) == 0) ? TRUE : FALSE;

	#endif // POSIX
}


int_fast8_t isDisconnected(const SOCKET s)
{
	char buffer[1];

	if (!setBlockingEnabled(s, FALSE)) return TRUE;

	int n = recv(s, buffer, 1, MSG_PEEK);

	if (!setBlockingEnabled(s, TRUE)) return TRUE;
	if (n == 0) return TRUE;

	return FALSE;
}


// Connect to TCP address addr (e.g. "kms.example.com:1688") and return an
// open socket for the connection if successful or INVALID_SOCKET otherwise
SOCKET connectToAddress(const char *const addr, const int AddressFamily, int_fast8_t showHostName)
{
	struct addrinfo *saList, *sa;
	SOCKET s = INVALID_SOCKET;
	char szAddr[128];

	if (!getSocketList(&saList, addr, 0, AddressFamily)) return INVALID_SOCKET;

	for (sa = saList; sa; sa = sa->ai_next)
	{
		// struct sockaddr_in* addr4 = (struct sockaddr_in*)sa->ai_addr;
		// struct sockaddr_in6* addr6 = (struct sockaddr_in6*)sa->ai_addr;

		if (ip2str(szAddr, sizeof(szAddr), sa->ai_addr, sa->ai_addrlen))
		{
			if (showHostName)
				printf("Connecting to %s (%s) ... ", addr, szAddr);
			else
				printf("Connecting to %s ... ", szAddr);

			fflush(stdout);
		}

		s = socket(sa->ai_family, SOCK_STREAM, IPPROTO_TCP);

		#ifndef _WIN32 // Standard Posix timeout structure

		// llvm-gcc 4.2 from Apple SDK can't compile this
		/*struct timeval to = {
				.tv_sec  = 10,
				.tv_usec = 0
		};*/

		// Doesn't seem to cause any perfomance degradation (neither speed nor size)
		struct timeval to;
		to.tv_sec = 10;
		to.tv_usec = 0;

		#else // Windows requires a DWORD with milliseconds

		DWORD to = 10000;

		#endif // _WIN32

		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (sockopt_t)&to, sizeof(to));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (sockopt_t)&to, sizeof(to));

		if (!connect(s, sa->ai_addr, sa->ai_addrlen))
		{
			printf("successful\n");
			break;
		}

		errorout("%s\n", socket_errno == VLMCSD_EINPROGRESS ? "Timed out" : vlmcsd_strerror(socket_errno));

		socketclose(s);
		s = INVALID_SOCKET;
	}

	freeaddrinfo(saList);
	return s;
}


#ifndef NO_DNS

static int kmsServerListCompareFunc1(const void* a, const void* b)
{
	if ( !a && !b) return 0;
	if ( a && !b) return -1;
	if ( !a && b) return 1;

	int priority_order =  (int)((*(kms_server_dns_ptr*)a)->priority) - ((int)(*(kms_server_dns_ptr*)b)->priority);

	if (priority_order) return priority_order;

	return (int)((*(kms_server_dns_ptr*)b)->random_weight) - ((int)(*(kms_server_dns_ptr*)a)->random_weight);
}


//TODO: move to helpers.c
static unsigned int isqrt(unsigned int n)
{
	unsigned int c = 0x8000;
	unsigned int g = 0x8000;

	for(;;)
	{
		if(g*g > n)
			g ^= c;

		c >>= 1;

		if(c == 0) return g;

		g |= c;
	}
}


void sortSrvRecords(kms_server_dns_ptr* serverlist, const int answers)
{
	int i;

	for (i = 0; i < answers; i++)
	{
		serverlist[i]->random_weight = (rand32() % 256) * isqrt(serverlist[i]->weight * 1000);
	}

	qsort(serverlist, answers, sizeof(kms_server_dns_ptr), kmsServerListCompareFunc1);
}


#define RECEIVE_BUFFER_SIZE 2048
#ifndef _WIN32 // UNIX resolver

static int getDnsRawAnswer(const char *restrict query, unsigned char** receive_buffer)
{
	if (res_init() < 0)
	{
		fprintf(stderr, "Cannot initialize resolver: %s", strerror(errno));
		return 0;
	}

	if(!(*receive_buffer = (unsigned char*)malloc(RECEIVE_BUFFER_SIZE))) OutOfMemory();

	int bytes_received;

	if (*query == '.')
	{
#		if __ANDROID__ || __GLIBC__ /* including __UCLIBC__*/ || __APPLE__ || __CYGWIN__ || __FreeBSD__ || __NetBSD__ || __DragonFly__ || __OpenBSD__ || __sun__
			bytes_received = res_querydomain("_vlmcs._tcp", query + 1, ns_c_in,	ns_t_srv, *receive_buffer, RECEIVE_BUFFER_SIZE);
#		else
			char* querystring = (char*)alloca(strlen(query) + 12);
			strcpy(querystring, "_vlmcs._tcp");
			strcat(querystring, query);
			bytes_received = res_query(querystring, ns_c_in, ns_t_srv, *receive_buffer, RECEIVE_BUFFER_SIZE);
#		endif
	}
	else
	{
		bytes_received = res_search("_vlmcs._tcp", ns_c_in, ns_t_srv, *receive_buffer, RECEIVE_BUFFER_SIZE);
	}

	if (bytes_received < 0)
	{
		fprintf(stderr, "Fatal: DNS query to %s%s failed: %s\n", "_vlmcs._tcp",	*query == '.' ? query : "", hstrerror(h_errno));
		return 0;
	}

	return bytes_received;
}


int getKmsServerList(kms_server_dns_ptr** serverlist, const char *restrict query)
{
	unsigned char* receive_buffer;
	*serverlist = NULL;

	int bytes_received = getDnsRawAnswer(query, &receive_buffer);

	if (bytes_received == 0) return 0;

	ns_msg msg;

	if (ns_initparse(receive_buffer, bytes_received, &msg) < 0)
	{
		fprintf(stderr, "Fatal: Incorrect DNS response: %s\n", strerror(errno));
		free(receive_buffer);
		return 0;
	}

	uint16_t i, answers = ns_msg_count(msg, ns_s_an);
	if(!(*serverlist = (kms_server_dns_ptr*)malloc(answers * sizeof(kms_server_dns_ptr)))) OutOfMemory();

	memset(*serverlist, 0, answers * sizeof(kms_server_dns_ptr));

	for (i = 0; i < answers; i++)
	{
		ns_rr rr;

		if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
		{
			fprintf(stderr, "Warning: Error in DNS resource record: %s\n", strerror(errno));
			continue;
		}

		if (ns_rr_type(rr) != ns_t_srv)
		{
			fprintf(stderr, "Warning: DNS server returned non-SRV record\n");
			continue;
		}

		if (ns_rr_class(rr) != ns_c_in)
		{
			fprintf(stderr, "Warning: DNS server returned non-IN class record\n");
			continue;
		}

		dns_srv_record_ptr srvrecord = (dns_srv_record_ptr)ns_rr_rdata(rr);
		kms_server_dns_ptr kms_server = (kms_server_dns_ptr)malloc(sizeof(kms_server_dns_t));

		if (!kms_server) OutOfMemory();

		(*serverlist)[i] = kms_server;

		if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), srvrecord->name, kms_server->serverName, NS_MAXLABEL + 1) < 0)
		{
			fprintf(stderr, "Warning: No valid DNS name returned in SRV record: %s\n", strerror(errno));
			continue;
		}

        sprintf(kms_server->serverName + strlen(kms_server->serverName), ":%hu", GET_UA16BE(&srvrecord->port));
        kms_server->priority = GET_UA16BE(&srvrecord->priority);
        kms_server->weight = GET_UA16BE(&srvrecord->weight);

	}

	free(receive_buffer);
	return answers;
}

#else // WIN32 (Windows Resolver)

int getKmsServerList(kms_server_dns_ptr** serverlist, const char *const restrict query)
{
#	define MAX_DNS_NAME_SIZE 64
#	define FQDN_QUERY_SIZE (MAX_DNS_NAME_SIZE + 12)
	*serverlist = NULL;
	PDNS_RECORD receive_buffer;
	char dnsDomain[64];
	char FqdnQuery[76];
	DWORD size = 64;
	DNS_STATUS result;
	int answers = 0;
	PDNS_RECORD dns_iterator;

	if (*query == '-' && !GetComputerNameExA(ComputerNamePhysicalDnsDomain, dnsDomain, &size))
	{
		errorout("Fatal: Could not determine computer's DNS name: %s\n", vlmcsd_strerror(GetLastError()));
		return 0;
	}

	if (*query == '-')
	{
		strcpy(FqdnQuery, "_vlmcs._tcp.");
		strncat(FqdnQuery, dnsDomain, size);
	}
	else
	{
		strcpy(FqdnQuery, "_vlmcs._tcp");
		strncat(FqdnQuery, query, MAX_DNS_NAME_SIZE);
	}

	if ((result = DnsQuery_UTF8(FqdnQuery, DNS_TYPE_SRV, 0, NULL, &receive_buffer, NULL)) != 0)
	{
		errorout("Fatal: DNS query to %s failed: %s\n", FqdnQuery, vlmcsd_strerror(result));
		return 0;
	}

	for (dns_iterator = receive_buffer; dns_iterator; dns_iterator = dns_iterator->pNext)
	{
		if (dns_iterator->Flags.S.Section != 1) continue;

		if (dns_iterator->wType != DNS_TYPE_SRV)
		{
			errorout("Warning: DNS server returned non-SRV record\n");
			continue;
		}

		answers++;
	}

	if(!(*serverlist = (kms_server_dns_ptr*)malloc(answers * sizeof(kms_server_dns_ptr)))) OutOfMemory();

	for (answers = 0, dns_iterator = receive_buffer; dns_iterator; dns_iterator = dns_iterator->pNext)
	{
		if (dns_iterator->wType != DNS_TYPE_SRV) continue;

		kms_server_dns_ptr kms_server = (kms_server_dns_ptr)malloc(sizeof(kms_server_dns_t));

		if (!kms_server) OutOfMemory();

		memset(kms_server, 0, sizeof(kms_server_dns_t));

		snprintf(kms_server->serverName, sizeof(kms_server->serverName), "%s:%hu", dns_iterator->Data.SRV.pNameTarget, dns_iterator->Data.SRV.wPort);
		kms_server->priority = dns_iterator->Data.SRV.wPriority;
		kms_server->weight = dns_iterator->Data.SRV.wWeight;

		(*serverlist)[answers++] = kms_server;
	}

	//sortSrvRecords(*serverlist, answers, NoSrvRecordPriority);

	DnsRecordListFree(receive_buffer, DnsFreeRecordList);

	return answers;
#	undef MAX_DNS_NAME_SIZE
#	undef FQDN_QUERY_SIZE
}
#endif // _WIN32
#undef RECEIVE_BUFFER_SIZE
#endif // NO_DNS
#ifndef NO_SOCKETS


// Create a Listening socket for addrinfo sa and return socket s
// szHost and szPort are for logging only
static int listenOnAddress(const struct addrinfo *const ai, SOCKET *s)
{
	int error;
	char ipstr[64];

	ip2str(ipstr, sizeof(ipstr), ai->ai_addr, ai->ai_addrlen);

	//*s = INVALID_SOCKET;
	*s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);

	if (*s == INVALID_SOCKET)
	{
		error = socket_errno;
		printerrorf("Warning: %s error. %s\n", ai->ai_family == AF_INET6 ? cIPv6 : cIPv4, vlmcsd_strerror(error));
		return error;
	}

	BOOL socketOption = TRUE;

	// fix for lame tomato toolchain
	#ifndef IPV6_V6ONLY
	#ifdef __linux__
	#define IPV6_V6ONLY (26)
	#endif // __linux__
	#endif // IPV6_V6ONLY

	#ifdef IPV6_V6ONLY
	if (ai->ai_family == AF_INET6) setsockopt(*s, IPPROTO_IPV6, IPV6_V6ONLY, (sockopt_t)&socketOption, sizeof(socketOption));
	#endif

	#ifndef _WIN32
	setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, (sockopt_t)&socketOption, sizeof(socketOption));
	#endif

	if (bind(*s, ai->ai_addr, ai->ai_addrlen) || listen(*s, SOMAXCONN))
	{
		error = socket_errno;
		printerrorf("Warning: %s: %s\n", ipstr, vlmcsd_strerror(error));
		socketclose(*s);
		return error;
	}

	#ifndef NO_LOG
	logger("Listening on %s\n", ipstr);
	#endif

	return 0;
}


// Adds a listening socket for an address string,
// e.g. 127.0.0.1:1688 or [2001:db8:dead:beef::1]:1688
BOOL addListeningSocket(const char *const addr)
{
	struct addrinfo *aiList, *ai;
	int result = FALSE;
	SOCKET *s = SocketList + numsockets;

	if (getSocketList(&aiList, addr, AI_PASSIVE | AI_NUMERICHOST, AF_UNSPEC))
	{
		for (ai = aiList; ai; ai = ai->ai_next)
		{
			// struct sockaddr_in* addr4 = (struct sockaddr_in*)sa->ai_addr;
			// struct sockaddr_in6* addr6 = (struct sockaddr_in6*)sa->ai_addr;

			if (numsockets >= FD_SETSIZE)
			{
				#ifdef _PEDANTIC // Do not report this error in normal builds to keep file size low
				printerrorf("Warning: Cannot listen on %s. Your OS only supports %u listening sockets in an FD_SET.\n", addr, FD_SETSIZE);
				#endif
				break;
			}

			if (!listenOnAddress(ai, s))
			{
				numsockets++;
				result = TRUE;
			}
		}

		freeaddrinfo(aiList);
	}
	return result;
}


// Just create some dummy sockets to see if we have a specific protocol (IPv4 or IPv6)
__pure int_fast8_t checkProtocolStack(const int addressfamily)
{
	SOCKET s; // = INVALID_SOCKET;

	s = socket(addressfamily, SOCK_STREAM, 0);
	int_fast8_t success = (s != INVALID_SOCKET);

	socketclose(s);
	return success;
}


// Build an fd_set of all listening socket then use select to wait for an incoming connection
static SOCKET network_accept_any()
{
    fd_set ListeningSocketsList;
    SOCKET maxSocket, sock;
    int i;
    int status;

    FD_ZERO(&ListeningSocketsList);
    maxSocket = 0;

    for (i = 0; i < numsockets; i++)
    {
        FD_SET(SocketList[i], &ListeningSocketsList);
        if (SocketList[i] > maxSocket) maxSocket = SocketList[i];
    }

    status = select(maxSocket + 1, &ListeningSocketsList, NULL, NULL, NULL);

    if (status < 0) return INVALID_SOCKET;

    sock = INVALID_SOCKET;

    for (i = 0; i < numsockets; i++)
    {
        if (FD_ISSET(SocketList[i], &ListeningSocketsList))
        {
            sock = SocketList[i];
            break;
        }
    }

    if (sock == INVALID_SOCKET)
        return INVALID_SOCKET;
    else
        return accept(sock, NULL, NULL);
}


void closeAllListeningSockets()
{
	int i;

	for (i = 0; i < numsockets; i++)
	{
		shutdown(SocketList[i], VLMCSD_SHUT_RDWR);
		socketclose(SocketList[i]);
	}
}
#endif // NO_SOCKETS


static void serveClient(const SOCKET s_client, const DWORD RpcAssocGroup)
{
	#ifndef _WIN32 // Standard Posix timeout structure

	// llvm-gcc 4.2 from Apple SDK can't compile this
	/*struct timeval to = {
		.tv_sec  = 60,
		.tv_usec = 0
	};*/

	struct timeval to;
	to.tv_sec = ServerTimeout;
	to.tv_usec = 0;

	#else // Windows requires a DWORD with milliseconds

	DWORD to = ServerTimeout * 1000;

	#endif // _WIN32

	if (
		setsockopt(s_client, SOL_SOCKET, SO_RCVTIMEO, (sockopt_t)&to, sizeof(to)) ||
		setsockopt(s_client, SOL_SOCKET, SO_SNDTIMEO, (sockopt_t)&to, sizeof(to))
	)
	{
		#ifndef _WIN32
		if (socket_errno == VLMCSD_ENOTSOCK)
			errorout("Fatal: %s\n", vlmcsd_strerror(socket_errno));
		#endif // _WIN32

		socketclose(s_client);
		return;
	}

	#ifndef NO_LOG
	socklen_t len;
	struct sockaddr_storage addr;

	char ipstr[64];

	len = sizeof addr;

	if (getpeername(s_client, (struct sockaddr*)&addr, &len) ||
		!ip2str(ipstr, sizeof(ipstr), (struct sockaddr*)&addr, len))
	{
		socketclose(s_client);
		return;
	}

	const char *const connection_type = addr.ss_family == AF_INET6 ? cIPv6 : cIPv4;
	static const char *const cAccepted = "accepted";
	static const char *const cClosed = "closed";
	static const char *const fIP = "%s connection %s: %s.\n";

	logger(fIP, connection_type, cAccepted, ipstr);
	#endif // NO_LOG

	rpcServer(s_client, RpcAssocGroup);

	#ifndef NO_LOG
	logger(fIP, connection_type, cClosed, ipstr);
	#endif // NO_LOG

	socketclose(s_client);
}


#ifndef NO_SOCKETS
static void post_sem(void)
{
	#if !defined(NO_LIMIT)
	if (!InetdMode && MaxTasks != SEM_VALUE_MAX)
	{
		semaphore_post(Semaphore);
	}
	#endif // !defined(NO_LIMIT) && !defined(NO_SOCKETS)
}


static void wait_sem(void)
{
	#if !defined(NO_LIMIT)
	if (!InetdMode && MaxTasks != SEM_VALUE_MAX)
	{
		semaphore_wait(Semaphore);
	}
	#endif // !defined(NO_LIMIT) && !defined(NO_SOCKETS)
}
#endif // NO_SOCKETS

#if defined(USE_THREADS) && !defined(NO_SOCKETS)

#if defined(_WIN32) || defined(__CYGWIN__) // Win32 Threads
static DWORD WINAPI serveClientThreadProc(PCLDATA clData)
#else // Posix threads
static void *serveClientThreadProc (PCLDATA clData)
#endif // Thread proc is identical in WIN32 and Posix threads
{
	serveClient(clData->socket, clData->RpcAssocGroup);
	free(clData);
	post_sem();

	return 0;
}

#endif // USE_THREADS


#ifndef NO_SOCKETS

#if defined(USE_THREADS) && (defined(_WIN32) || defined(__CYGWIN__)) // Windows Threads
static int serveClientAsyncWinThreads(const PCLDATA thr_CLData)
{
	wait_sem();

	HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)serveClientThreadProc, thr_CLData, 0, NULL);

	if (h)
		CloseHandle(h);
	else
	{
		socketclose(thr_CLData->socket);
		free(thr_CLData);
		post_sem();
		return GetLastError();
	}

	return NO_ERROR;
}
#endif // defined(USE_THREADS) && defined(_WIN32) // Windows Threads


#if defined(USE_THREADS) && !defined(_WIN32) && !defined(__CYGWIN__) // Posix Threads
static int ServeClientAsyncPosixThreads(const PCLDATA thr_CLData)
{
	pthread_t p_thr;
	pthread_attr_t attr;

	wait_sem();

	// Must set detached state to avoid memory leak
	if (pthread_attr_init(&attr) ||
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) ||
		pthread_create(&p_thr, &attr, (void * (*)(void *))serveClientThreadProc, thr_CLData))
	{
		socketclose(thr_CLData->socket);
		free(thr_CLData);
		post_sem();
		return !0;
	}

	return 0;
}
#endif //  defined(USE_THREADS) && !defined(_WIN32) // Posix Threads

#ifndef USE_THREADS // fork() implementation
static void ChildSignalHandler(const int signal)
{
	if (signal == SIGHUP) return;

	post_sem();

	#ifndef NO_LOG
	logger("Warning: Child killed/crashed by %s\n", strsignal(signal));
	#endif // NO_LOG

	exit(!0);
}

static int ServeClientAsyncFork(const SOCKET s_client, const DWORD RpcAssocGroup)
{
	int pid;
	wait_sem();

	if ((pid = fork()) < 0)
	{
		return errno;
	}
	else if ( pid )
	{
		// Parent process
		socketclose(s_client);
		return 0;
	}
	else
	{
		// Child process

		// Setup a Child Handler for most common termination signals
		struct sigaction sa;

		sa.sa_flags   = 0;
		sa.sa_handler = ChildSignalHandler;

		static int signallist[] = { SIGHUP, SIGINT, SIGTERM, SIGSEGV, SIGILL, SIGFPE, SIGBUS };

		if (!sigemptyset(&sa.sa_mask))
		{
			uint_fast8_t i;

			for (i = 0; i < _countof(signallist); i++)
			{
				sigaction(signallist[i], &sa, NULL);
			}
		}

		serveClient(s_client, RpcAssocGroup);
		post_sem();
		exit(0);
	}
}
#endif


int serveClientAsync(const SOCKET s_client, const DWORD RpcAssocGroup)
{
	#ifndef USE_THREADS // fork() implementation

	return ServeClientAsyncFork(s_client, RpcAssocGroup);

	#else // threads implementation

	PCLDATA thr_CLData = (PCLDATA)malloc(sizeof(CLDATA));

	if (thr_CLData)
	{
		thr_CLData->socket = s_client;
		thr_CLData->RpcAssocGroup = RpcAssocGroup;

		#if defined(_WIN32) || defined (__CYGWIN__) // Windows threads

		return serveClientAsyncWinThreads(thr_CLData);

		#else // Posix Threads

		return ServeClientAsyncPosixThreads(thr_CLData);

		#endif // Posix Threads
	}
	else
	{
		socketclose(s_client);
		return !0;
	}

	#endif // USE_THREADS
}

#endif // NO_SOCKETS


int runServer()
{
	DWORD RpcAssocGroup = rand32();

	// If compiled for inetd-only mode just serve the stdin socket
	#ifdef NO_SOCKETS
	serveClient(fileno(stdin), RpcAssocGroup);
	return 0;
	#else
	// In inetd mode just handle the stdin socket
	if (InetdMode)
	{
		serveClient(fileno(stdin), RpcAssocGroup);
		return 0;
	}

	// Standalone mode
	for (;;)
	{
		int error;
		SOCKET s_client;

		if ( (s_client = network_accept_any()) == INVALID_SOCKET )
		{
			error = socket_errno;

			if (error == VLMCSD_EINTR || error == VLMCSD_ECONNABORTED) continue;

			#ifdef _NTSERVICE
			if (ServiceShutdown) return 0;
			#endif

			#ifndef NO_LOG
			logger("Fatal: %s\n",vlmcsd_strerror(error));
			#endif

			return error;
		}

		RpcAssocGroup++;
		serveClientAsync(s_client, RpcAssocGroup);
	}
	#endif // NO_SOCKETS

	return 0;
}
