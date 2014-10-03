#include "network.h"
#include "output.h"
#include "vlmcs.h"

static const char *const cIPv4 = "IPv4";
static const char *const cIPv6 = "IPv6";

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


static int_fast8_t ip2str(char *restrict result, size_t resultlen, const struct sockaddr *const sa, socklen_t socklen)
{
	static const char *const fIPv4 = "%s:%s";
	static const char *const fIPv6 = "[%s]:%s";
	char addr[64], serv[8];

	if (getnameinfo(sa, socklen, addr, sizeof(addr), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) return FALSE;
	if ((unsigned int)snprintf(result, resultlen, sa->sa_family == AF_INET6 ? fIPv6 : fIPv4, addr, serv) > resultlen) return FALSE;
	return TRUE;
}


static int GetSocketList(struct addrinfo **saList, const char *const addr, const int flags, const int AddressFamily)
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


static BOOL SetBlockingEnabled(SOCKET fd, BOOL blocking)
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


int IsDisconnected(const SOCKET s)
{
	char buffer[1];

	if (!SetBlockingEnabled(s, FALSE)) return TRUE;

	int n = recv(s, buffer, 1, MSG_PEEK);

	if (!SetBlockingEnabled(s, TRUE)) return TRUE;
	if (n == 0) return TRUE;

	return FALSE;
}


// Connect to TCP address addr (e.g. "kms.example.com:1688") and return an
// open socket for the connection if successful or INVALID_SOCKET otherwise
SOCKET ConnectToAddress(const char *const addr, const int AddressFamily)
{
	struct addrinfo *saList, *sa;
	SOCKET s = INVALID_SOCKET;
	char szAddr[128];

	if (!GetSocketList(&saList, addr, 0, AddressFamily)) return INVALID_SOCKET;

	for (sa = saList; sa; sa = sa->ai_next)
	{
		// struct sockaddr_in* addr4 = (struct sockaddr_in*)sa->ai_addr;
		// struct sockaddr_in6* addr6 = (struct sockaddr_in6*)sa->ai_addr;

		if (ip2str(szAddr, sizeof(szAddr), sa->ai_addr, sa->ai_addrlen))
		{
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


#ifndef NO_SOCKETS

// Create a Listening socket for addrinfo sa and return socket s
// szHost and szPort are for logging only
static int ListenOnAddress(const struct addrinfo *const ai, SOCKET *s)
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
static int AddListeningSocket(const char *const addr)
{
	struct addrinfo *aiList, *ai;
	int result = FALSE;
	SOCKET *s = SocketList + numsockets;

	if (GetSocketList(&aiList, addr, AI_PASSIVE | AI_NUMERICHOST, AF_UNSPEC))
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

			if (!ListenOnAddress(ai, s))
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
__pure static int_fast8_t CheckProtocolStack(const int addressfamily)
{
	SOCKET s; // = INVALID_SOCKET;

	s = socket(addressfamily, SOCK_STREAM, 0);
	int_fast8_t success = (s != INVALID_SOCKET);

	socketclose(s);
	return success;
}


int SetupListeningSockets(uint_fast8_t maxsockets)
{
	int o;
	uint_fast8_t allocsockets = maxsockets ? maxsockets : 2;
	int_fast8_t HaveIPv6Stack = 0;
	int_fast8_t HaveIPv4Stack = 0;
	int_fast8_t v6required = 0;
	int_fast8_t v4required = 0;

	if (!(SocketList = (SOCKET*)malloc((size_t)allocsockets * sizeof(SOCKET)))) return !0;

	HaveIPv4Stack = CheckProtocolStack(AF_INET);
	HaveIPv6Stack = CheckProtocolStack(AF_INET6);

	// Reset getopt since we've alread used it
	OptReset();

	for (opterr = 0; ( o = getopt(global_argc, (char* const*)global_argv, optstring) ) > 0; ) switch (o)
	{
	case '4':

		if (!HaveIPv4Stack)
		{
			printerrorf("Fatal: Your system does not support %s.\n", cIPv4);
			return(!0);
		}
		v4required = 1;
		break;

	case '6':

		if (!HaveIPv6Stack)
		{
			printerrorf("Fatal: Your system does not support %s.\n", cIPv6);
			return(!0);
		}
		v6required = 1;
		break;

	case 'L':

		AddListeningSocket(optarg);
		break;

	case 'P':

		defaultport = optarg;
		break;

	default:

		break;
	}

	// if -L hasn't been specified on the command line, use default sockets (all IP addresses)
	// maxsocket results from first pass parsing the arguments
	if (!maxsockets)
	{
		if (HaveIPv6Stack && (v6required || !v4required)) AddListeningSocket("::");
		if (HaveIPv4Stack && (v4required || !v6required)) AddListeningSocket("0.0.0.0");
	}

	if (!numsockets)
	{
		printerrorf("Fatal: Could not listen on any socket.\n");
		return(!0);
	}
	return(0);
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


void CloseAllListeningSockets()
{
	int i;

	for (i = 0; i < numsockets; i++)
	{
		shutdown(SocketList[i], VLMCSD_SHUT_RDWR);
		socketclose(SocketList[i]);
	}
}
#endif // NO_SOCKETS


static void ServeClient(const SOCKET s_client, const DWORD RpcAssocGroup)
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

	RpcServer(s_client, RpcAssocGroup);

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
static DWORD WINAPI ServeClientThreadProc(PCLDATA clData)
#else // Posix threads
static void *ServeClientThreadProc (PCLDATA clData)
#endif // Thread proc is identical in WIN32 and Posix threads
{
	ServeClient(clData->socket, clData->RpcAssocGroup);
	free(clData);
	post_sem();

	return 0;
}

#endif // USE_THREADS


#ifndef NO_SOCKETS

#if defined(USE_THREADS) && (defined(_WIN32) || defined(__CYGWIN__)) // Windows Threads
static int ServeClientAsyncWinThreads(const PCLDATA thr_CLData)
{
	wait_sem();

	HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ServeClientThreadProc, thr_CLData, 0, NULL);

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
		pthread_create(&p_thr, &attr, (void * (*)(void *))ServeClientThreadProc, thr_CLData))
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

		// Restore default handlers for SIGINT and SIGTERM
		struct sigaction sa;
		sa.sa_handler = ChildSignalHandler;
		sa.sa_flags   = 0;

		static int signallist[] = { SIGHUP, SIGINT, SIGTERM, SIGSEGV, SIGILL, SIGFPE, SIGBUS };

		if (!sigemptyset(&sa.sa_mask))
		{
			uint_fast8_t i;

			for (i = 0; i < _countof(signallist); i++)
			{
				sigaction(signallist[i], &sa, 0);
			}
		}

		ServeClient(s_client, RpcAssocGroup);
		post_sem();
		exit(0);
	}
}
#endif


int ServeClientAsync(const SOCKET s_client, const DWORD RpcAssocGroup)
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

		return ServeClientAsyncWinThreads(thr_CLData);

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


int RunServer()
{
	DWORD RpcAssocGroup = rand32();

	// If compiled for inetd-only mode just serve the stdin socket
	#ifdef NO_SOCKETS
	ServeClient(fileno(stdin), RpcAssocGroup);
	return 0;
	#else
	// In inetd mode just handle the stdin socket
	if (InetdMode)
	{
		ServeClient(fileno(stdin), RpcAssocGroup);
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
		ServeClientAsync(s_client, RpcAssocGroup);
	}
	#endif // NO_SOCKETS

	return 0;
}
