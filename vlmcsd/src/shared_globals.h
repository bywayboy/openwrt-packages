#ifndef INCLUDED_SHARED_GLOBALS_H
#define INCLUDED_SHARED_GLOBALS_H

#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>
#include <semaphore.h>
#include "output.h"
#include "rpc.h"

#define MAX_KMSAPPS 3
typedef struct
{
	const char* Epid;
	const BYTE* HwId;
	#ifndef NO_LOG
	const char* EpidSource;
	#endif // NO_LOG
	//uint_fast8_t HwIdSource;
	uint_fast8_t EpidFromMalloc;
	uint_fast8_t HwIdFromMalloc;
} KmsResponseParam_t, *PKmsResponseParam_t;

#ifndef NO_LIMIT
#ifndef SEM_VALUE_MAX // Android does not define this
#ifdef __ANDROID__
#define SEM_VALUE_MAX 0x3fffffff
#elif !defined(_WIN32)
#define SEM_VALUE_MAX 0x7fffffff
#else
#define SEM_VALUE_MAX 0x7fff // Be cautious if unknown
#endif // __ANDROID__
#endif // !defined(SEM_VALUE_MAX)
#endif // NO_LIMIT

#ifndef _WIN32
#define SENDRECV_T(v)  int (*v)(int, BYTE*, int, int)
#else
#define SENDRECV_T(v)  int (WINAPI *v)(int, BYTE*, int, int)
#endif

#ifndef VERSION
#define VERSION "private build"
#endif

extern const char *const Version;

//Fix for stupid eclipse parser
#ifndef UINT_MAX
#define UINT_MAX 4294967295
#endif

#ifndef NO_PID_FILE
extern char *fn_pid;
#endif
#ifndef NO_INI_FILE
extern char *fn_ini;
#endif

extern const char *defaultport;
extern int global_argc;
extern CARGV global_argv;
extern int_fast8_t nodaemon;
extern int_fast8_t InetdMode;
extern const char* const optstring;
extern DWORD ActivationInterval;
extern DWORD RenewalInterval;
extern int_fast8_t UseMultiplexedRpc;
extern int_fast8_t DisconnectImmediately;
extern DWORD ServerTimeout;
extern KmsResponseParam_t KmsResponseParameters[MAX_KMSAPPS];

#if !defined(NO_LIMIT) && !defined (NO_SOCKETS)
extern int32_t MaxTasks;
#endif // !defined(NO_LIMIT) && !defined (NO_SOCKETS)

#ifndef NO_LOG
extern char *fn_log;
extern int_fast8_t logstdout;
#ifndef NO_VERBOSE_LOG
extern int_fast8_t logverbose;
#endif
#endif

#ifndef NO_RANDOM_EPID
extern int_fast8_t RandomizationLevel;
extern uint16_t Lcid;
#endif

#ifndef NO_SOCKETS
extern SOCKET *SocketList;
extern int numsockets;

#ifndef NO_LIMIT
#ifndef _WIN32
extern sem_t *Semaphore;
#else // _WIN32
extern HANDLE Semaphore;
#endif // _WIN32
#endif // NO_LIMIT
#endif // NO_SOCKETS

#ifdef _NTSERVICE
extern int_fast8_t IsNTService;
extern int_fast8_t ServiceShutdown;
#endif

#ifndef _WIN32
extern gid_t gid;
extern uid_t uid;
#endif

#ifndef NO_LOG
#ifdef USE_THREADS
#if !defined(_WIN32) && !defined(__CYGWIN__)
extern pthread_mutex_t logmutex;
#else
extern CRITICAL_SECTION logmutex;
#endif // _WIN32
#endif // USE_THREADS
#endif // NO_LOG

#ifndef _WIN32
#ifdef USE_THREADS
extern pthread_rwlock_t SighupLock;
#endif // USE_THREADS
#endif // _WIN32

#endif // INCLUDED_SHARED_GLOBALS_H
