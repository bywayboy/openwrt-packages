#include "shared_globals.h"

#ifndef NO_PID_FILE
char *fn_pid = NULL;
#endif
#ifndef NO_INI_FILE
char *fn_ini = NULL;
#endif

const char *defaultport = "1688";
int global_argc;
CARGV global_argv;
const char* const optstring = "m:t:w:0:3:H:A:R:u:g:L:p:i:P:l:r:U:W:C:SsfeDd46VvId";
const char *const Version = VERSION;
const char *CommandLineEpid[] = { NULL, NULL, NULL };
const char *CommandLineHwId = NULL;
DWORD ActivationInterval = 60 * 2;   // 2 hours
DWORD RenewalInterval = 60 * 24 * 7; // 7 days
int_fast8_t UseMultiplexedRpc = TRUE;
int_fast8_t DisconnectImmediately = FALSE;
DWORD ServerTimeout = 30;

#if !defined(NO_LIMIT) && !defined (NO_SOCKETS)
int32_t MaxTasks = SEM_VALUE_MAX;
#endif // !defined(NO_LIMIT) && !defined (NO_SOCKETS)

#ifndef NO_LOG
char *fn_log = NULL;
int_fast8_t logstdout = 0;
#ifndef NO_VERBOSE_LOG
int_fast8_t logverbose = 0;
#endif // NO_VERBOSE_LOG
#endif // NO_LOG

#ifndef NO_SOCKETS
int_fast8_t nodaemon = 0;
int_fast8_t InetdMode = 0;
#else
int_fast8_t nodaemon = 1;
int_fast8_t InetdMode = 1;
#endif

#ifndef NO_RANDOM_EPID
int_fast8_t RandomizationLevel = 1;
uint16_t Lcid = 0;
#endif

#ifndef NO_SOCKETS
SOCKET *SocketList;
int numsockets = 0;

#ifndef NO_LIMIT
#ifndef _WIN32 // Posix
sem_t *Semaphore;
#else // _WIN32
HANDLE Semaphore;
#endif // _WIN32

#endif // NO_LIMIT
#endif // NO_SOCKETS

#ifdef _NTSERVICE
int_fast8_t IsNTService = TRUE;
#endif // _NTSERVICE

#ifndef _WIN32
gid_t gid = INVALID_GID;
uid_t uid = INVALID_UID;
#endif

#ifndef NO_LOG
#ifdef USE_THREADS
#if !defined(_WIN32) && !defined(__CYGWIN__)
pthread_mutex_t logmutex = PTHREAD_MUTEX_INITIALIZER;
#else
CRITICAL_SECTION logmutex;
#endif // _WIN32
#endif // USE_THREADS
#endif // NO_LOG
