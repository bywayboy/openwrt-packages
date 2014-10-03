#include "vlmcsd.h"

#ifndef NO_SOCKETS
static uint_fast8_t maxsockets = 0;
#endif

#if !defined(NO_LIMIT) && !defined (NO_SOCKETS)

#if !defined(USE_THREADS) && !defined(CYGWIN)
static int shmid = -1;
#endif

#if __ANDROID__ // Bionic does not wrap these syscalls (willingly because Google fears, developers don't know how to use it)
static int shmget(key_t key, size_t size, int shmflg)
{
       return syscall(__NR_shmget, key, size, shmflg);
}


static void *shmat(int shmid, const void *shmaddr, int shmflg)
{
       return (void *)syscall(__NR_shmat, shmid, shmaddr, shmflg);
}


static int shmdt(const void *shmaddr)
{
  return syscall(__NR_shmdt, shmaddr);
}


static int shmctl(int shmid, int cmd, /*struct shmid_ds*/void *buf)
{
  return syscall(__NR_shmctl, shmid, cmd, buf);
}
#endif // __ANDROID__

#endif // !defined(NO_LIMIT) && !defined (NO_SOCKETS)

#ifndef NO_USER_SWITCH
#ifndef _WIN32
// Get Numeric id of user/group
static char GetNumericId(gid_t *restrict i, const char *const c)
{
	char* endptr;
	*i = (gid_t)strtoll(c, &endptr, 10);

	if (*endptr)
		printerrorf("Fatal: setgid/setuid for %s failed.\n", optarg);

	return *endptr;
}


// Get group id from option argument
static char GetGid()
{
	struct group *g;

	if ((g = getgrnam(optarg)))
		gid = g->gr_gid;
	else
		return GetNumericId(&gid, optarg);

	return 0;
}


// Get user id from option argument
static char GetUid()
{
	struct passwd *u;

	////PORTABILITY: Assumes uid_t and gid_t are of same size (shouldn't be a problem)
	if ((u = getpwnam(optarg)))
		uid = u->pw_uid;
	else
		return GetNumericId((gid_t*)&uid, optarg);

	return 0;
}
#endif // _WIN32
#endif //NO_USER_SWITCH

#ifdef NO_HELP
static __noreturn void Usage(const char *const argv0)
{
	printerrorf("Incorrect parameters\n\n");
	exit(!0);
}
#else // HELP
static __noreturn void Usage(const char *const argv0)
{
	printerrorf("vlmcsd %s\n"
			"\nUsage:\n"
			"   %s [ options ]\n\n"
			"Where:\n"
			#ifndef NO_CL_PIDS
			"  -w <ePID>		always use <ePID> for Windows\n"
			"  -0 <ePID>		always use <ePID> for Office2010\n"
			"  -3 <ePID>		always use <ePID> for Office2013\n"
			"  -H <HwId>		always use hardware Id <HwId>\n"
			#endif // NO_CL_PIDS
			#if !defined(_WIN32) && !defined(NO_USER_SWITCH)
			"  -u <user>		set uid to <user>\n"
			"  -g <group>		set gid to <group>\n"
			#endif
			#ifndef NO_RANDOM_EPID
			"  -r 0|1|2		set ePID randomization level (default 1)\n"
			"  -C <LCID>		Use fixed <LCID> in random ePIDs\n"
			#endif // !defined(_WIN32) && !defined(NO_USER_SWITCH)
			#ifndef NO_SOCKETS
			"  -4			use IPv4 (no effect if -L is used)\n"
			"  -6			use IPv6 (no effect if -L is used)\n"
			"  -P <port>		set TCP port for subsequent -L statements (default 1688)\n"
			"  -L <address>[:<port>]	listen on IP address <address> with optional <port>\n"
			#ifndef NO_LIMIT
			"  -m <clients>\t\tHandle max. <clients> simultaneously (default no limit)\n"
			#endif // NO_LIMIT
			#ifdef _NTSERVICE
			"  -s			install vlmcsd as an NT service. Ignores -e"
			#ifndef _WIN32
			", -f and -D"
			#endif // _WIN32
			". Can't be used with -I\n"
			"  -S			remove vlmcsd service. Ignores all other options\n"
			"  -U <username>		run NT service as <username>. Must be used with -s\n"
			"  -W <password>		optional <password> for -U. Must be used with -s\n"
			#endif // _NTSERVICE
			#ifndef NO_LOG
			"  -e			log to stdout\n"
			#endif // NO_LOG
			#ifndef _WIN32 //
			"  -D			run in foreground\n"
			"  -f			run in foreground"
			#ifndef NO_LOG
			" and log to stdout"
			#endif // NO_LOG
			"\n"
			#endif // _WIN32
			#endif // NO_SOCKETS
			"  -t <seconds>\t\tdisconnect clients after <seconds> of inactivity (default 30)\n"
			"  -d\t\t\tdisconnect clients after each request\n"
			#ifndef NO_PID_FILE
			"  -p <file>		write pid to <file>\n"
			#endif // NO_PID_FILE
			#ifndef NO_INI_FILE
			"  -i <file>		load KMS ePIDs from <file>\n"
			#endif // NO_INI_FILE
			#ifndef NO_CUSTOM_INTERVALS
			"  -R <interval>		renew activation every <interval> (default 1w)\n"
			"  -A <interval>		retry activation every <interval> (default 2h)\n"
			#endif // NO_CUSTOM_INTERVALS
			#ifndef NO_LOG
			#ifndef _WIN32
			"  -l syslog		log to syslog\n"
			#endif // _WIN32
			"  -l <file>		log to <file>\n"
			#ifndef NO_VERBOSE_LOG
			"  -v			log verbose\n"
			#endif // NO_VERBOSE_LOG
			#endif // NO_LOG
			#ifndef _WIN32
			"  -I			inetd mode"
			#ifndef NO_SOCKETS
			". Implies -D. Ignores "
			#ifndef NO_LIMIT
			"-m, "
			#endif // NO_LIMIT
			"-t, -4, -6, -e, -f, -P and -L"
			"\n"
			#endif // NO_SOCKETS
			#endif // _WIN32
			"  -V			display version information and exit"
			"\n",
			Version, argv0);

	exit(!0);
}
#endif // HELP


#ifndef NO_INI_FILE

static __pure int isControlCharOrSlash(const char c)
{
	if ((unsigned char)c < '!') return !0;
	if (c == '/') return !0;
	return 0;
}

static void IniFileNextWord(const char **s)
{
	while ( **s && isspace((int)**s) ) (*s)++;
}


static BOOL SetHwIdFromIniFileLine(const char **s, const ProdListIndex_t index)
{
	IniFileNextWord(s);

	if (**s == '/')
	{
		if (KmsResponseParameters[index].HwId) return FALSE;

		BYTE* HwId = (BYTE*)malloc(sizeof(((RESPONSE_V6 *)0)->HwId));
		if (!HwId) return FALSE;

		Hex2bin(HwId, *s+1, sizeof(((RESPONSE_V6 *)0)->HwId));
		KmsResponseParameters[index].HwId = HwId;
		KmsResponseParameters[index].HwIdFromMalloc = TRUE;
	}

	return TRUE;
}


static BOOL CheckGuidInIniFileLine(const char **s, ProdListIndex_t *const index)
{
	GUID AppGuid;

	IniFileNextWord(s);
	if (!String2Uuid(*s, &AppGuid)) return FALSE;

	(*s) += GUID_STRING_LENGTH;
	GetProductNameHE(&AppGuid, AppList, index);

	if (*index > GetAppListSize()) return FALSE;
	IniFileNextWord(s);
	if ( *(*s)++ != '=' ) return FALSE;

	return TRUE;
}


static BOOL SetEpidFromIniFileLine(const char **s, const ProdListIndex_t index)
{
	IniFileNextWord(s);
	const char *savedPosition = *s;
	uint_fast16_t i;

	for (i = 0; !isControlCharOrSlash(**s); i++)
	{
		if (utf8_to_ucs2_char((const unsigned char*)*s, (const unsigned char**)s) == (WCHAR)~0)
		{
			return FALSE;
		}
	}

	if (i < 1 || i >= PID_BUFFER_SIZE) return FALSE;
	if (KmsResponseParameters[index].Epid) return FALSE;

	size_t size = *s - savedPosition + 1;

	char* epidbuffer = (char*)malloc(size);
	if (!epidbuffer) return FALSE;

	memcpy(epidbuffer, savedPosition, size - 1);
	epidbuffer[size - 1] = 0;

	KmsResponseParameters[index].EpidFromMalloc = TRUE;
	KmsResponseParameters[index].Epid = epidbuffer;

	#ifndef NO_LOG
	KmsResponseParameters[index].EpidSource = fn_ini;
	#endif //NO_LOG

	return TRUE;
}


static BOOL ReadIniFile()
{
	char  str_file[256];
	const char *s;
	ProdListIndex_t appIndex;

	FILE *restrict f;
	BOOL result = TRUE;

	if ( !fn_ini || !(f = fopen(fn_ini, "r") )) return FALSE;

	while ( (s = fgets(str_file, sizeof(str_file), f)) )
	{
		if (!CheckGuidInIniFileLine(&s, &appIndex)) continue;
		SetEpidFromIniFileLine(&s, appIndex);
		SetHwIdFromIniFileLine(&s, appIndex);
	}

	if (ferror(f)) result = FALSE;

	fclose(f);
	return result;
}
#endif // NO_INI_FILE


#if !defined(NO_SOCKETS)
#if !defined(_WIN32)
static void HangupHandler(const int signal)
{
	#ifdef USE_THREADS // Some fix for buggy pthread implementations

	static int_fast8_t inHandler;

	if (inHandler) return;
	inHandler = TRUE;
	#endif // USE_THREADS

	#if defined(NO_INI_FILE) && defined(NO_RANDOM_EPID)

	#ifndef NO_LOG
	logger("Hangup: No configuration to refresh.\n");
	#endif // NO_LOG

	#else // !defined(NO_INI_FILE) || !defined(NO_RANDOM_EPID)
	#ifndef NO_LOG
	logger("Hangup: Refreshing configuration.\n");
	#endif // NO_LOG

	ProdListIndex_t i;

	// Wait for worker threads no longer accessing the ePID / HWID configuration
	if (lock_write(SighupLock))
	{
		#ifdef USE_THREADS
		inHandler = FALSE;
		#endif // USE_THREADS
		return;
	}

	for (i = 0; i < MAX_KMSAPPS; i++)
	{
		if (KmsResponseParameters[i].EpidFromMalloc)
		{
			free((void*)KmsResponseParameters[i].Epid);
			KmsResponseParameters[i].Epid = NULL;
		}

		if (KmsResponseParameters[i].HwIdFromMalloc)
		{
			free((void*)KmsResponseParameters[i].HwId);
			KmsResponseParameters[i].HwId = NULL;
		}
	}

	#ifndef NO_INI_FILE
	if (fn_ini && !ReadIniFile())
	{
		#ifndef NO_LOG
		logger("Warning: Can't read %s: %s\n", fn_ini, strerror(errno));
		#endif
	}
	#endif // NO_INI_FILE

	#ifndef NO_RANDOM_EPID
	if (RandomizationLevel == 1) RandomPidInit();
	#endif // NO_RANDOM_EPID

	// Free worker threads
	unlock_write(SighupLock);

	#endif // !defined(NO_INI_FILE) || !defined(NO_RANDOM_EPID)

	#ifdef USE_THREADS
	inHandler = FALSE;
	#endif // USE_THREADS
}

static void TerminationHandler(const int signal)
{
	CleanUp();
	exit(0);
}


static int DaemonizeAndSetSignalAction()
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);

	#ifndef NO_LOG
	if ( !nodaemon) if (daemon(!0, logstdout))
	#else // NO_LOG
	if ( !nodaemon) if (daemon(!0, 0))
	#endif // NO_LOG
	{
		printerrorf("Fatal: Could not daemonize to background.\n");
		return(errno);
	}

	if (!InetdMode)
	{
		#ifndef USE_THREADS

		sa.sa_handler = SIG_IGN;
		sa.sa_flags   = SA_NOCLDWAIT;

		if (sigaction(SIGCHLD, &sa, NULL))
			return(errno);

		#endif // !USE_THREADS

		sa.sa_handler = TerminationHandler;
		sa.sa_flags   = 0;

		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);

		#ifndef NO_SOCKETS
		sa.sa_handler = HangupHandler;
		sigaction(SIGHUP, &sa, NULL);
		#endif // NO_SOCKETS
	}

	return 0;
}


#else // _WIN32

static BOOL TerminationHandler(const DWORD fdwCtrlType)
{
	// What a lame substitute for Unix signal handling
	switch(fdwCtrlType)
	{
		case CTRL_C_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			CleanUp();
			exit(0);
		default:
			return FALSE;
	}
}


static DWORD DaemonizeAndSetSignalAction()
{
	if(!SetConsoleCtrlHandler( (PHANDLER_ROUTINE) TerminationHandler, TRUE ))
	{
		#ifndef NO_LOG
		DWORD rc = GetLastError();
		logger("Warning: Could not register Windows signal handler: Error %u\n", rc);
		#endif // NO_LOG
	}

	return ERROR_SUCCESS;
}
#endif // _WIN32
#endif // !defined(NO_SOCKETS)


#ifdef _NTSERVICE
static int_fast8_t installService = 0;
static const char *restrict ServiceUser = NULL;
static const char *restrict ServicePassword = "";
#endif

#ifndef NO_CUSTOM_INTERVALS

// Convert time span strings (e.g. "2h", "5w") to minutes
__pure static DWORD TimeSpanString2Minutes(const char *const restrict optarg, const char optchar)
{
	char *unitId;

	long long val = strtoll(optarg, &unitId, 10);

	switch(toupper((int)*unitId))
	{
		case 0:
		case 'M':
			break;
		case 'H':
			val *= 60;
			break;
		case 'D':
			val *= 60 * 24;
			break;
		case 'W':
			val *= 60 * 24 * 7;
			break;
		case 'S':
			val /= 60;
			break;
		default:
			printerrorf("Fatal: No valid time span specified in option -%c.\n", optchar);
			exit (!0);
			break;
	}

	if (val < 1) val = 1;
	if (val > UINT_MAX) val = UINT_MAX;

	return (DWORD)val;
}

#endif // NO_CUSTOM_INTERVALS


// Workaround for Cygwin fork bug (only affects cygwin processes that are Windows services)
// Best is to compile for Cygwin with threads. fork() is slow and unreliable on Cygwin
#if !defined(NO_INI_FILE) || !defined(NO_LOG) || !defined(NO_CL_PIDS)
__pure static char* GetCommandLineArg(char *const restrict optarg)
{
	#if !defined (__CYGWIN__) || defined(USE_THREADS)
		return optarg;
	#else
		if (!IsNTService) return optarg;

		char* result = (char*)malloc(strlen(optarg) + 1);
		if (result) strcpy(result, optarg);
		return result;
	#endif
}
#endif // !defined(NO_INI_FILE) || !defined(NO_LOG)


static void ParseGeneralArguments() {
	int o;

	#ifndef NO_CL_PIDS
	BYTE* HwId;
	#endif // NO_CL_PIDS

	for (opterr = 0; ( o = getopt(global_argc, (char* const*)global_argv, optstring) ) > 0; ) switch (o)
	{
		#ifndef NO_CL_PIDS
		case 'w':
			KmsResponseParameters[APP_ID_WINDOWS].Epid          = GetCommandLineArg(optarg);
			#ifndef NO_LOG
			KmsResponseParameters[APP_ID_WINDOWS].EpidSource    = "command line";
			#endif // NO_LOG
			break;

		case '0':
			KmsResponseParameters[APP_ID_OFFICE2010].Epid       = GetCommandLineArg(optarg);
			#ifndef NO_LOG
			KmsResponseParameters[APP_ID_OFFICE2010].EpidSource = "command line";
			#endif // NO_LOG
			break;

		case '3':
			KmsResponseParameters[APP_ID_OFFICE2013].Epid       = GetCommandLineArg(optarg);
			#ifndef NO_LOG
			KmsResponseParameters[APP_ID_OFFICE2013].EpidSource = "command line";
			#endif // NO_LOG
			break;

		case 'H':
			HwId = (BYTE*)malloc(sizeof(((RESPONSE_V6 *)0)->HwId));
			if (!HwId) break;

			Hex2bin(HwId, optarg, sizeof(((RESPONSE_V6 *)0)->HwId));

			KmsResponseParameters[APP_ID_WINDOWS].HwId = HwId;
			KmsResponseParameters[APP_ID_OFFICE2010].HwId = HwId;
			KmsResponseParameters[APP_ID_OFFICE2013].HwId = HwId;
			break;
		#endif

		#ifndef NO_SOCKETS

		case '4':
		case '6':
		case 'P':
			break;

		#ifndef NO_LIMIT

		case 'm':
			MaxTasks = GetOptionArgumentInt(o, 1, SEM_VALUE_MAX);
			break;

		#endif // NO_LIMIT
		#endif // NO_SOCKETS

		case 't':
			ServerTimeout = GetOptionArgumentInt(o, 1, 600);
			break;

		#ifndef NO_PID_FILE
		case 'p':
			fn_pid = optarg;
			break;
		#endif

		#ifndef NO_INI_FILE
		case 'i':
			fn_ini = GetCommandLineArg(optarg);
			break;
		#endif

		#ifndef NO_LOG
		case 'l':
			fn_log = GetCommandLineArg(optarg);
			break;

		#ifndef NO_VERBOSE_LOG
		case 'v':
			logverbose = 1;
			break;

		#endif // NO_VERBOSE_LOG
		#endif // NO_LOG

		#ifndef NO_SOCKETS
		case 'L':
			if (!InetdMode) maxsockets++;
			break;

		case 'f':
			nodaemon = 1;
			#ifndef NO_LOG
			if (!InetdMode) logstdout = 1;
			#endif
			break;

		#ifdef _NTSERVICE
		case 'U':
			ServiceUser = optarg;
			break;

		case 'W':
			ServicePassword = optarg;
			break;

		case 's':
        	if (InetdMode) Usage(global_argv[0]);
            if (!IsNTService) installService = 1; // Install
            break;

		case 'S':
        	if (!IsNTService) installService = 2; // Remove
        	break;
        #endif // _NTSERVICE

		case 'D':
			nodaemon = 1;
			break;

			#ifndef NO_LOG
		case 'e':
			if (!InetdMode) logstdout = 1;
			break;
		#endif // NO_LOG
		#endif // NO_SOCKETS

		#ifndef _WIN32
		case 'I':
			#ifndef NO_SOCKETS
			InetdMode = 1;
			nodaemon = 1;
			maxsockets = 0;
			#ifndef NO_LOG
			logstdout = 0;
			#endif // NO_LOG
			#endif // NO_SOCKETS
			break;
		#endif // _WIN32

		#ifndef NO_RANDOM_EPID
		case 'r':
			RandomizationLevel = (int_fast8_t)GetOptionArgumentInt(o, 0, 2);
			break;

		case 'C':
			Lcid = (uint16_t)GetOptionArgumentInt(o, 0, 32767);

			#ifdef _PEDANTIC
			if (!IsValidLcid(Lcid))
			{
				printerrorf("Warning: %s is not a valid LCID.\n", optarg);
			}
			#endif // _PEDANTIC

			break;
		#endif // NO_RANDOM_PID

		#if !defined(NO_USER_SWITCH) && !defined(_WIN32)
		case 'g':
			if (GetGid()) exit(!0);
			break;

		case 'u':
			if (GetUid()) exit(!0);
			break;
		#endif // NO_USER_SWITCH && !_WIN32

		#ifndef NO_CUSTOM_INTERVALS
		case 'R':
			RenewalInterval = TimeSpanString2Minutes(optarg, o);
			break;

		case 'A':
			ActivationInterval = TimeSpanString2Minutes(optarg, o);
			break;
		#endif

		case 'd':
			DisconnectImmediately = TRUE;
			break;

		case 'V':
			#ifdef _NTSERVICE
			if (IsNTService) break;
			#endif
			printf("vlmcsd %s\n", Version);
			exit(0);

		default:
			Usage(global_argv[0]);
	}

	// Do not allow non-option arguments
	if (optind != global_argc)
		Usage(global_argv[0]);

	#ifdef _NTSERVICE
	// -U and -W must be used with -s
	if ((ServiceUser || *ServicePassword) && installService != 1) Usage(global_argv[0]);
	#endif // _NTSERVICE
}


#ifndef NO_PID_FILE
static void WritePidFile()
{
	if (fn_pid && !InetdMode)
	{
		FILE *_f = fopen(fn_pid, "w");

		if ( _f )
		{
			fprintf(_f, "%u", (uint32_t)getpid());
			fclose(_f);
		}

		#ifndef NO_LOG
		else
		{
			logger("Warning: Cannot write pid file.\n");
		}
		#endif // NO_LOG
	}
}
#else
#define WritePidFile(x)
#endif // NO_PID_FILE


void CleanUp()
{
	#ifndef NO_SOCKETS

	if (!InetdMode)
	{
		#ifndef NO_PID_FILE
		if (fn_pid) unlink(fn_pid);
		#endif // NO_PID_FILE
		CloseAllListeningSockets();

		#if !defined(NO_LIMIT) && !defined(NO_SOCKETS) && !defined(_WIN32)
		sem_unlink("/vlmcsd");
		#if !defined(USE_THREADS) && !defined(CYGWIN)
		if (shmid >= 0)
		{
			if (Semaphore != (sem_t*)-1) shmdt(Semaphore);
			shmctl(shmid, IPC_RMID, NULL);
		}
		#endif // !defined(USE_THREADS) && !defined(CYGWIN)
		#endif // !defined(NO_LIMIT) && !defined(NO_SOCKETS) && !defined(_WIN32)

		#ifndef NO_LOG
		logger("vlmcsd %s was shutdown\n", Version);
		#endif // NO_LOG
	}

	#endif // NO_SOCKETS
}


#if !defined(NO_LIMIT) && !defined(NO_SOCKETS)
// Get a semaphore for limiting the maximum concurrent tasks
static void AllocateSemaphore(void)
{
	#ifdef USE_THREADS
	#define sharemode 0
	#else
	#define sharemode 1
	#endif

	if(MaxTasks < SEM_VALUE_MAX && !InetdMode)
	{
		#ifndef _WIN32
		#if !defined(USE_THREADS) && !defined(CYGWIN)

		sem_unlink("/vlmcsd");

		if ((Semaphore = sem_open("/vlmcsd",  O_CREAT /*| O_EXCL*/, 0700, MaxTasks)) == SEM_FAILED) // fails on many systems
		{
			// We didn't get a named Semaphore (/dev/shm on Linux) so let's try our own shared page

			if (
                ( shmid = shmget(IPC_PRIVATE, sizeof(sem_t), IPC_CREAT | 0600) ) < 0 ||
                ( Semaphore = (sem_t*)shmat(shmid, NULL, 0) ) == (sem_t*)-1 ||
                sem_init(Semaphore, 1, MaxTasks) < 0
			)
			{
				int errno_save = errno;
				if (Semaphore != (sem_t*)-1) shmdt(Semaphore);
				if (shmid >= 0) shmctl(shmid, IPC_RMID, NULL);
				printerrorf("Warning: Could not create semaphore: %s\n", vlmcsd_strerror(errno_save));
				MaxTasks = SEM_VALUE_MAX;
			}
		}

		#else // THREADS or CYGWIN

		if ( // sem_init is not implemented in Darwin (MacOS / iOS) thus we need a backup strategy
                !(Semaphore = (sem_t*)malloc(sizeof(sem_t))) ||
                sem_init(Semaphore, sharemode, MaxTasks) < 0
		)
		{
			if (Semaphore) free(Semaphore);

			sem_unlink("/vlmcsd");

			if ((Semaphore = sem_open("/vlmcsd",  O_CREAT /*| O_EXCL*/, 0700, MaxTasks)) == SEM_FAILED)
			{
				printerrorf("Warning: Could not create semaphore: %s\n", vlmcsd_strerror(errno));
				MaxTasks = SEM_VALUE_MAX;
			}
		}

        #endif // THREADS or CYGWIN

		#else // _WIN32

		if (!(Semaphore = CreateSemaphoreA(NULL, MaxTasks, MaxTasks, NULL)))
		{
			printerrorf("Warning: Could not create semaphore: %s\n", vlmcsd_strerror(GetLastError()));
			MaxTasks = SEM_VALUE_MAX;
		}

		#endif // _WIN32
	}
}
#endif // !defined(NO_LIMIT) && !defined(NO_SOCKETS


int server_main(int argc, CARGV argv)
{
	#if !defined(_NTSERVICE) && !defined(NO_SOCKETS)
	int error;
	#endif // !defined(_NTSERVICE) && !defined(NO_SOCKETS)

	// Initialize ePID / HwId parameters
	memset(KmsResponseParameters, 0, sizeof(KmsResponseParameters));

	global_argc = argc;
	global_argv = argv;

	#ifdef _NTSERVICE // #endif is in newmain()
	DWORD lasterror = ERROR_SUCCESS;

	if (!StartServiceCtrlDispatcher(NTServiceDispatchTable) && (lasterror = GetLastError()) == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
	{
		IsNTService = FALSE;
		return newmain();
	}

	return lasterror;
}


int newmain()
{
	int error;

	// Initialize thread synchronization objects for Windows and Cygwin
	#ifdef USE_THREADS

	#ifndef NO_LOG
	// Initialize the Critical Section for proper logging
	InitializeCriticalSection(&logmutex);
	#endif // NO_LOG

	#endif // USE_THREADS

	#ifdef _WIN32

	// Windows Sockets must be initialized
	WSADATA wsadata;

	if ((error = WSAStartup(0x0202, &wsadata)))
	{
		printerrorf("Fatal: Could not initialize Windows sockets (Error: %d).\n", error);
		return error;
	}

	// Windows can never daemonize
	nodaemon = 1;

	#else // __CYGWIN__

	// Do not daemonize if we are a Windows service
	if (IsNTService) nodaemon = 1;

	#endif // _WIN32 / __CYGWIN__
	#endif // _NTSERVICE ( #ifdef is main(int argc, CARGV argv) )

	ParseGeneralArguments(); // Does not return if an error occurs

	#ifndef NO_INI_FILE
	if (fn_ini && !ReadIniFile())
	{
		printerrorf("Warning: Can't read %s: %s\n", fn_ini, strerror(errno));
	}
	#endif // NO_INI_FILE

	#if !defined(NO_LIMIT) && !defined(NO_SOCKETS)
	AllocateSemaphore();
	#endif // !defined(NO_LIMIT) && !defined(NO_SOCKETS)

	#ifdef _NTSERVICE
	if (installService)
		return NtServiceInstallation(installService, ServiceUser, ServicePassword);
	#endif // _NTSERVICE

	#ifndef NO_SOCKETS
	if (!InetdMode && (error = SetupListeningSockets(maxsockets))) return error;
	#endif // NO_SOCKETS

	// After sockets have been set up, we may switch to a lower privileged user
	#if !defined(_WIN32) && !defined(NO_USER_SWITCH)
	if ((gid != INVALID_GID && setgid(gid)) || (uid != INVALID_UID && setuid(uid)))
	{
		printerrorf("Fatal: setgid/setuid for %s failed.\n", optarg);
		return !0;
	}
	#endif

	RandomNumberInit();

	// Randomization Level 1 means generate ePIDs at startup and use them during
	// the lifetime of the process. So we generate them now
	#ifndef NO_RANDOM_EPID
	if (RandomizationLevel == 1) RandomPidInit();
	#endif

	#if !defined(NO_SOCKETS)
	#ifdef _WIN32
	if (!IsNTService)
	#endif // _WIN32
	if ((error = DaemonizeAndSetSignalAction())) return error;
	#endif

	WritePidFile();

	#if !defined(NO_LOG) && !defined(NO_SOCKETS)
	if (!InetdMode) logger("vlmcsd %s started successfully\n", Version);
	#endif

	#ifdef _NTSERVICE
	if (IsNTService) ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 200);
	#endif

	int rc = RunServer();

	// Clean up things and exit
	#ifdef _NTSERVICE
	if (!ServiceShutdown)
	#endif
		CleanUp();
	#ifdef _NTSERVICE
	else
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
	#endif

	return rc;
}
