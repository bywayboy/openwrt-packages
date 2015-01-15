#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifndef _WIN32
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#ifndef NO_LIMIT
#include <sys/ipc.h>
#if !__ANDROID__
#include <sys/shm.h>
#else
#include <sys/syscall.h>
#endif // !__ANDROID__
#endif // NO_LIMIT

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#endif // !_WIN32

#if __APPLE__
#include <mach-o/dyld.h>
#endif // __APPLE__

#if __linux__ && defined(USE_AUXV)
#include <sys/auxv.h>
#endif

#if __FreeBSD__
#include <sys/sysctl.h>
#endif

#include "vlmcsd.h"
#include "endian.h"
#include "shared_globals.h"
#include "output.h"
#include "network.h"
#include "ntservice.h"
#include "helpers.h"


static const char* const optstring = "m:t:w:0:3:H:A:R:u:g:L:p:i:P:l:r:U:W:C:SsfeDd46VvIdqkZ";

#ifndef NO_SOCKETS
static uint_fast8_t maxsockets = 0;
static int_fast8_t haveIPv6Stack = 0;
static int_fast8_t haveIPv4Stack = 0;
static int_fast8_t v6required = 0;
static int_fast8_t v4required = 0;
#endif

#ifndef NO_INI_FILE

static const char* IniFileErrorMessage = "";
char* IniFileErrorBuffer = NULL;
#define INIFILE_ERROR_BUFFERSIZE 256

static IniFileParameter_t IniFileParameterList[] =
{
#	ifndef NO_RANDOM_EPID
		{ "RandomizationLevel", INI_PARAM_RANDOMIZATION_LEVEL },
		{ "LCID", INI_PARAM_LCID },
#	endif // NO_RANDOM_EPID

#	ifndef NO_SOCKETS
		{ "Listen", INI_PARAM_LISTEN },
#	ifndef NO_LIMIT
		{ "MaxWorkers", INI_PARAM_MAX_WORKERS },
#	endif // NO_LIMIT
#	endif // NO_SOCKETS
		{ "ConnectionTimeout", INI_PARAM_CONNECTION_TIMEOUT },
		{ "DisconnectClientsImmediately", INI_PARAM_DISCONNECT_IMMEDIATELY },
#	ifndef NO_PID_FILE
		{ "PIDFile", INI_PARAM_PID_FILE },
#	endif // NO_PID_FILE
#	ifndef NO_LOG
		{ "LogFile", INI_PARAM_LOG_FILE },
#	ifndef NO_VERBOSE_LOG
		{ "LogVerbose", INI_PARAM_LOG_VERBOSE },
#	endif // NO_VERBOSE_LOG
#	endif // NO_LOG
#	ifndef NO_CUSTOM_INTERVALS
		{"ActivationInterval", INI_PARAM_ACTIVATION_INTERVAL },
		{"RenewalInterval", INI_PARAM_RENEWAL_INTERVAL },
#	endif // NO_CUSTOM_INTERVALS
#	if !defined(NO_USER_SWITCH) && !defined(_WIN32)
		{ "user", INI_PARAM_UID },
		{ "group", INI_PARAM_GID},
#	endif // !defined(NO_USER_SWITCH) && !defined(_WIN32)
};

#endif // NO_INI_FILE


#if !defined(NO_LIMIT) && !defined (NO_SOCKETS)

#if !defined(USE_THREADS) && !defined(CYGWIN)
static int shmid = -1;
#endif

#if __ANDROID__ && !defined(USE_THREADS) // Bionic does not wrap these syscalls (willingly because Google fears, developers don't know how to use it)

#ifdef __NR_shmget
static int shmget(key_t key, size_t size, int shmflg)
{
       return syscall(__NR_shmget, key, size, shmflg);
}
#endif // __NR_shmget

#ifdef __NR_shmat
static void *shmat(int shmid, const void *shmaddr, int shmflg)
{
       return (void *)syscall(__NR_shmat, shmid, shmaddr, shmflg);
}
#endif // __NR_shmat

#ifdef __NR_shmdt
static int shmdt(const void *shmaddr)
{
  return syscall(__NR_shmdt, shmaddr);
}
#endif // __NR_shmdt

#ifdef __NR_shmctl
static int shmctl(int shmid, int cmd, /*struct shmid_ds*/void *buf)
{
  return syscall(__NR_shmctl, shmid, cmd, buf);
}
#endif // __NR_shmctl

#endif // __ANDROID__ && !defined(USE_THREADS)

#endif // !defined(NO_LIMIT) && !defined (NO_SOCKETS)

#ifndef NO_USER_SWITCH
#ifndef _WIN32

static const char *uname = NULL, *gname = NULL;
static gid_t gid = INVALID_GID;
static uid_t uid = INVALID_UID;

// Get Numeric id of user/group
static char GetNumericId(gid_t *restrict id, const char *const c)
{
	char* endptr;
	gid_t temp;

	temp = (gid_t)strtoll(c, &endptr, 10);

	if (!*endptr) *id = temp;

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
static __noreturn void usage()
{
	printerrorf("Incorrect parameters\n\n");
	exit(!0);
}
#else // HELP


static __noreturn void usage()
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
			#endif // !defined(_WIN32) && !defined(NO_USER_SWITCH)
			#ifndef NO_RANDOM_EPID
			"  -r 0|1|2		set ePID randomization level (default 1)\n"
			"  -C <LCID>		Use fixed <LCID> in random ePIDs\n"
			#endif // NO_RANDOM_EPID
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
			"  -k\t\t\tdon't disconnect clients after each request (default)\n"
			#ifndef NO_PID_FILE
			"  -p <file>		write pid to <file>\n"
			#endif // NO_PID_FILE
			#ifndef NO_INI_FILE
			"  -i <file>\t\tuse config file <file>\n"
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
			"  -v\t\t\tlog verbose\n"
			"  -q\t\t\tdon't log verbose (default)\n"
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
			Version, global_argv[0]);

	exit(!0);
}
#endif // HELP


#ifndef NO_CUSTOM_INTERVALS

// Convert time span strings (e.g. "2h", "5w") to minutes
__pure static DWORD timeSpanString2Minutes(const char *const restrict argument)
{
	char *unitId;

	long long val = strtoll(argument, &unitId, 10);

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
			return 0;
	}

	if (val < 1) val = 1;
	if (val > UINT_MAX) val = UINT_MAX;

	return (DWORD)val;
}


__pure static BOOL getTimeSpanFromIniFile(DWORD* result, const char *const restrict argument)
{
	DWORD val = timeSpanString2Minutes(argument);
	if (!val)
	{
		IniFileErrorMessage = "Incorrect time span.";
		return FALSE;
	}

	*result = val;
	return TRUE;
}


__pure static DWORD getTimeSpanFromCommandLine(const char *const restrict optarg, const char optchar)
{
	long long val = timeSpanString2Minutes(optarg);

	if (!val)
	{
		printerrorf("Fatal: No valid time span specified in option -%c.\n", optchar);
		exit (!0);
	}

	return (DWORD)val;
}

#endif // NO_CUSTOM_INTERVALS


#ifndef NO_INI_FILE
static void ignoreIniFileParameter(uint_fast8_t iniFileParameterId)
{
	uint_fast8_t i;

	for (i = 0; i < _countof(IniFileParameterList); i++)
	{
		if (IniFileParameterList[i].Id != iniFileParameterId) continue;
		IniFileParameterList[i].Id = 0;
		break;
	}
}
#else // NO_INI_FILE
#define ignoreIniFileParameter(x)
#endif // NO_INI_FILE


#ifndef NO_INI_FILE
__pure static BOOL getIniFileArgumentBool(int_fast8_t *result, const char *const argument)
{
	if (
		!strncasecmp(argument, "true", 4) ||
		!strncasecmp(argument, "on", 4) ||
		!strncasecmp(argument, "yes", 3) ||
		!strncasecmp(argument, "1", 1)
	)
	{
		*result = TRUE;
		return TRUE;
	}
	else if (
			!strncasecmp(argument, "false", 5) ||
			!strncasecmp(argument, "off", 3) ||
			!strncasecmp(argument, "no", 2) ||
			!strncasecmp(argument, "0", 1)
	)
	{
		*result = FALSE;
		return TRUE;
	}

	IniFileErrorMessage = "Argument must be true/on/yes/1 or false/off/no/0";
	return FALSE;
}


__pure static BOOL getIniFileArgumentInt(int *result, const char *const argument, const int min, const int max)
{
	int tempResult;

	if (!stringToInt(argument, min, max, &tempResult))
	{
		snprintf(IniFileErrorBuffer, INIFILE_ERROR_BUFFERSIZE, "Must be integer between %i and %i", min, max);
		IniFileErrorMessage = IniFileErrorBuffer;
		return FALSE;
	}

	*result = tempResult;
	return TRUE;
}


__pure static char* allocateStringArgument(const char *const argument)
{
	char* result = (char*)malloc(strlen(argument) + 1);
	if (result) strcpy(result, argument);
	return result;
}


static BOOL setIniFileParameter(uint_fast8_t id, const char *const iniarg)
{
	int result;
	BOOL success = TRUE;

	switch(id)
	{
#	if !defined(NO_USER_SWITCH) && !defined(_WIN32)

		case INI_PARAM_GID:
		{
			struct group *g;
			IniFileErrorMessage = "Invalid group id or name";
			if (!(gname = allocateStringArgument(iniarg))) return FALSE;

			if ((g = getgrnam(iniarg)))
				gid = g->gr_gid;
			else
				success = !GetNumericId(&gid, iniarg);
			break;
		}

		case INI_PARAM_UID:
		{
			struct passwd *p;
			IniFileErrorMessage = "Invalid user id or name";
			if (!(uname = allocateStringArgument(iniarg))) return FALSE;

			if ((p = getpwnam(iniarg)))
				uid = p->pw_uid;
			else
				success = !GetNumericId(&uid, iniarg);
			break;
		}

#	endif // !defined(NO_USER_SWITCH) && !defined(_WIN32)

#	ifndef NO_RANDOM_EPID

		case INI_PARAM_LCID:
			success = getIniFileArgumentInt(&result, iniarg, 0, 32767);
			if (success) Lcid = (uint16_t)result;
			break;

		case INI_PARAM_RANDOMIZATION_LEVEL:
			success = getIniFileArgumentInt(&result, iniarg, 0, 2);
			if (success) RandomizationLevel = (int_fast8_t)result;
			break;

#	endif // NO_RANDOM_EPID

#	ifndef NO_SOCKETS

		case INI_PARAM_LISTEN:
			maxsockets++;
			return TRUE;

#	ifndef NO_LIMIT

		case INI_PARAM_MAX_WORKERS:
			success = getIniFileArgumentInt(&MaxTasks, iniarg, 1, SEM_VALUE_MAX);
			break;

#	endif // NO_LIMIT
#	endif // NO_SOCKETS

#	ifndef NO_PID_FILE

		case INI_PARAM_PID_FILE:
			fn_pid = allocateStringArgument(iniarg);
			break;

#	endif // NO_PID_FILE

#	ifndef  NO_LOG

		case INI_PARAM_LOG_FILE:
			fn_log = allocateStringArgument(iniarg);
			break;

#	ifndef NO_VERBOSE_LOG
		case INI_PARAM_LOG_VERBOSE:
			success = getIniFileArgumentBool(&logverbose, iniarg);
			break;

#	endif // NO_VERBOSE_LOG
#	endif // NO_LOG

#	ifndef NO_CUSTOM_INTERVALS

		case INI_PARAM_ACTIVATION_INTERVAL:
			success = getTimeSpanFromIniFile(&ActivationInterval, iniarg);
			break;

		case INI_PARAM_RENEWAL_INTERVAL:
			success = getTimeSpanFromIniFile(&RenewalInterval, iniarg);
			break;

#	endif // NO_CUSTOM_INTERVALS

		case INI_PARAM_CONNECTION_TIMEOUT:
			success = getIniFileArgumentInt(&result, iniarg, 1, 600);
			if (success) ServerTimeout = (DWORD)result;
			break;

		case INI_PARAM_DISCONNECT_IMMEDIATELY:
			success = getIniFileArgumentBool(&DisconnectImmediately, iniarg);
			break;

		default:
			return FALSE;
	}

	return success;
}


static __pure int isControlCharOrSlash(const char c)
{
	if ((unsigned char)c < '!') return !0;
	if (c == '/') return !0;
	return 0;
}


static void iniFileLineNextWord(const char **s)
{
	while ( **s && isspace((int)**s) ) (*s)++;
}


static BOOL setHwIdFromIniFileLine(const char **s, const ProdListIndex_t index)
{
	iniFileLineNextWord(s);

	if (**s == '/')
	{
		if (KmsResponseParameters[index].HwId) return TRUE;

		BYTE* HwId = (BYTE*)malloc(sizeof(((RESPONSE_V6 *)0)->HwId));
		if (!HwId) return FALSE;

		hex2bin(HwId, *s + 1, sizeof(((RESPONSE_V6 *)0)->HwId));
		KmsResponseParameters[index].HwId = HwId;
	}

	return TRUE;
}


static BOOL checkGuidInIniFileLine(const char **s, ProdListIndex_t *const index)
{
	GUID AppGuid;

	if (!string2Uuid(*s, &AppGuid)) return FALSE;

	(*s) += GUID_STRING_LENGTH;
	getProductNameHE(&AppGuid, AppList, index);

	if (*index > getAppListSize() - 2)
	{
		IniFileErrorMessage = "Unknown App Guid.";
		return FALSE;
	}

	iniFileLineNextWord(s);
	if ( *(*s)++ != '=' ) return FALSE;

	return TRUE;
}


static BOOL setEpidFromIniFileLine(const char **s, const ProdListIndex_t index)
{
	iniFileLineNextWord(s);
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
	if (KmsResponseParameters[index].Epid) return TRUE;

	size_t size = *s - savedPosition + 1;

	char* epidbuffer = (char*)malloc(size);
	if (!epidbuffer) return FALSE;

	memcpy(epidbuffer, savedPosition, size - 1);
	epidbuffer[size - 1] = 0;

	KmsResponseParameters[index].Epid = epidbuffer;

	#ifndef NO_LOG
	KmsResponseParameters[index].EpidSource = fn_ini;
	#endif //NO_LOG

	return TRUE;
}


static BOOL getIniFileArgument(const char **s)
{
	while (!isspace((int)**s) && **s != '=' && **s) (*s)++;
	iniFileLineNextWord(s);

	if (*((*s)++) != '=')
	{
		IniFileErrorMessage = "'=' required after keyword.";
		return FALSE;
	}

	iniFileLineNextWord(s);

	if (!**s)
	{
		IniFileErrorMessage = "missing argument after '='.";
		return FALSE;
	}

	return TRUE;
}


static BOOL handleIniFileParameter(const char *s)
{
	uint_fast8_t i;

	for (i = 0; i < _countof(IniFileParameterList); i++)
	{
		if (strncasecmp(IniFileParameterList[i].Name, s, strlen(IniFileParameterList[i].Name))) continue;
		if (!IniFileParameterList[i].Id) return TRUE;

		if (!getIniFileArgument(&s)) return FALSE;

		return setIniFileParameter(IniFileParameterList[i].Id, s);
	}

	IniFileErrorMessage = "Unknown keyword.";
	return FALSE;
}


#ifndef NO_SOCKETS
static BOOL setupListeningSocketsFromIniFile(const char *s)
{
	if (!maxsockets) return TRUE;
	if (strncasecmp("Listen", s, 6)) return TRUE;
	if (!getIniFileArgument(&s)) return TRUE;

	snprintf(IniFileErrorBuffer, INIFILE_ERROR_BUFFERSIZE, "Cannot listen on %s.", s);
	IniFileErrorMessage = IniFileErrorBuffer;
	return addListeningSocket(s);
}
#endif // NO_SOCKETS


static BOOL readIniFile(const uint_fast8_t pass)
{
	char  line[256];
	const char *s;
	ProdListIndex_t appIndex;
	unsigned int lineNumber;
	uint_fast8_t lineParseError;

	FILE *restrict f;
	BOOL result = TRUE;

	IniFileErrorBuffer = (char*)malloc(INIFILE_ERROR_BUFFERSIZE);

	if (!IniFileErrorBuffer)
	{
		printerrorf("Fatal: Cannot allocate memory for ini file error message.\n");
		exit(!0);
	}

	if ( !fn_ini || !(f = fopen(fn_ini, "r") )) return FALSE;

	for (lineNumber = 1; (s = fgets(line, sizeof(line), f)); lineNumber++)
	{
		line[strlen(line) - 1] = 0;

		iniFileLineNextWord(&s);
		if (*s == ';' || *s == '#' || !*s) continue;

#		ifndef NO_SOCKETS
		if (pass == INI_FILE_PASS_1)
#		endif // NO_SOCKETS
		{
			if (handleIniFileParameter(s)) continue;

			lineParseError = !checkGuidInIniFileLine(&s, &appIndex) ||
					!setEpidFromIniFileLine(&s, appIndex) ||
					!setHwIdFromIniFileLine(&s, appIndex);
		}
#		ifndef NO_SOCKETS
		else if (pass == INI_FILE_PASS_2)
		{
			lineParseError = !setupListeningSocketsFromIniFile(s);
		}
		else
		{
			return FALSE;
		}
#		endif // NO_SOCKETS

		if (lineParseError)
		{
			printerrorf("Warning: %s line %u: \"%s\". %s\n", fn_ini, lineNumber, line, IniFileErrorMessage);
			continue;
		}
	}

	free(IniFileErrorBuffer);
	if (ferror(f)) result = FALSE;

	fclose(f);
	return result;
}
#endif // NO_INI_FILE


#if !defined(NO_SOCKETS)
#if !defined(_WIN32)
#if !defined(NO_SIGHUP)
static void exec_self(char** argv)
{
#	if __linux__ && defined(USE_AUXV)

		char *execname_ptr = (char*)getauxval(AT_EXECFN);
		if (execname_ptr) execv(execname_ptr, argv);

#	elif (__linux__ || __CYGWIN__) && !defined(NO_PROCFS)

		execv(realpath("/proc/self/exe", NULL), argv);

#	elif (__FreeBSD__) && !defined(NO_PROCFS)

		int mib[4];
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROC;
		mib[2] = KERN_PROC_PATHNAME;
		mib[3] = -1;
		char path[PATH_MAX + 1];
		size_t cb = sizeof(path);
		if (!sysctl(mib, 4, path, &cb, NULL, 0)) execv(path, argv);

#	elif (__DragonFly__) && !defined(NO_PROCFS)

		execv(realpath("/proc/curproc/file", NULL), argv);

#	elif __NetBSD__ && !defined(NO_PROCFS)

		execv(realpath("/proc/curproc/exe", NULL), argv);

#	elif __sun__

		const char* exename = getexecname();
		if (exename) execv(exename, argv);

#	elif __APPLE__

		char path[PATH_MAX + 1];
		uint32_t size = sizeof(path);
		if (_NSGetExecutablePath(path, &size) == 0) execv(path, argv);

#	else

		execvp(argv[0], argv);

#	endif
}


static void HangupHandler(const int signal)
{
	int i;
	int_fast8_t daemonize_protection = TRUE;
	CARGV argv_in = multi_argv == NULL ? global_argv : multi_argv;
	int argc_in = multi_argc == 0 ? global_argc : multi_argc;
	const char** argv_out = (const char**)malloc((argc_in + 2) * sizeof(char**));

	if (argv_out)
	{
		for (i = 0; i < argc_in; i++)
		{
			if (!strcmp(argv_in[i], "-Z")) daemonize_protection = FALSE;
			argv_out[i] = argv_in[i];
		}

		argv_out[argc_in] = argv_out[argc_in + 1] = NULL;
		if (daemonize_protection) argv_out[argc_in] = (char*) "-Z";

		cleanup(FALSE);
		exec_self((char**)argv_out);
		//execvp(argv_out[0], (char **const)argv_out);
	}

#	ifndef NO_LOG
		logger("Fatal: Unable to restart on SIGHUP: %s\n", strerror(errno));
#	endif

	if (fn_pid) unlink(fn_pid);
	exit(errno);
}
#endif // NO_SIGHUP


static void terminationHandler(const int signal)
{
	cleanup(TRUE);
	exit(0);
}


static int daemonizeAndSetSignalAction()
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

		sa.sa_handler = terminationHandler;
		sa.sa_flags   = 0;

		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);

		#ifndef NO_SIGHUP
		sa.sa_handler = HangupHandler;
		sa.sa_flags   = SA_NODEFER;
		sigaction(SIGHUP, &sa, NULL);
		#endif // NO_SIGHUP
	}

	return 0;
}


#else // _WIN32

static BOOL terminationHandler(const DWORD fdwCtrlType)
{
	// What a lame substitute for Unix signal handling
	switch(fdwCtrlType)
	{
		case CTRL_C_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			cleanup(TRUE);
			exit(0);
		default:
			return FALSE;
	}
}


static DWORD daemonizeAndSetSignalAction()
{
	if(!SetConsoleCtrlHandler( (PHANDLER_ROUTINE) terminationHandler, TRUE ))
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

// Workaround for Cygwin fork bug (only affects cygwin processes that are Windows services)
// Best is to compile for Cygwin with threads. fork() is slow and unreliable on Cygwin
#if !defined(NO_INI_FILE) || !defined(NO_LOG) || !defined(NO_CL_PIDS)
__pure static char* getCommandLineArg(char *const restrict optarg)
{
	#if !defined (__CYGWIN__) || defined(USE_THREADS)
		return optarg;
	#else
		if (!IsNTService) return optarg;

		/*char* result = (char*)malloc(strlen(optarg) + 1);
		if (result) strcpy(result, optarg);
		return result;*/
		return allocateStringArgument(optarg);
	#endif
}
#endif // !defined(NO_INI_FILE) || !defined(NO_LOG) || !defined(NO_CL_PIDS)


static void parseGeneralArguments() {
	int o;

	#ifndef NO_CL_PIDS
	BYTE* HwId;
	#endif // NO_CL_PIDS

	for (opterr = 0; ( o = getopt(global_argc, (char* const*)global_argv, optstring) ) > 0; ) switch (o)
	{
		#if !defined(NO_SOCKETS) && !defined(NO_SIGHUP) && !defined(_WIN32)
		case 'Z':
			IsRestarted = TRUE;
			nodaemon = TRUE;
			break;
		#endif // !defined(NO_SOCKETS) && !defined(NO_SIGHUP) && !defined(_WIN32)

		#ifndef NO_CL_PIDS
		case 'w':
			KmsResponseParameters[APP_ID_WINDOWS].Epid          = getCommandLineArg(optarg);
			#ifndef NO_LOG
			KmsResponseParameters[APP_ID_WINDOWS].EpidSource    = "command line";
			#endif // NO_LOG
			break;

		case '0':
			KmsResponseParameters[APP_ID_OFFICE2010].Epid       = getCommandLineArg(optarg);
			#ifndef NO_LOG
			KmsResponseParameters[APP_ID_OFFICE2010].EpidSource = "command line";
			#endif // NO_LOG
			break;

		case '3':
			KmsResponseParameters[APP_ID_OFFICE2013].Epid       = getCommandLineArg(optarg);
			#ifndef NO_LOG
			KmsResponseParameters[APP_ID_OFFICE2013].EpidSource = "command line";
			#endif // NO_LOG
			break;

		case 'H':
			HwId = (BYTE*)malloc(sizeof(((RESPONSE_V6 *)0)->HwId));
			if (!HwId) break;

			hex2bin(HwId, optarg, sizeof(((RESPONSE_V6 *)0)->HwId));

			KmsResponseParameters[APP_ID_WINDOWS].HwId = HwId;
			KmsResponseParameters[APP_ID_OFFICE2010].HwId = HwId;
			KmsResponseParameters[APP_ID_OFFICE2013].HwId = HwId;
			break;
		#endif // NO_CL_PIDS

		#ifndef NO_SOCKETS

		case '4':
		case '6':
		case 'P':
			ignoreIniFileParameter(INI_PARAM_LISTEN);
			break;

		#ifndef NO_LIMIT

		case 'm':
			MaxTasks = getOptionArgumentInt(o, 1, SEM_VALUE_MAX);
			ignoreIniFileParameter(INI_PARAM_MAX_WORKERS);
			break;

		#endif // NO_LIMIT
		#endif // NO_SOCKETS

		case 't':
			ServerTimeout = getOptionArgumentInt(o, 1, 600);
			ignoreIniFileParameter(INI_PARAM_CONNECTION_TIMEOUT);
			break;

		#ifndef NO_PID_FILE
		case 'p':
			fn_pid = getCommandLineArg(optarg);
			ignoreIniFileParameter(INI_PARAM_PID_FILE);
			break;
		#endif

		#ifndef NO_INI_FILE
		case 'i':
			fn_ini = getCommandLineArg(optarg);
			break;
		#endif

		#ifndef NO_LOG
		case 'l':
			fn_log = getCommandLineArg(optarg);
			ignoreIniFileParameter(INI_PARAM_LOG_FILE);
			break;

		#ifndef NO_VERBOSE_LOG
		case 'v':
		case 'q':
			logverbose = o == 'v';
			ignoreIniFileParameter(INI_PARAM_LOG_VERBOSE);
			break;

		#endif // NO_VERBOSE_LOG
		#endif // NO_LOG

		#ifndef NO_SOCKETS
		case 'L':
			maxsockets++;
			ignoreIniFileParameter(INI_PARAM_LISTEN);
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
        	if (InetdMode) usage();
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
			RandomizationLevel = (int_fast8_t)getOptionArgumentInt(o, 0, 2);
			ignoreIniFileParameter(INI_PARAM_RANDOMIZATION_LEVEL);
			break;

		case 'C':
			Lcid = (uint16_t)getOptionArgumentInt(o, 0, 32767);

			ignoreIniFileParameter(INI_PARAM_LCID);

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
			gname = optarg;
			ignoreIniFileParameter(INI_PARAM_GID);
			#ifndef NO_SIGHUP
			if (!IsRestarted)
			#endif // NO_SIGHUP
			if (GetGid())
			{
				printerrorf("Fatal: setgid for %s failed.\n", optarg);
				exit(!0);
			}
			break;

		case 'u':
			uname = optarg;
			ignoreIniFileParameter(INI_PARAM_UID);
			#ifndef NO_SIGHUP
			if (!IsRestarted)
			#endif // NO_SIGHUP
			if (GetUid())
			{
				printerrorf("Fatal: setuid for %s failed.\n", optarg);
				exit(!0);
			}
			break;
		#endif // NO_USER_SWITCH && !_WIN32

		#ifndef NO_CUSTOM_INTERVALS
		case 'R':
			RenewalInterval = getTimeSpanFromCommandLine(optarg, o);
			ignoreIniFileParameter(INI_PARAM_RENEWAL_INTERVAL);
			break;

		case 'A':
			ActivationInterval = getTimeSpanFromCommandLine(optarg, o);
			ignoreIniFileParameter(INI_PARAM_ACTIVATION_INTERVAL);
			break;
		#endif

		case 'd':
		case 'k':
			DisconnectImmediately = o == 'd';
			ignoreIniFileParameter(INI_PARAM_DISCONNECT_IMMEDIATELY);
			break;

		case 'V':
			#ifdef _NTSERVICE
			if (IsNTService) break;
			#endif
			printf("vlmcsd %s\n", Version);
			exit(0);

		default:
			usage();
	}

	// Do not allow non-option arguments
	if (optind != global_argc)
		usage();

	#ifdef _NTSERVICE
	// -U and -W must be used with -s
	if ((ServiceUser || *ServicePassword) && installService != 1) usage();
	#endif // _NTSERVICE
}


#ifndef NO_PID_FILE
static void writePidFile()
{
#	ifndef NO_SIGHUP
		if (IsRestarted) return;
#	endif // NO_SIGHUP

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
			logger("Warning: Cannot write pid file '%s'. %s.\n", fn_pid, strerror(errno));
		}
		#endif // NO_LOG
	}
}
#else
#define writePidFile(x)
#endif // NO_PID_FILE


void cleanup(int_fast8_t RemovePidFile)
{
	#ifndef NO_SOCKETS

	if (!InetdMode)
	{
		#ifndef NO_PID_FILE
		if (RemovePidFile && fn_pid) unlink(fn_pid);
		#endif // NO_PID_FILE
		closeAllListeningSockets();

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
static void allocateSemaphore(void)
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


#ifndef NO_SOCKETS
int setupListeningSockets()
{
	int o;
	uint_fast8_t allocsockets = maxsockets ? maxsockets : 2;

	if (!(SocketList = (SOCKET*)malloc((size_t)allocsockets * sizeof(SOCKET)))) return !0;

	haveIPv4Stack = checkProtocolStack(AF_INET);
	haveIPv6Stack = checkProtocolStack(AF_INET6);

	// Reset getopt since we've alread used it
	optReset();

	for (opterr = 0; ( o = getopt(global_argc, (char* const*)global_argv, optstring) ) > 0; ) switch (o)
	{
	case '4':

		if (!haveIPv4Stack)
		{
			printerrorf("Fatal: Your system does not support %s.\n", cIPv4);
			return !0;
		}
		v4required = 1;
		break;

	case '6':

		if (!haveIPv6Stack)
		{
			printerrorf("Fatal: Your system does not support %s.\n", cIPv6);
			return !0;
		}
		v6required = 1;
		break;

	case 'L':

		addListeningSocket(optarg);
		break;

	case 'P':

		defaultport = optarg;
		break;

	default:

		break;
	}


#	ifndef NO_INI_FILE
	if (maxsockets && !numsockets)
	{
		if (fn_ini && !readIniFile(INI_FILE_PASS_2))
		{
			printerrorf("Warning: Can't read %s: %s\n", fn_ini, strerror(errno));
		}
	}
#	endif

	// if -L hasn't been specified on the command line, use default sockets (all IP addresses)
	// maxsocket results from first pass parsing the arguments
	if (!maxsockets)
	{
		if (haveIPv6Stack && (v6required || !v4required)) addListeningSocket("::");
		if (haveIPv4Stack && (v4required || !v6required)) addListeningSocket("0.0.0.0");
	}

	if (!numsockets)
	{
		printerrorf("Fatal: Could not listen on any socket.\n");
		return(!0);
	}

	return 0;
}
#endif


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

	parseGeneralArguments(); // Does not return if an error occurs

	#ifndef NO_INI_FILE
	if (fn_ini && !readIniFile(INI_FILE_PASS_1))
	{
		printerrorf("Warning: Can't read %s: %s\n", fn_ini, strerror(errno));
	}
	#endif // NO_INI_FILE

	#if !defined(NO_LIMIT) && !defined(NO_SOCKETS)
	allocateSemaphore();
	#endif // !defined(NO_LIMIT) && !defined(NO_SOCKETS)

	#ifdef _NTSERVICE
	if (installService)
		return NtServiceInstallation(installService, ServiceUser, ServicePassword);
	#endif // _NTSERVICE

	#ifndef NO_SOCKETS
	if (!InetdMode)
	{
		if ((error = setupListeningSockets())) return error;
	}
	#endif // NO_SOCKETS

	// After sockets have been set up, we may switch to a lower privileged user
	#if !defined(_WIN32) && !defined(NO_USER_SWITCH)
	#ifndef NO_SIGHUP
	if (!IsRestarted)
	{
	#endif // NO_SIGHUP
		if (gid != INVALID_GID && setgid(gid))
		{
			printerrorf("Fatal: setgid for %s failed.\n", gname);
			return !0;
		}

		if (uid != INVALID_UID && setuid(uid))
		{
			printerrorf("Fatal: setuid for %s failed.\n", uname);
			return !0;
		}
	#ifndef NO_SIGHUP
	}
	#endif // NO_SIGHUP
	#endif // !defined(_WIN32) && !defined(NO_USER_SWITCH)

	randomNumberInit();

	// Randomization Level 1 means generate ePIDs at startup and use them during
	// the lifetime of the process. So we generate them now
	#ifndef NO_RANDOM_EPID
	if (RandomizationLevel == 1) randomPidInit();
	#endif

	#if !defined(NO_SOCKETS)
	#ifdef _WIN32
	if (!IsNTService)
	#endif // _WIN32
	if ((error = daemonizeAndSetSignalAction())) return error;
	#endif // !defined(NO_SOCKETS)

	writePidFile();

	#if !defined(NO_LOG) && !defined(NO_SOCKETS)
	if (!InetdMode) logger("vlmcsd %s started successfully\n", Version);
	#endif

	#ifdef _NTSERVICE
	if (IsNTService) ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 200);
	#endif

	int rc = runServer();

	// Clean up things and exit
	#ifdef _NTSERVICE
	if (!ServiceShutdown)
	#endif
		cleanup(TRUE);
	#ifdef _NTSERVICE
	else
		ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
	#endif

	return rc;
}
