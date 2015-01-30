#ifndef CONFIG
#define CONFIG "config.h"
#endif // CONFIG
#include CONFIG

#include "output.h"
#include "shared_globals.h"
#include "endian.h"
#include "helpers.h"

#ifndef NO_LOG
static void vlogger(const char *message, va_list args)
{
	FILE *log;

	#ifdef _NTSERVICE
	if (!IsNTService && logstdout) log = stdout;
	#else
	if (logstdout) log = stdout;
	#endif
	else
	{
		if (fn_log == NULL) return;

		#ifndef _WIN32
		if (!strcmp(fn_log, "syslog"))
		{
			openlog("vlmcsd", LOG_CONS | LOG_PID, LOG_USER);

			////PORTABILITY: vsyslog is not in Posix but virtually all Unixes have it
			vsyslog(LOG_INFO, message, args);

			closelog();
			return;
		}
		#endif // _WIN32

		log = fopen(fn_log, "a");
		if ( !log ) return;
	}

	time_t now = time(0);

	#ifdef USE_THREADS
	char mbstr[2048];
	#else
	char mbstr[24];
	#endif

	strftime(mbstr, sizeof(mbstr), "%Y-%m-%d %X", localtime(&now));

	#ifndef USE_THREADS

	fprintf(log, "%s: ", mbstr);
	vfprintf(log, message, args);
	fflush(log);

	#else // USE_THREADS

	// We write everything to a string before we really log inside the critical section
	// so formatting the output can be concurrent
	strcat(mbstr, ": ");
	int len = strlen(mbstr);
	vsnprintf(mbstr + len, sizeof(mbstr) - len, message, args);

	lock_mutex(&logmutex);
	fputs(mbstr, log);
	fflush(log);
	unlock_mutex(&logmutex);

	#endif // USE_THREADS
	if (log != stdout) fclose(log);
}


int logger(const char *const fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogger(fmt, args);
	va_end(args);
	return 0;
}

#endif //NO_LOG


void printerrorf(const char *const fmt, ...)
{
	va_list arglist;

	va_start(arglist, fmt);

	#ifndef NO_LOG
	#ifdef _NTSERVICE
	if (InetdMode || IsNTService)
	#else // !_NTSERVICE
	if (InetdMode)
	#endif // NTSERVIICE
		vlogger(fmt, arglist);
	else
	#endif //NO_LOG
	{
		vfprintf(stderr, fmt, arglist);
		fflush(stderr);
	}

	va_end(arglist);
}


int errorout(const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int i = vfprintf(stderr, fmt, args);
	va_end(args);
	fflush(stderr);

	return i;
}


static const char *LicenseStatusText[] =
{
	"Unlicensed", "Licensed", "OOB grace", "OOT grace", "Non-Genuine", "Notification", "Extended grace"
};


void uuid2StringLE(const GUID *const guid, char *const string)
{
	sprintf(string,
				#ifdef _WIN32
				"%08x-%04x-%04x-%04x-%012I64x",
				#else
				"%08x-%04x-%04x-%04x-%012llx",
				#endif
				(unsigned int)LE32( guid->Data1 ),
				(unsigned int)LE16( guid->Data2 ),
				(unsigned int)LE16( guid->Data3 ),
				(unsigned int)BE16( *(uint16_t*)guid->Data4 ),
				(unsigned long long)BE64(*(uint64_t*)(guid->Data4)) & 0xffffffffffffLL
				);
}


void logRequestVerbose(const REQUEST *const Request, const PRINTFUNC p)
{
	char guidBuffer[GUID_STRING_LENGTH + 1];
	char WorkstationBuffer[3 * WORKSTATION_NAME_BUFFER];
	const char *productName;
	ProdListIndex_t index;

	p("Protocol version                : %u.%u\n", LE16(Request->MajorVer), LE16(Request->MinorVer));
	p("Client is a virtual machine     : %s\n", LE32(Request->IsClientVM) ? "Yes" : "No");
	p("Current client license status   : %u (%s)\n", (uint32_t)LE32(Request->LicenseStatus), LE32(Request->LicenseStatus) < _countof(LicenseStatusText) ? LicenseStatusText[LE32(Request->LicenseStatus)] : "Unknown");
	p("Remaining time (0 = forever)    : %i minutes\n", (uint32_t)LE32(Request->GraceTime));

	uuid2StringLE(&Request->AppId, guidBuffer);
	productName = getProductNameLE(&Request->AppId, AppList, &index);
	p("Application ID                  : %s (%s)\n", guidBuffer, productName);

	uuid2StringLE(&Request->SkuId, guidBuffer);

	#ifndef NO_EXTENDED_PRODUCT_LIST
	productName = getProductNameLE(&Request->SkuId, ExtendedProductList, &index);
	#else
	productName = "Unknown";
	#endif

	p("Client SKU ID                   : %s (%s)\n", guidBuffer, productName);

	uuid2StringLE(&Request->KmsId, guidBuffer);

	#ifndef NO_BASIC_PRODUCT_LIST
	productName = getProductNameLE(&Request->KmsId, ProductList, &index);
	#else
	productName = "Unknown";
	#endif

	p("Server SKU ID                   : %s (%s)\n", guidBuffer, productName);

	uuid2StringLE(&Request->ClientMachineId, guidBuffer);
	p("Client machine ID               : %s\n", guidBuffer);

	char mbstr[64];
	time_t st;
	st = fileTimeToUnixTime(&Request->TimeStamp);
	strftime(mbstr, sizeof(mbstr), "%Y-%m-%d %X", gmtime(&st));
	p("Time stamp (UTC)                : %s\n", mbstr);

	ucs2_to_utf8(Request->WorkstationName, WorkstationBuffer, WORKSTATION_NAME_BUFFER, sizeof(WorkstationBuffer));

	p("Workstation name                : %s\n", WorkstationBuffer);
	p("Minimum required clients        : %u\n", (uint32_t)LE32(Request->MinimumClients));
}


void logResponseVerbose(const char *const ePID, const BYTE *const hwid, const RESPONSE *const response, const PRINTFUNC p)
{
	char guidBuffer[GUID_STRING_LENGTH + 1];
	//SYSTEMTIME st;

	p("Protocol version                : %u.%u\n", (uint32_t)LE16(response->MajorVer), (uint32_t)LE16(response->MinorVer));
	p("KMS host extended PID           : %s\n", ePID);
	if (LE16(response->MajorVer) > 5)
#		ifndef _WIN32
		p("KMS host Hardware ID            : %016llX\n", (unsigned long long)BE64(*(uint64_t*)hwid));
#		else // _WIN32
		p("KMS host Hardware ID            : %016I64X\n", (unsigned long long)BE64(*(uint64_t*)hwid));
#		endif // WIN32

	uuid2StringLE(&response->ClientMachineId, guidBuffer);
	p("Client machine ID               : %s\n", guidBuffer);

	char mbstr[64];
	time_t st;

	st = fileTimeToUnixTime(&response->TimeStamp);
	strftime(mbstr, sizeof(mbstr), "%Y-%m-%d %X", gmtime(&st));
	p("Time stamp (UTC)                : %s\n", mbstr);

	p("KMS host current active clients : %u\n", (uint32_t)LE32(response->ActivatedMachines));
	p("Activation renewal interval     : %u\n", (uint32_t)LE32(response->RenewalInterval));
	p("Activation retry interval       : %u\n", (uint32_t)LE32(response->ActivationInterval));
}

