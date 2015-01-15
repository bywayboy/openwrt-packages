#include "vlmcs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <getopt.h>
#ifndef _WIN32
#include <sys/ioctl.h>
#include <termios.h>
#endif // _WIN32
#include "endian.h"
#include "shared_globals.h"
#include "output.h"
#include "network.h"
#include "kms.h"
#include "helpers.h"
#include "rpc.h"


// Function Prototypes
void CreateRequestBase(REQUEST *Request);


// KMS Parameters
static BOOL verbose = FALSE;
static BOOL PretendVM = FALSE;
static BOOL dnsnames = TRUE;
static int FixedRequests = 0;
static BYTE licenseStatus = 0x02;
static const char *ClientGuid = NULL;
static const char *WorkstationName = NULL;
static int GracePeriodRemaining = 43200; //30 days
static const char *RemoteAddr;
static int_fast8_t ReconnectForEachRequest = FALSE;
static WORD kmsVersionMinor = 0;
static int AddressFamily = AF_UNSPEC;


// Structure for handling "License Packs" (e.g. Office2013v5 or WindowsVista)
typedef struct
{
	const char *names;			//This is a list of strings. Terminate with additional Zero!!!
	int RequiredClientCount;
	int kmsVersionMajor;
	const GUID *ApplicationID;
	GUID ID;
	GUID KmsID;
} LicensePack;


// Well known "license packs"
static const LicensePack LicensePackList[] =
{
	// List of names          min lics version  appID            skuId                                                                                KMSCountedID
	{ "W6\000Vista\000"
	  "WindowsVista\000"
	  "Windows\000",                25,      4, PWINGUID,        { 0x4f3d1606, 0x3fea, 0x4c01, { 0xbe, 0x3c, 0x8d, 0x67, 0x1c, 0x40, 0x1e, 0x3b, } }, { 0x212a64dc, 0x43b1, 0x4d3d, { 0xa3, 0x0c, 0x2f, 0xc6, 0x9d, 0x20, 0x95, 0xc6 } } },
	{ "W7\000Windows7\000",         25,      4, PWINGUID,        { 0xb92e9980, 0xb9d5, 0x4821, { 0x9c, 0x94, 0x14, 0x0f, 0x63, 0x2f, 0x63, 0x12, } }, { 0x7fde5219, 0xfbfa, 0x484a, { 0x82, 0xc9, 0x34, 0xd1, 0xad, 0x53, 0xe8, 0x56 } } },
	{ "W8\000Windows8\000",         25,      5, PWINGUID,        { 0xa98bcd6d, 0x5343, 0x4603, { 0x8a, 0xfe, 0x59, 0x08, 0xe4, 0x61, 0x11, 0x12, } }, { 0x3c40b358, 0x5948, 0x45af, { 0x92, 0x3b, 0x53, 0xd2, 0x1f, 0xcc, 0x7e, 0x79 } } },
	{ "W8C\000Windows8C\000",       25,      5, PWINGUID,        { 0xc04ed6bf, 0x55c8, 0x4b47, { 0x9f, 0x8e, 0x5a, 0x1f, 0x31, 0xce, 0xee, 0x60, } }, { 0xbbb97b3b, 0x8ca4, 0x4a28, { 0x97, 0x17, 0x89, 0xfa, 0xbd, 0x42, 0xc4, 0xac } } },
	{ "W81\000Windows81\000",       25,      6, PWINGUID,        { 0xc06b6981, 0xd7fd, 0x4a35, { 0xb7, 0xb4, 0x05, 0x47, 0x42, 0xb7, 0xaf, 0x67, } }, { 0xcb8fc780, 0x2c05, 0x495a, { 0x97, 0x10, 0x85, 0xaf, 0xff, 0xc9, 0x04, 0xd7 } } },
	{ "W81C\000Windows81C\000",     25,      6, PWINGUID,        { 0xfe1c3238, 0x432a, 0x43a1, { 0x8e, 0x25, 0x97, 0xe7, 0xd1, 0xef, 0x10, 0xf3, } }, { 0x6d646890, 0x3606, 0x461a, { 0x86, 0xab, 0x59, 0x8b, 0xb8, 0x4a, 0xce, 0x82 } } },
	{ "2008" "\0" "2008A\000",       5,      4, PWINGUID,        { 0xddfa9f7c, 0xf09e, 0x40b9, { 0x8c, 0x1a, 0xbe, 0x87, 0x7a, 0x9a, 0x7f, 0x4b, } }, { 0x33e156e4, 0xb76f, 0x4a52, { 0x9f, 0x91, 0xf6, 0x41, 0xdd, 0x95, 0xac, 0x48 } } },
	{ "2008B\000",                   5,      4, PWINGUID,        { 0xc1af4d90, 0xd1bc, 0x44ca, { 0x85, 0xd4, 0x00, 0x3b, 0xa3, 0x3d, 0xb3, 0xb9, } }, { 0x8fe53387, 0x3087, 0x4447, { 0x89, 0x85, 0xf7, 0x51, 0x32, 0x21, 0x5a, 0xc9 } } },
	{ "2008C\000",                   5,      4, PWINGUID,        { 0x68b6e220, 0xcf09, 0x466b, { 0x92, 0xd3, 0x45, 0xcd, 0x96, 0x4b, 0x95, 0x09, } }, { 0x8a21fdf3, 0xcbc5, 0x44eb, { 0x83, 0xf3, 0xfe, 0x28, 0x4e, 0x66, 0x80, 0xa7 } } },
	{ "2008R2" "\0" "2008R2A\000",   5,      4, PWINGUID,        { 0xa78b8bd9, 0x8017, 0x4df5, { 0xb8, 0x6a, 0x09, 0xf7, 0x56, 0xaf, 0xfa, 0x7c, } }, { 0x0fc6ccaf, 0xff0e, 0x4fae, { 0x9d, 0x08, 0x43, 0x70, 0x78, 0x5b, 0xf7, 0xed } } },
	{ "2008R2B\000",                 5,      4, PWINGUID,        { 0x620e2b3d, 0x09e7, 0x42fd, { 0x80, 0x2a, 0x17, 0xa1, 0x36, 0x52, 0xfe, 0x7a, } }, { 0xca87f5b6, 0xcd46, 0x40c0, { 0xb0, 0x6d, 0x8e, 0xcd, 0x57, 0xa4, 0x37, 0x3f } } },
	{ "2008R2C\000",                 5,      4, PWINGUID,        { 0x7482e61b, 0xc589, 0x4b7f, { 0x8e, 0xcc, 0x46, 0xd4, 0x55, 0xac, 0x3b, 0x87, } }, { 0xb2ca2689, 0xa9a8, 0x42d7, { 0x93, 0x8d, 0xcf, 0x8e, 0x9f, 0x20, 0x19, 0x58 } } },
	{ "2012\000",                    5,      5, PWINGUID,        { 0xf0f5ec41, 0x0d55, 0x4732, { 0xaf, 0x02, 0x44, 0x0a, 0x44, 0xa3, 0xcf, 0x0f, } }, { 0x8665cb71, 0x468c, 0x4aa3, { 0xa3, 0x37, 0xcb, 0x9b, 0xc9, 0xd5, 0xea, 0xac } } },
	{ "2012R2\000" "12R2\000",       5,      6, PWINGUID,        { 0x00091344, 0x1ea4, 0x4f37, { 0xb7, 0x89, 0x01, 0x75, 0x0b, 0xa6, 0x98, 0x8c, } }, { 0x8456EFD3, 0x0C04, 0x4089, { 0x87, 0x40, 0x5b, 0x72, 0x38, 0x53, 0x5a, 0x65 } } },
	{ "O14\000Office2010\000",       5,      4, POFFICE2010GUID, { 0x6f327760, 0x8c5c, 0x417c, { 0x9b, 0x61, 0x83, 0x6a, 0x98, 0x28, 0x7e, 0x0c, } }, { 0xe85af946, 0x2e25, 0x47b7, { 0x83, 0xe1, 0xbe, 0xbc, 0xeb, 0xea, 0xc6, 0x11 } } },
	{ "O15\000Office2013\000",       5,      6, POFFICE2013GUID, { 0xb322da9c, 0xa2e2, 0x4058, { 0x9e, 0x4e, 0xf5, 0x9a, 0x69, 0x70, 0xbd, 0x69, } }, { 0xe6a6f1bf, 0x9d40, 0x40c3, { 0xaa, 0x9f, 0xc7, 0x7b, 0xa2, 0x15, 0x78, 0xc0 } } },
	{ "Office2013V5\000",            5,      5, POFFICE2013GUID, { 0xb322da9c, 0xa2e2, 0x4058, { 0x9e, 0x4e, 0xf5, 0x9a, 0x69, 0x70, 0xbd, 0x69, } }, { 0xe6a6f1bf, 0x9d40, 0x40c3, { 0xaa, 0x9f, 0xc7, 0x7b, 0xa2, 0x15, 0x78, 0xc0 } } },
	{ NULL, 0, 0, NULL, { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } }, { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } } }
};


typedef struct
{
	const char* first[16];
	const char* second[16];
	const char* tld[22];
} DnsNames;


// Some names for the DNS name random generator
static DnsNames ClientDnsNames =
{
	{ "www", "ftp", "kms", "hack-me", "smtp", "ns1", "mx1", "ns1", "pop3", "imap", "mail", "dns", "headquarter", "we-love", "_vlmcs._tcp", "ceo-laptop" },
	{ ".microsoft", ".apple", ".amazon", ".samsung", ".adobe", ".google", ".yahoo", ".facebook", ".ubuntu", ".oracle", ".borland", ".htc", ".acer", ".windows", ".linux", ".sony" },
	{ ".com", ".net", ".org", ".cn", ".co.uk", ".de", ".com.tw", ".us", ".fr", ".it", ".me", ".info", ".biz", ".co.jp", ".ua", ".at", ".es", ".pro", ".by", ".ru", ".pl", ".kr" }
};


// This is the one, we are actually using. We use Vista, if user selects nothing
LicensePack ActiveLicensePack;


// Request Count Control Variables
static int RequestsToGo = 1;
static BOOL firstRequestSent = FALSE;


static void string2UuidOrExit(const char *const restrict input, GUID *const restrict guid)
{
	if (strlen(input) != GUID_STRING_LENGTH || !string2Uuid(input, guid))
	{
		errorout("Fatal: Command line contains an invalid GUID.\n");
		exit(!0);
	}
}


#ifndef NO_HELP

__noreturn static void clientUsage(const char* const programName)
{
	errorout(
		"vlmcs %s \n\n"
		"Usage: %s [options] [<host>[:<port>]] [options]\n\n"

		"Options:\n\n"

		"  -v Be verbose\n"
		"  -l <app>\n"
		"  -4 Force V4 protocol\n"
		"  -5 Force V5 protocol\n"
		"  -6 Force V6 protocol\n"
		"  -i <IpVersion> Use IP protocol (4 or 6)\n"
		"  -m Pretend to be a virtual machine\n"
		"  -e Show some valid examples\n"
		"  -x Show valid Apps\n"
		"  -d no DNS names, use Netbios names (no effect if -W is used)\n\n"

		"Advanced options:\n\n"

		"  -a <AppGUID> Use custom Application GUID\n"
		"  -s <SkuGUID> Use custom SKU GUID\n"
		"  -k <KmsGUID> Use custom KMS GUID\n"
		"  -c <ClientGUID> Use custom Client GUID. Default: Use random\n"
		"  -w <Workstation> Use custom workstation name. Default: Use random\n"
		"  -r <RequiredClientCount> Fake required clients\n"
		"  -n <Requests> Fixed # of requests (Default: Enough to charge)\n"
		"  -T Use a new TCP connection for each request.\n"
		"  -t <LicenseStatus> Use specfic license status (0 <= T <= 6)\n"
		"  -g <GraceTime> Use specfic grace time in minutes. Default 43200\n"
		"  -p Don't use multiplexed RPC bind\n\n"

		"<port>:\tTCP port name of the KMS to use. Default 1688.\n"
		"<host>:\thost name of the KMS to use. Default 127.0.0.1\n"
		"<app>:\t(Type %s -x to see a list of valid apps)\n\n",
		Version, programName, programName
	);

	exit(!0);
}

__pure static int getLineWidth(void)
{
	#ifdef TERMINAL_FIXED_WIDTH // For Toolchains that to not have winsize
	return TERMINAL_FIXED_WIDTH;
	#else // Can determine width of terminal
	#ifndef _WIN32

	struct winsize w;

	if(ioctl(fileno(stdout), TIOCGWINSZ, &w))
	{
		return 80; // Return this if stdout is not a tty
	}

	return w.ws_col;

	#else // _WIN32

	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	if (!GetConsoleScreenBufferInfo(hStdout, &csbiInfo))
	{
		return 80; // Return this if stdout is not a Console
	}

	return csbiInfo.srWindow.Right - csbiInfo.srWindow.Left;

	#endif // WIN32

	#endif // Can determine width of terminal

}

__noreturn static void showProducts(const char* const programName, PRINTFUNC p)
{
	int cols = getLineWidth();
	int itemsPerLine;
	uint8_t i;

	p(
		"The following "
		#if !defined(NO_EXTENDED_PRODUCT_LIST) && !defined(NO_BASIC_PRODUCT_LIST)
		"aliases "
		#else
		"names "
		#endif
		"can be used with -l:\n\n"
	);

	const LicensePack* lp;

	itemsPerLine = cols / 20;
	if (!itemsPerLine) itemsPerLine = 1;

	for (i = 1, lp = LicensePackList; lp->names; lp++)
	{
		const char* name;

		for (name = lp->names; *name; name += strlen(name) + 1, i++)
		{
			uint8_t j;
			p("%s", name);

			for (j = 0; j < 20 - strlen(name); j++)
			{
				p(" ");
			}

			if (!(i % itemsPerLine)) p("\n");
		}
	}

	p("\n\n");

	#if !defined(NO_EXTENDED_PRODUCT_LIST) && !defined(NO_BASIC_PRODUCT_LIST)

	const KmsIdList* currentProduct;
	uint_fast8_t longestString = 0;
	uint8_t k, items = getExtendedProductListSize();

	p("You may also use these product names or numbers:\n\n");

	for (currentProduct = ExtendedProductList; currentProduct->name; currentProduct++)
	{
		uint_fast8_t len = strlen(currentProduct->name);
		if (len > longestString)
			longestString = len;
	}

	itemsPerLine = cols / (longestString + 10);
	if (!itemsPerLine) itemsPerLine = 1;
	uint8_t lines = items / itemsPerLine;
	if (items % itemsPerLine) lines++;

	for (i = 0; i < lines; i++)
	{
		for (k = 0; k < itemsPerLine; k++)
		{
			uint8_t j;
			uint8_t index = k * lines + i;
			if (index >= items) break;
			p("%3u = %s",  index + 1, ExtendedProductList[index].name);

			for (j = 0; j < longestString + 4 - strlen(ExtendedProductList[index].name); j++)
			{
				p(" ");
			}
		}

		p("\n");
	}

	p("\n");

	#endif // !defined(NO_EXTENDED_PRODUCT_LIST) && !defined(NO_BASIC_PRODUCT_LIST)

	exit(0);
}

__noreturn static void examples(const char* const programName)
{
	printf(
		"\nRequest activation for Office2013 using V4 protocol from 192.168.1.5:1688\n"
		"\t%s -l O15 -4 192.168.1.5\n"
		"\t%s -l O15 -4 192.168.1.5:1688\n\n"

		"Request activation for Windows Server 2012 using V4 protocol from localhost:1688\n"
		"\t%s -4 -l Windows -k 8665cb71-468c-4aa3-a337-cb9bc9d5eaac\n"
		"\t%s -4 -l 2012\n"
		"\t%s -4 -l 2012 [::1]:1688\n"
		"\t%s -4 -l 12 127.0.0.2:1688\n\n"

		"Send 100,000 requests to localhost:1688\n"
		"\t%s -n 100000 -l Office2010\n\n"

		"Request Activation for Windows 8 from 10.0.0.1:4711 and pretend to be Steve Ballmer\n"
		"\t%s -l Windows8 -w steveb1.redmond.microsoft.com 10.0.0.1:4711\n\n",
		programName, programName, programName, programName, programName, programName, programName, programName
	);

	exit(0);
}


#else // NO_HELP


__noreturn static void clientUsage(const char* const programName)
{
	errorout("Incorrect parameter specified.\n");
	exit(!0);
}


#endif // NO_HELP


static BOOL findLicensePackByName(const char* const name, LicensePack* const lp)
{
	// Try to find a package in the short list first

	LicensePack *licensePack;
	for (licensePack = (LicensePack*)&LicensePackList; licensePack->names; licensePack ++)
	{
		const char *currentName;
		for (currentName = licensePack->names; *currentName; currentName += strlen(currentName) + 1)
		{
			if (!strcasecmp(name, currentName))
			{
				*lp = *licensePack;
				return TRUE;
			}
		}
	}

	#if defined(NO_BASIC_PRODUCT_LIST) || defined(NO_EXTENDED_PRODUCT_LIST)

	return FALSE;

	#else // Both Lists are available

	// search extended product list

    uint8_t items = getExtendedProductListSize();
    int index;

    if (stringToInt(name, 1, items, &index))
    {
    	index--;
    }
    else
    {
    	for (index = 0; index < items; index++)
    	{
    		if (!strcasecmp(ExtendedProductList[index].name, name)) break;
    	}

    	if (index >= items) return FALSE;
    }

	lp->ApplicationID       = &AppList[ExtendedProductList[index].AppIndex].guid;
	lp->KmsID               = ProductList[ExtendedProductList[index].KmsIndex].guid;
	lp->ID                  = ExtendedProductList[index].guid;
	lp->RequiredClientCount = ProductList[ExtendedProductList[index].KmsIndex].KMS_PARAM_REQUIREDCOUNT;
	lp->kmsVersionMajor     = ProductList[ExtendedProductList[index].KmsIndex].KMS_PARAM_MAJOR;

	return TRUE;

	#endif // Both Lists are available
}

static const char* const client_optstring = "+i:l:a:s:k:c:w:r:n:t:g:pTv456mexd";


//First pass. We handle only "-l". Since -a -k -s -4 -5 and -6 are exceptions to -l, we process -l first
static void parseCommandLinePass1(const char *const programName, const int argc, CARGV argv)
{
	int o;
	optReset();

	for (opterr = 0; ( o = getopt(argc, (char* const*)argv, client_optstring) ) > 0; ) switch (o)
	{
		case 'l': // Set "License Pack" and protocol version (e.g. Windows8, Office2013v5, ...)

			if (!findLicensePackByName(optarg, &ActiveLicensePack))
			{
				errorout("Invalid client application. \"%s\" is not valid for -l.\n\n", optarg);
				#ifndef NO_HELP
				showProducts(programName, &printf);
				#endif // !NO_HELP
			}

			break;

		default:
			break;
	}
}


// Second Pass. Handle all options except "-l"
static void parseCommandLinePass2(const char *const programName, const int argc, CARGV argv)
{
	int o;
	optReset();

	for (opterr = 0; ( o = getopt(argc, (char* const*)argv, client_optstring) ) > 0; ) switch (o)
	{
			#ifndef NO_HELP

			case 'e': // Show examples

				examples(programName);
				break;

			case 'x': // Show Apps

				showProducts(programName, &errorout);
				break;

			#endif // NO_HELP

			case 'i':

				switch(getOptionArgumentInt(o, 4, 6))
				{
					case 4:
						AddressFamily = AF_INET;
						break;
					case 6:
						AddressFamily = AF_INET6;
						break;
					default:
						errorout("IPv5 does not exist.\n");
						exit(!0);
						break;
				}

				break;

			case 'p': // Multiplexed RPC

				UseMultiplexedRpc = FALSE;
				break;

			case 'n': // Fixed number of Requests (regardless, whether they are required)

				FixedRequests = getOptionArgumentInt(o, 1, INT_MAX);
				break;

			case 'r': // Fake minimum required client count

				ActiveLicensePack.RequiredClientCount = getOptionArgumentInt(o, 1, INT_MAX);
				break;

			case 'c': // use a specific client GUID

				// If using a constant Client ID, send only one request unless /N= explicitly specified
				if (!FixedRequests) FixedRequests = 1;

				ClientGuid = optarg;
				break;

			case 'a': // Set specific App Id

				ActiveLicensePack.ApplicationID = (GUID*)malloc(sizeof(GUID));

				if (!ActiveLicensePack.ApplicationID)
				{
					errorout("Out of memory\n");
					exit(!0);
				}

				string2UuidOrExit(optarg, (GUID*)ActiveLicensePack.ApplicationID);
				break;

			case 'g': // Set custom "grace" time in minutes (default 30 days)

				GracePeriodRemaining = getOptionArgumentInt(o, 0, INT_MAX);
				break;

			case 's': // Set specfic SKU ID

				string2UuidOrExit(optarg, &ActiveLicensePack.ID);
				break;

			case 'k': // Set specific KMS ID

				string2UuidOrExit(optarg, &ActiveLicensePack.KmsID);
				break;

			case '4': // Force V4 protocol
			case '5': // Force V5 protocol
			case '6': // Force V5 protocol

				ActiveLicensePack.kmsVersionMajor = o - 0x30;
				break;

			case 'd': // Don't use DNS names

				dnsnames = FALSE;
				break;

			case 'v': // Be verbose

				verbose = TRUE;
				break;

			case 'm': // Pretend to be a virtual machine

				PretendVM = TRUE;
				break;

			case 'w': // WorkstationName (max. 63 chars)

				WorkstationName = optarg;

				if (strlen(WorkstationName) > 63)
				{
					errorout("\007WARNING! Truncating Workstation name to 63 characters (%s).\n", WorkstationName);
				}

				break;

			case 't':

				licenseStatus = getOptionArgumentInt(o, 0, 6) & 0xff;
				break;

			case 'T':

				ReconnectForEachRequest = TRUE;
				break;

			case 'l': // We already handled /l in the first pass. break; to avoid error
				break;

			default:
				clientUsage(programName);
	}
}


void displayResponse(const RESPONSE_RESULT result, RESPONSE* response, BYTE *hwid)
{
	fflush(stdout);

	if (!result.RpcOK)				errorout("\n\007ERROR: Non-Zero RPC result code.");
	if (!result.DecryptSuccess)		errorout("\n\007ERROR: Decryption of V5/V6 response failed.");
	if (!result.IVsOK)				errorout("\n\007ERROR: AES CBC initialization vectors (IVs) of request and response do not match.");
	if (!result.PidLengthOK)		errorout("\n\007ERROR: The length of the PID is not valid.");
	if (!result.HashOK)				errorout("\n\007ERROR: Computed hash does not match hash in response.");
	if (!result.ClientMachineIDOK)	errorout("\n\007ERROR: Client machine GUIDs of request and response do not match.");
	if (!result.TimeStampOK)		errorout("\n\007ERROR: Time stamps of request and response do not match.");
	if (!result.VersionOK)			errorout("\n\007ERROR: Protocol versions of request and response do not match.");
	if (!result.HmacSha256OK)		errorout("\n\007ERROR: Keyed-Hash Message Authentication Code (HMAC) is incorrect.");

	if (result.effectiveResponseSize != result.correctResponseSize)
	{
		errorout("\n\007WARNING: Size of RPC payload (KMS Message) should be %u but is %u.", result.correctResponseSize, result.effectiveResponseSize);
	}

	if (!result.DecryptSuccess) return; // Makes no sense to display anything

	char ePID[3 * PID_BUFFER_SIZE];
	if (!ucs2_to_utf8(response->KmsPID, ePID, PID_BUFFER_SIZE, 3 * PID_BUFFER_SIZE))
	{
		memset(ePID + 3 * PID_BUFFER_SIZE - 3, 0, 3);
	}

	// Read KMSPID from Response
	if (!verbose)
	{
		printf(" -> %s", ePID);

		if (LE16(response->MajorVer) > 5)
		{
			printf(" (%02X%02X%02X%02X%02X%02X%02X%02X)", hwid[0], hwid[1], hwid[2], hwid[3], hwid[4], hwid[5], hwid[6], hwid[7]);
		}

		printf("\n");
	}
	else
	{
		printf(
				"\n\nResponse from KMS server\n========================\n\n"
				"Size of KMS Response            : %u (0x%x)\n", result.effectiveResponseSize, result.effectiveResponseSize
		);

		logResponseVerbose(ePID, hwid, response, &printf);
		printf("\n");
	}
}


static void establishRpc(SOCKET *s)
{
	*s = connectToAddress(RemoteAddr, AddressFamily);
	if (*s == INVALID_SOCKET)
	{
		errorout("Fatal: Could not connect to %s\n", RemoteAddr);
		exit(!0);
	}
	if (verbose)
		printf("\nPerforming RPC bind ...\n");

	if (rpcBindClient(*s))
	{
		errorout("Fatal: Could not bind RPC\n");
		exit(!0);
	}

	if (verbose) printf("... successful\n");
}


static int SendActivationRequest(const SOCKET sock, RESPONSE *baseResponse, REQUEST *baseRequest, RESPONSE_RESULT *result, BYTE *const hwid)
{
	size_t requestSize, responseSize;
	BYTE *request, *response;
	int status;

	result->mask = 0;

	if (LE16(baseRequest->MajorVer) == 4)
		request = CreateRequestV4(&requestSize, baseRequest);
	else
		request = CreateRequestV6(&requestSize, baseRequest);

	if (!(status = rpcSendRequest(sock, request, requestSize, &response, &responseSize)))
	{
		if (LE16(((RESPONSE*)(response))->MajorVer) == 4)
		{
			RESPONSE_V4 response_v4;
			*result = DecryptResponseV4(&response_v4, responseSize, response, request);
			memcpy(baseResponse, &response_v4.ResponseBase, sizeof(RESPONSE));
		}
		else
		{
			RESPONSE_V6 response_v6;
			*result = DecryptResponseV6(&response_v6, responseSize, response, request, hwid);
			memcpy(baseResponse, &response_v6.ResponseBase, sizeof(RESPONSE));
		}

		result->RpcOK = TRUE;
	}

	if (response) free(response);
	free(request);
	return status;
}


int client_main(const int argc, CARGV argv)
{
	#ifdef _WIN32

	// Windows Sockets must be initialized

	WSADATA wsadata;
	int error;

	if ((error = WSAStartup(0x0202, &wsadata)))
	{
		printerrorf("Fatal: Could not initialize Windows sockets (Error: %d).\n", error);
		return error;
	}

	#endif // _WIN32

	#ifdef _NTSERVICE

	// We are not a service
	IsNTService = FALSE;

	// Set console output page to UTF-8
	// SetConsoleOutputCP(65001);

	#endif // _NTSERVICE

	randomNumberInit();
	ActiveLicensePack = *LicensePackList; //first license is Windows Vista

	parseCommandLinePass1(argv[0], argc, argv);

	int_fast8_t useDefaultHost = FALSE;

	if (optind < argc)
		RemoteAddr = argv[optind];
	else
		useDefaultHost = TRUE;

	int hostportarg = optind;

	if (optind < argc - 1)
	{
		parseCommandLinePass1(argv[0], argc - hostportarg, argv + hostportarg);

		if (optind < argc - hostportarg)
			clientUsage(argv[0]);
	}

	parseCommandLinePass2(argv[0], argc, argv);

	if (optind < argc - 1)
		parseCommandLinePass2(argv[0], argc - hostportarg, argv + hostportarg);

	if (useDefaultHost)
		RemoteAddr = AddressFamily == AF_INET6 ? "::1" : "127.0.0.1";

	SOCKET s = INVALID_SOCKET;
	RESPONSE response;
	RESPONSE_RESULT result;
	int requests;

	for (requests = 0, RequestsToGo = ActiveLicensePack.RequiredClientCount - 1; RequestsToGo; requests++)
	{
		REQUEST request;
		CreateRequestBase(&request);
		hwid_t hwid;
		int status;

		if (s == INVALID_SOCKET )
			establishRpc(&s);
		else
		{
			// Check for lame KMS emulators that close the socket after each request
			int_fast8_t disconnected = isDisconnected(s);

			if (disconnected)
				errorout("\nWarning: Server closed RPC connection (probably non-multitasked KMS emulator)\n");

			if (ReconnectForEachRequest || disconnected)
			{
				socketclose(s);
				establishRpc(&s);
			}
		}

		printf("Sending activation request (KMS V%u) ", ActiveLicensePack.kmsVersionMajor);
		fflush(stdout);

		status = SendActivationRequest(s, &response, &request, &result, hwid);

		if (FixedRequests) RequestsToGo = FixedRequests - requests - 1;

		if (status)
		{
			errorout("\nError 0x%08X while sending request %u of %u\n", status, requests + 1, RequestsToGo + requests + 1);

			switch(status)
			{
			case 0xC004F042: // not licensed
				errorout("The server refused to activate the requested product\n");
				break;

			case 0x8007000D:  // e.g. v6 protocol on a v5 server
				errorout("The server didn't understand the request\n");
				break;

			case 1:
				errorout("An RPC protocol error has occured\n");
				socketclose(s);
				establishRpc(&s);
				break;

			default:
				break;
			}

			if (!FixedRequests)
				RequestsToGo = 0;
		}
		else
		{
			if (!FixedRequests)
			{
				if (firstRequestSent && ActiveLicensePack.RequiredClientCount - (int)response.ActivatedMachines >= RequestsToGo)
				{
					errorout("\nThe KMS server does not increment it's active clients. Aborting...\n");
					RequestsToGo = 0;
				}
				else
				{
					RequestsToGo = ActiveLicensePack.RequiredClientCount - response.ActivatedMachines;
					if (RequestsToGo < 0) RequestsToGo = 0;
				}
			}

			fflush(stderr);
			printf("%i of %i ", requests + 1, RequestsToGo + requests + 1);
			displayResponse(result, &response, hwid);
			firstRequestSent = TRUE;
		}
	}

	return 0;
}

// Create Base KMS Client Request
void CreateRequestBase(REQUEST *Request)
{

	Request->MinorVer = LE16((WORD)kmsVersionMinor);
	Request->MajorVer = LE16((WORD)ActiveLicensePack.kmsVersionMajor);
	Request->IsClientVM = LE32(PretendVM);
	Request->LicenseStatus = LE32(licenseStatus);
	Request->GraceTime = LE32(GracePeriodRemaining);
	LEGUID(&Request->AppId, ActiveLicensePack.ApplicationID);
	LEGUID(&Request->SkuId, &ActiveLicensePack.ID);
	LEGUID(&Request->KmsId, &ActiveLicensePack.KmsID);

	getUnixTimeAsFileTime(&Request->TimeStamp);
	Request->MinimumClients = LE32(ActiveLicensePack.RequiredClientCount);

	if (ClientGuid)
	{
		string2UuidOrExit(ClientGuid, &Request->ClientMachineId);
	}
	else
	{
		get16RandomBytes(&Request->ClientMachineId);

		// Set reserved UUID bits
		Request->ClientMachineId.Data4[0] &= 0x3F;
		Request->ClientMachineId.Data4[0] |= 0x80;

		// Set UUID type 4 (random UUID)
		Request->ClientMachineId.Data3 &= LE16(0xfff);
		Request->ClientMachineId.Data3 |= LE16(0x4000);
	}


	static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" /*"abcdefghijklmnopqrstuvwxyz" */;

	if (WorkstationName)
	{
		utf8_to_ucs2(Request->WorkstationName, WorkstationName, WORKSTATION_NAME_BUFFER, WORKSTATION_NAME_BUFFER * 3);
	}
	else if (dnsnames)
	{
		int len, len2;
		unsigned int index = rand() % _countof(ClientDnsNames.first);
		len = utf8_to_ucs2(Request->WorkstationName, ClientDnsNames.first[index], WORKSTATION_NAME_BUFFER, WORKSTATION_NAME_BUFFER * 3);

		index = rand() % _countof(ClientDnsNames.second);
		len2 = utf8_to_ucs2(Request->WorkstationName + len, ClientDnsNames.second[index], WORKSTATION_NAME_BUFFER, WORKSTATION_NAME_BUFFER * 3);

		index = rand() % _countof(ClientDnsNames.tld);
		utf8_to_ucs2(Request->WorkstationName + len + len2, ClientDnsNames.tld[index], WORKSTATION_NAME_BUFFER, WORKSTATION_NAME_BUFFER * 3);
	}
	else
	{
		unsigned int size = (rand() % 14) + 1;
		const unsigned char *dummy;
		unsigned int i;

		for (i = 0; i < size; i++)
		{
			Request->WorkstationName[i] = utf8_to_ucs2_char((unsigned char*)alphanum + (rand() % (sizeof(alphanum) - 1)), &dummy);
		}

		Request->WorkstationName[size] = 0;
	}

	//Show Details
	if (verbose)
	{
		printf("\nRequest Parameters\n==================\n\n");
		logRequestVerbose(Request, &printf);
		printf("\n");
	}
}


