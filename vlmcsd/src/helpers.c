/*
 * Helper functions used by other modules
 */

#include "helpers.h"


// Checks, whether a string is a valid integer number between min and max. Returns TRUE or FALSE. Puts int value in *value
BOOL StringToInt(const char *const szValue, const int min, const int max, int *const value)
{
	char *nextchar;

	errno = 0;
	long long result = strtoll(szValue, &nextchar, 10);

	if (errno || result < (long long)min || result > (long long)max || *nextchar)
	{
		return FALSE;
	}

	*value = (int)result;
	return TRUE;
}


//Checks a command line argument if it is numeric and between min and max. Returns the numeric value
__pure int GetOptionArgumentInt(const char o, const int min, const int max)
{
	int result;

	if (!StringToInt(optarg, min, max, &result))
	{
		printerrorf("Fatal: Option \"-%c\" must be numeric between %i and %i.\n", o, min, max);
		exit(!0);
	}

	return result;
}



// Resets getopt() to start parsing from the beginning
void OptReset(void)
{
	#if defined(__BSD__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
	optind = 1;
	optreset = 1; // Makes newer BSD getopt happy
	#elif defined(__UCLIBC__) // uClibc headers also define __GLIBC__ so be careful here
	optind = 0; // uClibc seeks compatibility with GLIBC
	#elif defined(__GLIBC__)
	optind = 0; // Makes GLIBC getopt happy
	#else // Standard for most systems
	optind = 1;
	#endif
}


#ifdef _WIN32

// Returns a static message buffer containing text for a given Win32 error. Not thread safe (same as strerror)
char* win_strerror(const int message)
{
	#define STRERROR_BUFFER_SIZE 256
	static char buffer[STRERROR_BUFFER_SIZE];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, message, 0, buffer, STRERROR_BUFFER_SIZE, NULL);
	return buffer;
}

#endif // _WIN32



