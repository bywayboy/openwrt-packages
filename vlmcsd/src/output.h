#ifndef INCLUDED_OUTPUT_H
#define INCLUDED_OUTPUT_H

#include "kms.h"
#include "shared_globals.h"

typedef int (*PRINTFUNC)(const char *const fmt, ...);

void printerrorf(const char *const fmt, ...);
int errorout(const char* fmt, ...);
void LogRequestVerbose(const REQUEST *const Request, const PRINTFUNC p);
void LogResponseVerbose(const char *const ePID, const BYTE *const hwid, const RESPONSE *const response, const PRINTFUNC p);
void Uuid2String(const GUID *const guid, char *const string);

#ifndef NO_LOG
int logger(const char *const fmt, ...);
#endif //NO_LOG

//void copy_arguments(int argc, char **argv, char ***new_argv);
//void destroy_arguments(int argc, char **argv);

#endif // INCLUDED_OUTPUT_H
