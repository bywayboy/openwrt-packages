#ifndef __main_h
#define __main_h

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

#define __T(x)    #x
#define  _T(x) __T(x)

extern char *fn_pid;
extern char *fn_ini;
extern char *fn_log;

#include "types.h"
#include "endian.h"
#include "shared_globals.h"
#include "output.h"
#include "network.h"
#include "ntservice.h"
#include "helpers.h"

//int main(int argc, CARGV);
extern void CleanUp();

#ifdef _NTSERVICE
int newmain();
#endif

#if MULTI_CALL_BINARY < 1
#define server_main main
#else
int server_main(int argc, CARGV argv);
#endif

#ifndef SA_NOCLDWAIT    // required for Cygwin
#define SA_NOCLDWAIT 0
#endif


#endif // __main_h
