#ifndef VLMCS_H_
#define VLMCS_H_

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
#include "types.h"
#include "endian.h"
#include "shared_globals.h"
#include "output.h"
#include "network.h"
#include "ntservice.h"
#include "kms.h"
#include "output.h"
#include "helpers.h"

#endif /* VLMCS_H_ */

#if MULTI_CALL_BINARY < 1
#define client_main main
#else
int client_main(int argc, CARGV argv);
#endif

