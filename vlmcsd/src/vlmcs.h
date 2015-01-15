#ifndef VLMCS_H_
#define VLMCS_H_

#ifndef CONFIG
#define CONFIG "config.h"
#endif // CONFIG
#include CONFIG

#include "types.h"

#if MULTI_CALL_BINARY < 1
#define client_main main
#else
int client_main(int argc, CARGV argv);
#endif

#endif /* VLMCS_H_ */

