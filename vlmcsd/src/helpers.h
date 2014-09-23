#ifndef HELPERS_H
#define HELPERS_H

#include "types.h"
#include "output.h"

BOOL StringToInt(const char *const szValue, const int min, const int max, int *const value);
int GetOptionArgumentInt(const char o, const int min, const int max);
void OptReset(void);
char* win_strerror(const int message);

#endif // HELPERS_H
