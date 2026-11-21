// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <stddef.h>
#include <stdarg.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct __sFILE FILE;
extern FILE *stdout; extern FILE *stderr;
int printf(const char *, ...); int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...); int vsnprintf(char *, size_t, const char *, va_list);
int puts(const char *); FILE *popen(const char *command, const char *mode); int pclose(FILE *);
#ifdef __cplusplus
}
#endif
