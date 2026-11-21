// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void *malloc(size_t); void *calloc(size_t, size_t); void *realloc(void *, size_t); void free(void *);
int atoi(const char *); long atol(const char *); long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int); double atof(const char *);
int system(const char *command); char *getenv(const char *); void abort(void); void exit(int);
int rand(void); void srand(unsigned);
#ifdef __cplusplus
}
#endif
