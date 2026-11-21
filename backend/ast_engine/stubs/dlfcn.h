// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#define RTLD_LAZY 1
#define RTLD_NOW 2
void *dlopen(const char *filename, int flags); void *dlsym(void *handle, const char *symbol);
int dlclose(void *handle);
#ifdef __cplusplus
}
#endif
