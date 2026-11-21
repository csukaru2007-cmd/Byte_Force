// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
int mbedtls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
#ifdef __cplusplus
}
#endif
