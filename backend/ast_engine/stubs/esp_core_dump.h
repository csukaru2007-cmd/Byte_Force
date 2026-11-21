// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t esp_core_dump_image_get(size_t *out_addr, size_t *out_size);
esp_err_t esp_core_dump_image_erase(void);
#ifdef __cplusplus
}
#endif
