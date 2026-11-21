// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
bool esp_secure_boot_enabled(void);
esp_err_t esp_secure_boot_permanently_enable(void);
#ifdef __cplusplus
}
#endif
