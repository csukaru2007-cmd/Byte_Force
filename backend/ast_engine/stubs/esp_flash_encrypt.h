// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
bool esp_flash_encryption_enabled(void);
void esp_flash_encryption_init_checks(void);
esp_err_t esp_flash_encrypt_contents(void);
#ifdef __cplusplus
}
#endif
