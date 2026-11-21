// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct esp_flash_t esp_flash_t;
extern esp_flash_t *esp_flash_default_chip;
esp_err_t esp_flash_write(esp_flash_t *chip, const void *buffer, uint32_t address, uint32_t length);
esp_err_t esp_flash_erase_region(esp_flash_t *chip, uint32_t start, uint32_t len);
esp_err_t esp_flash_erase_chip(esp_flash_t *chip);
esp_err_t esp_flash_read(esp_flash_t *chip, void *buffer, uint32_t address, uint32_t length);
#ifdef __cplusplus
}
#endif
