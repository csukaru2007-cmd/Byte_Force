// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
esp_err_t spi_flash_write(size_t dest_addr, const void *src, size_t size);
esp_err_t spi_flash_erase_sector(size_t sector);
esp_err_t spi_flash_erase_range(size_t start_address, size_t size);
esp_err_t spi_flash_read(size_t src_addr, void *dest, size_t size);
#ifdef __cplusplus
}
#endif
