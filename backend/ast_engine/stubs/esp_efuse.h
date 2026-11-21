// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct esp_efuse_desc_t esp_efuse_desc_t;
esp_err_t esp_efuse_write_field_bit(const esp_efuse_desc_t *field[]);
esp_err_t esp_efuse_write_field_blob(const esp_efuse_desc_t *field[], const void *src, size_t src_size_bits);
esp_err_t esp_efuse_write_field_cnt(const esp_efuse_desc_t *field[], size_t cnt);
esp_err_t esp_efuse_write_block(int blk, const void *src_key, size_t offset_in_bits, size_t size_bits);
esp_err_t esp_efuse_set_read_protect(int blk);
esp_err_t esp_efuse_set_write_protect(int blk);
esp_err_t esp_efuse_read_field_blob(const esp_efuse_desc_t *field[], void *dst, size_t dst_size_bits);
#ifdef __cplusplus
}
#endif
