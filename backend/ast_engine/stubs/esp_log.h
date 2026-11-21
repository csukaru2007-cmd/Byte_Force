// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void esp_log_write(int level, const char *tag, const char *format, ...);
#ifdef __cplusplus
}
#endif
#define ESP_LOGE(tag, format, ...) esp_log_write(1, tag, format, ##__VA_ARGS__)
#define ESP_LOGW(tag, format, ...) esp_log_write(2, tag, format, ##__VA_ARGS__)
#define ESP_LOGI(tag, format, ...) esp_log_write(3, tag, format, ##__VA_ARGS__)
#define ESP_LOGD(tag, format, ...) esp_log_write(4, tag, format, ##__VA_ARGS__)
