// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_https_ota.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct esp_http_client *esp_http_client_handle_t;
esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *config);
esp_err_t esp_http_client_perform(esp_http_client_handle_t client);
int esp_http_client_read(esp_http_client_handle_t client, char *buffer, int len);
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client);
#ifdef __cplusplus
}
#endif
