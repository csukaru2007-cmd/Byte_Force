// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <esp_err.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { const char *url; const char *cert_pem; int skip_cert_common_name_check; } esp_http_client_config_t;
typedef struct { const esp_http_client_config_t *http_config; } esp_https_ota_config_t;
esp_err_t esp_https_ota(const esp_https_ota_config_t *ota_config);
#ifdef __cplusplus
}
#endif
