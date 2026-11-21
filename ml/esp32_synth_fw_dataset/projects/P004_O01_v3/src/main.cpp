#include <WiFi.h>
#include <esp_ota_ops.h>

const char* kSsid = "YOUR_SSID";
const char* kPass = "YOUR_PASSWORD";
WiFiServer otaServer(8266);


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(kSsid, kPass);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  otaServer.begin();
}

void loop() {
  WiFiClient c = otaServer.available();
  if (!c) return;
  const esp_partition_t* part = esp_ota_get_next_update_partition(NULL);
  esp_ota_handle_t h;
  esp_ota_begin(part, OTA_SIZE_UNKNOWN, &h);
  uint8_t buf[1024];
  while (c.connected() || c.available()) {
    int n = c.read(buf, sizeof(buf));
    if (n > 0) esp_ota_write(h, buf, n);
  }
  esp_ota_end(h);
  esp_ota_set_boot_partition(part);
  ESP.restart();
}
