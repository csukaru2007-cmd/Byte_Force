#include <WiFi.h>
#include <HTTPUpdate.h>

const char* kSsid = "YOUR_SSID";
const char* kPass = "YOUR_PASSWORD";
const char* FW_URL = "http://fw.example.com/fw/esp32-node-19/firmware.bin";


void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(kSsid, kPass);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  WiFiClient client;
  t_httpUpdate_return ret = httpUpdate.update(client, FW_URL);
  if (ret == HTTP_UPDATE_OK) Serial.println("updated");
}

void loop() {
  delay(1000);
}
