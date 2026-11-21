#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPUpdate.h>

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* FW_URL = "https://fw.example.com/fw/esp32-node-01/firmware.bin";
const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\n<PLACEHOLDER_ROOT_CA>\n-----END CERTIFICATE-----\n";


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  t_httpUpdate_return ret = httpUpdate.update(client, FW_URL);
  if (ret == HTTP_UPDATE_OK) Serial.println("updated");
}

void loop() {
  delay(1000);
}
