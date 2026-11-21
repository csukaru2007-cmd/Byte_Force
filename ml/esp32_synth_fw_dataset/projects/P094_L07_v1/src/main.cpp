#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* FW_URL = "https://firmware.example.com/fw/esp32-node-01/firmware.bin";
const char* MANIFEST_URL = "https://firmware.example.com/fw/esp32-node-01/manifest.json";
const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\n<PLACEHOLDER_ROOT_CA>\n-----END CERTIFICATE-----\n";
const char* OTA_TOKEN = "REPLACE_WITH_DEVICE_TOKEN";
const int CURRENT_VERSION = 9;


bool httpGetString(const char* URL, String& out) {
  HTTPClient http;
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  http.begin(client, URL);
  http.addHeader("Authorization", String("Bearer ") + OTA_TOKEN);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  out = http.getString();
  http.end();
  return true;
}

bool performUpdate() {
  String m;
  if (!httpGetString(MANIFEST_URL, m)) return false;
  JsonDocument doc;
  if (deserializeJson(doc, m)) return false;
  String expectedSha = doc["sha256"] | "";
  int newVer = doc["version"] | 0;
  if (newVer <= CURRENT_VERSION) return false;  // no downgrade
  const char* URL = FW_URL;
  HTTPClient http;
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  http.begin(client, URL);
  http.addHeader("Authorization", String("Bearer ") + OTA_TOKEN);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  File f = LittleFS.open("/fw.bin", "w");
  if (!f) { http.end(); return false; }
  http.writeToStream(&f);
  f.close();
  http.end();
  File fw = LittleFS.open("/fw.bin", "r");
  if (!Update.begin(fw.size())) return false;
  Update.writeStream(fw);
  fw.close();
  return Update.end(true);
}

float readBattery() { return analogRead(34) * (3.3f / 4095.0f) * 2.0f; }

void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  LittleFS.begin(true);
  if (performUpdate()) { Serial.println("Update OK"); ESP.restart(); }
  else Serial.println("Update rejected");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 5000) { last = millis(); Serial.printf("vbat=%.2f\n", readBattery()); }
}
