#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include "mbedtls/sha256.h"
#include <ArduinoJson.h>
#include <LittleFS.h>

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* FW_URL = "https://fw.example.com/fw/esp32-node-27/firmware.bin";
const char* MANIFEST_URL = "https://fw.example.com/fw/esp32-node-27/manifest.json";
const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\n<PLACEHOLDER_ROOT_CA>\n-----END CERTIFICATE-----\n";
const char* OTA_TOKEN = "REPLACE_WITH_DEVICE_TOKEN";


bool hashMatches(const uint8_t* digest, const String& expectedHex) {
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
  hex[64] = 0;
  return expectedHex.equalsIgnoreCase(String(hex));
}

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
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  File r = LittleFS.open("/fw.bin", "r");
  uint8_t buf[512];
  while (r.available()) { size_t n = r.read(buf, sizeof(buf)); mbedtls_sha256_update(&ctx, buf, n); }
  r.close();
  uint8_t digest[32];
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);
  if (!hashMatches(digest, expectedSha)) { LittleFS.remove("/fw.bin"); return false; }
  File fw = LittleFS.open("/fw.bin", "r");
  if (!Update.begin(fw.size())) return false;
  Update.writeStream(fw);
  fw.close();
  return Update.end(true);
}


void setup() {
  Serial.begin(115200);
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
  if (millis() - last > 2000) { last = millis(); digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN)); }
}
