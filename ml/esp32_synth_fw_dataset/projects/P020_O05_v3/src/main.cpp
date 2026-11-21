#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include "mbedtls/sha256.h"
#include <ArduinoJson.h>

const char* kSsid = "YOUR_SSID";
const char* kPass = "YOUR_PASSWORD";
const char* FW_URL = "http://fw.example.com/fw/esp32-node-03/firmware.bin";
const char* MANIFEST_URL = "http://fw.example.com/fw/esp32-node-03/manifest.json";
const char* OTA_TOKEN = "REPLACE_WITH_DEVICE_TOKEN";


bool hashMatches(const uint8_t* digest, const String& expectedHex) {
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
  hex[64] = 0;
  return expectedHex.equalsIgnoreCase(String(hex));
}

bool httpGetString(const char* URL, String& out) {
  HTTPClient http;
  WiFiClient client;
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
  WiFiClient client;
  http.begin(client, URL);
  http.addHeader("Authorization", String("Bearer ") + OTA_TOKEN);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  int len = http.getSize();
  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) { http.end(); return false; }
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  WiFiClient* s = http.getStreamPtr();
  uint8_t buf[1024];
  int remaining = len;
  while (http.connected() && remaining > 0) {
    size_t n = s->readBytes(buf, min(remaining, 1024));
    if (n == 0) break;
    Update.write(buf, n);
    mbedtls_sha256_update(&ctx, buf, n);
    remaining -= n;
  }
  http.end();
  uint8_t digest[32];
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);
  if (!hashMatches(digest, expectedSha)) { Update.abort(); return false; }
  return Update.end(true);
}


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(kSsid, kPass);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  if (performUpdate()) { Serial.println("Update OK"); ESP.restart(); }
  else Serial.println("Update rejected");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 5000) { last = millis(); digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN)); }
}
