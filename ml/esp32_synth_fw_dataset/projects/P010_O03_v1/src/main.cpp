#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include <LittleFS.h>

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";
const char* FW_URL = "https://updates.example.com/fw/esp32-node-29/firmware.bin";
const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\n<PLACEHOLDER_ROOT_CA>\n-----END CERTIFICATE-----\n";
const char* OTA_TOKEN = "REPLACE_WITH_DEVICE_TOKEN";


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


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  LittleFS.begin(true);
  if (performUpdate()) { Serial.println("Update OK"); ESP.restart(); }
  else Serial.println("Update rejected");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 10000) { last = millis(); digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN)); }
}
