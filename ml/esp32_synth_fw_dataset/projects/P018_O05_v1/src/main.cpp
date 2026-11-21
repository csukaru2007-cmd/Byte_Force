#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";
const char* FW_URL = "http://ota.example.com/fw/esp32-node-52/firmware.bin";
const char* OTA_TOKEN = "REPLACE_WITH_DEVICE_TOKEN";


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
  const char* URL = FW_URL;
  HTTPClient http;
  WiFiClient client;
  http.begin(client, URL);
  http.addHeader("Authorization", String("Bearer ") + OTA_TOKEN);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  int len = http.getSize();
  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) { http.end(); return false; }
  WiFiClient* s = http.getStreamPtr();
  uint8_t buf[1024];
  int remaining = len;
  while (http.connected() && remaining > 0) {
    size_t n = s->readBytes(buf, min(remaining, 1024));
    if (n == 0) break;
    Update.write(buf, n);
    remaining -= n;
  }
  http.end();
  return Update.end(true);
}


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  if (performUpdate()) { Serial.println("Update OK"); ESP.restart(); }
  else Serial.println("Update rejected");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 5000) { last = millis(); Serial.println("heartbeat"); }
}
