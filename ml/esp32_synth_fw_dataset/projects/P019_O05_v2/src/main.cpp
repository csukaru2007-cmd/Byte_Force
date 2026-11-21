#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <LittleFS.h>

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";
const char* FW_URL = "http://updates.example.com/fw/esp32-node-56/firmware.bin";


bool httpGetString(const char* URL, String& out) {
  HTTPClient http;
  WiFiClient client;
  http.begin(client, URL);
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
  if (millis() - last > 10000) { last = millis(); Serial.println("heartbeat"); }
}
