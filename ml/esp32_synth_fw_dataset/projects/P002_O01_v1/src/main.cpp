#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <Update.h>

const char* NET_SSID = "YOUR_SSID";
const char* NET_PW = "YOUR_PASSWORD";
AsyncWebServer server(80);


void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  server.on("/ota", HTTP_POST,
    [](AsyncWebServerRequest* request) {
      request->send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
      ESP.restart();
    },
    [](AsyncWebServerRequest* request, String filename, size_t index, uint8_t* data, size_t len, bool final) {
      if (index == 0) Update.begin(UPDATE_SIZE_UNKNOWN);
      Update.write(data, len);
      if (final) Update.end(true);
    });
  server.begin();
}

void loop() {
  delay(10);
}
