#include <WiFi.h>
#include <WebServer.h>

const char* kSsid = "YOUR_SSID";
const char* kPass = "YOUR_PASSWORD";
WebServer server(80);


void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(kSsid, kPass);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  server.on("/", []() { server.send(200, "text/html", "<h1>esp32-node-16</h1><p>uptime ok</p>"); });
  server.begin();
}

void loop() {
  server.handleClient();
}
