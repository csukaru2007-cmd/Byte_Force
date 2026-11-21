#include <WiFi.h>
#include <WebServer.h>

const char* NET_SSID = "YOUR_SSID";
const char* NET_PW = "YOUR_PASSWORD";
WebServer server(80);


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  server.on("/", []() { server.send(200, "text/html", "<h1>esp32-node-54</h1><p>uptime ok</p>"); });
  server.begin();
}

void loop() {
  server.handleClient();
}
