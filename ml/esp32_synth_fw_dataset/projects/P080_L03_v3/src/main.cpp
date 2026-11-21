#include <WiFi.h>
#include <WebServer.h>

const char* NET_SSID = "YOUR_SSID";
const char* NET_PW = "YOUR_PASSWORD";
WebServer server(80);
bool ledOn = false;


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  pinMode(2, OUTPUT);
  server.on("/", []() { server.send(200, "text/html", ledOn ? "LED is ON" : "LED is OFF"); });
  server.on("/toggle", []() { ledOn = !ledOn; digitalWrite(2, ledOn); server.sendHeader("Location", "/"); server.send(303); });
  server.onNotFound([]() { server.send(404, "text/plain", "not found"); });
  server.begin();
}

void loop() {
  server.handleClient();
}
