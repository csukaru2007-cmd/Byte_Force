#include <WiFi.h>
#include <WebServer.h>

const char* NET_SSID = "YOUR_SSID";
const char* NET_PW = "YOUR_PASSWORD";
const int IN1 = 18, IN2 = 19, ENA = 5;
WebServer server(80);


void drive(int speed) {              // -255..255
  digitalWrite(IN1, speed > 0);
  digitalWrite(IN2, speed < 0);
  ledcWrite(0, abs(speed));
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  pinMode(IN1, OUTPUT); pinMode(IN2, OUTPUT);
  ledcSetup(0, 5000, 8);
  ledcAttachPin(ENA, 0);
  server.on("/fwd",  []() { drive(200);  server.send(200, "text/plain", "fwd"); });
  server.on("/back", []() { drive(-200); server.send(200, "text/plain", "back"); });
  server.on("/stop", []() { drive(0);    server.send(200, "text/plain", "stop"); });
  server.begin();
}

void loop() {
  server.handleClient();
}
