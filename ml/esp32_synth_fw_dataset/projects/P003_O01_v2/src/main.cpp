#include <WiFi.h>
#include <ArduinoOTA.h>

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  ArduinoOTA.setHostname("esp32-node-41");
  // no password configured
  ArduinoOTA.begin();
}

void loop() {
  ArduinoOTA.handle();
}
