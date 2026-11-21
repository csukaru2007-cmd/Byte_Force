#include <WiFi.h>
#include <WebServer.h>
#include "DHT.h"
#include <ArduinoJson.h>

const char* kSsid = "YOUR_SSID";
const char* kPass = "YOUR_PASSWORD";
#define DHTPIN 15
DHT dht(DHTPIN, DHT11);
WebServer server(80);


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(kSsid, kPass);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  dht.begin();
  server.on("/data", []() {
    JsonDocument d;
    d["temperature"] = dht.readTemperature();
    d["humidity"] = dht.readHumidity();
    String out; serializeJson(d, out);
    server.send(200, "application/json", out);
  });
  server.begin();
}

void loop() {
  server.handleClient();
}
