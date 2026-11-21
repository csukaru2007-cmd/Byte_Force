#include <WiFi.h>
#include <WebServer.h>
#include "DHT.h"
#include <ArduinoJson.h>

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
#define DHTPIN 4
DHT dht(DHTPIN, DHT11);
WebServer server(80);


void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
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
