#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ArduinoOTA.h>
#include <HTTPUpdate.h>

extern const char UPDATE_SERVER_CA[];
String loadOtaPassword();

void setup() {
  ArduinoOTA.setHostname("greenhouse-node");
  ArduinoOTA.setPassword(loadOtaPassword().c_str());   // authenticated local OTA
  ArduinoOTA.begin();
}

void checkForUpdate() {
  WiFiClientSecure client;
  client.setCACert(UPDATE_SERVER_CA);                   // verified TLS
  httpUpdate.update(client, "https://updates.example.com/greenhouse.bin");
}

void loop() {
  ArduinoOTA.handle();
}
