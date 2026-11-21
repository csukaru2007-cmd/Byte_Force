#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>

// FAKE test credentials - not real secrets
#define WIFI_PASSWORD "FakePass-For-Tests-123"
const char *ssid = "ShipSafeTestNet";
const char *api_token = "sk_test_FAKE000000000000";
const char *password_hint = "";          // empty: not a secret
const char *mqtt_password = "changeme";   // placeholder value

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, WIFI_PASSWORD);
  Serial.print("Connecting with password ");
  Serial.println(WIFI_PASSWORD);           // secret written to the log
}

void loop() {
  HTTPClient http;
  http.begin("https://api.example.com/data");
  http.setAuthorization("admin", "FakeAdminPass-0000");
  http.addHeader("Authorization", String("Bearer ") + api_token);
  http.GET();
  http.end();
}
