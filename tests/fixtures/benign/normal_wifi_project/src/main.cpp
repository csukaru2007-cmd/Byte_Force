#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Preferences.h>

// Credentials are provisioned at run time and stored in NVS, not in source code.
Preferences prefs;
extern const char ROOT_CA_PEM[];

String readSetting(const char *key);

void setup() {
  Serial.begin(115200);
  String ssid = readSetting("ssid");
  String password = readSetting("pass");
  WiFi.begin(ssid.c_str(), password.c_str());
}

void loop() {
  WiFiClientSecure client;
  client.setCACert(ROOT_CA_PEM);
  HTTPClient https;
  https.begin(client, "https://api.example.com/v1/weather");
  int status = https.GET();
  if (status == 200) {
    Serial.println(https.getString());
  }
  https.end();
  delay(60000);
}
