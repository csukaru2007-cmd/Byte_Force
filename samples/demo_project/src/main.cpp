// ShipSafe DEMO PROJECT: a small weather station with intentional, harmless issues.
#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <PubSubClient.h>
#include <ArduinoOTA.h>
#include <Adafruit_BME280.h>
#include <RainGauge.h>

#define WIFI_SSID "DemoNetwork"
#define WIFI_PASSWORD "demo-FAKE-passw0rd"     // fake credential committed to source

const int SOIL_SENSOR_PIN = 26;               // ADC2 channel: unusable while Wi-Fi is on
const int WIND_SENSOR_PIN = 35;               // ADC1 channel: fine

WiFiClient netClient;
PubSubClient mqtt(netClient);
Adafruit_BME280 bme;
RainGauge rain(27);

void setup() {
  Serial.begin(115200);
  pinMode(STATUS_LED_PIN, OUTPUT);            // STATUS_LED_PIN = 34 (input-only GPIO)
  Wire.begin(21, 22);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  mqtt.setServer("broker.example.com", MQTT_PORT);

  ArduinoOTA.setHostname("demo-weather");
  ArduinoOTA.begin();                         // no OTA password configured
}

void loop() {
  ArduinoOTA.handle();
  if (!mqtt.connected()) {
    mqtt.connect("demo-weather");
  }
  int soil = analogRead(SOIL_SENSOR_PIN);
  int wind = analogRead(WIND_SENSOR_PIN);
  float rainfall = rain.millimetres();
  mqtt.publish("demo/weather/soil", String(soil).c_str());
  mqtt.publish("demo/weather/wind", String(wind).c_str());
  mqtt.publish("demo/weather/rain", String(rainfall).c_str());
  mqtt.loop();
  digitalWrite(STATUS_LED_PIN, HIGH);
  delay(10000);
}
