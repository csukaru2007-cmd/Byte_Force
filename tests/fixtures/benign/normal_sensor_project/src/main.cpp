#include <Arduino.h>
#include <Wire.h>

const int LIGHT_SENSOR_PIN = 34;   // ADC1_CH6, input only: read-only use is correct
const int STATUS_LED_PIN = 23;

void setup() {
  Serial.begin(115200);
  Wire.begin(21, 22);
  pinMode(STATUS_LED_PIN, OUTPUT);
  pinMode(LIGHT_SENSOR_PIN, INPUT);
}

void loop() {
  uint16_t light = analogRead(LIGHT_SENSOR_PIN);
  digitalWrite(STATUS_LED_PIN, light > 2000 ? HIGH : LOW);
  Serial.println(light);
  delay(500);
}
