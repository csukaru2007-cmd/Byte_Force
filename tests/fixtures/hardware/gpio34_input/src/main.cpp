#include <Arduino.h>

void setup() {
  pinMode(34, INPUT);
  Serial.begin(115200);
}

void loop() {
  int level = digitalRead(34);
  uint16_t raw = analogRead(34);   // ADC1_CH6
  Serial.println(level + raw);
}
