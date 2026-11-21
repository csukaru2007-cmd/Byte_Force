#include <Arduino.h>

void setup() {
  pinMode(34, OUTPUT);   // GPIO34 is input-only on ESP32
  digitalWrite(34, HIGH);
}

void loop() {}
