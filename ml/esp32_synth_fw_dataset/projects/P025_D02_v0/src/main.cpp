#include <WiFi.h>
#include "sensor_calib0.h"

TempHelper sensor(32);

void setup() {
  Serial.begin(115200);
  sensor.begin();
}

void loop() {
  Serial.printf("temp=%.1f\n", sensor.readTemperature());
  delay(2000);
}
