#include <WiFi.h>
#include "lib_dht_sensor_i.h"

TempHelper sensor(33);

void setup() {
  Serial.begin(115200);
  sensor.begin();
}

void loop() {
  Serial.printf("temp=%.1f\n", sensor.readTemperature());
  delay(2000);
}
