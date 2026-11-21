#include <WiFi.h>
#include "ringbuf_esp.h"

TempHelper sensor(34);

void setup() {
  Serial.begin(115200);
  sensor.begin();
}

void loop() {
  Serial.printf("temp=%.1f\n", sensor.readTemperature());
  delay(2000);
}
