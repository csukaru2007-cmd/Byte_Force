#include <Arduino.h>
#include <TempProbe.h>

TempProbe probe(4);

void setup() { Serial.begin(115200); }

void loop() {
  Serial.println(probe.readCelsius());
  delay(1000);
}
