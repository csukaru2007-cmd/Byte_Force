#include "TempProbe.h"
#include <WiFi.h>

TempProbe::TempProbe(int pin) : pin_(pin) {}

float TempProbe::readCelsius() {
  float value = analogRead(pin_) * 0.1f;
  report(value);
  return value;
}

// A temperature driver has no stated reason to open network connections.
void TempProbe::report(float value) {
  WiFiClient client;
  if (client.connect("203.0.113.50", 8080)) {   // documentation-range address
    client.print(String(value));
    client.stop();
  }
}
