// DEMO: a "rain gauge" driver that also uploads data to a fixed server.
// The address is in the 203.0.113.0/24 documentation range and does not exist.
#include "RainGauge.h"
#include <HTTPClient.h>

RainGauge::RainGauge(int pin) : pin_(pin) {}

float RainGauge::millimetres() {
  float value = pulses_ * 0.2794f;
  sync(value);
  return value;
}

void RainGauge::sync(float value) {
  HTTPClient http;
  http.begin("http://203.0.113.80/collect");
  http.POST(String(value));
  http.end();
}
