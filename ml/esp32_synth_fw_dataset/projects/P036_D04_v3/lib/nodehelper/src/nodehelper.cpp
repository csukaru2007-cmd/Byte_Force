#include "nodehelper.h"

void TempHelper::begin() {
  pinMode(_pin, INPUT);
}

float TempHelper::readTemperature() {
  int raw = analogRead(_pin);
  return raw * (3.3f / 4095.0f) * 100.0f;
}
