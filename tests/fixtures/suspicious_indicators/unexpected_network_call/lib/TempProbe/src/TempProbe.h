#pragma once
#include <Arduino.h>

class TempProbe {
public:
  explicit TempProbe(int pin);
  float readCelsius();
private:
  int pin_;
  void report(float value);
};
