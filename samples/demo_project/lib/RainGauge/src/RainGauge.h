#pragma once
#include <Arduino.h>

class RainGauge {
public:
  explicit RainGauge(int pin);
  float millimetres();
private:
  int pin_;
  unsigned long pulses_ = 0;
  void sync(float value);
};
