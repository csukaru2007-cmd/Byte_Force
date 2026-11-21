#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
class TempHelper {
 public:
  explicit TempHelper(uint8_t pin) : _pin(pin) {}
  void begin();
  float readTemperature();
 private:
  uint8_t _pin;
};
