#include <Arduino.h>
const int TRIG = 5, ECHO = 18;

float medianOf3(float a, float b, float c) {
  if (a > b) { float t = a; a = b; b = t; }
  if (b > c) { float t = b; b = c; c = t; }
  if (a > b) { float t = a; a = b; b = t; }
  return b;
}

float ping() {
  digitalWrite(TRIG, LOW); delayMicroseconds(2);
  digitalWrite(TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG, LOW);
  return pulseIn(ECHO, HIGH, 30000) * 0.0343f / 2.0f;
}

void setup() { Serial.begin(115200); pinMode(TRIG, OUTPUT); pinMode(ECHO, INPUT); }
void loop() { Serial.println(medianOf3(ping(), ping(), ping())); delay(200); }
