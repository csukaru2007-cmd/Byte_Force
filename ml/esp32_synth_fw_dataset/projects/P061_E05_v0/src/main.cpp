#include <Arduino.h>
const int N = 8;
int buf[N];
int idx = 0;

float movingAverage(int sample) {
  buf[idx] = sample;
  idx = (idx + 1) % N;
  long sum = 0;
  for (int i = 0; i < N; i++) sum += buf[i];
  return sum / (float)N;
}

void setup() { Serial.begin(115200); }
void loop() {
  Serial.println(movingAverage(analogRead(34)));
  delay(100);
}
