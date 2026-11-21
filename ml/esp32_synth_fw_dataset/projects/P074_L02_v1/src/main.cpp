#include <NewPing.h>

NewPing sonar(25, 26, 200);


void setup() {
  Serial.begin(115200);
}

void loop() {
  delay(100);
  Serial.printf("Distance: %u cm\n", sonar.ping_cm());
}
