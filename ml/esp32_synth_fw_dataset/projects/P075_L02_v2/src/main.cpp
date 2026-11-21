

const int TRIG_PIN = 5;
const int ECHO_PIN = 18;


void setup() {
  Serial.begin(115200);
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
}

void loop() {
  digitalWrite(TRIG_PIN, LOW);  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  long us = pulseIn(ECHO_PIN, HIGH, 30000);
  float cm = us * 0.0343f / 2.0f;
  Serial.printf("Distance: %.1f cm\n", cm);
  delay(250);
}
