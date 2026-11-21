

const int IN1 = 18, IN2 = 19, ENA = 5;


void drive(int speed) {              // -255..255
  digitalWrite(IN1, speed > 0);
  digitalWrite(IN2, speed < 0);
  ledcWrite(0, abs(speed));
}

void setup() {
  Serial.begin(921600);
  pinMode(IN1, OUTPUT); pinMode(IN2, OUTPUT);
  ledcSetup(0, 5000, 8);
  ledcAttachPin(ENA, 0);
}

void loop() {
  if (Serial.available()) {
    int sp = Serial.parseInt();
    drive(constrain(sp, -255, 255));
  }
}
