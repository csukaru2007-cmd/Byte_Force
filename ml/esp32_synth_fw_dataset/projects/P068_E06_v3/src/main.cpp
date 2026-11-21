#include <Arduino.h>
#include <string.h>

void handleCommand(const char* c) {
  if (strncmp(c, "led_on", 6) == 0)       digitalWrite(2, HIGH);
  else if (strncmp(c, "led_off", 7) == 0) digitalWrite(2, LOW);
  else Serial.println("unknown");
}

void setup() { Serial.begin(115200); pinMode(2, OUTPUT); }
void loop() {
  static char line[16];
  if (Serial.readBytesUntil('\n', line, sizeof(line) - 1) > 0) {
    line[sizeof(line) - 1] = 0;
    handleCommand(line);
    memset(line, 0, sizeof(line));
  }
}
