#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

Adafruit_SSD1306 oled(128, 64, &Wire, -1);


void setup() {
  Serial.begin(921600);
  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  oled.setTextColor(SSD1306_WHITE);
}

void loop() {
  oled.clearDisplay();
  oled.setCursor(0, 0);
  oled.printf("ADC: %d\n", analogRead(34));
  oled.printf("Up: %lus", millis() / 1000);
  oled.display();
  delay(500);
}
