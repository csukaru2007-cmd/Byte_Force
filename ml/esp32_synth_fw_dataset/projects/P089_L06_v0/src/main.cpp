#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

Adafruit_SSD1306 oled(128, 64, &Wire, -1);


void setup() {
  Serial.begin(115200);
  if (!oled.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { Serial.println("OLED not found"); for (;;); }
  oled.clearDisplay();
  oled.setTextSize(2);
  oled.setTextColor(SSD1306_WHITE);
  oled.setCursor(0, 0);
  oled.println("Hello");
  oled.display();
}

void loop() {
  delay(1000);
}
