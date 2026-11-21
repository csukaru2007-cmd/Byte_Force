#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
Adafruit_SSD1306 oled(128, 64, &Wire, -1);
void setup(){ oled.begin(SSD1306_SWITCHCAPVCC, 0x3C); oled.clearDisplay(); oled.println("ok"); oled.display(); }
void loop(){}
