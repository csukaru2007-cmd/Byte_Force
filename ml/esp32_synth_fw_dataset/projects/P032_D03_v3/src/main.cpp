#include <ArduinoJson.h>
void setup(){ Serial.begin(115200); JsonDocument d; d["t"]=21.5; serializeJson(d, Serial); }
void loop(){}
