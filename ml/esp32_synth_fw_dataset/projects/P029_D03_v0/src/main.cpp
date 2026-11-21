#include <DHT.h>
DHT dht(4, DHT11);
void setup(){ Serial.begin(115200); dht.begin(); }
void loop(){ Serial.println(dht.readTemperature()); delay(2000); }
