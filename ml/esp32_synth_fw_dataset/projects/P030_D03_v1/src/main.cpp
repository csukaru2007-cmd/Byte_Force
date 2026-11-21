#include <WiFi.h>
#include <PubSubClient.h>
WiFiClient net;
PubSubClient mqtt(net);
void setup(){ Serial.begin(115200); mqtt.setServer("broker.example.com", 1883); }
void loop(){ if (!mqtt.connected()) mqtt.connect("esp32-node-24"); mqtt.loop(); delay(100); }
