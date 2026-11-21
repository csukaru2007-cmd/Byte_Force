#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>

const char* NET_SSID = "YOUR_SSID";
const char* NET_PW = "YOUR_PASSWORD";
const char* MQTT_HOST = "broker.example.com";
const int MQTT_PORT = 8883;
const char* MQTT_USER = "esp32_user";
const char* MQTT_PASS = "REPLACE_ME";
WiFiClientSecure net;
PubSubClient mqtt(net);
const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\n<PLACEHOLDER_ROOT_CA>\n-----END CERTIFICATE-----\n";


bool reconnect() {
  return mqtt.connect("esp32-node-17", MQTT_USER, MQTT_PASS, "sensors/esp32-node-17/status", 1, true, "offline");
}

void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  net.setCACert(ROOT_CA);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  reconnect();
}

void loop() {
    if (!mqtt.connected()) { reconnect(); delay(1000); return; }
    mqtt.publish("sensors/esp32-node-17/status", "online", true);
    mqtt.publish("sensors/esp32-node-17/adc", String(analogRead(34)).c_str());
    mqtt.loop();
    delay(1000);
}
