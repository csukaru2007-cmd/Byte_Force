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


void reconnect() {
  while (!mqtt.connected()) {
    if (!mqtt.connect("esp32-node-11", MQTT_USER, MQTT_PASS)) delay(2000);
  }
}

void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  net.setCACert(ROOT_CA);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
}

void loop() {
    if (!mqtt.connected()) reconnect();
    mqtt.loop();
    char msg[48];
    snprintf(msg, sizeof(msg), "{\"temp\":%.1f}", 20.0 + random(0, 50) / 10.0);
    mqtt.publish("sensors/esp32-node-11/temp", msg);
    delay(5000);
}
