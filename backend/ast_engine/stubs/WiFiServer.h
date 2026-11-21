// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <WiFiClient.h>
class WiFiServer {
public:
    WiFiServer(uint16_t port = 80);
    void begin(uint16_t port = 0);
    WiFiClient available();
    WiFiClient accept();
    void stop();
};
