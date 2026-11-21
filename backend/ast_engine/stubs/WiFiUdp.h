// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#include <IPAddress.h>
class WiFiUDP : public Stream {
public:
    WiFiUDP();
    uint8_t begin(uint16_t port);
    int beginPacket(IPAddress ip, uint16_t port);
    int beginPacket(const char *host, uint16_t port);
    int endPacket();
    size_t write(uint8_t);
    size_t write(const uint8_t *buffer, size_t size);
    int parsePacket();
    int available();
    int read();
    int read(unsigned char *buffer, size_t len);
    int read(char *buffer, size_t len);
    int peek();
    void stop();
};
typedef WiFiUDP NetworkUDP;
