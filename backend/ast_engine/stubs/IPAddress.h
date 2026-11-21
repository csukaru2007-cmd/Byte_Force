// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
class IPAddress {
public:
    IPAddress();
    IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
    IPAddress(uint32_t address);
    bool fromString(const char *address);
    String toString() const;
};
