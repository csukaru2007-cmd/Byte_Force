// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
class TwoWire : public Stream {
public:
    TwoWire(uint8_t bus_num);
    bool setPins(int sda, int scl);
    bool begin();
    bool begin(int sda, int scl, uint32_t frequency = 0);
    bool begin(uint8_t slaveAddr, int sda, int scl, uint32_t frequency);
    void beginTransmission(uint16_t address);
    uint8_t endTransmission(bool sendStop = true);
    size_t requestFrom(uint16_t address, size_t size, bool sendStop = true);
    size_t write(uint8_t);
    size_t write(const uint8_t *, size_t);
    int available();
    int read();
    int peek();
};
extern TwoWire Wire;
extern TwoWire Wire1;
