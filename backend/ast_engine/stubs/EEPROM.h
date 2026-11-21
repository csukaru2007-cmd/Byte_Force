// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
class EEPROMClass {
public:
    bool begin(size_t size);
    uint8_t read(int address);
    void write(int address, uint8_t val);
    bool commit();
    void end();
};
extern EEPROMClass EEPROM;
