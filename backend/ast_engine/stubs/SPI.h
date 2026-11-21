// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
class SPISettings { public: SPISettings(uint32_t clock, uint8_t bitOrder, uint8_t dataMode); };
class SPIClass {
public:
    SPIClass(uint8_t spi_bus = 3);
    void begin(int8_t sck = -1, int8_t miso = -1, int8_t mosi = -1, int8_t ss = -1);
    void end();
    void beginTransaction(SPISettings settings);
    void endTransaction();
    uint8_t transfer(uint8_t data);
};
extern SPIClass SPI;
