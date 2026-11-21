// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#define UPDATE_SIZE_UNKNOWN 0xFFFFFFFF
#define U_FLASH 0
#define U_SPIFFS 100
class UpdateClass {
public:
    bool begin(size_t size = UPDATE_SIZE_UNKNOWN, int command = U_FLASH, int ledPin = -1, uint8_t ledOn = LOW, const char *label = nullptr);
    size_t write(uint8_t *data, size_t len);
    size_t writeStream(Stream &data);
    bool end(bool evenIfRemaining = false);
    void abort();
    bool hasError();
    bool isFinished();
    bool setMD5(const char *expected_md5);
    String errorString();
};
extern UpdateClass Update;
